/**
 * Audit Writer Queue - Distributed Redis Caching & Throughput Telemetry
 *
 * Provides a thread-safe queue for audit log writes to prevent race conditions
 * when multiple concurrent requests attempt to write audit logs simultaneously.
 *
 * Key features:
 * - Sequential processing: ensures writes happen one at a time (default)
 * - Promise-based queueing: callers await their turn
 * - Graceful error handling: one failed write doesn't block the queue
 * - Metrics integration: tracks queue depth, processing time, active concurrency, and throughput telemetry
 * - Memory bounded: configurable max queue size prevents OOM
 * - Distributed Redis caching: multi-tier (L1 memory + L2 Redis) caching for audit records & write results
 * - Throughput telemetry: Prometheus metrics and internal rolling-window telemetry for operations/sec & latency
 *
 * Concurrency control:
 *   Adds `setMaxConcurrency(n)` to control how many write operations run in
 *   parallel. Internally uses a semaphore (counter + waiter queue) so that
 *   transitioning from fully-sequential (n=1) to concurrent (n>1) is safe at
 *   runtime.
 */

import client from "prom-client";
import { auditLogQueueDepth, auditLogQueueWaitDuration } from "./metrics.js";
import { getRedisClient } from "./redis.js";
import { logger } from "./logger.js";

// ── Prometheus Metrics (Self-contained registry to prevent registration conflicts) ──────

const _queueRegistry = new client.Registry();

const auditWriteQueueConcurrencyActive = new client.Gauge({
  name: "audit_write_queue_concurrency_active",
  help: "Number of audit write operations currently executing (bounded by maxConcurrency)",
  labelNames: ["label"],
  registers: [_queueRegistry],
});

const auditWriteQueueThroughputTotal = new client.Counter({
  name: "audit_write_queue_throughput_total",
  help: "Total throughput count of audit write operations by status",
  labelNames: ["label", "status"],
  registers: [_queueRegistry],
});

const auditWriteQueueExecutionDuration = new client.Histogram({
  name: "audit_write_queue_execution_duration_seconds",
  help: "Execution duration of audit write operations in seconds",
  labelNames: ["label", "status"],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5],
  registers: [_queueRegistry],
});

const auditWriteQueueCacheOperationsTotal = new client.Counter({
  name: "audit_write_queue_cache_operations_total",
  help: "Audit writer queue cache operations total by operation and result",
  labelNames: ["label", "operation", "result"],
  registers: [_queueRegistry],
});

const auditWriteQueueThroughputRate = new client.Gauge({
  name: "audit_write_queue_throughput_rate",
  help: "Instantaneous audit write operations throughput per second",
  labelNames: ["label"],
  registers: [_queueRegistry],
});

export class AuditWriterQueue {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxQueueSize=1000]       - Maximum pending items before dropping
   * @param {string} [opts.label="audit-queue"]      - Prometheus/log label
   * @param {number} [opts.maxConcurrency=1]        - Max parallel write operations
   * @param {object} [opts.redisClient=null]        - Distributed Redis client instance (optional)
   * @param {boolean} [opts.useRedis=true]          - Whether Redis caching is enabled
   * @param {number} [opts.redisTtlSeconds=300]     - Default TTL for cached audit records (seconds)
   * @param {string} [opts.redisKeyPrefix]          - Prefix for Redis keys
   * @param {number} [opts.maxMemoryCacheSize=1000] - Max L1 in-memory cache entries
   */
  constructor({
    maxQueueSize = 1000,
    label = "audit-queue",
    maxConcurrency = 1,
    redisClient = null,
    useRedis = true,
    redisTtlSeconds = 300,
    redisKeyPrefix = "audit:queue:cache:",
    maxMemoryCacheSize = 1000,
  } = {}) {
    this.maxQueueSize = maxQueueSize;
    this.label = label;

    this.queue = [];
    this.processing = false;
    this.droppedCount = 0;

    // Semaphore state
    this._maxConcurrency = maxConcurrency;
    this._activeCount = 0; // currently running operations
    this._semWaiters = []; // resolve callbacks waiting to acquire a slot

    // Distributed Cache configuration
    this._redisClient = redisClient;
    this._useRedis = useRedis;
    this.redisTtlSeconds = redisTtlSeconds;
    this.defaultTtlMs = redisTtlSeconds * 1000;
    this.redisKeyPrefix = redisKeyPrefix;
    this._maxMemoryCacheSize = maxMemoryCacheSize;
    this._memoryCache = new Map();

    // Throughput Telemetry State
    this._telemetry = {
      totalByStatus: {},
      processedTimestamps: [],
      totalExecutionTimeMs: 0,
      executionCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      cacheErrors: 0,
    };
  }

  // ── Redis Resolution ────────────────────────────────────────────────────────

  /**
   * Safe getter for Redis client with lazy fallback.
   * @private
   */
  _getRedis() {
    if (!this._useRedis) return null;
    if (this._redisClient) return this._redisClient;
    try {
      this._redisClient = getRedisClient();
      return this._redisClient;
    } catch {
      return null;
    }
  }

  // ── Cache Operations ────────────────────────────────────────────────────────

  /**
   * Formats a cache key with namespace prefix.
   * @param {string} key
   * @returns {string}
   * @private
   */
  _formatCacheKey(key) {
    const rawKey = typeof key === "string" ? key : JSON.stringify(key);
    if (rawKey.startsWith(this.redisKeyPrefix)) {
      return rawKey;
    }
    return `${this.redisKeyPrefix}${rawKey}`;
  }

  /**
   * Records cache operation metrics.
   * @private
   */
  _recordCacheOp(operation, result) {
    if (result === "hit") this._telemetry.cacheHits++;
    if (result === "miss") this._telemetry.cacheMisses++;
    if (result === "error") this._telemetry.cacheErrors++;

    auditWriteQueueCacheOperationsTotal.inc({
      label: this.label,
      operation,
      result,
    });
  }

  /**
   * Sets L1 in-memory cache with eviction.
   * @private
   */
  _setMemoryCache(key, data, ttlMs) {
    if (this._memoryCache.size >= this._maxMemoryCacheSize) {
      const oldestKey = this._memoryCache.keys().next().value;
      if (oldestKey !== undefined) {
        this._memoryCache.delete(oldestKey);
      }
    }
    this._memoryCache.set(key, {
      data,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Retrieve an audit record from multi-tier cache (L1 memory, L2 Redis).
   *
   * @param {string} key - Cache key
   * @returns {Promise<any|null>} Cached record or null
   */
  async getCachedRecord(key) {
    if (!key) return null;
    const cacheKey = this._formatCacheKey(key);

    // 1. Check L1 Memory Cache
    const memEntry = this._memoryCache.get(cacheKey);
    if (memEntry) {
      if (memEntry.expiresAt > Date.now()) {
        this._recordCacheOp("get", "hit");
        return memEntry.data;
      }
      this._memoryCache.delete(cacheKey);
    }

    // 2. Check L2 Redis Cache
    const redis = this._getRedis();
    if (redis) {
      try {
        if (typeof redis.isOpen === "boolean" && !redis.isOpen) {
          this._recordCacheOp("get", "miss");
          return null;
        }
        const val = await redis.get(cacheKey);
        if (val) {
          const parsed = JSON.parse(val);
          this._setMemoryCache(cacheKey, parsed, this.defaultTtlMs);
          this._recordCacheOp("get", "hit");
          return parsed;
        }
      } catch (err) {
        logger?.warn?.({ err, key: cacheKey }, "[AuditWriterQueue] Redis get failed");
        this._recordCacheOp("get", "error");
      }
    }

    this._recordCacheOp("get", "miss");
    return null;
  }

  /**
   * Set an audit record in multi-tier cache (L1 memory, L2 Redis).
   *
   * @param {string} key - Cache key
   * @param {any} data - Data to cache
   * @param {number} [ttlSeconds] - Optional custom TTL
   * @returns {Promise<void>}
   */
  async setCachedRecord(key, data, ttlSeconds) {
    if (!key || data === undefined) return;
    const cacheKey = this._formatCacheKey(key);
    const ttl = ttlSeconds ? ttlSeconds * 1000 : this.defaultTtlMs;
    const ttlSec = Math.ceil(ttl / 1000);

    // L1 Memory Cache
    this._setMemoryCache(cacheKey, data, ttl);

    // L2 Redis Cache
    const redis = this._getRedis();
    if (redis) {
      try {
        if (typeof redis.isOpen === "boolean" && !redis.isOpen) {
          return;
        }
        const serialized = JSON.stringify(data);
        if (typeof redis.set === "function") {
          await redis.set(cacheKey, serialized, {
            EX: ttlSec,
            PX: ttl,
          });
        }
        this._recordCacheOp("set", "success");
      } catch (err) {
        logger?.warn?.({ err, key: cacheKey }, "[AuditWriterQueue] Redis set failed");
        this._recordCacheOp("set", "error");
      }
    }
  }

  /**
   * Invalidate a cached audit record from memory and Redis.
   *
   * @param {string} key - Cache key
   * @returns {Promise<void>}
   */
  async invalidateCachedRecord(key) {
    if (!key) return;
    const cacheKey = this._formatCacheKey(key);

    this._memoryCache.delete(cacheKey);

    const redis = this._getRedis();
    if (redis) {
      try {
        if (typeof redis.isOpen === "boolean" && !redis.isOpen) {
          return;
        }
        if (typeof redis.del === "function") {
          await redis.del(cacheKey);
        }
        this._recordCacheOp("invalidate", "success");
      } catch (err) {
        logger?.warn?.({ err, key: cacheKey }, "[AuditWriterQueue] Redis del failed");
        this._recordCacheOp("invalidate", "error");
      }
    }
  }

  /**
   * Clears in-memory cache.
   */
  clearCache() {
    this._memoryCache.clear();
  }

  // ── Throughput Telemetry Helpers ───────────────────────────────────────────

  /**
   * Records throughput telemetry metrics.
   * @private
   */
  _recordThroughput(status, durationMs = 0) {
    const now = Date.now();
    this._telemetry.totalByStatus[status] =
      (this._telemetry.totalByStatus[status] || 0) + 1;

    auditWriteQueueThroughputTotal.inc({ label: this.label, status });

    if (status === "success" || status === "failure" || status === "cached") {
      this._telemetry.processedTimestamps.push(now);

      // Maintain 60-second sliding window
      const cutoff = now - 60000;
      while (
        this._telemetry.processedTimestamps.length > 0 &&
        this._telemetry.processedTimestamps[0] < cutoff
      ) {
        this._telemetry.processedTimestamps.shift();
      }

      if (durationMs > 0) {
        this._telemetry.totalExecutionTimeMs += durationMs;
        this._telemetry.executionCount += 1;
      }

      const windowSec = Math.max(
        1,
        (now - (this._telemetry.processedTimestamps[0] || now)) / 1000
      );
      const rate = this._telemetry.processedTimestamps.length / (windowSec || 1);
      auditWriteQueueThroughputRate.set(
        { label: this.label },
        Math.round(rate * 100) / 100
      );
    }
  }

  /**
   * Returns calculated throughput telemetry.
   * @returns {object} Telemetry statistics
   */
  getThroughputTelemetry() {
    const now = Date.now();
    const cutoff = now - 60000;
    while (
      this._telemetry.processedTimestamps.length > 0 &&
      this._telemetry.processedTimestamps[0] < cutoff
    ) {
      this._telemetry.processedTimestamps.shift();
    }

    const windowSec =
      this._telemetry.processedTimestamps.length > 1
        ? Math.max(1, (now - this._telemetry.processedTimestamps[0]) / 1000)
        : 1;

    const ratePerSec =
      this._telemetry.processedTimestamps.length > 0
        ? Math.round((this._telemetry.processedTimestamps.length / windowSec) * 100) / 100
        : 0;

    const avgDurationMs =
      this._telemetry.executionCount > 0
        ? Math.round(
            (this._telemetry.totalExecutionTimeMs / this._telemetry.executionCount) * 100
          ) / 100
        : 0;

    const cacheTotal = this._telemetry.cacheHits + this._telemetry.cacheMisses;
    const cacheHitRatio =
      cacheTotal > 0
        ? Math.round((this._telemetry.cacheHits / cacheTotal) * 100) / 100
        : 0;

    return {
      totalEnqueued: this._telemetry.totalByStatus["enqueued"] || 0,
      totalProcessed:
        (this._telemetry.totalByStatus["success"] || 0) +
        (this._telemetry.totalByStatus["failure"] || 0),
      totalSuccess: this._telemetry.totalByStatus["success"] || 0,
      totalFailed: this._telemetry.totalByStatus["failure"] || 0,
      totalCached: this._telemetry.totalByStatus["cached"] || 0,
      totalDropped: this.droppedCount,
      operationsPerSecond: ratePerSec,
      averageExecutionTimeMs: avgDurationMs,
      cacheHits: this._telemetry.cacheHits,
      cacheMisses: this._telemetry.cacheMisses,
      cacheErrors: this._telemetry.cacheErrors,
      cacheHitRatio,
    };
  }

  /**
   * Returns cache stats.
   * @returns {object}
   */
  getCacheStats() {
    return {
      memoryEntries: this._memoryCache.size,
      maxMemoryEntries: this._maxMemoryCacheSize,
      cacheHits: this._telemetry.cacheHits,
      cacheMisses: this._telemetry.cacheMisses,
      cacheErrors: this._telemetry.cacheErrors,
      redisEnabled: this._useRedis && Boolean(this._getRedis()),
    };
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Dynamically update the concurrency limit.
   * Immediately allows additional waiters to proceed if the new limit is higher.
   *
   * @param {number} n - New maximum concurrency (must be >= 1)
   */
  setMaxConcurrency(n) {
    if (typeof n !== "number" || n < 1) {
      throw new RangeError("maxConcurrency must be a positive integer");
    }
    this._maxConcurrency = n;
    // Wake up any queued waiters that can now proceed.
    this._drainSemaphoreWaiters();
  }

  /**
   * Enqueues a write operation and waits for it to complete.
   * Supports optional distributed caching parameters.
   * Throws if queue is full.
   *
   * @param {Function} writeFn - Async write function to execute
   * @param {object} [options] - Optional caching / execution parameters
   * @param {string} [options.cacheKey] - Cache key to bypass write if cached
   * @param {any} [options.payload] - Payload metadata
   * @param {number} [options.ttlSeconds] - Custom TTL in seconds for cached result
   * @param {boolean} [options.skipCache=false] - Skip reading from cache
   * @returns {Promise<any>}
   */
  async enqueue(writeFn, options = {}) {
    const opts = typeof options === "object" && options !== null ? options : {};
    const cacheKey =
      opts.cacheKey || (opts.payload?.id ? `audit:record:${opts.payload.id}` : null);

    // Fast-path: Check distributed / memory cache if cacheKey provided
    if (cacheKey && !opts.skipCache) {
      const cached = await this.getCachedRecord(cacheKey);
      if (cached !== null && cached !== undefined) {
        this._recordThroughput("cached");
        return cached;
      }
    }

    if (this.queue.length >= this.maxQueueSize) {
      this.droppedCount++;
      this._recordThroughput("dropped");
      throw new Error(`Audit write queue full (${this.maxQueueSize} entries)`);
    }

    this._recordThroughput("enqueued");
    const enqueuedAt = process.hrtime.bigint();

    return new Promise((resolve, reject) => {
      this.queue.push({
        writeFn,
        resolve,
        reject,
        enqueuedAt,
        cacheKey,
        payload: opts.payload,
        ttlSeconds: opts.ttlSeconds,
      });

      auditLogQueueDepth.set({ label: this.label }, this.queue.length);

      // Start processing if not already running.
      if (!this.processing) {
        this.processQueue().catch((err) => {
          console.error(`[${this.label}] Queue processing failed:`, err);
        });
      }
    });
  }

  // ── Internal processing ─────────────────────────────────────────────────────

  async processQueue() {
    if (this.processing) return;
    this.processing = true;

    while (this.queue.length > 0) {
      // Acquire a concurrency slot before dispatching.
      await this._acquireSlot();

      const item = this.queue.shift();
      if (!item) {
        // Queue drained while we were waiting; release and re-check.
        this._releaseSlot();
        continue;
      }

      auditLogQueueDepth.set({ label: this.label }, this.queue.length);

      const waitDurationSeconds =
        Number(process.hrtime.bigint() - item.enqueuedAt) / 1e9;
      auditLogQueueWaitDuration.observe({ label: this.label }, waitDurationSeconds);

      auditWriteQueueConcurrencyActive.set({ label: this.label }, this._activeCount);

      const writeStart = process.hrtime.bigint();

      // Dispatch the write without awaiting here so that when maxConcurrency > 1
      // the loop can immediately grab another slot.
      const dispatch = Promise.resolve()
        .then(() => item.writeFn())
        .then(async (result) => {
          const durationSec = Number(process.hrtime.bigint() - writeStart) / 1e9;
          auditWriteQueueExecutionDuration.observe(
            { label: this.label, status: "success" },
            durationSec
          );
          this._recordThroughput("success", durationSec * 1000);

          if (item.cacheKey) {
            await this.setCachedRecord(
              item.cacheKey,
              result !== undefined ? result : item.payload,
              item.ttlSeconds
            );
          }
          item.resolve(result);
        })
        .catch((err) => {
          const durationSec = Number(process.hrtime.bigint() - writeStart) / 1e9;
          auditWriteQueueExecutionDuration.observe(
            { label: this.label, status: "failure" },
            durationSec
          );
          this._recordThroughput("failure", durationSec * 1000);
          item.reject(err);
        })
        .finally(() => {
          this._releaseSlot();
          auditWriteQueueConcurrencyActive.set({ label: this.label }, this._activeCount);
        });

      // When fully sequential (maxConcurrency === 1) we must wait for the
      // dispatch to finish before allowing the next item through; the semaphore
      // enforces this naturally because _activeCount will equal _maxConcurrency.
      // For maxConcurrency > 1 we let the loop continue immediately.
      if (this._maxConcurrency === 1) {
        await dispatch;
      }
    }

    this.processing = false;
  }

  // ── Semaphore helpers ────────────────────────────────────────────────────────

  /**
   * Waits until a concurrency slot is available, then claims it.
   * @returns {Promise<void>}
   */
  _acquireSlot() {
    if (this._activeCount < this._maxConcurrency) {
      this._activeCount++;
      return Promise.resolve();
    }
    // All slots taken — queue until one is released.
    return new Promise((resolve) => {
      this._semWaiters.push(resolve);
    });
  }

  /**
   * Releases a concurrency slot, waking the next waiter if any.
   */
  _releaseSlot() {
    this._activeCount = Math.max(0, this._activeCount - 1);
    this._drainSemaphoreWaiters();
  }

  /**
   * Wake up as many semaphore waiters as possible given current limit.
   */
  _drainSemaphoreWaiters() {
    while (
      this._semWaiters.length > 0 &&
      this._activeCount < this._maxConcurrency
    ) {
      this._activeCount++;
      const next = this._semWaiters.shift();
      next();
    }
  }

  // ── Monitoring & test helpers ────────────────────────────────────────────────

  /**
   * Returns queue stats and telemetry for monitoring.
   */
  getStats() {
    return {
      queueDepth: this.queue.length,
      droppedCount: this.droppedCount,
      processing: this.processing,
      maxQueueSize: this.maxQueueSize,
      maxConcurrency: this._maxConcurrency,
      activeCount: this._activeCount,
      telemetry: this.getThroughputTelemetry(),
      cache: this.getCacheStats(),
    };
  }

  /**
   * Test helper: reset queue and cache state.
   */
  _resetForTests() {
    this.queue = [];
    this.processing = false;
    this.droppedCount = 0;
    this._activeCount = 0;
    this._semWaiters = [];
    this._memoryCache.clear();
    this._telemetry = {
      totalByStatus: {},
      processedTimestamps: [],
      totalExecutionTimeMs: 0,
      executionCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      cacheErrors: 0,
    };
  }
}

/**
 * Wraps an audit writer to use the queue for all writes.
 *
 * @param {object} writer - Base writer object with `.write()` method
 * @param {string} queueLabel - Identifier label
 * @param {object} [options] - Options passed to AuditWriterQueue
 * @returns {object} Queued audit writer
 */
export function createQueuedAuditWriter(writer, queueLabel, options = {}) {
  const queue = new AuditWriterQueue({ label: queueLabel, ...options });

  return {
    ...writer,
    write: (sql, params, payload) => {
      // Enqueue the write, ensuring it executes within the concurrency limit.
      return queue.enqueue(() => writer.write(sql, params, payload), { payload });
    },
    getQueueStats: () => queue.getStats(),
    getTelemetry: () => queue.getThroughputTelemetry(),
    getCacheStats: () => queue.getCacheStats(),
    getCachedRecord: (key) => queue.getCachedRecord(key),
    setCachedRecord: (key, data, ttl) => queue.setCachedRecord(key, data, ttl),
    invalidateCachedRecord: (key) => queue.invalidateCachedRecord(key),
    _resetQueueForTests: () => queue._resetForTests(),
    // Expose the queue instance for tests that need setMaxConcurrency.
    _queue: queue,
  };
}
