'use strict';

const crypto = require('crypto');

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

function defaultHash(url) {
  return crypto.createHash('sha256').update(url).digest('hex').slice(0, 24);
}

function buildSegmentCacheKey(sessionId, segmentUrl, hashFn = defaultHash) {
  if (typeof sessionId !== 'string' || sessionId.trim() === '') {
    throw new Error('sessionId must be a non-empty string');
  }
  if (typeof segmentUrl !== 'string' || segmentUrl.trim() === '') {
    throw new Error('segmentUrl must be a non-empty string');
  }
  return `${sessionId}:${hashFn(segmentUrl)}`;
}

class SegmentCache {
  constructor(options = {}) {
    this.maxItems = clampInt(options.maxItems, 2048, 0, 200000);
    this.maxBytes = clampInt(options.maxBytes, 134217728, 0, 2147483647);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.entries = new Map();
    this.totalBytes = 0;
  }

  stats() {
    return {
      items: this.entries.size,
      totalBytes: this.totalBytes,
      maxItems: this.maxItems,
      maxBytes: this.maxBytes
    };
  }

  clear() {
    this.entries.clear();
    this.totalBytes = 0;
  }

  get(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;

    const now = this.now();
    if (entry.expires <= now) {
      this.delete(key);
      return null;
    }

    // Preserve LRU ordering by moving touched entry to the end.
    this.entries.delete(key);
    entry.lastAccess = now;
    this.entries.set(key, entry);
    return entry.data;
  }

  set(key, data, ttlMs) {
    if (typeof key !== 'string' || key.length === 0) return false;
    if (this.maxItems === 0 || this.maxBytes === 0) return false;

    const ttl = Number.parseInt(String(ttlMs), 10);
    if (!Number.isFinite(ttl) || ttl <= 0) return false;

    if (!Buffer.isBuffer(data)) return false;
    const bytes = data.length;
    if (bytes <= 0 || bytes > this.maxBytes) return false;

    const now = this.now();
    const expires = now + ttl;

    if (this.entries.has(key)) {
      this.delete(key);
    }

    this.entries.set(key, {
      data,
      bytes,
      expires,
      lastAccess: now
    });
    this.totalBytes += bytes;

    this.evictExpired(now);
    this.evictToBudget();
    return this.entries.has(key);
  }

  delete(key) {
    const entry = this.entries.get(key);
    if (!entry) return false;
    this.entries.delete(key);
    this.totalBytes -= entry.bytes;
    if (this.totalBytes < 0) this.totalBytes = 0;
    return true;
  }

  evictExpired(now = this.now()) {
    let removed = 0;
    for (const [key, entry] of this.entries.entries()) {
      if (entry.expires <= now) {
        this.delete(key);
        removed++;
      }
    }
    return removed;
  }

  evictToBudget() {
    let removed = 0;
    while (this.entries.size > this.maxItems || this.totalBytes > this.maxBytes) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey === undefined) break;
      if (this.delete(oldestKey)) removed++;
    }
    return removed;
  }
}

module.exports = {
  SegmentCache,
  buildSegmentCacheKey
};
