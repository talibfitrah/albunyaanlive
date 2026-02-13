'use strict';

function createSessionLimitError(maxSessions) {
  const err = new Error(`session limit reached (${maxSessions})`);
  err.code = 'SESSION_LIMIT';
  return err;
}

class SessionSlotManager {
  constructor(options = {}) {
    const {
      maxSessions,
      getActiveCount,
      evictIdle,
    } = options;

    if (!Number.isInteger(maxSessions) || maxSessions < 1) {
      throw new Error('maxSessions must be an integer >= 1');
    }
    if (typeof getActiveCount !== 'function') {
      throw new Error('getActiveCount must be a function');
    }

    this.maxSessions = maxSessions;
    this.getActiveCount = getActiveCount;
    this.evictIdle = typeof evictIdle === 'function' ? evictIdle : async () => {};
    this.pendingReservations = new Set();
    this.lock = Promise.resolve();
  }

  async reserve(id) {
    if (typeof id !== 'string' || id.trim() === '') {
      throw new Error('id must be a non-empty string');
    }
    const sessionId = id.trim();

    return this.withLock(async () => {
      await this.evictIdle();

      if (this.pendingReservations.has(sessionId)) {
        return;
      }

      const activeCountRaw = this.getActiveCount();
      const activeCount = Number.isFinite(activeCountRaw) && activeCountRaw > 0
        ? Math.floor(activeCountRaw)
        : 0;
      const projectedCount = activeCount + this.pendingReservations.size;

      if (projectedCount >= this.maxSessions) {
        throw createSessionLimitError(this.maxSessions);
      }

      this.pendingReservations.add(sessionId);
    });
  }

  release(id) {
    if (typeof id !== 'string' || id.trim() === '') {
      return false;
    }
    return this.pendingReservations.delete(id.trim());
  }

  pendingCount() {
    return this.pendingReservations.size;
  }

  snapshot() {
    return {
      maxSessions: this.maxSessions,
      pendingReservations: this.pendingReservations.size,
    };
  }

  withLock(fn) {
    const task = this.lock.then(() => fn());
    this.lock = task.catch(() => {});
    return task;
  }
}

module.exports = {
  SessionSlotManager,
  createSessionLimitError,
};
