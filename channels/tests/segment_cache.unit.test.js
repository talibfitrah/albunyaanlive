#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SegmentCache, buildSegmentCacheKey } = require('../lib/segment_cache');

test('buildSegmentCacheKey is session-scoped', () => {
  const url = 'https://example.com/segment.ts';
  const a = buildSegmentCacheKey('session-a', url);
  const b = buildSegmentCacheKey('session-b', url);
  assert.notEqual(a, b);
});

test('buildSegmentCacheKey rejects empty inputs', () => {
  assert.throws(() => buildSegmentCacheKey('', 'https://example.com/x.ts'), /sessionId/);
  assert.throws(() => buildSegmentCacheKey('session', ''), /segmentUrl/);
});

test('SegmentCache set/get stores binary buffers', () => {
  const cache = new SegmentCache({ maxItems: 10, maxBytes: 1024 });
  const payload = Buffer.from('abc123');

  assert.equal(cache.set('k1', payload, 1000), true);
  const hit = cache.get('k1');
  assert.ok(Buffer.isBuffer(hit));
  assert.equal(hit.toString('utf8'), 'abc123');
});

test('SegmentCache enforces maxBytes with LRU eviction', () => {
  const cache = new SegmentCache({ maxItems: 10, maxBytes: 10 });
  cache.set('a', Buffer.from('aaaa'), 1000); // 4
  cache.set('b', Buffer.from('bbbb'), 1000); // 8
  assert.ok(cache.get('a')); // make a most-recent

  cache.set('c', Buffer.from('cccc'), 1000); // 12 -> evict b

  assert.ok(cache.get('a'));
  assert.equal(cache.get('b'), null);
  assert.ok(cache.get('c'));
  assert.equal(cache.stats().totalBytes <= 10, true);
});

test('SegmentCache enforces maxItems', () => {
  const cache = new SegmentCache({ maxItems: 2, maxBytes: 1024 });
  cache.set('a', Buffer.from('1'), 1000);
  cache.set('b', Buffer.from('2'), 1000);
  cache.set('c', Buffer.from('3'), 1000);

  assert.equal(cache.get('a'), null);
  assert.ok(cache.get('b'));
  assert.ok(cache.get('c'));
  assert.equal(cache.stats().items, 2);
});

test('SegmentCache rejects oversized entries', () => {
  const cache = new SegmentCache({ maxItems: 10, maxBytes: 4 });
  const ok = cache.set('big', Buffer.from('12345'), 1000);
  assert.equal(ok, false);
  assert.equal(cache.get('big'), null);
});

test('SegmentCache evicts expired entries', () => {
  let now = 1000;
  const cache = new SegmentCache({
    maxItems: 10,
    maxBytes: 1024,
    now: () => now
  });

  cache.set('short', Buffer.from('x'), 10);
  now += 20;

  assert.equal(cache.get('short'), null);
  assert.equal(cache.stats().items, 0);
});
