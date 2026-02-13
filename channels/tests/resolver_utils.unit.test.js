#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  decodeSegmentUrl,
  rewriteManifest,
  validateSegmentProxyUrl
} = require('../lib/resolver_utils');

test('decodeSegmentUrl decodes valid encoded URLs', () => {
  const encoded = encodeURIComponent('https://example.com/live/seg.ts?x=1&y=2');
  const decoded = decodeSegmentUrl(encoded);
  assert.equal(decoded.ok, true);
  assert.equal(decoded.url, 'https://example.com/live/seg.ts?x=1&y=2');
});

test('decodeSegmentUrl rejects malformed encoding', () => {
  const decoded = decodeSegmentUrl('%E0%A4%A');
  assert.equal(decoded.ok, false);
  assert.equal(decoded.status, 400);
  assert.match(decoded.error, /malformed segment URL encoding/);
});

test('decodeSegmentUrl rejects empty input', () => {
  const decoded = decodeSegmentUrl('');
  assert.equal(decoded.ok, false);
  assert.equal(decoded.status, 400);
  assert.match(decoded.error, /missing encoded segment URL/);
});

test('validateSegmentProxyUrl allows expected YouTube CDN hosts', () => {
  const validated = validateSegmentProxyUrl('https://manifest.googlevideo.com/api/manifest/hls_playlist/example');
  assert.equal(validated.ok, true);
  assert.match(validated.url, /^https:\/\/manifest\.googlevideo\.com\//);
});

test('validateSegmentProxyUrl rejects non-http protocols', () => {
  const validated = validateSegmentProxyUrl('file:///tmp/segment.ts');
  assert.equal(validated.ok, false);
  assert.equal(validated.status, 400);
  assert.match(validated.error, /unsupported segment URL protocol/);
});

test('validateSegmentProxyUrl rejects disallowed hosts', () => {
  const validated = validateSegmentProxyUrl('https://127.0.0.1/internal.ts');
  assert.equal(validated.ok, false);
  assert.equal(validated.status, 403);
  assert.match(validated.error, /not allowed/);
});

test('validateSegmentProxyUrl rejects URLs with embedded credentials', () => {
  const validated = validateSegmentProxyUrl('https://user:pass@rr1.googlevideo.com/segment.ts');
  assert.equal(validated.ok, false);
  assert.equal(validated.status, 400);
  assert.match(validated.error, /credentials/);
});

test('rewriteManifest rewrites relative segment lines using manifest base URL', () => {
  const manifest = [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    'chunk-1.ts',
    'chunk-2.ts?token=abc'
  ].join('\n');

  const rewritten = rewriteManifest(
    manifest,
    'session-a',
    'http://127.0.0.1:8088',
    'https://manifest.googlevideo.com/api/manifest/hls_playlist/base/master.m3u8'
  );

  assert.match(rewritten, /http:\/\/127\.0\.0\.1:8088\/hls\/session-a\/segment\/https%3A%2F%2Fmanifest\.googlevideo\.com%2Fapi%2Fmanifest%2Fhls_playlist%2Fbase%2Fchunk-1\.ts/);
  assert.match(rewritten, /http:\/\/127\.0\.0\.1:8088\/hls\/session-a\/segment\/https%3A%2F%2Fmanifest\.googlevideo\.com%2Fapi%2Fmanifest%2Fhls_playlist%2Fbase%2Fchunk-2\.ts%3Ftoken%3Dabc/);
});

test('rewriteManifest rewrites URI attributes in EXT-X tags', () => {
  const manifest = [
    '#EXTM3U',
    '#EXT-X-MAP:URI="init.mp4"',
    '#EXT-X-KEY:METHOD=AES-128,URI="key.bin"',
    '#EXTINF:4.000,',
    'segment-10.ts'
  ].join('\n');

  const rewritten = rewriteManifest(
    manifest,
    'session-b',
    'http://127.0.0.1:8088',
    'https://rr1---sn-vgqs7n7d.googlevideo.com/videoplayback/index.m3u8'
  );

  assert.match(rewritten, /#EXT-X-MAP:URI="http:\/\/127\.0\.0\.1:8088\/hls\/session-b\/segment\/https%3A%2F%2Frr1---sn-vgqs7n7d\.googlevideo\.com%2Fvideoplayback%2Finit\.mp4"/);
  assert.match(rewritten, /#EXT-X-KEY:METHOD=AES-128,URI="http:\/\/127\.0\.0\.1:8088\/hls\/session-b\/segment\/https%3A%2F%2Frr1---sn-vgqs7n7d\.googlevideo\.com%2Fvideoplayback%2Fkey\.bin"/);
});

// ---------------------------------------------------------------------------
// Segment encoding round-trip tests
// Mirrors the chunked base64 encoding in youtube_browser_resolver_v2.js
// (fetchSegmentViaBrowser, lines 337-346) which runs inside page.evaluate.
// ---------------------------------------------------------------------------

/**
 * Replicate the browser-side encoding from fetchSegmentViaBrowser.
 * Browser uses: btoa(chunks.join(''))
 * Node equivalent: Buffer.from(str, 'binary').toString('base64')
 */
function chunkedBase64Encode(buffer, chunkSize) {
  const bytes = new Uint8Array(buffer);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize)));
  }
  return Buffer.from(chunks.join(''), 'binary').toString('base64');
}

test('chunked base64 encoding round-trips correctly for various buffer sizes', () => {
  const CHUNK_SIZE = 8192; // Must match youtube_browser_resolver_v2.js

  const sizes = [0, 1, 100, 8191, 8192, 8193, 16384, 20000, 65536, 100000];
  for (const size of sizes) {
    const original = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
      original[i] = (i * 7 + 13) % 256;
    }
    const encoded = chunkedBase64Encode(original.buffer, CHUNK_SIZE);
    const decoded = Buffer.from(encoded, 'base64');
    assert.equal(decoded.length, size, `round-trip size mismatch for ${size} bytes`);
    assert.ok(decoded.equals(original), `round-trip data mismatch for ${size} bytes`);
  }
});

test('chunked encoding produces identical output to single-pass encoding', () => {
  const CHUNK_SIZE = 8192;
  // Use a buffer larger than CHUNK_SIZE to exercise multi-chunk path
  const size = CHUNK_SIZE * 3 + 500;
  const original = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    original[i] = (i * 251 + 37) % 256; // different fill pattern
  }

  const chunked = chunkedBase64Encode(original.buffer, CHUNK_SIZE);
  const singlePass = original.toString('base64');
  assert.equal(chunked, singlePass, 'chunked encoding must match single-pass base64');
});

test('CHUNK_SIZE 8192 stays within V8 Function.prototype.apply argument limit', () => {
  // V8 max args for apply is 65536 on most engines, 32768 on some older.
  // Using 8192 provides a 4-8x safety margin.
  const CHUNK_SIZE = 8192;
  assert.ok(CHUNK_SIZE <= 32768, 'CHUNK_SIZE must be within safe V8 limits');
  assert.ok(CHUNK_SIZE > 0, 'CHUNK_SIZE must be positive');

  // Verify String.fromCharCode.apply actually works at this size
  const bytes = new Uint8Array(CHUNK_SIZE);
  for (let i = 0; i < CHUNK_SIZE; i++) bytes[i] = i % 256;
  const result = String.fromCharCode.apply(null, bytes);
  assert.equal(result.length, CHUNK_SIZE, 'fromCharCode.apply must handle full chunk');
});
