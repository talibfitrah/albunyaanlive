#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseRequestUrl } = require('../lib/resolver_utils');

test('parseRequestUrl accepts absolute-path request targets', () => {
  const parsed = parseRequestUrl('/hls/test/master.m3u8?x=1');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.url.pathname, '/hls/test/master.m3u8');
  assert.equal(parsed.url.searchParams.get('x'), '1');
});

test('parseRequestUrl rejects missing request target', () => {
  const parsed = parseRequestUrl('');
  assert.equal(parsed.ok, false);
  assert.equal(parsed.status, 400);
  assert.match(parsed.error, /missing URL/);
});

test('parseRequestUrl rejects malformed request target encoding', () => {
  const parsed = parseRequestUrl('/hls/%E0%A4%A/segment/test');
  assert.equal(parsed.ok, false);
  assert.equal(parsed.status, 400);
  assert.match(parsed.error, /malformed URL/);
});

test('parseRequestUrl supports absolute URLs but normalizes to parsed pathname', () => {
  const parsed = parseRequestUrl('http://evil.example/proxy/id.m3u8');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.url.pathname, '/proxy/id.m3u8');
});
