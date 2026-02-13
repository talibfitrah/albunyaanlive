#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const resolver = require('../seenshow_resolver');

test('parseTokenExpiry supports hdntl query, hdnts query, and hdntl path formats', () => {
  assert.equal(
    resolver.parseTokenExpiry('https://live.seenshow.com/hls/live/1/A/master.m3u8?hdntl=exp=1770913951~acl=*~hmac=x'),
    1770913951
  );
  assert.equal(
    resolver.parseTokenExpiry('https://live.seenshow.com/hls/live/1/A/master.m3u8?hdnts=exp=1770827601~data=x~acl=*~hmac=y'),
    1770827601
  );
  assert.equal(
    resolver.parseTokenExpiry('https://live.seenshow.com/hls/live/1/A/hdntl=exp=1770999999~acl=%2fhls%2flive%2f1%2fA%2f*~hmac=z/3.m3u8'),
    1770999999
  );
  assert.equal(resolver.parseTokenExpiry('https://live.seenshow.com/hls/live/1/A/master.m3u8'), null);
});

test('extractM3u8UrlsFromText normalizes escaped content and deduplicates', () => {
  const text = `
    {"url":"https:\\/\\/live.seenshow.com\\/hls\\/live\\/1\\/A\\/master.m3u8?hdntl=exp=1\\u0026acl=*"}
    https://live.seenshow.com/hls/live/1/A/master.m3u8?hdntl=exp=1&acl=*
  `;

  const urls = resolver.extractM3u8UrlsFromText(text);
  assert.equal(urls.length, 1);
  assert.ok(urls[0].includes('live.seenshow.com/hls/live/1/A/master.m3u8'));
  assert.ok(urls[0].includes('hdntl=exp=1'));
});

test('parseRoute handles path and query extraction', () => {
  const parsed = resolver.parseRoute('/resolve/2120830/LIVE-004-ELMIA?x=1');
  assert.equal(parsed.pathname, '/resolve/2120830/LIVE-004-ELMIA');
  assert.equal(parsed.params.get('x'), '1');
});

test('validateCredentialsShape requires base_url and normalizes it to origin', () => {
  assert.throws(
    () => resolver.validateCredentialsShape({
      username: 'user@example.com',
      password: 'secret',
      channels: {
        science: { seenshow_id: 33, hls_path: '2120830/LIVE-004-ELMIA' },
      },
    }),
    /missing base_url/
  );

  assert.throws(
    () => resolver.validateCredentialsShape({
      base_url: 'not-a-url',
      username: 'user@example.com',
      password: 'secret',
      channels: {
        science: { seenshow_id: 33, hls_path: '2120830/LIVE-004-ELMIA' },
      },
    }),
    /invalid base_url/
  );

  const valid = resolver.validateCredentialsShape({
    base_url: 'https://seenshow.com/path/ignored?x=1',
    username: ' user@example.com ',
    password: 'secret',
    channels: {
      science: { seenshow_id: 33, hls_path: '2120830/LIVE-004-ELMIA' },
    },
  });

  assert.equal(valid.base_url, 'https://seenshow.com');
  assert.equal(valid.username, 'user@example.com');
});

test('candidateMatchesChannel only accepts URLs for the requested hls_path', () => {
  const channelConfig = { hls_path: '2120830/LIVE-004-ELMIA' };
  assert.equal(
    resolver.candidateMatchesChannel(
      'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/master.m3u8?hdntl=exp=1~acl=*',
      channelConfig
    ),
    true
  );
  assert.equal(
    resolver.candidateMatchesChannel(
      'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/master.m3u8?hdntl=exp=1~acl=*',
      channelConfig
    ),
    false
  );
});

test('selectBestChannelCandidate ignores foreign-channel token URLs', () => {
  const channelConfig = { hls_path: '2120830/LIVE-004-ELMIA' };
  const candidates = new Set([
    'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/master.m3u8?hdntl=exp=999~acl=*',
    'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/master.m3u8?hdnts=exp=888~acl=*',
    'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/hdntl=exp=777~acl=*~hmac=z/3.m3u8',
  ]);
  const meta = new Map([
    [Array.from(candidates)[0], { status: 200, playable: true }],
    [Array.from(candidates)[1], { status: 200, playable: true }],
    [Array.from(candidates)[2], { status: 200, playable: true }],
  ]);

  const tokenOnly = resolver.selectBestChannelCandidate(candidates, meta, channelConfig, { requireToken: true });
  assert.equal(
    tokenOnly,
    'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/hdntl=exp=777~acl=*~hmac=z/3.m3u8'
  );
});

test('slot acquire enforces max concurrent and release frees capacity', () => {
  resolver.resetStateForTests();
  const max = resolver.constants.MAX_CONCURRENT;

  for (let i = 0; i < max; i++) {
    const acquired = resolver.acquireSlot(`ch${i}`);
    assert.equal(acquired.granted, true);
  }

  const denied = resolver.acquireSlot('overflow');
  assert.equal(denied.granted, false);
  assert.equal(denied.reason, 'max_concurrent_reached');

  const refreshed = resolver.acquireSlot('ch0');
  assert.equal(refreshed.granted, true);

  const released = resolver.releaseSlot('ch0');
  assert.equal(released.released, true);

  const retry = resolver.acquireSlot('overflow');
  assert.equal(retry.granted, true);
});

test('sweepStaleSlots removes expired slot entries', () => {
  resolver.resetStateForTests();
  resolver.acquireSlot('stale-channel');

  const realNow = Date.now;
  try {
    Date.now = () => realNow() + resolver.constants.SLOT_AUTO_RELEASE_MS + 5000;
    resolver.sweepStaleSlots();
  } finally {
    Date.now = realNow;
  }

  const staleRelease = resolver.releaseSlot('stale-channel');
  assert.equal(staleRelease.released, false);
});

test('MAX_CONCURRENT defaults to 3 (policy: max 3 unless manually overridden)', () => {
  // Run in a subprocess with SEENSHOW_MAX_CONCURRENT explicitly unset so the
  // test is reliable regardless of the caller's environment.
  // The module logs to stdout on load (puppeteer-extra banner), so we write
  // the result to a temp file to avoid mixing it with log output.
  const { execSync } = require('node:child_process');
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');
  const tmpFile = path.join(os.tmpdir(), `seenshow-test-${process.pid}.txt`);
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'SEENSHOW_MAX_CONCURRENT')
  );
  try {
    const script = `const r = require("./seenshow_resolver"); require("fs").writeFileSync(${JSON.stringify(tmpFile)}, String(r.constants.MAX_CONCURRENT))`;
    execSync(`node -e '${script}'`, {
      cwd: path.resolve(__dirname, '..'),
      env: cleanEnv,
      timeout: 10000,
      stdio: 'ignore',
    });
    const result = fs.readFileSync(tmpFile, 'utf8').trim();
    assert.equal(result, '3');
  } finally {
    try { fs.unlinkSync(tmpFile); } catch (_) { /* ignore */ }
  }
});
