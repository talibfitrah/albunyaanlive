#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SessionSlotManager } = require('../lib/session_slots');

test('SessionSlotManager reserves and releases pending slots', async () => {
  let activeCount = 0;
  const slots = new SessionSlotManager({
    maxSessions: 2,
    getActiveCount: () => activeCount,
  });

  await slots.reserve('a');
  assert.equal(slots.pendingCount(), 1);

  await slots.reserve('b');
  assert.equal(slots.pendingCount(), 2);

  assert.equal(slots.release('a'), true);
  assert.equal(slots.pendingCount(), 1);
  assert.equal(slots.release('missing'), false);
});

test('SessionSlotManager enforces max using active + pending counts', async () => {
  let activeCount = 1;
  const slots = new SessionSlotManager({
    maxSessions: 2,
    getActiveCount: () => activeCount,
  });

  await slots.reserve('a');
  await assert.rejects(
    slots.reserve('b'),
    (err) => err && err.code === 'SESSION_LIMIT'
  );
});

test('SessionSlotManager serializes concurrent reserve calls', async () => {
  let activeCount = 0;
  const slots = new SessionSlotManager({
    maxSessions: 1,
    getActiveCount: () => activeCount,
    evictIdle: () => new Promise((resolve) => setTimeout(resolve, 20)),
  });

  const [first, second] = await Promise.allSettled([
    slots.reserve('alpha'),
    slots.reserve('beta'),
  ]);

  const failed = [first, second].filter((result) => result.status === 'rejected');
  const passed = [first, second].filter((result) => result.status === 'fulfilled');

  assert.equal(passed.length, 1);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.code, 'SESSION_LIMIT');
  assert.equal(slots.pendingCount(), 1);

  // Release and verify another reservation can proceed.
  slots.release('alpha');
  slots.release('beta');
  await slots.reserve('gamma');
  assert.equal(slots.pendingCount(), 1);
});
