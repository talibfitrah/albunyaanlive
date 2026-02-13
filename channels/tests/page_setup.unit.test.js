#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createPageWithSetup } = require('../lib/page_setup');

function createFakePage() {
  return {
    closeCalls: 0,
    async close() {
      this.closeCalls += 1;
    },
  };
}

test('createPageWithSetup returns page and keeps it open after successful setup', async () => {
  const page = createFakePage();
  const browser = {
    async newPage() {
      return page;
    }
  };

  const result = await createPageWithSetup(browser, async (newPage) => {
    assert.equal(newPage, page);
  });

  assert.equal(result, page);
  assert.equal(page.closeCalls, 0);
});

test('createPageWithSetup closes page when setup throws', async () => {
  const page = createFakePage();
  const browser = {
    async newPage() {
      return page;
    }
  };

  await assert.rejects(
    createPageWithSetup(browser, async () => {
      throw new Error('setup failed');
    }),
    /setup failed/
  );

  assert.equal(page.closeCalls, 1);
});

test('createPageWithSetup ignores close errors and keeps original setup error', async () => {
  const page = {
    closeCalls: 0,
    async close() {
      this.closeCalls += 1;
      throw new Error('close failed');
    },
  };
  const browser = {
    async newPage() {
      return page;
    }
  };

  await assert.rejects(
    createPageWithSetup(browser, async () => {
      throw new Error('setup failed');
    }),
    /setup failed/
  );
  assert.equal(page.closeCalls, 1);
});

test('createPageWithSetup validates inputs', async () => {
  await assert.rejects(
    createPageWithSetup(null, async () => {}),
    /newPage/
  );

  const browser = {
    async newPage() {
      return createFakePage();
    }
  };
  await assert.rejects(
    createPageWithSetup(browser, null),
    /setupFn/
  );
});
