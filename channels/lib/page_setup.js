'use strict';

async function createPageWithSetup(browserInstance, setupFn) {
  if (!browserInstance || typeof browserInstance.newPage !== 'function') {
    throw new Error('browserInstance.newPage must be a function');
  }
  if (typeof setupFn !== 'function') {
    throw new Error('setupFn must be a function');
  }

  const page = await browserInstance.newPage();
  let setupCompleted = false;
  try {
    await setupFn(page);
    setupCompleted = true;
    return page;
  } finally {
    if (!setupCompleted && page && typeof page.close === 'function') {
      await page.close().catch(() => {});
    }
  }
}

module.exports = {
  createPageWithSetup,
};
