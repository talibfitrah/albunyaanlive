#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
let puppeteer;
try {
  const pextra = require('puppeteer-extra');
  const StealthPlugin = require('puppeteer-extra-plugin-stealth');
  pextra.use(StealthPlugin());
  puppeteer = pextra;
} catch (_) {
  puppeteer = require('puppeteer-core');
}

const chromeCandidates = [
  process.env.SEENSHOW_CHROME,
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
  '/snap/bin/chromium',
].filter(Boolean);

const chrome = chromeCandidates.find((p) => fs.existsSync(p));
if (!chrome) {
  console.error('No chrome binary found');
  process.exit(1);
}

const cookiesFile = path.join(__dirname, '.seenshow_cookies.json');
const cookies = fs.existsSync(cookiesFile) ? JSON.parse(fs.readFileSync(cookiesFile, 'utf8')) : [];

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: chrome,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--proxy-server=socks5://127.0.0.1:9050',
    ],
    defaultViewport: { width: 1366, height: 900 },
  });

  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');

  if (Array.isArray(cookies) && cookies.length > 0) {
    await page.setCookie(...cookies.filter((c) => c.domain && c.domain.includes('seenshow.com')));
    console.log(`restored cookies: ${cookies.length}`);
  }

  page.on('response', async (res) => {
    const url = res.url();
    if (!url.includes('seenshow.com')) return;
    if (!/api\.seenshow\.com|live\.seenshow\.com|\/api\//.test(url)) return;

    const status = res.status();
    const ct = String(res.headers()['content-type'] || '').toLowerCase();
    let marker = '';
    let bodySnippet = '';
    if (ct.includes('json') || ct.includes('text') || ct.includes('mpegurl')) {
      try {
        const body = await res.text();
        if (/hdntl=|live\.seenshow\.com|\.m3u8/.test(body)) {
          marker = ' [contains-stream]';
          bodySnippet = body.slice(0, 800).replace(/\s+/g, ' ');
        }
      } catch (_) {}
    }
    console.log(`[RES ${status}] ${url}${marker}`);
    if (bodySnippet) {
      console.log(`  BODY: ${bodySnippet}`);
    }
  });

  page.on('request', (req) => {
    const url = req.url();
    if (/live\.seenshow\.com.*\.m3u8|api\.seenshow\.com/.test(url)) {
      console.log(`[REQ] ${url}`);
    }
  });

  const target = 'https://seenshow.com/my/live_stream?channelId=18';
  console.log(`goto ${target}`);
  await page.goto(target, { waitUntil: 'networkidle2', timeout: 60000 });
  console.log(`landed at: ${page.url()}`);

  // profile selection attempt
  const profileClicked = await page.evaluate(() => {
    if (!location.pathname.includes('/profile/selectProfile')) return 0;
    const elements = Array.from(document.querySelectorAll('button, a, [role="button"], div'));
    for (const el of elements) {
      const text = (el.textContent || '').trim();
      if (!text) continue;
      if (text.includes('اختر') || text.toLowerCase().includes('profile') || text.includes('متابعة')) {
        try {
          el.click();
          return 1;
        } catch (_) {}
      }
    }
    const first = document.querySelector('button, a, [role="button"]');
    if (first) {
      try { first.click(); return 1; } catch (_) {}
    }
    return 0;
  });
  if (profileClicked) {
    console.log('profile selection click attempted');
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => null);
    console.log(`after profile click url: ${page.url()}`);
  }

  // try play-related clicks
  const clickCount = await page.evaluate(() => {
    const words = ['play', 'watch', 'live', 'تشغيل', 'مشاهدة', 'ابدأ'];
    let count = 0;
    const els = Array.from(document.querySelectorAll('button, a, [role="button"], div'));
    for (const el of els) {
      if (count >= 6) break;
      const txt = ((el.textContent || '') + ' ' + (el.getAttribute('aria-label') || '')).toLowerCase();
      if (!words.some((w) => txt.includes(w))) continue;
      try { el.click(); count++; } catch (_) {}
    }
    return count;
  });
  console.log(`play clicks attempted: ${clickCount}`);

  await page.waitForTimeout(35000);
  console.log(`final url: ${page.url()}`);

  await browser.close();
})();
