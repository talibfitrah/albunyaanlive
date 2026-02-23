#!/usr/bin/env node
'use strict';

// =============================================================================
// Seenshow Token Resolver Service
// =============================================================================
// Authenticates with seenshow.com (Keycloak OIDC) via Puppeteer, extracts
// Akamai hdntl-tokenized HLS URLs for all configured channels, caches tokens,
// and exposes an HTTP API for on-demand resolution and connection management.
//
// Endpoints:
//   GET  /health          — Service health + token/slot summary
//   GET  /resolve/:path   — Fresh tokenized URL for a channel (path = "ID/NAME")
//   GET  /token-status    — All cached tokens with expiry info
//   POST /acquire/:id     — Acquire a concurrent-stream slot for a channel
//   POST /release/:id     — Release a concurrent-stream slot
//   POST /refresh         — Trigger immediate token refresh for all channels
//
// Env vars:
//   SEENSHOW_RESOLVER_PORT       (default: 8090)
//   SEENSHOW_RESOLVER_HOST       (default: 127.0.0.1)
//   SEENSHOW_MAX_CONCURRENT      (default: 3)
//   SEENSHOW_CREDENTIALS_FILE    (default: seenshow_credentials.json)
//   SEENSHOW_TOKEN_REFRESH_MS    (default: 86400000 = 24h)
//   SEENSHOW_TOKEN_MARGIN_MS     (default: 21600000 = 6h before expiry)
//   SEENSHOW_AUTH_PROXY           (default: socks5://127.0.0.1:9050)
//   SEENSHOW_CHROME               (override Chrome path)
//   SEENSHOW_HEADLESS             (default: true, set "false" for debug)
// =============================================================================

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// Puppeteer setup (same pattern as youtube_browser_resolver_v2.js)
// ---------------------------------------------------------------------------
let puppeteer = null;
let puppeteerLoadError = null;
try {
  const puppeteerExtra = require('puppeteer-extra');
  const StealthPlugin = require('puppeteer-extra-plugin-stealth');
  puppeteerExtra.use(StealthPlugin());
  puppeteer = puppeteerExtra;
  console.log('[seenshow] Using puppeteer-extra with stealth plugin');
} catch (_) {
  try {
    puppeteer = require('puppeteer-core');
    console.log('[seenshow] Using puppeteer-core (no stealth)');
  } catch (_2) {
    try {
      puppeteer = require('puppeteer');
      console.log('[seenshow] Using puppeteer (no stealth)');
    } catch (_3) {
      puppeteerLoadError = new Error(
        'Missing dependency: install puppeteer-extra + stealth or puppeteer-core'
      );
      if (require.main === module) {
        console.error('[seenshow]', puppeteerLoadError.message);
        process.exit(1);
      } else {
        console.warn('[seenshow] WARN:', puppeteerLoadError.message);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function parseBoundedInt(raw, fallback, min, max) {
  const n = Number.parseInt(String(raw ?? fallback), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

const PORT = parseBoundedInt(process.env.SEENSHOW_RESOLVER_PORT, 8090, 1, 65535);
const HOST = process.env.SEENSHOW_RESOLVER_HOST || '127.0.0.1';
const MAX_CONCURRENT = parseBoundedInt(process.env.SEENSHOW_MAX_CONCURRENT, 3, 1, 20);
const TOKEN_REFRESH_MS = parseBoundedInt(process.env.SEENSHOW_TOKEN_REFRESH_MS, 86400000, 60000, 172800000); // 24h
const TOKEN_MARGIN_MS = parseBoundedInt(process.env.SEENSHOW_TOKEN_MARGIN_MS, 21600000, 600000, 86400000); // 6h
const AUTH_PROXY = process.env.SEENSHOW_AUTH_PROXY || 'socks5://127.0.0.1:9050';
const HEADLESS = process.env.SEENSHOW_HEADLESS !== 'false';
const CHANNELS_DIR = path.resolve(process.env.SEENSHOW_BASE_DIR || __dirname);
const COOKIES_FILE = path.join(CHANNELS_DIR, '.seenshow_cookies.json'); // session persistence
const CREDENTIALS_FILE = process.env.SEENSHOW_CREDENTIALS_FILE
  ? path.resolve(process.env.SEENSHOW_CREDENTIALS_FILE)
  : path.join(CHANNELS_DIR, 'seenshow_credentials.json');

// Page navigation / token extraction timeouts
const NAV_TIMEOUT = 60000;
const TOKEN_EXTRACT_TIMEOUT = 30000;
const SLOT_AUTO_RELEASE_MS = 1800000; // 30min — auto-release leaked slots
const LOGIN_RETRY_DELAY = 10000;
const MAX_LOGIN_RETRIES = 3;
const BROWSER_MAX_AGE_MS = parseBoundedInt(
  process.env.SEENSHOW_BROWSER_MAX_AGE_MS, 21600000, 3600000, 172800000
); // 6h default — recycle Chrome to prevent memory leaks

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(...args) {
  console.log(`[${new Date().toISOString()}] [seenshow]`, ...args);
}
function warn(...args) {
  console.warn(`[${new Date().toISOString()}] [seenshow] WARN:`, ...args);
}
function error(...args) {
  console.error(`[${new Date().toISOString()}] [seenshow] ERROR:`, ...args);
}

// ---------------------------------------------------------------------------
// Chrome path detection (reuse from youtube resolver)
// ---------------------------------------------------------------------------

function findChromePath() {
  const candidates = [
    process.env.SEENSHOW_CHROME,
    process.env.CHROMIUM,
    process.env.CHROME,
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/snap/bin/chromium',
  ];
  for (const p of candidates) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

const CHROME_PATH = findChromePath();
if (!CHROME_PATH) {
  const chromeError = '[seenshow] Chrome/Chromium not found. Set SEENSHOW_CHROME env var.';
  if (require.main === module) {
    console.error(chromeError);
    process.exit(1);
  } else {
    console.warn(`${chromeError} (module import mode)`);
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {{ base_url: string, username: string, password: string, channels: Object }} */
let credentials = null;

/** @type {Map<string, { url: string, expiry: number, hlsPath: string, extractedAt: number }>} */
const tokenCache = new Map(); // channelId → token info

/** @type {Map<string, { acquiredAt: number }>} */
const activeSlots = new Map(); // channelId → slot info

let browser = null;
let browserLaunchPromise = null;
let authenticated = false;
let lastAuthTime = null;
let lastRefreshTime = null;
let refreshTimer = null;
let refreshInProgress = false;
let slotSweepTimer = null;

// ---------------------------------------------------------------------------
// Credential loading
// ---------------------------------------------------------------------------

function loadCredentials() {
  if (!fs.existsSync(CREDENTIALS_FILE)) {
    error(`Credentials file not found: ${CREDENTIALS_FILE}`);
    error(`Create it from template: ${path.join(CHANNELS_DIR, 'seenshow_credentials.example.json')}`);
    error('Required keys: base_url, username, password, channels.<channel>.{seenshow_id,hls_path}');
    process.exit(1);
  }
  const raw = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf8'));
  try {
    credentials = validateCredentialsShape(raw);
  } catch (err) {
    error(`Invalid credentials file: ${err.message}`);
    error(`See template: ${path.join(CHANNELS_DIR, 'seenshow_credentials.example.json')}`);
    process.exit(1);
  }
  log(`Loaded credentials: ${Object.keys(credentials.channels).length} channels configured`);
}

function validateCredentialsShape(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('root must be a JSON object');
  }

  if (typeof raw.base_url !== 'string' || raw.base_url.trim() === '') {
    throw new Error('missing base_url');
  }

  let parsedBaseUrl;
  try {
    parsedBaseUrl = new URL(raw.base_url.trim());
  } catch (_) {
    throw new Error(`invalid base_url: ${raw.base_url}`);
  }
  if (!['http:', 'https:'].includes(parsedBaseUrl.protocol)) {
    throw new Error(`unsupported base_url protocol: ${parsedBaseUrl.protocol}`);
  }

  if (typeof raw.username !== 'string' || raw.username.trim() === '') {
    throw new Error('missing username');
  }
  if (typeof raw.password !== 'string' || raw.password === '') {
    throw new Error('missing password');
  }
  if (!raw.channels || typeof raw.channels !== 'object' || Array.isArray(raw.channels)) {
    throw new Error('missing channels object');
  }

  const channelEntries = Object.entries(raw.channels);
  if (channelEntries.length === 0) {
    throw new Error('channels object is empty');
  }

  for (const [channelId, cfg] of channelEntries) {
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
      throw new Error(`channels.${channelId} must be an object`);
    }
    if (!Number.isFinite(Number(cfg.seenshow_id)) || Number(cfg.seenshow_id) <= 0) {
      throw new Error(`channels.${channelId}.seenshow_id must be a positive number`);
    }
    if (typeof cfg.hls_path !== 'string' || cfg.hls_path.trim() === '') {
      throw new Error(`channels.${channelId}.hls_path is required`);
    }
  }

  // Deep-copy only validated fields to prevent untrusted properties leaking through
  const cleanChannels = {};
  for (const [channelId, cfg] of channelEntries) {
    cleanChannels[channelId] = {
      seenshow_id: Number(cfg.seenshow_id),
      hls_path: cfg.hls_path.trim(),
    };
  }

  return {
    base_url: parsedBaseUrl.origin,
    username: raw.username.trim(),
    password: raw.password,
    channels: cleanChannels,
  };
}

// ---------------------------------------------------------------------------
// Cookie persistence — save/restore session across restarts
// ---------------------------------------------------------------------------

function saveCookies(cookies) {
  try {
    fs.writeFileSync(COOKIES_FILE, JSON.stringify(cookies, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.chmodSync(COOKIES_FILE, 0o600);
    log(`Saved ${cookies.length} cookies to ${path.basename(COOKIES_FILE)}`);
  } catch (err) {
    warn(`Failed to save cookies: ${err.message}`);
  }
}

function loadSavedCookies() {
  try {
    if (!fs.existsSync(COOKIES_FILE)) return [];
    const raw = JSON.parse(fs.readFileSync(COOKIES_FILE, 'utf8'));
    if (!Array.isArray(raw)) return [];
    log(`Loaded ${raw.length} saved cookies from ${path.basename(COOKIES_FILE)}`);
    return raw;
  } catch (err) {
    warn(`Failed to load cookies: ${err.message}`);
    return [];
  }
}

async function restoreCookiesToPage(page) {
  const cookies = loadSavedCookies();
  if (cookies.length === 0) return false;

  // Filter for seenshow/keycloak cookies
  const relevant = cookies.filter(c =>
    c.domain && (c.domain.includes('seenshow.com') || c.domain.includes('keycloak'))
  );
  if (relevant.length === 0) return false;

  await page.setCookie(...relevant);
  log(`Restored ${relevant.length} session cookies`);
  return true;
}

// ---------------------------------------------------------------------------
// Browser management
// ---------------------------------------------------------------------------

let browserLaunchTime = 0;

async function recycleBrowserIfStale() {
  if (!browser || !browser.isConnected()) return;
  const age = Date.now() - browserLaunchTime;
  if (age < BROWSER_MAX_AGE_MS) return;
  log(`Recycling browser (age: ${Math.round(age / 3600000)}h, max: ${Math.round(BROWSER_MAX_AGE_MS / 3600000)}h)`);
  try {
    // Save cookies before closing
    const pages = await browser.pages();
    if (pages.length > 0) {
      const cookies = await pages[0].cookies();
      if (cookies.length > 0) {
        saveCookies(cookies);
      }
    }
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('close timeout')), 5000);
      browser.close().then(() => { clearTimeout(timer); resolve(); }, reject);
    });
  } catch (e) {
    warn(`Browser recycle close error: ${e.message}`);
    try { browser.process()?.kill('SIGKILL'); } catch (_) { /* ignore */ }
  }
  browser = null;
  browserLaunchPromise = null;
  authenticated = false;
}

async function ensureBrowser() {
  await recycleBrowserIfStale();
  if (browser && browser.isConnected()) return browser;

  if (browserLaunchPromise) return browserLaunchPromise;

  browserLaunchPromise = (async () => {
    if (!puppeteer) {
      throw puppeteerLoadError || new Error('Puppeteer dependency is unavailable');
    }
    if (!CHROME_PATH) {
      throw new Error('Chrome/Chromium not found. Set SEENSHOW_CHROME env var.');
    }

    log('Launching browser...');

    const args = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--no-first-run',
      '--no-zygote',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-default-apps',
      '--mute-audio',
    ];

    // Use proxy for authentication (geo-blocking bypass)
    if (AUTH_PROXY) {
      args.push(`--proxy-server=${AUTH_PROXY}`);
      log(`Using proxy for browser: ${AUTH_PROXY}`);
    }

    // No userDataDir — snap Chromium has locking issues with custom profiles.
    // Session cookies are saved/restored manually via .seenshow_cookies.json
    browser = await puppeteer.launch({
      headless: HEADLESS ? 'new' : false,
      executablePath: CHROME_PATH,
      args,
      defaultViewport: { width: 1280, height: 720 },
    });

    browser.on('disconnected', () => {
      log('Browser disconnected');
      browser = null;
      browserLaunchPromise = null;
      authenticated = false;
    });

    browserLaunchTime = Date.now();
    log('Browser launched');
    return browser;
  })();

  try {
    return await browserLaunchPromise;
  } catch (err) {
    browserLaunchPromise = null;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Authentication — Keycloak OIDC login
// ---------------------------------------------------------------------------

async function checkSessionValid(page) {
  // Check NextAuth session API — empty object means not authenticated.
  try {
    await page.goto(`${credentials.base_url}/api/auth/session`, {
      waitUntil: 'networkidle2',
      timeout: 20000,
    });
    const text = await page.evaluate(() => document.body.textContent || '{}');
    const session = JSON.parse(text || '{}');
    return !!(session && session.user);
  } catch (err) {
    warn(`Session check failed: ${err.message}`);
    return false;
  }
}

async function triggerNextAuthKeycloak(page, callbackUrl) {
  const signinUrl = `${credentials.base_url}/api/auth/signin?callbackUrl=${encodeURIComponent(callbackUrl)}`;
  log(`Opening NextAuth signin page: ${signinUrl}`);
  await page.goto(signinUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });

  if (page.url().includes('keycloak')) {
    return true;
  }

  const selectors = [
    'form[action*="/api/auth/signin/keycloak"] button[type="submit"]',
    'form[action*="/api/auth/signin/keycloak"] input[type="submit"]',
    'button[name="provider"][value="keycloak"]',
    'button[value="keycloak"]',
    'a[href*="/api/auth/signin/keycloak"]',
  ];

  for (const selector of selectors) {
    const el = await page.$(selector);
    if (!el) continue;
    log(`Triggering Keycloak flow with selector: ${selector}`);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: NAV_TIMEOUT }).catch(() => null),
      el.click().catch(() => null),
    ]);
    if (page.url().includes('keycloak')) {
      return true;
    }
  }

  // Fallback: emulate NextAuth's csrf + signin POST sequence.
  log('Keycloak button not detected, trying CSRF-signin fallback...');
  const fallback = await page.evaluate(async (cbUrl) => {
    try {
      const csrfRes = await fetch('/api/auth/csrf', { credentials: 'include' });
      if (!csrfRes.ok) {
        return { ok: false, stage: 'csrf', status: csrfRes.status };
      }

      const csrfJson = await csrfRes.json().catch(() => ({}));
      if (!csrfJson || typeof csrfJson.csrfToken !== 'string' || !csrfJson.csrfToken) {
        return { ok: false, stage: 'csrf', error: 'missing_csrf_token' };
      }

      const form = new URLSearchParams();
      form.set('csrfToken', csrfJson.csrfToken);
      form.set('callbackUrl', cbUrl);
      form.set('json', 'true');

      const signinRes = await fetch('/api/auth/signin/keycloak', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: form.toString(),
      });

      const body = await signinRes.text().catch(() => '');
      let redirectUrl = '';
      try {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed.url === 'string') {
          redirectUrl = parsed.url;
        }
      } catch (_) {}

      if (!redirectUrl && signinRes.redirected && signinRes.url) {
        redirectUrl = signinRes.url;
      }

      return {
        ok: true,
        status: signinRes.status,
        redirectUrl,
      };
    } catch (err) {
      return { ok: false, stage: 'fetch', error: err && err.message ? err.message : String(err) };
    }
  }, callbackUrl);

  if (fallback && fallback.redirectUrl) {
    await page.goto(fallback.redirectUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
  }

  return page.url().includes('keycloak');
}

async function authenticate(retries = MAX_LOGIN_RETRIES) {
  const b = await ensureBrowser();
  const page = await b.newPage();

  try {
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    );

    // Restore saved session cookies before navigating
    await restoreCookiesToPage(page);

    // Verify session is actually valid via the NextAuth session API
    log('Checking existing session...');
    const sessionValid = await checkSessionValid(page);

    if (sessionValid) {
      log('Session is valid (cookies restored successfully)');
      const cookies = await page.cookies();
      saveCookies(cookies);
      authenticated = true;
      lastAuthTime = Date.now();
      return true;
    }

    log('Session invalid or expired, starting Keycloak login flow...');
    const firstChannel = Object.values(credentials.channels)[0];
    const callbackChannelId = firstChannel?.seenshow_id || 18;
    const callbackUrl = `${credentials.base_url}/my/live_stream?channelId=${callbackChannelId}`;
    const redirectOk = await triggerNextAuthKeycloak(page, callbackUrl);
    log(`After signin trigger: ${page.url().substring(0, 140)}`);
    if (!redirectOk) {
      warn('Signin trigger did not reach Keycloak directly; continuing with retry loop');
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      log(`Login attempt ${attempt}/${retries}...`);

      try {
        if (await checkSessionValid(page)) {
          log('Already authenticated before form submit');
          const cookies = await page.cookies();
          saveCookies(cookies);
          authenticated = true;
          lastAuthTime = Date.now();
          return true;
        }

        // If we're not on the Keycloak page, try to trigger sign-in flow again.
        if (!page.url().includes('keycloak')) {
          const retriggered = await triggerNextAuthKeycloak(page, callbackUrl);
          if (!retriggered && attempt < retries) {
            await sleep(LOGIN_RETRY_DELAY);
            continue;
          }
        }

        // Wait for the Keycloak login form
        await page.waitForSelector('input[name="username"], input[id="username"]', {
          timeout: 15000,
        });

        // Fill credentials
        const usernameField = await page.$('input[name="username"]') || await page.$('input[id="username"]');
        const passwordField = await page.$('input[name="password"]') || await page.$('input[id="password"]');

        if (!usernameField || !passwordField) {
          warn('Could not find username/password fields');
          if (attempt < retries) {
            await sleep(LOGIN_RETRY_DELAY);
          }
          continue;
        }

        // Clear and type credentials
        await usernameField.click({ clickCount: 3 });
        await usernameField.type(credentials.username, { delay: 40 });
        await passwordField.click({ clickCount: 3 });
        await passwordField.type(credentials.password, { delay: 40 });

        // Submit the form
        const submitButton = await page.$('#kc-login') ||
          await page.$('button[type="submit"]') ||
          await page.$('input[type="submit"]');

        if (submitButton) {
          await submitButton.click().catch(() => null);
        } else {
          await page.keyboard.press('Enter').catch(() => null);
        }

        // Some Keycloak flows don't trigger a full navigation event every time.
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: NAV_TIMEOUT }).catch(() => null);
        await sleep(1500);

        // Verify login succeeded via session API
        const afterLoginUrl = page.url();
        log(`After submit: ${afterLoginUrl.substring(0, 140)}`);

        if (afterLoginUrl.includes('seenshow.com') && !afterLoginUrl.includes('keycloak')) {
          const valid = await checkSessionValid(page);
          if (valid) {
            log('Login successful! Session verified.');
            const cookies = await page.cookies();
            saveCookies(cookies);
            authenticated = true;
            lastAuthTime = Date.now();
            return true;
          }
        }

        // Still on Keycloak — login failed
        warn(`Login may have failed. Current URL: ${afterLoginUrl.substring(0, 140)}`);
        if (attempt < retries) {
          await sleep(LOGIN_RETRY_DELAY);
        }
      } catch (err) {
        warn(`Login attempt ${attempt} error: ${err.message}`);
        if (attempt < retries) {
          await sleep(LOGIN_RETRY_DELAY);
        }
      }
    }

    error('All login attempts failed');
    return false;
  } finally {
    await page.close().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Token extraction — resolve m3u8 URL and token from page/API/network signals
// ---------------------------------------------------------------------------

function decodeURIComponentSafe(value) {
  if (typeof value !== 'string') return '';
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
}

function normalizeCapturedUrl(value) {
  if (typeof value !== 'string') return '';
  return value
    .trim()
    .replace(/^['"]+|['"]+$/g, '')
    .replace(/\\u0026/g, '&')
    .replace(/\\\//g, '/')
    .replace(/&amp;/g, '&');
}

function channelPathNeedle(channelConfig) {
  if (!channelConfig || typeof channelConfig.hls_path !== 'string') return '';
  const hlsPath = channelConfig.hls_path.trim().replace(/^\/+|\/+$/g, '');
  if (!hlsPath) return '';
  return `/hls/live/${hlsPath}/`.toLowerCase();
}

function candidateMatchesChannel(candidateUrl, channelConfig) {
  const needle = channelPathNeedle(channelConfig);
  if (!needle) return false;

  const normalized = normalizeCapturedUrl(candidateUrl);
  if (!normalized || !normalized.includes('live.seenshow.com') || !normalized.includes('.m3u8')) {
    return false;
  }

  const decodedOnce = decodeURIComponentSafe(normalized);
  const decodedTwice = decodeURIComponentSafe(decodedOnce);
  const haystacks = [
    normalized.toLowerCase(),
    decodedOnce.toLowerCase(),
    decodedTwice.toLowerCase(),
  ];

  return haystacks.some((text) => text.includes(needle));
}

function tokenStrength(url) {
  if (typeof url !== 'string') return 0;
  if (url.includes('hdntl=')) return 2;
  if (url.includes('hdnts=')) return 1;
  return 0;
}

function selectBestChannelCandidate(candidates, candidateMeta, channelConfig, options = {}) {
  const requireToken = options.requireToken === true;
  const list = Array.from(candidates).filter((candidate) => {
    if (!candidateMatchesChannel(candidate, channelConfig)) return false;
    if (requireToken && tokenStrength(candidate) === 0) return false;
    return true;
  });
  if (list.length === 0) return null;

  list.sort((a, b) => {
    const tokenRankDiff = tokenStrength(b) - tokenStrength(a);
    if (tokenRankDiff !== 0) return tokenRankDiff;

    const aMeta = candidateMeta.get(a) || {};
    const bMeta = candidateMeta.get(b) || {};
    const playableDiff = Number(!!bMeta.playable) - Number(!!aMeta.playable);
    if (playableDiff !== 0) return playableDiff;

    const aStatusOk = Number(Number.isFinite(aMeta.status) && aMeta.status >= 200 && aMeta.status < 400);
    const bStatusOk = Number(Number.isFinite(bMeta.status) && bMeta.status >= 200 && bMeta.status < 400);
    const statusDiff = bStatusOk - aStatusOk;
    if (statusDiff !== 0) return statusDiff;

    return a.length - b.length;
  });

  return list[0];
}

function extractM3u8UrlsFromText(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const cleaned = text
    .replace(/\\u0026/g, '&')
    .replace(/\\\//g, '/');
  const matches = cleaned.match(/https?:\/\/live\.seenshow\.com[^"'\s<>\\]+\.m3u8(?:\?[^"'\s<>\\]*)?/gi) || [];
  const deduped = [];
  const seen = new Set();
  for (const raw of matches) {
    const normalized = normalizeCapturedUrl(raw);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    deduped.push(normalized);
  }
  return deduped;
}

function buildApiHeadersFromCookies(pageCookies, referer) {
  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Origin': credentials.base_url,
    'Referer': referer || `${credentials.base_url}/`,
  };

  const cookieHeader = pageCookies
    .filter((c) => c && c.name && typeof c.value === 'string')
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
  if (cookieHeader) {
    headers.Cookie = cookieHeader;
  }

  const accessTokenCookie = pageCookies.find((c) => c && c.name === 'access_token');
  if (accessTokenCookie && accessTokenCookie.value) {
    headers.Authorization = `Bearer ${accessTokenCookie.value}`;
  }

  return headers;
}

function parseJsonSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

function resolveRelativeM3u8Url(rawUri, baseUrl) {
  const uri = normalizeCapturedUrl(rawUri);
  if (!uri || !uri.includes('.m3u8')) return null;
  if (/^https?:\/\//i.test(uri)) return uri;
  try {
    return new URL(uri, baseUrl).toString();
  } catch (_) {
    return null;
  }
}

function extractBestVariantFromMasterPlaylist(masterText, baseUrl) {
  if (typeof masterText !== 'string' || !masterText.includes('#EXTM3U')) return null;

  const lines = masterText
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  /** @type {Array<{url: string, bandwidth: number, hdntl: boolean}>} */
  const variants = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.startsWith('#EXT-X-STREAM-INF')) continue;

    const bandwidthMatch = line.match(/BANDWIDTH=(\d+)/i);
    const bandwidth = bandwidthMatch ? parseInt(bandwidthMatch[1], 10) : 0;

    let uri = null;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].startsWith('#')) continue;
      uri = lines[j];
      break;
    }
    if (!uri) continue;

    const absolute = resolveRelativeM3u8Url(uri, baseUrl);
    if (!absolute) continue;
    variants.push({
      url: absolute,
      bandwidth,
      hdntl: absolute.includes('hdntl='),
    });
  }

  if (variants.length > 0) {
    variants.sort((a, b) => {
      if (a.hdntl !== b.hdntl) return a.hdntl ? -1 : 1;
      return b.bandwidth - a.bandwidth;
    });
    return variants[0].url;
  }

  // Fallback: pick any playlist line, preferring hdntl entries.
  const loose = lines
    .filter((line) => !line.startsWith('#') && line.includes('.m3u8'))
    .map((line) => resolveRelativeM3u8Url(line, baseUrl))
    .filter(Boolean);
  if (loose.length === 0) return null;
  return loose.find((line) => line.includes('hdntl=')) || loose[0];
}

async function promoteHdntsToHdntl(page, channelId, manifestUrl) {
  if (typeof manifestUrl !== 'string' || !manifestUrl.includes('hdnts=')) return null;

  const fetchViaNavigation = async (targetUrl) => {
    const response = await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 20000 }).catch(() => null);
    const status = response ? response.status() : null;
    const finalUrl = page.url();
    const text = await page.evaluate(() => {
      if (!document || !document.body) return '';
      return document.body.innerText || document.body.textContent || '';
    }).catch(() => '');
    return { status, finalUrl, text };
  };

  let payload = await fetchViaNavigation(manifestUrl);

  // Fallback: explicit fetch from the browser context if navigation body is empty.
  if (!payload.text || !payload.text.includes('.m3u8')) {
    const viaFetch = await page.evaluate(async (targetUrl) => {
      try {
        const resp = await fetch(targetUrl, {
          method: 'GET',
          redirect: 'follow',
          credentials: 'include',
          headers: {
            'Accept': 'application/vnd.apple.mpegurl, application/x-mpegURL, */*',
            'Referer': 'https://seenshow.com/',
            'Origin': 'https://seenshow.com',
          },
        });
        const text = await resp.text().catch(() => '');
        return {
          ok: true,
          status: resp.status,
          finalUrl: resp.url || targetUrl,
          text,
        };
      } catch (err) {
        return {
          ok: false,
          status: null,
          finalUrl: targetUrl,
          text: '',
          error: err && err.message ? err.message : String(err),
        };
      }
    }, manifestUrl).catch(() => null);

    if (viaFetch && viaFetch.ok) {
      payload = {
        status: Number.isFinite(viaFetch.status) ? viaFetch.status : payload.status,
        finalUrl: viaFetch.finalUrl || payload.finalUrl || manifestUrl,
        text: viaFetch.text || payload.text || '',
      };
    }
  }

  const bestVariant = extractBestVariantFromMasterPlaylist(
    payload.text || '',
    payload.finalUrl || manifestUrl
  );

  if (bestVariant && bestVariant.includes('hdntl=')) {
    log(`Promoted hdnts -> hdntl variant for ${channelId}`);
    return {
      url: bestVariant,
      status: Number.isFinite(payload.status) ? payload.status : null,
    };
  }

  return null;
}

let authPromise = null;

async function ensureAuthenticated() {
  if (authenticated) return true;
  if (authPromise) return authPromise;
  authPromise = authenticate().finally(() => { authPromise = null; });
  return authPromise;
}

async function extractToken(channelId, channelConfig) {
  if (!authenticated) {
    warn(`Not authenticated while extracting ${channelId}, attempting login...`);
    const loginOk = await ensureAuthenticated();
    if (!loginOk) {
      error(`Authentication failed; cannot extract token for ${channelId}`);
      return null;
    }
  }

  const b = await ensureBrowser();
  const page = await b.newPage();
  let tokenUrl = null;
  let ignoredForeignCandidates = 0;
  const capturedUrls = new Set();
  const candidateMeta = new Map(); // url -> { status: number|null, playable: boolean, sources: Set<string> }
  let requestListener = null;
  let responseListener = null;

  const captureCandidate = (rawUrl, source = 'unknown', meta = {}) => {
    const normalized = normalizeCapturedUrl(rawUrl);
    if (!normalized) return;
    if (!normalized.includes('live.seenshow.com')) return;
    if (!normalized.includes('.m3u8')) return;
    if (!candidateMatchesChannel(normalized, channelConfig)) {
      ignoredForeignCandidates += 1;
      return;
    }
    capturedUrls.add(normalized);

    const existing = candidateMeta.get(normalized) || {
      status: null,
      playable: false,
      sources: new Set(),
    };
    existing.sources.add(source);
    if (Number.isFinite(meta.status)) {
      existing.status = meta.status;
      if (meta.status >= 200 && meta.status < 400) {
        existing.playable = true;
      }
    }
    if (meta.playable === true) {
      existing.playable = true;
    }
    candidateMeta.set(normalized, existing);

    if (tokenStrength(normalized) > 0) {
      const currentRank = tokenStrength(tokenUrl);
      const nextRank = tokenStrength(normalized);
      const currentMeta = tokenUrl ? (candidateMeta.get(tokenUrl) || {}) : {};
      const nextPlayable = existing.playable === true;
      const shouldPromote =
        !tokenUrl ||
        nextRank > currentRank ||
        (nextRank === currentRank && nextPlayable && currentMeta.playable !== true);
      if (!shouldPromote) return;
      tokenUrl = normalized;
      log(`Token candidate captured for ${channelId} via ${source}`);
    }
  };

  try {
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    );
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9',
    });

    await restoreCookiesToPage(page);
    const pageCookies = await page.cookies('https://seenshow.com').catch(() => []);

    requestListener = (request) => {
      captureCandidate(request.url(), 'request');
    };

    responseListener = async (response) => {
      try {
        const responseUrl = response.url();
        captureCandidate(responseUrl, 'response-url', { status: response.status() });

        if (!responseUrl.includes('seenshow.com') && !responseUrl.includes('api.seenshow.com')) {
          return;
        }

        const headers = response.headers();
        const contentType = String(headers['content-type'] || '').toLowerCase();
        const inspectBody =
          responseUrl.includes('api.seenshow.com') ||
          contentType.includes('json') ||
          contentType.includes('mpegurl') ||
          contentType.startsWith('text/');

        if (!inspectBody) return;
        // Skip large responses to avoid leaking memory on abandoned response.text()
        const contentLength = parseInt(headers['content-length'] || '0', 10);
        if (contentLength > 2 * 1024 * 1024) return;
        const body = await Promise.race([
          response.text().catch(() => ''),
          new Promise(resolve => setTimeout(() => resolve(''), 5000)),
        ]);
        if (!body) return;

        for (const found of extractM3u8UrlsFromText(body)) {
          captureCandidate(found, 'response-body');
        }
      } catch (_) {}
    };

    page.on('request', requestListener);
    page.on('response', responseListener);

    // Strategy 1 (primary): live-channel EPG API returns tokenized manifest_url.
    if (!tokenUrl) {
      const now = new Date();
      const date = now.toISOString().slice(0, 10);
      const timezoneOffset = 0;
      const epgUrl = `https://api.seenshow.com/media/live-channel/${channelConfig.seenshow_id}/epg?timeZoneOffset=${timezoneOffset}&date=${date}`;
      const headers = buildApiHeadersFromCookies(
        pageCookies,
        `${credentials.base_url}/my/live_stream?channelId=${channelConfig.seenshow_id}`
      );

      try {
        const epg = await httpGetText(epgUrl, headers, 15000);
        log(`API token probe for ${channelId}: ${epg.status} ${epgUrl}`);
        if (epg.body) {
          const parsed = parseJsonSafe(epg.body);
          const manifestCandidates = [
            parsed?.manifest_url,
            parsed?.manifestUrl,
            parsed?.response?.data?.manifest_url,
            parsed?.response?.data?.manifestUrl,
          ];
          for (const candidate of manifestCandidates) {
            captureCandidate(candidate, 'api-epg-manifest', { status: epg.status, playable: epg.status >= 200 && epg.status < 400 });
          }
          for (const found of extractM3u8UrlsFromText(epg.body)) {
            captureCandidate(found, 'api-epg-body', { status: epg.status, playable: epg.status >= 200 && epg.status < 400 });
          }
        }
      } catch (err) {
        warn(`API token probe failed for ${channelId}: ${err.message}`);
      }
    }

    // Strategy 1b: convert short-lived hdnts manifest into long-lived hdntl variant.
    if (tokenUrl && tokenUrl.includes('hdnts=')) {
      const promoted = await promoteHdntsToHdntl(page, channelId, tokenUrl).catch(() => null);
      if (promoted && promoted.url) {
        captureCandidate(promoted.url, 'hdnts-promote', {
          status: promoted.status,
          playable: true,
        });
        tokenUrl = promoted.url;
      }
    }

    // Strategy 2: direct playlist probes. Many providers redirect these to a
    // signed token URL when session cookies are valid.
    const directCandidates = [
      `https://live.seenshow.com/hls/live/${channelConfig.hls_path}/master.m3u8`,
      `https://live.seenshow.com/hls/live/${channelConfig.hls_path}/3.m3u8`,
    ];
    for (const candidate of directCandidates) {
      if (tokenUrl) break;
      log(`Direct probe for ${channelId}: ${candidate}`);
      const directNavResponse = await page.goto(candidate, { waitUntil: 'networkidle2', timeout: 20000 }).catch(() => null);
      captureCandidate(page.url(), 'direct-goto', { status: directNavResponse ? directNavResponse.status() : null });

      const fetchResult = await page.evaluate(async (targetUrl) => {
        try {
          const resp = await fetch(targetUrl, { method: 'GET', redirect: 'follow', credentials: 'include' });
          const snippet = await resp.text().catch(() => '');
          return {
            ok: true,
            status: resp.status,
            finalUrl: resp.url || '',
            isPlaylist: /^#EXTM3U/m.test(snippet),
            snippet: snippet.slice(0, 6000),
          };
        } catch (err) {
          return { ok: false, error: err && err.message ? err.message : String(err) };
        }
      }, candidate).catch(() => null);

      if (fetchResult && fetchResult.finalUrl && Number.isFinite(fetchResult.status) && fetchResult.status >= 200 && fetchResult.status < 400) {
        captureCandidate(fetchResult.finalUrl, 'direct-fetch', {
          status: fetchResult.status,
          playable: !!fetchResult.isPlaylist,
        });
      }
      if (fetchResult && fetchResult.snippet) {
        for (const found of extractM3u8UrlsFromText(fetchResult.snippet)) {
          captureCandidate(found, 'direct-fetch-body', {
            status: Number.isFinite(fetchResult.status) ? fetchResult.status : null,
            playable: !!fetchResult.isPlaylist,
          });
        }
      }
      await sleep(1000);
    }

    // Strategy 3: call likely API endpoints server-side (Node) with cookies and
    // bearer token from the authenticated browser session.
    if (!tokenUrl) {
      const apiCandidates = [
        'https://api.seenshow.com/live',
        `https://api.seenshow.com/live/${channelConfig.seenshow_id}`,
        `https://api.seenshow.com/live?channelId=${channelConfig.seenshow_id}`,
        `https://api.seenshow.com/live?channel_id=${channelConfig.seenshow_id}`,
        `https://api.seenshow.com/channel/${channelConfig.seenshow_id}`,
        `https://api.seenshow.com/media/live-channel/${channelConfig.seenshow_id}`,
        `https://api.seenshow.com/media/live-channel/${channelConfig.seenshow_id}/epg?timeZoneOffset=0&date=${new Date().toISOString().slice(0, 10)}`,
        'https://api.seenshow.com/web/sections',
      ];

      for (const probeUrl of apiCandidates) {
        const headers = buildApiHeadersFromCookies(pageCookies, `${credentials.base_url}/`);

        try {
          const entry = await httpGetText(probeUrl, headers, 15000);
          const statusLabel = Number.isFinite(entry.status) ? String(entry.status) : 'error';
          log(`API probe for ${channelId}: ${statusLabel} ${probeUrl}`);
          if (!entry.body) continue;

          for (const found of extractM3u8UrlsFromText(entry.body)) {
            captureCandidate(found, 'api-probe-body', { status: entry.status });
          }

          // If API response contains known hls_path + a token fragment, synthesize a candidate URL.
          if (entry.body.includes(channelConfig.hls_path)) {
            const hdntlMatch = entry.body.match(/hdntl(?:=|%3D)([^"',\s}\\]+)/i);
            if (hdntlMatch) {
              const hdntlRaw = normalizeCapturedUrl(hdntlMatch[1]).replace(/^=/, '');
              const inferredUrl = `https://live.seenshow.com/hls/live/${channelConfig.hls_path}/master.m3u8?hdntl=${hdntlRaw}`;
              captureCandidate(inferredUrl, 'api-probe-inferred', { status: entry.status });
            }
          }
        } catch (err) {
          warn(`API probe error for ${probeUrl}: ${err.message}`);
        }
      }
    }

    // Strategy 4: load channel page and trigger potential play controls.
    if (!tokenUrl) {
      const channelPageUrl = `${credentials.base_url}/my/live_stream?channelId=${channelConfig.seenshow_id}`;
      log(`Page probe for ${channelId}: ${channelPageUrl}`);
      await page.goto(channelPageUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });

      const clicked = await page.evaluate(() => {
        const keywords = ['play', 'watch', 'live', 'تشغيل', 'مشاهدة', 'ابدأ'];
        let count = 0;
        const elements = Array.from(document.querySelectorAll('button, a, [role="button"]'));
        for (const el of elements) {
          if (count >= 4) break;
          const text = (el.textContent || '').trim().toLowerCase();
          const aria = (el.getAttribute('aria-label') || '').trim().toLowerCase();
          const haystack = `${text} ${aria}`;
          if (!keywords.some((k) => haystack.includes(k))) continue;
          try {
            el.click();
            count += 1;
          } catch (_) {}
        }
        return count;
      }).catch(() => 0);

      if (clicked > 0) {
        log(`Clicked ${clicked} potential play controls for ${channelId}`);
      }

      await sleep(5000);
      const pageContent = await page.content().catch(() => '');
      for (const found of extractM3u8UrlsFromText(pageContent)) {
        captureCandidate(found, 'page-content');
      }
    }

    // Wait a little longer for async XHR/fetch traffic.
    const waitUntil = Date.now() + TOKEN_EXTRACT_TIMEOUT;
    while (!tokenUrl && Date.now() < waitUntil) {
      const tokenCandidate = selectBestChannelCandidate(capturedUrls, candidateMeta, channelConfig, {
        requireToken: true,
      });
      if (tokenCandidate) {
        tokenUrl = tokenCandidate;
        break;
      }
      await sleep(400);
    }

    // Fallback: use any captured m3u8 URL.
    if (!tokenUrl && capturedUrls.size > 0) {
      const best = selectBestChannelCandidate(capturedUrls, candidateMeta, channelConfig, {
        requireToken: false,
      });
      if (best) {
        tokenUrl = best;
        const meta = candidateMeta.get(best) || {};
        const quality = meta.playable ? 'playable' : 'unverified';
        warn(`Using ${quality} non-tokenized fallback URL for ${channelId}`);
      }
    }

    if (!tokenUrl) {
      const summary = Array.from(capturedUrls).slice(0, 6).map((candidate) => {
        const meta = candidateMeta.get(candidate);
        const status = meta && Number.isFinite(meta.status) ? meta.status : 'na';
        const playable = meta && meta.playable ? 'playable' : 'unverified';
        return `${candidate.substring(0, 90)} [${status}, ${playable}]`;
      }).join(' | ');
      warn(`No usable m3u8 URL found for ${channelId} (captured=${capturedUrls.size}, ignored_foreign=${ignoredForeignCandidates})${summary ? `: ${summary}` : ''}`);
      return null;
    }

    const expiry = parseTokenExpiry(tokenUrl);
    const result = {
      url: tokenUrl,
      expiry,
      hlsPath: channelConfig.hls_path,
      extractedAt: Date.now(),
    };

    tokenCache.set(channelId, result);
    const expiresIn = expiry ? formatDuration(expiry * 1000 - Date.now()) : 'unknown';
    log(`Token extracted for ${channelId}: expires in ${expiresIn}`);
    return result;
  } catch (err) {
    error(`Token extraction failed for ${channelId}: ${err.message}`);
    return null;
  } finally {
    if (requestListener) page.off('request', requestListener);
    if (responseListener) page.off('response', responseListener);
    await page.close().catch(() => {});
  }
}

function parseTokenExpiry(url) {
  if (typeof url !== 'string' || url === '') return null;

  const direct = url.match(/[?&]exp=(\d{9,})/);
  if (direct) return parseInt(direct[1], 10);

  const hdntsMatch = url.match(/[?&]hdnts=([^&]+)/i);
  if (hdntsMatch) {
    const decodedHdnts = decodeURIComponentSafe(hdntsMatch[1]);
    const exp = decodedHdnts.match(/(?:^|~)exp=(\d{9,})/);
    if (exp) return parseInt(exp[1], 10);
  }

  const hdntlMatch = url.match(/[?&]hdntl=([^&]+)/i);
  if (hdntlMatch) {
    const decodedHdntl = decodeURIComponentSafe(hdntlMatch[1]);
    const exp = decodedHdntl.match(/(?:^|~)exp=(\d{9,})/);
    if (exp) return parseInt(exp[1], 10);
  }

  const hdntlPathMatch = url.match(/\/hdntl=([^/]+)/i);
  if (hdntlPathMatch) {
    const decodedHdntlPath = decodeURIComponentSafe(hdntlPathMatch[1]);
    const exp = decodedHdntlPath.match(/(?:^|~)exp=(\d{9,})/);
    if (exp) return parseInt(exp[1], 10);
  }

  const decodedUrl = decodeURIComponentSafe(url);
  const anyExp = decodedUrl.match(/(?:[?&~])exp=(\d{9,})/);
  if (anyExp) return parseInt(anyExp[1], 10);

  const looseExp = decodedUrl.match(/exp=(\d{9,})/);
  if (looseExp) return parseInt(looseExp[1], 10);

  return null;
}

function formatDuration(ms) {
  if (ms <= 0) return 'expired';
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  return `${hours}h ${minutes}m`;
}

function httpGetText(url, headers = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (err) {
      reject(err);
      return;
    }

    const isHttps = parsed.protocol === 'https:';
    const httpModule = isHttps ? https : http;
    const req = httpModule.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET',
      timeout: timeoutMs,
      headers,
    }, (res) => {
      const MAX_BODY_SIZE = 2 * 1024 * 1024; // 2MB
      let body = '';
      let destroyed = false;
      res.on('data', (chunk) => {
        if (destroyed) return;
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
          destroyed = true;
          res.destroy();
          reject(new Error('Response body too large'));
        }
      });
      res.on('end', () => {
        if (destroyed) return;
        resolve({
          status: res.statusCode || 0,
          body,
          headers: res.headers || {},
          finalUrl: url,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`timeout after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Token refresh — batch extract for all channels
// ---------------------------------------------------------------------------

async function refreshAllTokens() {
  if (refreshInProgress) {
    log('Refresh already in progress, skipping');
    return;
  }

  refreshInProgress = true;
  log('Starting token refresh for all channels...');

  try {
    // Ensure we're authenticated (use mutex to prevent concurrent login attempts)
    if (!authenticated) {
      const ok = await ensureAuthenticated();
      if (!ok) {
        error('Authentication failed, cannot refresh tokens');
        return;
      }
    }

    const channelEntries = Object.entries(credentials.channels);
    let success = 0;
    let failed = 0;

    for (const [channelId, channelConfig] of channelEntries) {
      try {
        const result = await extractToken(channelId, channelConfig);
        if (result) {
          success++;
        } else {
          failed++;
        }
      } catch (err) {
        error(`Token refresh failed for ${channelId}: ${err.message}`);
        failed++;
      }

      // Stagger requests — don't hit seenshow too fast
      await sleep(3000);
    }

    lastRefreshTime = Date.now();
    log(`Token refresh complete: ${success} success, ${failed} failed out of ${channelEntries.length}`);
  } catch (err) {
    error(`Token refresh error: ${err.message}`);
  } finally {
    refreshInProgress = false;
  }
}

function needsRefresh(channelId) {
  const cached = tokenCache.get(channelId);
  if (!cached) return true;
  if (!cached.expiry) return true;

  const now = Date.now();
  const expiryMs = cached.expiry * 1000;

  // Refresh if within TOKEN_MARGIN_MS of expiry
  if (expiryMs - now < TOKEN_MARGIN_MS) return true;

  return false;
}

function isTokenValid(channelId) {
  const cached = tokenCache.get(channelId);
  if (!cached || !cached.url) return false;
  if (!cached.expiry) return true; // No expiry info, assume valid
  return cached.expiry * 1000 > Date.now();
}

// ---------------------------------------------------------------------------
// Connection semaphore — limit concurrent seenshow streams
// ---------------------------------------------------------------------------

function acquireSlot(channelId) {
  // Check if this channel already has a slot
  if (activeSlots.has(channelId)) {
    // Refresh the timestamp
    activeSlots.set(channelId, { acquiredAt: Date.now() });
    return { granted: true, slot: activeSlots.size, remaining: MAX_CONCURRENT - activeSlots.size };
  }

  if (activeSlots.size >= MAX_CONCURRENT) {
    return {
      granted: false,
      reason: 'max_concurrent_reached',
      max: MAX_CONCURRENT,
      active: Array.from(activeSlots.keys()),
    };
  }

  activeSlots.set(channelId, { acquiredAt: Date.now() });
  log(`Slot acquired for ${channelId} (${activeSlots.size}/${MAX_CONCURRENT})`);
  return { granted: true, slot: activeSlots.size, remaining: MAX_CONCURRENT - activeSlots.size };
}

function releaseSlot(channelId) {
  const had = activeSlots.delete(channelId);
  if (had) {
    log(`Slot released for ${channelId} (${activeSlots.size}/${MAX_CONCURRENT})`);
  }
  return { released: had, remaining: MAX_CONCURRENT - activeSlots.size };
}

function sweepStaleSlots() {
  const now = Date.now();
  for (const [channelId, info] of activeSlots.entries()) {
    if (now - info.acquiredAt > SLOT_AUTO_RELEASE_MS) {
      warn(`Auto-releasing stale slot for ${channelId} (acquired ${formatDuration(now - info.acquiredAt)} ago)`);
      activeSlots.delete(channelId);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP API Server
// ---------------------------------------------------------------------------

function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function parseRoute(urlStr) {
  const parsed = new URL(urlStr, 'http://localhost');
  return { pathname: parsed.pathname, params: parsed.searchParams };
}

const server = http.createServer(async (req, res) => {
  const { pathname } = parseRoute(req.url);
  const method = req.method.toUpperCase();

  try {
    // GET /health
    if (method === 'GET' && pathname === '/health') {
      let validCount = 0;
      let expiredCount = 0;
      for (const [chId] of tokenCache) {
        if (isTokenValid(chId)) validCount++;
        else expiredCount++;
      }

      sendJson(res, 200, {
        status: 'ok',
        authenticated,
        lastAuth: lastAuthTime ? new Date(lastAuthTime).toISOString() : null,
        lastRefresh: lastRefreshTime ? new Date(lastRefreshTime).toISOString() : null,
        refreshInProgress,
        tokens: {
          total: Object.keys(credentials.channels).length,
          cached: tokenCache.size,
          valid: validCount,
          expired: expiredCount,
        },
        slots: {
          max: MAX_CONCURRENT,
          used: activeSlots.size,
          channels: Array.from(activeSlots.keys()),
        },
      });
      return;
    }

    // GET /resolve/:streamId/:channelName  (e.g., /resolve/2120779/LIVE-013-MASA)
    if (method === 'GET' && pathname.startsWith('/resolve/')) {
      const hlsPath = decodeURIComponent(pathname.slice('/resolve/'.length));
      if (!hlsPath) {
        sendJson(res, 400, { error: 'Missing path parameter. Use /resolve/STREAM_ID/CHANNEL_NAME' });
        return;
      }

      // Find channel by hls_path
      let matchedChannelId = null;
      for (const [chId, chConf] of Object.entries(credentials.channels)) {
        if (chConf.hls_path === hlsPath) {
          matchedChannelId = chId;
          break;
        }
      }

      if (!matchedChannelId) {
        sendJson(res, 404, { error: `No channel configured for path: ${hlsPath}` });
        return;
      }

      // Check cache first
      let cached = tokenCache.get(matchedChannelId);
      if (!cached || !isTokenValid(matchedChannelId)) {
        // Try to extract a fresh token
        log(`Cache miss/expired for ${matchedChannelId}, extracting fresh token...`);
        const result = await extractToken(matchedChannelId, credentials.channels[matchedChannelId]);
        if (result) {
          cached = result;
        } else {
          sendJson(res, 503, { error: `Failed to extract token for ${matchedChannelId}` });
          return;
        }
      }

      const expiresIn = cached.expiry
        ? formatDuration(cached.expiry * 1000 - Date.now())
        : 'unknown';

      sendJson(res, 200, {
        url: cached.url,
        channelId: matchedChannelId,
        expiry: cached.expiry,
        expiresIn,
        extractedAt: new Date(cached.extractedAt).toISOString(),
      });
      return;
    }

    // GET /token-status
    if (method === 'GET' && pathname === '/token-status') {
      const status = {};
      for (const [chId, chConf] of Object.entries(credentials.channels)) {
        const cached = tokenCache.get(chId);
        status[chId] = {
          seenshow_id: chConf.seenshow_id,
          hls_path: chConf.hls_path,
          hasToken: !!cached,
          valid: isTokenValid(chId),
          expiry: cached?.expiry || null,
          expiresIn: cached?.expiry ? formatDuration(cached.expiry * 1000 - Date.now()) : null,
          extractedAt: cached?.extractedAt ? new Date(cached.extractedAt).toISOString() : null,
          url: cached?.url ? cached.url.substring(0, 100) + '...' : null,
        };
      }
      sendJson(res, 200, { channels: status });
      return;
    }

    // POST /acquire/:channelId
    if (method === 'POST' && pathname.startsWith('/acquire/')) {
      const channelId = pathname.slice('/acquire/'.length);
      if (!channelId) {
        sendJson(res, 400, { error: 'Missing channelId' });
        return;
      }
      const result = acquireSlot(channelId);
      sendJson(res, result.granted ? 200 : 429, result);
      return;
    }

    // POST /release/:channelId
    if (method === 'POST' && pathname.startsWith('/release/')) {
      const channelId = pathname.slice('/release/'.length);
      if (!channelId) {
        sendJson(res, 400, { error: 'Missing channelId' });
        return;
      }
      const result = releaseSlot(channelId);
      sendJson(res, 200, result);
      return;
    }

    // POST /refresh
    if (method === 'POST' && pathname === '/refresh') {
      if (refreshInProgress) {
        sendJson(res, 409, { error: 'Refresh already in progress' });
        return;
      }
      // Trigger async refresh, respond immediately
      refreshAllTokens().catch(err => error(`Refresh error: ${err.message}`));
      sendJson(res, 202, { status: 'refresh_started', channels: Object.keys(credentials.channels).length });
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    error(`HTTP handler error: ${err.message}`);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function resetStateForTests() {
  tokenCache.clear();
  activeSlots.clear();
  authenticated = false;
  lastAuthTime = null;
  lastRefreshTime = null;
  refreshInProgress = false;
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function startup() {
  log('Seenshow Token Resolver starting...');
  log(`Config: port=${PORT}, maxConcurrent=${MAX_CONCURRENT}, refreshInterval=${TOKEN_REFRESH_MS}ms`);

  loadCredentials();

  // Start HTTP server
  await new Promise((resolve, reject) => {
    server.listen(PORT, HOST, () => {
      log(`HTTP server listening on http://${HOST}:${PORT}`);
      resolve();
    });
    server.once('error', reject);
  });

  // Initial token extraction
  log('Starting initial authentication and token extraction...');
  try {
    const ok = await authenticate();
    if (ok) {
      await refreshAllTokens();
    } else {
      error('Initial authentication failed — tokens will be extracted on demand');
    }
  } catch (err) {
    error(`Startup token extraction failed: ${err.message}`);
    error('Service will retry authentication on next request or refresh cycle');
  }

  // Periodic token refresh
  refreshTimer = setInterval(async () => {
    // Check if any tokens need refresh
    let needsAnyRefresh = false;
    for (const [chId] of Object.entries(credentials.channels)) {
      if (needsRefresh(chId)) {
        needsAnyRefresh = true;
        break;
      }
    }

    if (needsAnyRefresh) {
      log('Periodic refresh: some tokens need renewal');
      await refreshAllTokens().catch(err => error(`Periodic refresh error: ${err.message}`));
    } else {
      log('Periodic refresh: all tokens still valid');
    }
  }, TOKEN_REFRESH_MS);
  refreshTimer.unref();

  // Stale slot sweeper
  slotSweepTimer = setInterval(sweepStaleSlots, 300000); // Every 5 min
  slotSweepTimer.unref();

  log('Seenshow resolver ready');
}

// Graceful shutdown
async function shutdown() {
  log('Shutting down...');
  if (refreshTimer) clearInterval(refreshTimer);
  if (slotSweepTimer) clearInterval(slotSweepTimer);

  server.close();

  if (browser) {
    try {
      await browser.close();
    } catch (_) {}
  }

  log('Shutdown complete');
  process.exit(0);
}

if (require.main === module) {
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  startup().catch((err) => {
    error(`Fatal startup error: ${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  validateCredentialsShape,
  parseTokenExpiry,
  extractM3u8UrlsFromText,
  candidateMatchesChannel,
  selectBestChannelCandidate,
  parseRoute,
  acquireSlot,
  releaseSlot,
  sweepStaleSlots,
  resetStateForTests,
  constants: {
    MAX_CONCURRENT,
    SLOT_AUTO_RELEASE_MS,
  },
};
