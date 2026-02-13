#!/usr/bin/env node

/**
 * YouTube Browser Resolver v2 - Full Segment Proxy
 * -------------------------------------------------
 * CRITICAL FIX: Proxies BOTH the HLS manifest AND all video segments
 * through the browser session, so FFmpeg never contacts YouTube directly.
 *
 * Why this matters:
 * - YouTube binds segment URLs to the browser's IP + session + cookies
 * - When FFmpeg fetches segments directly, it gets blocked (403)
 * - By proxying segments through the browser, all requests look legitimate
 *
 * Endpoints:
 *   GET /register?url=<youtube_url>&id=<name>
 *     - Starts (or reuses) a watcher for the URL
 *     - Returns: http://HOST:PORT/hls/<id>/master.m3u8
 *
 *   GET /hls/<id>/master.m3u8
 *     - Returns the HLS manifest with segment URLs rewritten to local proxy
 *
 *   GET /hls/<id>/segment/<encoded_url>
 *     - Fetches the actual segment through the browser and returns it
 *
 *   GET /health
 *     - Health check + list of active sessions
 *
 * Env vars:
 *   YT_RESOLVER_PORT              (default: 8088)
 *   YT_RESOLVER_HOST              (default: 127.0.0.1)
 *   YT_RESOLVER_CHROME            (default: auto-detect)
 *   YT_RESOLVER_REFRESH_MARGIN    (seconds before expire to reload, default 600)
 *   YT_RESOLVER_SEGMENT_CACHE_SEC (segment cache TTL, default 10)
 *   YT_RESOLVER_SEGMENT_TIMEOUT   (segment fetch timeout ms, default 15000)
 */

const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { URL } = require('url');
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);
const { SegmentCache, buildSegmentCacheKey } = require('./lib/segment_cache');
const { createPageWithSetup } = require('./lib/page_setup');
const { SessionSlotManager } = require('./lib/session_slots');
const {
  DEFAULT_SEGMENT_HOST_SUFFIXES,
  decodeSegmentUrl,
  hostnameMatchesAllowedSuffix,
  parseRequestUrl,
  rewriteManifest,
  validateSegmentProxyUrl
} = require('./lib/resolver_utils');

// Puppeteer setup with optional stealth
let puppeteer;
let StealthPlugin;
try {
  // Try puppeteer-extra with stealth first (best anti-detection)
  const puppeteerExtra = require('puppeteer-extra');
  StealthPlugin = require('puppeteer-extra-plugin-stealth');
  puppeteerExtra.use(StealthPlugin());
  puppeteer = puppeteerExtra;
  console.log('[resolver] Using puppeteer-extra with stealth plugin');
} catch (err) {
  try {
    puppeteer = require('puppeteer-core');
    console.log('[resolver] Using puppeteer-core (no stealth)');
  } catch (err2) {
    try {
      puppeteer = require('puppeteer');
      console.log('[resolver] Using puppeteer (no stealth)');
    } catch (err3) {
      console.error('[resolver] Missing dependency: install puppeteer-extra + puppeteer-extra-plugin-stealth (recommended) or puppeteer-core');
      process.exit(1);
    }
  }
}

// Configuration
function parseBoundedInt(rawValue, fallback, min, max) {
  const parsed = Number.parseInt(String(rawValue ?? fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

const PORT = Number(process.env.YT_RESOLVER_PORT || 8088);
const HOST = process.env.YT_RESOLVER_HOST || '127.0.0.1';
const PROXY_ORIGIN = `http://${HOST}:${PORT}`;
const REFRESH_MARGIN = Number(process.env.YT_RESOLVER_REFRESH_MARGIN || 600);
const FORCE_RELOAD_SEC = Number(process.env.YT_RESOLVER_FORCE_RELOAD_SEC || 3600);
const NAV_TIMEOUT = Number(process.env.YT_RESOLVER_NAV_TIMEOUT || 45000);
const SEGMENT_CACHE_SEC = Number(process.env.YT_RESOLVER_SEGMENT_CACHE_SEC || 10);
const SEGMENT_TIMEOUT = Number(process.env.YT_RESOLVER_SEGMENT_TIMEOUT || 15000);
const SEGMENT_CACHE_MAX_ITEMS = parseBoundedInt(process.env.YT_RESOLVER_SEGMENT_CACHE_MAX_ITEMS, 2048, 0, 200000);
const SEGMENT_CACHE_MAX_BYTES = parseBoundedInt(process.env.YT_RESOLVER_SEGMENT_CACHE_MAX_BYTES, 134217728, 0, 2147483647);
const MAX_SESSIONS = parseBoundedInt(process.env.YT_RESOLVER_MAX_SESSIONS, 64, 1, 1024);
const SESSION_IDLE_SEC = parseBoundedInt(process.env.YT_RESOLVER_SESSION_IDLE_SEC, 21600, 60, 604800);
const SESSION_IDLE_MS = SESSION_IDLE_SEC * 1000;
const SESSION_SWEEP_MS = Math.min(Math.max(Math.floor(SESSION_IDLE_MS / 2), 30000), 300000);
const SEGMENT_ALLOWED_HOST_SUFFIXES = (() => {
  const raw = process.env.YT_RESOLVER_SEGMENT_ALLOWED_HOSTS || '';
  const parsed = raw
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return parsed.length > 0 ? parsed : DEFAULT_SEGMENT_HOST_SUFFIXES;
})();

// Persistent browser profile for YouTube login persistence
// To log in: Set HEADLESS=false, run once, log into YouTube manually, then restart with headless
const USER_DATA_DIR = process.env.YT_RESOLVER_USER_DATA_DIR || path.join(os.homedir(), '.config', 'youtube-resolver-chrome');
const HEADLESS_MODE = process.env.YT_RESOLVER_HEADLESS !== 'false'; // Set to 'false' for login

// Optional bootstrap cookie file (Netscape format). Persistent profile
// remains the source of truth after successful login.
const COOKIES_FILE = process.env.YT_RESOLVER_COOKIES || '';

const USER_AGENT = process.env.YT_RESOLVER_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// Parse Netscape cookies.txt format
function parseNetscapeCookies(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  const cookies = [];
  const content = fs.readFileSync(filePath, 'utf8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split('\t');
    if (parts.length >= 7) {
      const [domain, , path, secure, expires, name, value] = parts;
      cookies.push({
        name,
        value,
        domain: domain.startsWith('.') ? domain : '.' + domain,
        path: path || '/',
        expires: parseInt(expires) || -1,
        httpOnly: false,
        secure: secure.toUpperCase() === 'TRUE',
        sameSite: 'Lax',
      });
    }
  }
  return cookies;
}

// Load cookies into a browser page
async function loadCookiesIntoPage(page) {
  if (!COOKIES_FILE) return 0;
  const cookies = parseNetscapeCookies(COOKIES_FILE);
  if (cookies.length === 0) return 0;

  // Filter for YouTube/Google cookies
  // Use suffix matching (not substring) to prevent domain spoofing
  const ytCookies = cookies.filter(c => {
    const d = c.domain.replace(/^\./, '').toLowerCase();
    return d === 'youtube.com' || d.endsWith('.youtube.com')
        || d === 'google.com' || d.endsWith('.google.com');
  });

  if (ytCookies.length > 0) {
    await page.setCookie(...ytCookies);
    log(`Loaded ${ytCookies.length} cookies from ${COOKIES_FILE}`);
  }
  return ytCookies.length;
}

// Auto-detect Chrome/Chromium path
function findChromePath() {
  const candidates = [
    process.env.YT_RESOLVER_CHROME,
    process.env.CHROMIUM,
    process.env.CHROME,
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/snap/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ];
  for (const path of candidates) {
    if (path && fs.existsSync(path)) return path;
  }
  return null;
}

const CHROME_PATH = findChromePath();
if (!CHROME_PATH) {
  console.error('[resolver] Chrome/Chromium not found. Set YT_RESOLVER_CHROME env var.');
  process.exit(1);
}

// State
const sessions = new Map(); // id -> SessionState
const pendingSessions = new Map(); // id -> Promise (prevents duplicate startWatcher)
const segmentCache = new SegmentCache({
  maxItems: SEGMENT_CACHE_MAX_ITEMS,
  maxBytes: SEGMENT_CACHE_MAX_BYTES
});
let browser;
let browserLaunchPromise;
let sessionSweepTimer;
let segmentCacheSweepTimer;

// Logging
const log = (...args) => console.log(new Date().toISOString(), ...args);
const warn = (...args) => console.warn(new Date().toISOString(), '[warn]', ...args);
const error = (...args) => console.error(new Date().toISOString(), '[error]', ...args);

function touchSession(state) {
  if (!state) return;
  state.lastAccess = Date.now();
}

async function closeSession(id, state, reason = 'unknown') {
  if (!state) return;
  if (state.timer) {
    clearTimeout(state.timer);
    state.timer = null;
  }
  sessions.delete(id);
  try {
    if (state.page) {
      await state.page.close();
    }
  } catch (err) {
    warn(`failed to close page for ${id}: ${err.message}`);
  }
  log(`session closed: ${id} (${reason})`);
}

async function evictIdleSessions(reason = 'idle-sweep') {
  const now = Date.now();
  const idleIds = [];
  for (const [id, state] of sessions.entries()) {
    const lastAccess = state.lastAccess || state.lastRegister || state.lastUpdate || 0;
    if (now - lastAccess > SESSION_IDLE_MS) {
      idleIds.push(id);
    }
  }

  for (const id of idleIds) {
    const state = sessions.get(id);
    await closeSession(id, state, reason);
  }
  return idleIds.length;
}

const sessionSlots = new SessionSlotManager({
  maxSessions: MAX_SESSIONS,
  getActiveCount: () => sessions.size,
  evictIdle: () => evictIdleSessions('capacity-check')
});

// Cleanup handlers
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

async function ensureBrowser() {
  if (browser && browser.isConnected()) return browser;
  if (browserLaunchPromise) return browserLaunchPromise;

  // Ensure user data directory exists
  if (!fs.existsSync(USER_DATA_DIR)) {
    fs.mkdirSync(USER_DATA_DIR, { recursive: true });
    log(`Created user data directory: ${USER_DATA_DIR}`);
  }

  log(`Launching browser (headless: ${HEADLESS_MODE})...`);
  browserLaunchPromise = puppeteer.launch({
    headless: HEADLESS_MODE ? 'new' : false,
    executablePath: CHROME_PATH,
    userDataDir: USER_DATA_DIR,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-setuid-sandbox',
      '--disable-gpu',
      '--autoplay-policy=no-user-gesture-required',
      '--mute-audio',
      // Anti-detection
      '--disable-blink-features=AutomationControlled',
      '--window-size=1920,1080',
    ],
    ignoreDefaultArgs: ['--enable-automation'],
  });

  try {
    browser = await browserLaunchPromise;
    browser.on('disconnected', () => {
      warn('Browser disconnected; will relaunch on next request');
      browser = undefined;
      browserLaunchPromise = undefined;
    });
    log(`Browser launched (PID: ${browser.process()?.pid})`);
    return browser;
  } catch (err) {
    throw err;
  } finally {
    browserLaunchPromise = undefined;
  }
}

function safeId(raw) {
  return (raw || 'default').toLowerCase().replace(/[^a-z0-9._-]/g, '_').slice(0, 80);
}

function extractExpire(url) {
  try {
    const match = url.match(/[/&?]expire[=/](\d+)/);
    if (match) return Number(match[1]);
  } catch (_) {}
  return null;
}

// Fetch segment through browser's network context
async function fetchSegmentViaBrowser(page, segmentUrl, timeoutMs = SEGMENT_TIMEOUT) {
  try {
    const result = await page.evaluate(async (url, timeout) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          signal: controller.signal,
          credentials: 'include',
          redirect: 'manual',
        });
        clearTimeout(timeoutId);

        if (response.status >= 300 && response.status < 400) {
          return { error: `redirect not allowed: HTTP ${response.status}`, status: response.status };
        }

        if (!response.ok) {
          return { error: `HTTP ${response.status}`, status: response.status };
        }

        const buffer = await response.arrayBuffer();
        // Convert to base64 for transport back to Node (chunked to stay within
        // V8's maximum argument count for Function.prototype.apply — using 8192
        // is well within safe limits on all engines).
        const bytes = new Uint8Array(buffer);
        const CHUNK_SIZE = 8192;
        const chunks = [];
        for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
          chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE)));
        }
        return { data: btoa(chunks.join('')), size: buffer.byteLength };
      } catch (err) {
        clearTimeout(timeoutId);
        return { error: err.message || 'fetch failed' };
      }
    }, segmentUrl, timeoutMs);

    if (result.error) {
      return { error: result.error, status: result.status };
    }

    // Decode base64 back to buffer
    const data = Buffer.from(result.data, 'base64');
    return { data, size: result.size };
  } catch (err) {
    return { error: err.message };
  }
}

// Alternative: Fetch segment using Node.js https with cookies from browser
async function fetchSegmentWithCookies(page, segmentUrl, timeoutMs = SEGMENT_TIMEOUT) {
  try {
    // Validate host against allowlist (defense-in-depth — callers should also validate)
    const targetUrl = new URL(segmentUrl);
    if (!hostnameMatchesAllowedSuffix(targetUrl.hostname, SEGMENT_ALLOWED_HOST_SUFFIXES)) {
      return { error: `host not allowed: ${targetUrl.hostname}`, status: 403 };
    }
    const cookies = await page.cookies(`https://${targetUrl.hostname}`);
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');

    return new Promise((resolve, reject) => {
      const url = new URL(segmentUrl);
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Referer': 'https://www.youtube.com/',
          'Origin': 'https://www.youtube.com',
          'Cookie': cookieHeader,
        },
      };

      const req = https.request(options, (res) => {
        if (res.statusCode !== 200) {
          resolve({ error: `HTTP ${res.statusCode}`, status: res.statusCode });
          return;
        }

        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const data = Buffer.concat(chunks);
          resolve({ data, size: data.length });
        });
      });

      req.on('error', err => resolve({ error: err.message }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ error: 'timeout' });
      });

      req.end();
    });
  } catch (err) {
    return { error: err.message };
  }
}

async function fetchManifestViaPlayer(state) {
  if (!state.page) return false;

  try {
    await state.page.waitForFunction(
      () => {
        const r = globalThis.ytInitialPlayerResponse;
        return r && r.streamingData && r.streamingData.hlsManifestUrl;
      },
      { timeout: NAV_TIMEOUT }
    );

    const hlsUrl = await state.page.evaluate(() => {
      const r = globalThis.ytInitialPlayerResponse;
      return r?.streamingData?.hlsManifestUrl;
    });

    if (!hlsUrl) return false;

    // Fetch manifest through browser (redirect:'manual' prevents SSRF via open redirects)
    const body = await state.page.evaluate(async (url) => {
      const resp = await fetch(url, { credentials: 'include', redirect: 'manual' });
      if (resp.status >= 300 && resp.status < 400) return '';
      return resp.ok ? await resp.text() : '';
    }, hlsUrl);

    if (!body.startsWith('#EXTM3U')) {
      warn(`manifest not HLS for ${state.id}`);
      return false;
    }

    // Store original manifest and create rewritten version
    state.originalManifest = body;
    state.manifest = rewriteManifest(body, state.id, PROXY_ORIGIN, hlsUrl);
    state.hlsUrl = hlsUrl;
    state.lastUpdate = Date.now();
    state.expireAt = extractExpire(hlsUrl) || Math.floor(Date.now() / 1000) + 18000;

    log(`manifest captured for ${state.id}; expires ${state.expireAt}, segments proxied`);
    scheduleRefresh(state, 'player-fetch');
    return true;
  } catch (err) {
    warn(`manifest fetch failed for ${state.id}: ${err.message}`);
    return false;
  }
}

function scheduleRefresh(state, reason = 'timer') {
  if (state.timer) clearTimeout(state.timer);
  const now = Date.now() / 1000;
  const target = (state.expireAt || now + FORCE_RELOAD_SEC) - REFRESH_MARGIN;
  const delaySec = Math.max(60, target - now);
  state.timer = setTimeout(() => refresh(state, reason), delaySec * 1000);
  log(`scheduled refresh for ${state.id} in ${Math.round(delaySec)}s`);
}

async function refresh(state, reason = 'timer') {
  if (!state.page || state.refreshing) return;
  state.refreshing = true;
  touchSession(state);
  log(`refresh(${state.id}) reason=${reason}`);

  try {
    try {
      await state.page.reload({ waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
    } catch (err) {
      warn(`reload failed for ${state.id}: ${err.message}`);
      try {
        await state.page.goto(state.youtubeUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
      } catch (err2) {
        error(`goto failed for ${state.id}: ${err2.message}`);
      }
    }

    await fetchManifestViaPlayer(state);
    scheduleRefresh(state, 'post-refresh');
  } finally {
    state.refreshing = false;
  }
}

async function startWatcher(id, youtubeUrl) {
  const existing = sessions.get(id);
  if (existing) {
    existing.youtubeUrl = youtubeUrl;
    existing.lastRegister = Date.now();
    touchSession(existing);
    if (!existing.manifest || Date.now() - (existing.lastUpdate || 0) > FORCE_RELOAD_SEC * 1000) {
      refresh(existing, 'stale-register').catch(() => {});
    }
    return existing;
  }

  // Prevent duplicate creation: if another call is already creating this session, await it
  if (pendingSessions.has(id)) {
    return pendingSessions.get(id);
  }

  const createPromise = (async () => {
    await sessionSlots.reserve(id);
    try {
      log(`starting watcher for ${id}: ${youtubeUrl}`);
      const browserInstance = await ensureBrowser();
      const page = await createPageWithSetup(browserInstance, async (newPage) => {
        // Anti-detection measures
        await newPage.setUserAgent(USER_AGENT);
        await newPage.setViewport({ width: 1920, height: 1080 });
        await newPage.setExtraHTTPHeaders({
          'Accept-Language': 'en-US,en;q=0.9',
        });

        // Hide webdriver property
        await newPage.evaluateOnNewDocument(() => {
          Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
          // Hide automation indicators
          window.chrome = { runtime: {} };
        });

        // Load cookies from file if configured
        await loadCookiesIntoPage(newPage);
      });

      const state = {
        id,
        youtubeUrl,
        page,
        manifest: '',
        originalManifest: '',
        hlsUrl: '',
        expireAt: 0,
        lastUpdate: 0,
        lastRegister: Date.now(),
        lastAccess: Date.now(),
        timer: null,
        refreshing: false,
      };

      // Listen for HLS manifest responses
      page.on('response', async (res) => {
        const url = res.url();
        if (url.includes('manifest.googlevideo.com/api/manifest/hls_playlist')) {
          try {
            const body = await res.text();
            if (body.startsWith('#EXTM3U')) {
              state.originalManifest = body;
              state.manifest = rewriteManifest(body, id, PROXY_ORIGIN, url);
              state.hlsUrl = url;
              state.lastUpdate = Date.now();
              state.expireAt = extractExpire(url) || Math.floor(Date.now() / 1000) + 18000;
              log(`manifest intercepted for ${id}; expires ${state.expireAt}`);
              scheduleRefresh(state, 'intercept');
            }
          } catch (_) {}
        }
      });

      // Log 403 errors on segments
      page.on('response', async (res) => {
        if (res.status() === 403 && res.url().includes('googlevideo.com/videoplayback')) {
          warn(`403 on segment for ${id}; scheduling refresh`);
          setTimeout(() => refresh(state, '403'), 5000);
        }
      });

      try {
        await page.goto(youtubeUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });

        // Try to click play button if video is paused
        try {
          await page.click('button.ytp-large-play-button', { timeout: 3000 }).catch(() => {});
        } catch (_) {}

        // Wait for manifest
        const gotManifest = await fetchManifestViaPlayer(state);
        if (!gotManifest) {
          // Wait a bit more for network intercept
          await new Promise(r => setTimeout(r, 5000));
        }

        scheduleRefresh(state, 'initial');
      } catch (err) {
        error(`initial navigation failed for ${id}: ${err.message}`);
        scheduleRefresh(state, 'initial-failed');
      }

      sessions.set(id, state);
      touchSession(state);
      return state;
    } finally {
      sessionSlots.release(id);
    }
  })();

  pendingSessions.set(id, createPromise);
  try {
    return await createPromise;
  } catch (err) {
    sessions.delete(id);
    throw err;
  } finally {
    pendingSessions.delete(id);
  }
}

function shutdown() {
  log('Shutting down...');
  if (sessionSweepTimer) {
    clearInterval(sessionSweepTimer);
    sessionSweepTimer = undefined;
  }
  if (segmentCacheSweepTimer) {
    clearInterval(segmentCacheSweepTimer);
  }
  for (const state of sessions.values()) {
    if (state.timer) clearTimeout(state.timer);
    if (state.page) state.page.close().catch(() => {});
  }
  sessions.clear();
  segmentCache.clear();
  if (browser) {
    browser.close().catch(() => {}).finally(() => process.exit(0));
  } else {
    process.exit(0);
  }
}

// Clean expired segment cache entries periodically
segmentCacheSweepTimer = setInterval(() => {
  segmentCache.evictExpired();
  segmentCache.evictToBudget();
}, 30000);
segmentCacheSweepTimer.unref();

sessionSweepTimer = setInterval(() => {
  evictIdleSessions('idle-sweep').catch((err) => warn(`idle sweep failed: ${err.message}`));
}, SESSION_SWEEP_MS);
sessionSweepTimer.unref();

// HTTP Server handlers
async function handleHealth(req, res) {
  // Check if logged into YouTube
  let loggedIn = false;
  try {
    if (browser && browser.isConnected()) {
      const pages = await browser.pages();
      for (const page of pages) {
        const cookies = await page.cookies('https://www.youtube.com');
        const hasLogin = cookies.some(c => c.name === 'LOGIN_INFO' || c.name === 'SID');
        if (hasLogin) {
          loggedIn = true;
          break;
        }
      }
    }
  } catch (_) {}

  const sessionsInfo = {};
  const cacheStats = segmentCache.stats();
  for (const [id, state] of sessions.entries()) {
    sessionsInfo[id] = {
      hasManifest: !!state.manifest,
      lastUpdate: state.lastUpdate ? new Date(state.lastUpdate).toISOString() : null,
      expireAt: state.expireAt ? new Date(state.expireAt * 1000).toISOString() : null,
      lastAccess: state.lastAccess ? new Date(state.lastAccess).toISOString() : null,
    };
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    ok: true,
    loggedIn,
    headless: HEADLESS_MODE,
    userDataDir: USER_DATA_DIR,
    sessionLimits: {
      maxSessions: MAX_SESSIONS,
      idleSeconds: SESSION_IDLE_SEC,
      sweepSeconds: Math.floor(SESSION_SWEEP_MS / 1000),
      pendingReservations: sessionSlots.pendingCount()
    },
    segmentCache: {
      ...cacheStats,
      ttlSeconds: SEGMENT_CACHE_SEC,
      timeoutMs: SEGMENT_TIMEOUT
    },
    segmentProxyAllowlist: SEGMENT_ALLOWED_HOST_SUFFIXES,
    sessions: sessionsInfo,
  }, null, 2));
}

// Opens YouTube login page in the browser (for manual login when in visible mode)
let loginPage = null;

async function handleLogin(req, res) {
  if (HEADLESS_MODE) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Login only available in visible mode. Restart with YT_RESOLVER_HEADLESS=false');
    return;
  }

  try {
    // Close any previously opened login page to prevent leaks
    if (loginPage) {
      await loginPage.close().catch(() => {});
      loginPage = null;
    }
    const browserInstance = await ensureBrowser();
    loginPage = await browserInstance.newPage();
    await loginPage.setUserAgent(USER_AGENT);
    await loginPage.setViewport({ width: 1920, height: 1080 });
    await loginPage.goto('https://accounts.google.com/signin/v2/identifier?service=youtube', {
      waitUntil: 'networkidle2',
      timeout: 60000,
    });
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Login page opened. Complete login in the browser, then check /health for status.');
    log('Login page opened for manual authentication');
  } catch (err) {
    error('Failed to open login page:', err.message);
    if (loginPage) { await loginPage.close().catch(() => {}); loginPage = null; }
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end(`Failed to open login page: ${err.message}`);
  }
}

async function handleRegister(req, res, parsed) {
  const youtubeUrl = parsed.searchParams.get('url');
  const idRaw = parsed.searchParams.get('id') || youtubeUrl || 'default';

  if (!youtubeUrl) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing url parameter');
    return;
  }

  const id = safeId(idRaw);
  let state;
  try {
    state = await startWatcher(id, youtubeUrl);
  } catch (err) {
    if (err && err.code === 'SESSION_LIMIT') {
      res.writeHead(429, { 'Content-Type': 'text/plain' });
      res.end(`session capacity reached (${MAX_SESSIONS}); retry later`);
      return;
    }
    throw err;
  }
  touchSession(state);
  const playbackUrl = `http://${HOST}:${PORT}/hls/${id}/master.m3u8`;

  if (!state.manifest) {
    // Wait briefly for manifest
    await new Promise(r => setTimeout(r, 3000));
  }

  if (!state.manifest) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('manifest not ready yet');
    log(`register ${id}: manifest pending`);
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(playbackUrl);
  log(`register ${id}: ${playbackUrl}`);
}

function handleManifest(req, res, sessionId) {
  const state = sessions.get(sessionId);
  if (!state || !state.manifest) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('#EXTM3U\n#EXT-X-VERSION:3\n# Manifest not ready\n');
    return;
  }
  touchSession(state);
  res.writeHead(200, {
    'Content-Type': 'application/vnd.apple.mpegurl',
    'Cache-Control': 'no-cache',
  });
  res.end(state.manifest);
}

async function handleSegment(req, res, sessionId, encodedUrl) {
  const state = sessions.get(sessionId);
  if (!state || !state.page) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('session not found');
    return;
  }
  touchSession(state);

  const decoded = decodeSegmentUrl(encodedUrl);
  if (!decoded.ok) {
    res.writeHead(decoded.status, { 'Content-Type': 'text/plain' });
    res.end(decoded.error);
    return;
  }
  const validatedTarget = validateSegmentProxyUrl(decoded.url, SEGMENT_ALLOWED_HOST_SUFFIXES);
  if (!validatedTarget.ok) {
    res.writeHead(validatedTarget.status, { 'Content-Type': 'text/plain' });
    res.end(validatedTarget.error);
    return;
  }
  const segmentUrl = validatedTarget.url;
  // Only treat as playlist if it's a manifest URL without segment indicators
  const isPlaylist = (segmentUrl.includes('manifest.googlevideo.com/api/manifest/hls') ||
                      segmentUrl.endsWith('index.m3u8')) &&
                     !segmentUrl.includes('/sq/') &&      // segment sequence number
                     !segmentUrl.includes('file/seg.ts'); // actual segment file
  const cacheKey = buildSegmentCacheKey(sessionId, segmentUrl);

  // Check cache (skip for playlists - they change frequently)
  if (!isPlaylist) {
    const cached = segmentCache.get(cacheKey);
    if (cached) {
      res.writeHead(200, {
        'Content-Type': 'video/mp2t',
        'Content-Length': cached.length,
        'X-Cache': 'HIT',
      });
      res.end(cached);
      return;
    }
  }

  // Fetch through browser
  log(`fetching ${isPlaylist ? 'playlist' : 'segment'} for ${sessionId}: ${segmentUrl.slice(0, 80)}...`);

  // For playlists, fetch as text; for segments, fetch as binary
  let result;
  if (isPlaylist) {
    // Fetch playlist as text through browser (redirect:'manual' prevents SSRF)
    try {
      const body = await state.page.evaluate(async (url) => {
        const resp = await fetch(url, { credentials: 'include', redirect: 'manual' });
        if (resp.status >= 300 && resp.status < 400) return { error: `redirect not allowed: HTTP ${resp.status}`, status: resp.status };
        if (!resp.ok) return { error: `HTTP ${resp.status}`, status: resp.status };
        return { text: await resp.text() };
      }, segmentUrl);

      if (body.error) {
        result = { error: body.error, status: body.status };
      } else if (body.text && body.text.startsWith('#EXTM3U')) {
        // Rewrite URLs in the variant playlist
        const rewritten = rewriteManifest(body.text, sessionId, PROXY_ORIGIN, segmentUrl);
        res.writeHead(200, {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Cache-Control': 'no-cache',
        });
        res.end(rewritten);
        return;
      } else {
        result = { error: 'Not a valid playlist' };
      }
    } catch (err) {
      result = { error: err.message };
    }
  } else {
    // Fetch segment as binary
    result = await fetchSegmentViaBrowser(state.page, segmentUrl);
    if (result.error) {
      warn(`browser fetch failed for ${sessionId}: ${result.error}, trying cookies method`);
      result = await fetchSegmentWithCookies(state.page, segmentUrl);
    }
  }

  if (result.error) {
    error(`${isPlaylist ? 'playlist' : 'segment'} fetch failed for ${sessionId}: ${result.error}`);

    // If 403, trigger refresh
    if (result.status === 403) {
      setTimeout(() => refresh(state, 'segment-403'), 1000);
    }

    res.writeHead(result.status || 502, { 'Content-Type': 'text/plain' });
    res.end(`fetch failed: ${result.error}`);
    return;
  }

  // Cache the segment (not playlists)
  if (!isPlaylist) {
    segmentCache.set(cacheKey, result.data, SEGMENT_CACHE_SEC * 1000);
  }

  res.writeHead(200, {
    'Content-Type': 'video/mp2t',
    'Content-Length': result.data.length,
    'X-Cache': 'MISS',
  });
  res.end(result.data);
}

const server = http.createServer(async (req, res) => {
  const parsedRequest = parseRequestUrl(req.url);
  if (!parsedRequest.ok) {
    res.writeHead(parsedRequest.status, { 'Content-Type': 'text/plain' });
    res.end(parsedRequest.error);
    return;
  }

  const parsed = parsedRequest.url;
  const path = parsed.pathname;

  try {
    if (path === '/health') {
      await handleHealth(req, res);
      return;
    }

    if (path === '/login') {
      await handleLogin(req, res);
      return;
    }

    if (path === '/register') {
      await handleRegister(req, res, parsed);
      return;
    }

    // /hls/<id>/master.m3u8
    const manifestMatch = path.match(/^\/hls\/([^/]+)\/master\.m3u8$/);
    if (manifestMatch) {
      handleManifest(req, res, manifestMatch[1]);
      return;
    }

    // /hls/<id>/segment/<encoded_url>
    const segmentMatch = path.match(/^\/hls\/([^/]+)\/segment\/(.+)$/);
    if (segmentMatch) {
      await handleSegment(req, res, segmentMatch[1], segmentMatch[2]);
      return;
    }

    // Legacy /proxy/<id>.m3u8 endpoint (for backwards compatibility)
    const legacyMatch = path.match(/^\/proxy\/([^/]+)\.m3u8$/);
    if (legacyMatch) {
      handleManifest(req, res, legacyMatch[1]);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  } catch (err) {
    error('request error:', err.message);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('internal error');
  }
});

server.timeout = 120000;
server.headersTimeout = 30000;
server.requestTimeout = 60000;

server.listen(PORT, HOST, () => {
  log(`YouTube Browser Resolver v2 listening on http://${HOST}:${PORT}`);
  log(`Using Chrome at: ${CHROME_PATH}`);
  log(`User data dir: ${USER_DATA_DIR}`);
  log(`Headless mode: ${HEADLESS_MODE}`);
  log(`Session limits: max=${MAX_SESSIONS}, idle=${SESSION_IDLE_SEC}s, sweep=${Math.floor(SESSION_SWEEP_MS / 1000)}s`);
  log(`Segment cache limits: maxItems=${SEGMENT_CACHE_MAX_ITEMS}, maxBytes=${SEGMENT_CACHE_MAX_BYTES}, ttl=${SEGMENT_CACHE_SEC}s`);
  log(`Segment proxy host allowlist: ${SEGMENT_ALLOWED_HOST_SUFFIXES.join(', ')}`);
  log(`Features: Full segment proxying, ${StealthPlugin ? 'stealth enabled' : 'no stealth'}`);
  if (!HEADLESS_MODE) {
    log('');
    log('=== LOGIN MODE ===');
    log('Browser will open in visible mode. Log into YouTube, then restart in headless mode.');
    log('To restart in headless mode: systemctl restart youtube-resolver');
    log('==================');
  }
});
