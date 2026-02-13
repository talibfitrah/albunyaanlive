#!/usr/bin/env node

/**
 * YouTube browser-backed resolver + HLS proxy
 * -------------------------------------------
 * - Launches headless Chromium (puppeteer-core or puppeteer)
 * - Opens YouTube live URLs and captures the real HLS manifest the player uses
 * - Keeps manifests fresh by reloading before expiry and on 403s
 * - Serves the manifest locally so ffmpeg/streamlink never talk to YouTube directly
 *
 * Endpoints:
 *   GET /register?url=<youtube_url>&id=<name>
 *     - Starts (or reuses) a watcher for the URL
 *     - Returns plain-text playback URL: http://HOST:PORT/proxy/<id>.m3u8
 *
 *   GET /proxy/<id>.m3u8
 *     - Returns the latest captured manifest for that id
 *
 *   GET /health
 *     - Basic health + list of active ids
 *
 * Env vars:
 *   YT_RESOLVER_PORT              (default: 8088)
 *   YT_RESOLVER_HOST              (default: 127.0.0.1)
 *   YT_RESOLVER_CHROME            (default: /usr/bin/chromium-browser)
 *   YT_RESOLVER_UA                (default: Chrome UA)
 *   YT_RESOLVER_REFRESH_MARGIN    (seconds before expire to reload, default 600)
 *   YT_RESOLVER_FORCE_RELOAD_SEC  (reload even without expire, default 3600)
 *   YT_RESOLVER_NAV_TIMEOUT       (ms, default 45000)
 */

const fs = require('fs');
const http = require('http');
const { URL } = require('url');
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);
const { createPageWithSetup } = require('./lib/page_setup');
const { parseRequestUrl } = require('./lib/resolver_utils');
const { SessionSlotManager } = require('./lib/session_slots');

let puppeteer;
try {
  puppeteer = require('puppeteer-core');
} catch (err) {
  try {
    puppeteer = require('puppeteer');
  } catch (err2) {
    console.error('[resolver] Missing dependency: install puppeteer-core (preferred) or puppeteer');
    console.error('[resolver] First error:', err && err.message ? err.message : err);
    console.error('[resolver] Second error:', err2 && err2.message ? err2.message : err2);
    process.exit(1);
  }
}

function parseBoundedInt(rawValue, fallback, min, max) {
  const parsed = Number.parseInt(String(rawValue ?? fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

const PORT = Number(process.env.YT_RESOLVER_PORT || 8088);
const HOST = process.env.YT_RESOLVER_HOST || '127.0.0.1';
const USER_AGENT =
  process.env.YT_RESOLVER_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const CHROME_PATH =
  process.env.YT_RESOLVER_CHROME ||
  process.env.CHROMIUM ||
  process.env.CHROME ||
  '/usr/bin/chromium-browser';
const REFRESH_MARGIN = Number(process.env.YT_RESOLVER_REFRESH_MARGIN || 600); // seconds before expiry to reload
const FORCE_RELOAD_SEC = Number(process.env.YT_RESOLVER_FORCE_RELOAD_SEC || 3600); // safety reload window
const NAV_TIMEOUT = Number(process.env.YT_RESOLVER_NAV_TIMEOUT || 45000);
const YT_RESOLVER_YTDLP_TIMEOUT = Number(process.env.YT_RESOLVER_YTDLP_TIMEOUT || 20);
const MAX_SESSIONS = parseBoundedInt(process.env.YT_RESOLVER_MAX_SESSIONS, 64, 1, 1024);
const SESSION_IDLE_SEC = parseBoundedInt(process.env.YT_RESOLVER_SESSION_IDLE_SEC, 21600, 60, 604800);
const SESSION_IDLE_MS = SESSION_IDLE_SEC * 1000;
const SESSION_SWEEP_MS = Math.min(Math.max(Math.floor(SESSION_IDLE_MS / 2), 30000), 300000);

const sessions = new Map(); // id -> { page, youtubeUrl, manifest, expireAt, lastUpdate, timer }
const pendingSessions = new Map(); // id -> Promise (prevents duplicate startWatcher)
let browser;
let browserPromise;
let sessionSweepTimer;

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

if (!fs.existsSync(CHROME_PATH)) {
  error(`Chromium not found at ${CHROME_PATH}. Set YT_RESOLVER_CHROME to your chromium-browser path.`);
  process.exit(1);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

async function ensureBrowser() {
  if (browser) return browser;
  if (browserPromise) return browserPromise;

  browserPromise = puppeteer.launch({
    headless: 'new',
    executablePath: CHROME_PATH,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--autoplay-policy=no-user-gesture-required',
      '--mute-audio',
    ],
  });

  try {
    browser = await browserPromise;
    browser.on('disconnected', () => {
      warn('Browser disconnected; will relaunch on next request');
      browser = undefined;
      browserPromise = undefined;
    });
    return browser;
  } catch (err) {
    throw err;
  } finally {
    browserPromise = undefined;
  }
}

function safeId(raw) {
  const base = (raw || 'default').toLowerCase();
  return base.replace(/[^a-z0-9._-]/g, '_').slice(0, 80);
}

function extractExpire(url) {
  try {
    const parsed = new URL(url);
    const exp = parsed.searchParams.get('expire');
    if (exp) return Number(exp);
  } catch (_) {
    /* ignore */
  }
  const match = url.match(/\/expire\/(\d+)/);
  if (match) return Number(match[1]);
  return null;
}

function buildProxyUrl(id) {
  return `http://${HOST}:${PORT}/proxy/${encodeURIComponent(id)}.m3u8`;
}

function scheduleRefresh(state, reason = 'timer') {
  if (state.timer) clearTimeout(state.timer);
  const now = Date.now() / 1000;
  const target = (state.expireAt || now + FORCE_RELOAD_SEC) - REFRESH_MARGIN;
  const delaySec = Math.max(30, target - now); // never shorter than 30s
  state.timer = setTimeout(() => refresh(state, reason), delaySec * 1000);
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
      return r && r.streamingData && r.streamingData.hlsManifestUrl;
    });
    if (!hlsUrl) return false;

    const body = await state.page.evaluate(async (url) => {
      const resp = await fetch(url, { redirect: 'manual' });
      if (resp.status >= 300 && resp.status < 400) return '';
      return resp.ok ? await resp.text() : '';
    }, hlsUrl);

    if (!body.startsWith('#EXTM3U')) {
      warn(`manifest fetch via player failed for ${state.id}: not an HLS manifest`);
      return false;
    }

    state.manifest = body;
    state.lastUpdate = Date.now();
    state.expireAt = extractExpire(hlsUrl) || Math.floor(Date.now() / 1000) + 18000;
    log(`manifest fetched via player for ${state.id}; expires ${state.expireAt}, length=${body.length}`);
    scheduleRefresh(state, 'player-fetch');
    return true;
  } catch (err) {
    warn(`manifest fetch via player failed for ${state.id}: ${err.message}`);
    return false;
  }
}

async function fetchManifestFromUrl(state, manifestUrl) {
  if (typeof globalThis.fetch !== 'function') {
    warn(`fetchManifestFromUrl: global fetch unavailable (requires Node 18+)`);
    return false;
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  try {
    const resp = await fetch(manifestUrl, {
      headers: { 'User-Agent': USER_AGENT },
      signal: controller.signal,
      redirect: 'manual',
    });
    clearTimeout(timeoutId);
    if (!resp.ok) {
      warn(`manifest fetch via URL failed for ${state.id}: HTTP ${resp.status}`);
      return false;
    }
    const body = await resp.text();
    if (!body.startsWith('#EXTM3U')) {
      warn(`manifest fetch via URL failed for ${state.id}: not an HLS manifest`);
      return false;
    }
    state.manifest = body;
    state.lastUpdate = Date.now();
    state.expireAt = extractExpire(manifestUrl) || Math.floor(Date.now() / 1000) + 18000;
    log(`manifest fetched via URL for ${state.id}; expires ${state.expireAt}, length=${body.length}`);
    scheduleRefresh(state, 'url-fetch');
    return true;
  } catch (err) {
    clearTimeout(timeoutId);
    warn(`manifest fetch via URL failed for ${state.id}: ${err.message}`);
    return false;
  }
}

async function fetchManifestViaYtdlp(state) {
  const args = ['-g', '--no-warnings', '--no-playlist', '-f', 'best'];
  if (process.env.YT_RESOLVER_COOKIES && fs.existsSync(process.env.YT_RESOLVER_COOKIES)) {
    args.push('--cookies', process.env.YT_RESOLVER_COOKIES);
  }
  args.push(state.youtubeUrl);

  try {
    const { stdout } = await execFileAsync('yt-dlp', args, {
      timeout: YT_RESOLVER_YTDLP_TIMEOUT * 1000,
      maxBuffer: 1024 * 1024,
    });
    const manifestUrl = stdout.trim().split('\n')[0];
    if (!manifestUrl || !manifestUrl.startsWith('http')) {
      warn(`yt-dlp did not return a manifest URL for ${state.id}`);
      return false;
    }
    return await fetchManifestFromUrl(state, manifestUrl);
  } catch (err) {
    warn(`yt-dlp manifest fetch failed for ${state.id}: ${err.message}`);
    return false;
  }
}

async function refresh(state, reason = 'timer') {
  if (!state.page) return;
  if (state.refreshing) return;
  state.refreshing = true;
  touchSession(state);
  log(`refresh(${state.id}) reason=${reason}`);
  try {
    await state.page.reload({ waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
  } catch (err) {
    warn(`reload failed for ${state.id}, retrying goto: ${err.message}`);
    try {
      await state.page.goto(state.youtubeUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
    } catch (err2) {
      error(`goto failed for ${state.id}: ${err2.message}`);
    }
  } finally {
    const gotPlayer = await fetchManifestViaPlayer(state);
    if (!gotPlayer) {
      await fetchManifestViaYtdlp(state);
    }
    state.refreshing = false;
    scheduleRefresh(state);
  }
}

async function captureManifest(state, res) {
  const body = await res.text().catch(() => '');
  if (!body.startsWith('#EXTM3U')) return;

  state.manifest = body;
  state.lastUpdate = Date.now();
  const expire = extractExpire(res.url());
  state.expireAt = expire || Math.floor(Date.now() / 1000) + 18000; // assume ~5h if missing
  log(`manifest updated for ${state.id}; expires ${state.expireAt}, length=${body.length}`);
  scheduleRefresh(state, 'manifest');
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
      const browserInstance = await ensureBrowser();
      const page = await createPageWithSetup(browserInstance, async (newPage) => {
        await newPage.setUserAgent(USER_AGENT);
        await newPage.setViewport({ width: 1280, height: 720 });
      });

      const state = {
        id,
        youtubeUrl,
        page,
        manifest: '',
        expireAt: 0,
        lastUpdate: 0,
        lastRegister: Date.now(),
        lastAccess: Date.now(),
        timer: null,
        refreshing: false,
      };

      page.on('response', async (res) => {
        const url = res.url();
        const status = res.status();
        if (url.includes('manifest.googlevideo.com/api/manifest/hls_playlist')) {
          await captureManifest(state, res);
          return;
        }
        if (status === 403 && url.includes('googlevideo.com/videoplayback')) {
          warn(`403 on segment for ${state.id}; forcing refresh`);
          refresh(state, '403').catch(() => {});
        }
      });

      page.on('requestfailed', (req) => {
        const url = req.url();
        if (url.includes('googlevideo.com')) {
          const failure = req.failure ? req.failure() : null;
          const reason = (failure && failure.errorText) ? failure.errorText : 'unknown';
          warn(`request failed for ${state.id}: ${url} (${reason})`);
        }
      });

      try {
        await page.goto(youtubeUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT });
        const gotPlayer = await fetchManifestViaPlayer(state); // eager fetch via player response
        if (!gotPlayer) {
          await fetchManifestViaYtdlp(state);
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
  log('Shutting down resolver...');
  if (sessionSweepTimer) {
    clearInterval(sessionSweepTimer);
    sessionSweepTimer = undefined;
  }
  for (const state of sessions.values()) {
    if (state.timer) clearTimeout(state.timer);
    if (state.page) state.page.close().catch(() => {});
  }
  sessions.clear();
  if (browser) {
    browser.close().catch(() => {}).finally(() => process.exit(0));
  } else {
    process.exit(0);
  }
}

function handleHealth(req, res) {
  const sessionsInfo = {};
  for (const [id, state] of sessions.entries()) {
    sessionsInfo[id] = {
      hasManifest: !!state.manifest,
      lastUpdate: state.lastUpdate ? new Date(state.lastUpdate).toISOString() : null,
      lastAccess: state.lastAccess ? new Date(state.lastAccess).toISOString() : null,
    };
  }

  const body = {
    ok: true,
    sessionLimits: {
      maxSessions: MAX_SESSIONS,
      idleSeconds: SESSION_IDLE_SEC,
      sweepSeconds: Math.floor(SESSION_SWEEP_MS / 1000),
      pendingReservations: sessionSlots.pendingCount()
    },
    sessions: sessionsInfo,
  };
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function handleRegister(req, res, parsed) {
  const youtubeUrl = parsed.searchParams.get('url');
  const idRaw = parsed.searchParams.get('id') || youtubeUrl || 'default';
  if (!youtubeUrl) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('missing url');
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
  const playback = buildProxyUrl(id);

  if (!state.manifest) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('manifest not ready');
    log(`registered ${id} -> ${youtubeUrl} (manifest pending)`);
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(playback);
  log(`registered ${id} -> ${youtubeUrl} (playback ${playback})`);
}

function handleProxy(req, res, id) {
  const state = sessions.get(id);
  if (!state || !state.manifest) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('#EXTM3U\n# Unavailable yet\n');
    return;
  }
  touchSession(state);
  res.writeHead(200, { 'Content-Type': 'application/vnd.apple.mpegurl' });
  res.end(state.manifest);
}

sessionSweepTimer = setInterval(() => {
  evictIdleSessions('idle-sweep').catch((err) => warn(`idle sweep failed: ${err.message}`));
}, SESSION_SWEEP_MS);
sessionSweepTimer.unref();

const server = http.createServer(async (req, res) => {
  const parsedRequest = parseRequestUrl(req.url);
  if (!parsedRequest.ok) {
    res.writeHead(parsedRequest.status, { 'Content-Type': 'text/plain' });
    res.end(parsedRequest.error);
    return;
  }
  const parsed = parsedRequest.url;

  if (parsed.pathname === '/health') {
    handleHealth(req, res);
    return;
  }

  if (parsed.pathname === '/register') {
    try {
      await handleRegister(req, res, parsed);
    } catch (err) {
      error('register failed:', err.message);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('error');
    }
    return;
  }

  if (parsed.pathname.startsWith('/proxy/')) {
    let id;
    try {
      id = decodeURIComponent(parsed.pathname.replace('/proxy/', '').replace(/\.m3u8$/, ''));
    } catch (err) {
      warn(`Bad proxy URL encoding: ${parsed.pathname}: ${err.message}`);
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('bad request: malformed URL encoding');
      return;
    }
    handleProxy(req, res, id);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

server.listen(PORT, HOST, () => {
  log(`YouTube browser resolver listening on http://${HOST}:${PORT}`);
  log(`Using Chromium at ${CHROME_PATH}`);
  log(`Session limits: max=${MAX_SESSIONS}, idle=${SESSION_IDLE_SEC}s, sweep=${Math.floor(SESSION_SWEEP_MS / 1000)}s`);
});
