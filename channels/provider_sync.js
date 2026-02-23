#!/usr/bin/env node
'use strict';

// =============================================================================
// IPTV Provider Sync Service
// =============================================================================
// Periodically syncs channel catalog from Xtream Codes compatible provider,
// tracks credential health, and updates channel_*.sh config files when URLs
// change. Exposes HTTP API for on-demand resolution and status.
// =============================================================================

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function parseBoundedInt(rawValue, fallback, min, max) {
  const parsed = Number.parseInt(String(rawValue ?? fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

function parsePortValue(value) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > 65535) {
    return null;
  }
  return parsed;
}

function parsePortList(rawValue, fallbackPorts = []) {
  const source = typeof rawValue === 'string' ? rawValue : '';
  const parsed = source
    .split(',')
    .map((item) => parsePortValue(item.trim()))
    .filter((port) => port !== null);

  const combined = parsed.length > 0 ? parsed : fallbackPorts;
  const deduped = [];
  const seen = new Set();
  for (const port of combined) {
    const normalized = parsePortValue(port);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    deduped.push(normalized);
  }
  return deduped;
}

function buildApiPortCandidates({
  preferredPort,
  defaultPort,
  discoveredPorts = [],
  probePorts = []
}) {
  const candidates = [];
  const seen = new Set();
  const pushPort = (value) => {
    const normalized = parsePortValue(value);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    candidates.push(normalized);
  };

  pushPort(preferredPort);
  pushPort(defaultPort);

  if (Array.isArray(discoveredPorts)) {
    for (const value of discoveredPorts) {
      pushPort(value);
    }
  }
  if (Array.isArray(probePorts)) {
    for (const value of probePorts) {
      pushPort(value);
    }
  }

  return candidates;
}

const PORT = parseBoundedInt(process.env.PROVIDER_SYNC_PORT, 8089, 1, 65535);
const HOST = process.env.PROVIDER_SYNC_HOST || '127.0.0.1';
const SYNC_INTERVAL_MS = parseBoundedInt(process.env.SYNC_INTERVAL_MS, 1800000, 1000, 86400000); // 30 min
const CREDENTIAL_CHECK_STAGGER_MS = 2000; // 2s between credential checks
const API_TIMEOUT_MS = 15000;
const API_PORT_PROBE_TIMEOUT_MS = parseBoundedInt(
  process.env.PROVIDER_SYNC_API_PORT_TIMEOUT_MS,
  API_TIMEOUT_MS,
  1000,
  60000
);
const API_PORT_PROBE_PORTS = parsePortList(
  process.env.PROVIDER_SYNC_API_PORTS,
  [80, 8080, 8000, 9000]
);
const CHANNEL_CONFIG_BASENAME_RE = /^channel_[a-z0-9_]+\.sh$/i;

function resolvePathFromBase(baseDir, configuredPath, defaultBasename) {
  if (typeof configuredPath === 'string' && configuredPath.trim() !== '') {
    return path.isAbsolute(configuredPath)
      ? configuredPath
      : path.join(baseDir, configuredPath);
  }
  return path.join(baseDir, defaultBasename);
}

const CHANNELS_DIR = path.resolve(process.env.PROVIDER_BASE_DIR || __dirname);
const CREDENTIALS_FILE = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.PROVIDER_CREDENTIALS_FILE,
  'provider_credentials.json'
);
const REGISTRY_FILE = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.PROVIDER_REGISTRY_FILE,
  'channel_registry.json'
);
const CATALOG_FILE = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.PROVIDER_CATALOG_FILE,
  'provider_catalog.json'
);
const GRACEFUL_RESTART_SCRIPT = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.PROVIDER_GRACEFUL_RESTART_SCRIPT,
  'graceful_restart.sh'
);
const GRACEFUL_RESTART_TIMEOUT_MS = parseBoundedInt(
  process.env.PROVIDER_GRACEFUL_RESTART_TIMEOUT_MS,
  120000,
  1000,
  600000
);
const SKIP_INITIAL_SYNC = process.env.PROVIDER_SYNC_SKIP_INITIAL_SYNC === '1';
const EXIT_AFTER_INITIAL_SYNC = process.env.PROVIDER_SYNC_EXIT_AFTER_INITIAL_SYNC === '1';
const SEENSHOW_RESOLVER_URL = (process.env.SEENSHOW_RESOLVER_URL || 'http://127.0.0.1:8090').replace(/\/+$/, '');
const SEENSHOW_RESOLVER_TIMEOUT_MS = parseBoundedInt(
  process.env.SEENSHOW_RESOLVER_TIMEOUT_MS,
  10000,
  1000,
  60000
);
const SEENSHOW_ENABLE_RESOLVER = process.env.SEENSHOW_ENABLE_RESOLVER !== '0';

// ---------------------------------------------------------------------------
// Ayyadonline Provider Configuration
// ---------------------------------------------------------------------------
const AYYADONLINE_CREDENTIALS_FILE = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.AYYADONLINE_CREDENTIALS_FILE,
  'ayyadonline_credentials.json'
);
const AYYADONLINE_CATALOG_FILE = resolvePathFromBase(
  CHANNELS_DIR,
  process.env.AYYADONLINE_CATALOG_FILE,
  'ayyadonline_catalog.json'
);

// Hardcoded channel→ayyadonline stream mappings (1 credential per channel).
// Stored here because the registry sanitizer strips unknown fields.
const AYYADONLINE_CHANNEL_MAP = {
  'almajd-news':           { stream_id: 77453,   credential: 'farouq10226' },
  'almajd-kids':           { stream_id: 77336,   credential: 'farouq20226' },
  'almajd-3aamah':         { stream_id: 201243,  credential: 'farouq30226' },
  'natural':               { stream_id: 77334,   credential: 'farouq40226' },
  'basmah':                { stream_id: 77338,   credential: 'farouq50226' },
  'ajaweed':               { stream_id: 1302160, credential: 'farouq60226' },
  'makkah':                { stream_id: 28179,   credential: 'farouq70226' },
  'rawdah':                { stream_id: 77333,   credential: 'farouq80226' },
  'arrahmah':              { stream_id: 28183,   credential: 'farouq90226' },
  'almajd-islamic-science':{ stream_id: 1302162, credential: 'farouq100226' },
  'uthaymeen':             { stream_id: 170860,  credential: 'farouq120226' },
  'maassah':               { stream_id: 13058,   credential: 'farouq13226' },
  'daal':                  { stream_id: 1302163, credential: 'farouq150226' },
  'sunnah':                { stream_id: 50230,   credential: 'farouq160226' },
  'mekkah-quran':          { stream_id: 50223,   credential: 'farouq170226' },
  'almajd-documentary':    { stream_id: 77337,   credential: 'farouq180226' },
  'nada':                  { stream_id: 75516,   credential: 'farouq190226' },
  'zaad':                  { stream_id: 77065,   credential: 'farouq200226' },
};

// Credentials reserved for testing/spare — never assigned to any channel.
const RESERVED_CREDENTIALS = new Set(
  (process.env.RESERVED_CREDENTIALS || '302285257136,964683414160')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(...args) {
  console.log(`[${new Date().toISOString()}] [provider-sync]`, ...args);
}

function warn(...args) {
  console.warn(`[${new Date().toISOString()}] [provider-sync] WARN:`, ...args);
}

function error(...args) {
  console.error(`[${new Date().toISOString()}] [provider-sync] ERROR:`, ...args);
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {{ server: string, default_port: number, credentials: Array<{username: string, password: string}> }} */
let providerConfig = null;

/** @type {Map<string, { username: string, password: string, status: string, server_url: string, server_port: number, server_protocol: string, expiry_date: Date|null, last_check: Date|null, error: string|null }>} */
const credentialPool = new Map();

/** @type {Map<number, { stream_id: number, name: string, stream_icon: string, category_id: string }>} */
const catalog = new Map();

/** @type {Map<string, number[]>} normalized name → stream_id candidates */
const catalogNameIndex = new Map();

/** @type {{ channels: Object }} */
let registry = { channels: {} };

/** @type {{ server: string, default_port: number, credentials: Array<{username: string, password: string}> } | null} */
let ayyadonlineConfig = null;

/** @type {Map<string, { username: string, password: string }>} */
const ayyadonlineCredentialPool = new Map();

/** @type {Map<number, { stream_id: number, name: string }>} */
const ayyadonlineCatalog = new Map();

let lastSyncTime = null;
let syncInProgress = false;
let syncTimer = null;
let preferredApiPort = null;

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function normalizeName(name) {
  if (!name) return '';
  return name
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // strip diacritics
    .replace(/\bal[\s-]*/gi, '')     // remove "al ", "al-" prefix
    .replace(/[^a-z0-9\s]/g, ' ')   // non-alphanum → space
    .replace(/\s+/g, ' ')           // collapse whitespace
    .trim();
}

function wordSimilarity(a, b) {
  const wordsA = new Set(a.split(' ').filter(Boolean));
  const wordsB = new Set(b.split(' ').filter(Boolean));
  if (wordsA.size === 0 || wordsB.size === 0) return 0;
  let common = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) common++;
  }
  return common / Math.max(wordsA.size, wordsB.size);
}

// Provider catalogs sometimes rename channels by adding/removing "HD", "SD", etc.
// Treat these as non-semantic tokens during matching so stream_id drift can be corrected.
const CHANNEL_MATCH_STOPWORDS = new Set([
  'hd',
  'sd',
  'fhd',
  'uhd',
  '4k',
  '8k',
  'hevc',
  'h265',
  'h264',
  'x265',
  'x264',
  'tv',
  'channel',
]);

function tokenizeNormalizedName(normalized) {
  if (!normalized) return [];
  const tokens = normalized
    .split(' ')
    .map((t) => t.trim())
    .filter(Boolean)
    .filter((t) => !CHANNEL_MATCH_STOPWORDS.has(t));
  return [...new Set(tokens)];
}

function tokenOverlapStats(tokensA, tokensB) {
  if (!Array.isArray(tokensA) || !Array.isArray(tokensB)) {
    return { common: 0, coverage: 0, jaccard: 0, extra: 0 };
  }
  if (tokensA.length === 0 || tokensB.length === 0) {
    return { common: 0, coverage: 0, jaccard: 0, extra: 0 };
  }

  const setA = new Set(tokensA);
  const setB = new Set(tokensB);
  let common = 0;
  for (const token of setA) {
    if (setB.has(token)) common++;
  }

  const coverage = common / setA.size;
  const union = setA.size + setB.size - common;
  const jaccard = union > 0 ? (common / union) : 0;
  const extra = setB.size - common;
  return { common, coverage, jaccard, extra };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function redactUrlCredentials(url) {
  if (!url || typeof url !== 'string') return url;
  // Redact Xtream-style path credentials: http://host:port/user/pass/stream_id
  let redacted = url.replace(
    /^(https?:\/\/[^/]+\/)[^/]+\/[^/]+\/([^/?#]+)([/?#].*)?$/i,
    (_match, prefix, streamId, suffix = '') => `${prefix}***/***/${streamId}${suffix}`
  );
  // Redact query-parameter credentials: ?username=X&password=Y
  redacted = redacted.replace(/([?&])(username|password)=[^&#]*/gi, '$1$2=***');
  return redacted;
}

function redactSecretForApi(_secret) {
  return '<redacted>';
}

function buildPlayerApiUrl(server, port, username, password, action = '') {
  const target = new URL(`http://${server}:${port}/player_api.php`);
  target.searchParams.set('username', username);
  target.searchParams.set('password', password);
  if (action) {
    target.searchParams.set('action', action);
  }
  return target.toString();
}

function arraysEqual(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function isSeenshowUrl(url) {
  return typeof url === 'string' && /^https?:\/\/live\.seenshow\.com(\/|$)/i.test(url.trim());
}

/**
 * Strip ALL hdntl/hdnts tokens from a Seenshow URL (both path-segment and
 * query-string forms), returning the clean base URL suitable for persistent
 * storage.  Non-Seenshow URLs are returned unchanged.
 *
 * Handled forms:
 *   Path segment:  .../hdntl=exp=...~hmac=.../3.m3u8  →  .../3.m3u8
 *   Query param:   ...master.m3u8?hdntl=exp=...        →  ...master.m3u8
 *   Query mixed:   ...3.m3u8?foo=1&hdnts=exp=...&bar=2 →  ...3.m3u8?foo=1&bar=2
 */
function stripSeenshowToken(url) {
  if (!isSeenshowUrl(url)) return url;
  // 1. Strip path-segment tokens:  /hdntl=.../  or  /hdnts=.../
  let cleaned = url.replace(/\/hdnt[ls]=[^/]+\//g, '/');
  // 2. Strip query-string tokens using URL API when possible (handles multiple
  //    hdnt params, mixed hdntl+hdnts, and fragment edge cases correctly).
  try {
    const parsed = new URL(cleaned);
    let changed = false;
    for (const key of [...parsed.searchParams.keys()]) {
      if (/^hdnt[ls]$/.test(key)) {
        parsed.searchParams.delete(key);
        changed = true;
      }
    }
    if (changed) cleaned = parsed.toString();
  } catch (_) {
    // Fallback regex for malformed URLs
    cleaned = cleaned.replace(/[?&]hdnt[ls]=[^&#]*/g, '');
    cleaned = cleaned.replace(/\?(?=[&#]|$)/, '');
  }
  return cleaned;
}

function parseVlcNewsUrl(url) {
  if (typeof url !== 'string' || url.trim() === '') return null;
  const trimmed = url.trim();
  const match = trimmed.match(/^https?:\/\/vlc\.news:(\d+)\/([^/]+)\/([^/]+)\/(\d+)(?:[/?#].*)?$/i);
  if (!match) return null;

  const port = parsePortValue(match[1]);
  const streamId = parsePositiveStreamId(match[4]);
  if (!port || !streamId) return null;

  return {
    port,
    username: match[2],
    password: match[3],
    streamId,
    url: trimmed
  };
}

function parseSeenshowHlsPath(url) {
  if (typeof url !== 'string') return null;
  const trimmed = url.trim();
  // Accept both:
  //   /hls/live/<id>/<name>/master.m3u8?hdntl=...
  //   /hls/live/<id>/<name>/hdntl=.../3.m3u8
  const match = trimmed.match(
    /^https?:\/\/live\.seenshow\.com\/hls\/live\/([^/?#]+\/[^/?#]+)\/(?:hdnt[ls]=[^/]+\/)?[^/?#]+\.m3u8(?:[?#].*)?$/i
  );
  return match ? match[1] : null;
}

async function resolveSeenshowTokenUrl(hlsPath, fetchJson = httpGetJson) {
  if (!SEENSHOW_ENABLE_RESOLVER) {
    return null;
  }
  if (typeof hlsPath !== 'string' || hlsPath.trim() === '') {
    throw new Error('hlsPath must be a non-empty string');
  }

  const endpoint = `${SEENSHOW_RESOLVER_URL}/resolve/${hlsPath.trim()}`;
  const payload = await fetchJson(endpoint, SEENSHOW_RESOLVER_TIMEOUT_MS);
  if (!payload || typeof payload.url !== 'string' || payload.url.trim() === '') {
    throw new Error(`Resolver response missing URL for ${hlsPath}`);
  }
  return payload.url.trim();
}

async function refreshSeenshowBackups(nonVlcBackups, options = {}) {
  const fetchJson = typeof options.fetchJson === 'function' ? options.fetchJson : httpGetJson;
  const cache = options.cache instanceof Map ? options.cache : new Map();

  if (!SEENSHOW_ENABLE_RESOLVER || !Array.isArray(nonVlcBackups) || nonVlcBackups.length === 0) {
    return {
      backups: Array.isArray(nonVlcBackups) ? [...nonVlcBackups] : [],
      changed: false,
      refreshedCount: 0,
      failedCount: 0,
    };
  }

  const refreshed = [];
  let changed = false;
  let refreshedCount = 0;
  let failedCount = 0;

  for (const backupUrl of nonVlcBackups) {
    if (!isSeenshowUrl(backupUrl)) {
      refreshed.push(backupUrl);
      continue;
    }

    const hlsPath = parseSeenshowHlsPath(backupUrl);
    if (!hlsPath) {
      warn(`Could not parse Seenshow hls_path from backup URL, leaving unchanged: ${backupUrl}`);
      refreshed.push(backupUrl);
      failedCount++;
      continue;
    }

    try {
      let tokenized = cache.get(hlsPath);
      if (!tokenized) {
        tokenized = await resolveSeenshowTokenUrl(hlsPath, fetchJson);
        if (tokenized) {
          cache.set(hlsPath, tokenized);
        }
      }

      if (tokenized) {
        refreshed.push(tokenized);
        if (tokenized !== backupUrl) {
          changed = true;
          refreshedCount++;
        }
      } else {
        refreshed.push(backupUrl);
      }
    } catch (e) {
      failedCount++;
      warn(`Seenshow token resolve failed for ${hlsPath}: ${e.message}`);
      refreshed.push(backupUrl);
    }
  }

  return { backups: refreshed, changed, refreshedCount, failedCount };
}

function toNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function toPort(value, fieldName) {
  const port = parseInt(String(value), 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(`${fieldName} must be an integer between 1 and 65535`);
  }
  return port;
}

function sanitizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const cleaned = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const normalized = item.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    cleaned.push(normalized);
  }
  return cleaned;
}

function parsePositiveStreamId(value) {
  let parsed = value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) return null;
    parsed = Number.parseInt(trimmed, 10);
  }
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function assertValidChannelConfigFilename(configFile, fieldName = 'config_file') {
  const trimmed = toNonEmptyString(configFile, fieldName);
  if (trimmed !== path.basename(trimmed)) {
    throw new Error(`${fieldName} must be a file name without path separators`);
  }
  if (!CHANNEL_CONFIG_BASENAME_RE.test(trimmed)) {
    throw new Error(`${fieldName} must match channel_*.sh`);
  }
  return trimmed;
}

function resolveChannelConfigPath(configFile, baseDir = CHANNELS_DIR) {
  const safeFile = assertValidChannelConfigFilename(configFile, 'config_file');
  const resolvedBase = path.resolve(baseDir);
  const resolvedPath = path.resolve(resolvedBase, safeFile);
  const baseWithSep = resolvedBase.endsWith(path.sep) ? resolvedBase : `${resolvedBase}${path.sep}`;
  if (resolvedPath !== resolvedBase && !resolvedPath.startsWith(baseWithSep)) {
    throw new Error(`config_file escapes channels directory: ${configFile}`);
  }
  return resolvedPath;
}

function validateProviderConfigShape(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('provider config must be a JSON object');
  }

  const server = toNonEmptyString(config.server, 'server');
  const defaultPort = toPort(config.default_port ?? 80, 'default_port');
  if (!Array.isArray(config.credentials) || config.credentials.length === 0) {
    throw new Error('credentials must be a non-empty array');
  }

  const credentials = [];
  const seenUsernames = new Set();
  for (let i = 0; i < config.credentials.length; i++) {
    const cred = config.credentials[i];
    if (!cred || typeof cred !== 'object' || Array.isArray(cred)) {
      throw new Error(`credentials[${i}] must be an object`);
    }
    const username = toNonEmptyString(cred.username, `credentials[${i}].username`);
    const password = toNonEmptyString(cred.password, `credentials[${i}].password`);
    if (seenUsernames.has(username)) {
      throw new Error(`duplicate username in credentials: ${username}`);
    }
    seenUsernames.add(username);
    credentials.push({ username, password });
  }

  return {
    server,
    default_port: defaultPort,
    credentials
  };
}

function sanitizeRegistryChannel(channelId, rawChannel) {
  if (!rawChannel || typeof rawChannel !== 'object' || Array.isArray(rawChannel)) {
    throw new Error('entry must be an object');
  }

  const configFile = assertValidChannelConfigFilename(rawChannel.config_file, `${channelId}.config_file`);
  const streamId = parsePositiveStreamId(rawChannel.stream_id);
  if (!streamId) {
    throw new Error(`${channelId}.stream_id must be a positive integer`);
  }

  const scaleRaw = rawChannel.scale;
  const scaleParsed = parseInt(String(scaleRaw ?? 0), 10);
  const scale = Number.isFinite(scaleParsed) && scaleParsed >= 0 ? scaleParsed : 0;

  const providerName = typeof rawChannel.provider_name === 'string'
    ? rawChannel.provider_name.trim()
    : '';
  const preferredCredential = typeof rawChannel.preferred_credential === 'string'
    ? rawChannel.preferred_credential.trim()
    : '';

  const matchNames = sanitizeStringArray(rawChannel.match_names);
  if (matchNames.length === 0 && providerName) {
    matchNames.push(providerName);
  }

  const nonVlcBackups = sanitizeStringArray(rawChannel.non_vlc_backups).filter(url => !/vlc\.news/i.test(url));
  const vlcAsBackup = rawChannel.vlc_as_backup === true;
  const lastUpdated = typeof rawChannel.last_updated === 'string' && rawChannel.last_updated.trim() !== ''
    ? rawChannel.last_updated
    : null;

  // Ayyadonline provider metadata (optional — only for channels mapped to ayyadonline)
  const ayyadonlineStreamId = parsePositiveStreamId(rawChannel.ayyadonline_stream_id);
  const ayyadonlineCredential = typeof rawChannel.ayyadonline_credential === 'string'
    ? rawChannel.ayyadonline_credential.trim()
    : '';

  const result = {
    stream_id: streamId,
    match_names: matchNames,
    config_file: configFile,
    provider_name: providerName,
    preferred_credential: preferredCredential,
    scale,
    non_vlc_backups: nonVlcBackups,
    vlc_as_backup: vlcAsBackup,
    last_updated: lastUpdated
  };

  // Only include ayyadonline fields when present (avoid polluting channels without mapping)
  if (ayyadonlineStreamId) {
    result.ayyadonline_stream_id = ayyadonlineStreamId;
  }
  if (ayyadonlineCredential) {
    result.ayyadonline_credential = ayyadonlineCredential;
  }

  return result;
}

function sanitizeRegistryData(data, sourceLabel = 'registry') {
  const cleaned = { channels: {} };
  const warnings = [];

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    warnings.push(`${sourceLabel}: root value must be an object`);
    return { registry: cleaned, warnings };
  }

  if (!data.channels || typeof data.channels !== 'object' || Array.isArray(data.channels)) {
    warnings.push(`${sourceLabel}: missing "channels" object`);
    return { registry: cleaned, warnings };
  }

  for (const [channelId, rawChannel] of Object.entries(data.channels)) {
    try {
      cleaned.channels[channelId] = sanitizeRegistryChannel(channelId, rawChannel);
    } catch (e) {
      warnings.push(`${sourceLabel}: skipping "${channelId}" (${e.message})`);
    }
  }

  return { registry: cleaned, warnings };
}

function computeServiceStatus({ credentialTotal, activeCredentials, errorCredentials, lastSync }) {
  if (credentialTotal === 0) return 'starting';
  if (activeCredentials === 0) return 'degraded';
  if (errorCredentials > 0) return 'degraded';
  if (!lastSync) return 'starting';
  return 'ok';
}

function formatFileModeOctal(mode) {
  return (mode & 0o777).toString(8).padStart(3, '0');
}

function isStrictCredentialPermsEnabled() {
  return process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS !== '0';
}

function validateCredentialFilePermissions(filePath) {
  const mode = fs.statSync(filePath).mode & 0o777;
  const isOverPermissive = (mode & 0o077) !== 0;
  if (!isOverPermissive) {
    return;
  }

  const message =
    `Credentials file ${filePath} has mode ${formatFileModeOctal(mode)}; expected 600 or stricter`;

  if (process.env.NODE_ENV === 'production' && isStrictCredentialPermsEnabled()) {
    throw new Error(message);
  }

  warn(`${message}. Continuing because strict production enforcement is disabled.`);
}

function loadProviderConfigFile(filePath, baseDirForMessage = CHANNELS_DIR) {
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Credentials file not found: ${filePath}. ` +
      `Set PROVIDER_CREDENTIALS_FILE or copy ${path.join(baseDirForMessage, 'provider_sync.example.json')} ` +
      `and fill real credentials.`
    );
  }
  validateCredentialFilePermissions(filePath);

  let parsed;
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Failed reading credentials file ${filePath}: ${e.message}`);
  }

  return validateProviderConfigShape(parsed);
}

/**
 * Make an HTTP GET request and return parsed JSON.
 */
function httpGetJson(url, timeoutMs = API_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const httpModule = isHttps ? https : http;
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      timeout: timeoutMs,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, */*'
      }
    };

    const req = httpModule.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message} (status ${res.statusCode}, body: ${data.slice(0, 200)})`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timeout after ${timeoutMs}ms`));
    });

    req.on('error', reject);
    req.end();
  });
}

/**
 * Atomic file write: write to .tmp then rename.
 */
function atomicWriteFileSync(filePath, content) {
  const tmpPath = filePath + '.tmp';
  let mode = 0o644;
  try {
    mode = fs.statSync(filePath).mode & 0o777;
  } catch (_e) {
    // New file, keep default mode.
  }

  const fd = fs.openSync(tmpPath, 'w', mode);
  try {
    fs.writeFileSync(fd, content, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tmpPath, filePath);
  fs.chmodSync(filePath, mode);
}

// ---------------------------------------------------------------------------
// Credential Pool Manager
// ---------------------------------------------------------------------------

function loadCredentials() {
  providerConfig = loadProviderConfigFile(CREDENTIALS_FILE, CHANNELS_DIR);
  credentialPool.clear();
  preferredApiPort = providerConfig.default_port;

  for (const cred of providerConfig.credentials) {
    credentialPool.set(cred.username, {
      username: cred.username,
      password: cred.password,
      status: 'unchecked',
      server_url: providerConfig.server,
      server_port: providerConfig.default_port,
      server_protocol: 'http',
      expiry_date: null,
      last_check: null,
      error: null
    });
  }

  log(`Loaded ${providerConfig.credentials.length} credentials for server ${providerConfig.server}`);
}

function getDiscoveredApiPorts() {
  const ports = [];
  for (const cred of credentialPool.values()) {
    const port = parsePortValue(cred.server_port);
    if (port) ports.push(port);
  }
  return ports;
}

function updatePreferredApiPort(port, reason = 'unknown') {
  const normalized = parsePortValue(port);
  if (!normalized) return;
  const changed = preferredApiPort !== normalized;
  preferredApiPort = normalized;
  if (changed) {
    log(`API port switched to ${normalized} (${reason})`);
  }
}

async function fetchPlayerApiWithPortFallback(options) {
  const {
    server,
    username,
    password,
    action = '',
    timeoutMs = API_TIMEOUT_MS,
    preferredPort,
    defaultPort,
    discoveredPorts = [],
    probePorts = API_PORT_PROBE_PORTS,
    fetchJson = httpGetJson
  } = options || {};

  const attemptedPorts = [];
  const candidates = buildApiPortCandidates({
    preferredPort,
    defaultPort,
    discoveredPorts,
    probePorts
  });
  let lastError = null;

  for (const port of candidates) {
    attemptedPorts.push(port);
    const url = buildPlayerApiUrl(server, port, username, password, action);
    try {
      const response = await fetchJson(url, timeoutMs);
      return { response, port, attemptedPorts };
    } catch (e) {
      lastError = e;
    }
  }

  const actionLabel = action || 'auth';
  const portLabel = attemptedPorts.join(', ');
  const err = new Error(`All API port probes failed for ${actionLabel} (ports: ${portLabel || 'none'})`);
  if (lastError) err.cause = lastError;
  throw err;
}

async function checkCredential(username) {
  const cred = credentialPool.get(username);
  if (!cred) return;

  try {
    const { response: resp, port: apiPort } = await fetchPlayerApiWithPortFallback({
      server: providerConfig.server,
      username: cred.username,
      password: cred.password,
      preferredPort: preferredApiPort,
      defaultPort: providerConfig.default_port,
      discoveredPorts: getDiscoveredApiPorts(),
      probePorts: API_PORT_PROBE_PORTS,
      timeoutMs: API_PORT_PROBE_TIMEOUT_MS
    });
    updatePreferredApiPort(apiPort, `credential check ${cred.username}`);

    const authValue = resp && resp.user_info ? resp.user_info.auth : null;
    const isAuthorized = authValue === 1 || authValue === '1';

    if (resp.user_info && isAuthorized) {
      cred.status = resp.user_info.status || 'Active';
      cred.server_url = (resp.server_info && resp.server_info.url) || providerConfig.server;
      cred.server_port = (resp.server_info && parseInt(resp.server_info.port, 10)) || apiPort || providerConfig.default_port;
      cred.server_protocol = (resp.server_info && resp.server_info.server_protocol) || 'http';
      cred.expiry_date = resp.user_info.exp_date
        ? new Date(parseInt(resp.user_info.exp_date, 10) * 1000)
        : null;
      cred.last_check = new Date();
      cred.error = null;

      // Check if expired by date
      if (cred.expiry_date && cred.expiry_date < new Date()) {
        cred.status = 'Expired';
      }
    } else {
      cred.status = 'Expired';
      cred.last_check = new Date();
      cred.error = resp.user_info ? `status: ${resp.user_info.status}` : 'auth failed';
    }
  } catch (e) {
    cred.status = 'error';
    cred.last_check = new Date();
    cred.error = e.message.replace(/password=[^&\s]+/gi, 'password=<redacted>');
  }
}

async function checkAllCredentials() {
  log(`Checking ${credentialPool.size} credentials...`);
  const usernames = [...credentialPool.keys()];

  for (let i = 0; i < usernames.length; i++) {
    await checkCredential(usernames[i]);
    const cred = credentialPool.get(usernames[i]);
    const expiryStr = cred.expiry_date ? cred.expiry_date.toISOString().split('T')[0] : 'n/a';
    log(`  [${i + 1}/${usernames.length}] ${usernames[i]}: ${cred.status} (expires: ${expiryStr}, port: ${cred.server_port}${cred.error ? ', error: ' + cred.error : ''})`);

    if (i < usernames.length - 1) {
      await sleep(CREDENTIAL_CHECK_STAGGER_MS);
    }
  }

  const active = [...credentialPool.values()].filter(c => c.status === 'Active').length;
  const expired = [...credentialPool.values()].filter(c => c.status === 'Expired').length;
  const errors = [...credentialPool.values()].filter(c => c.status === 'error').length;
  log(`Credential check complete: ${active} active, ${expired} expired, ${errors} errors`);
}

/**
 * Get active credentials sorted by expiry date (furthest expiry first).
 */
function getActiveCredentials() {
  return [...credentialPool.values()]
    .filter(c => c.status === 'Active')
    .sort((a, b) => {
      if (!a.expiry_date) return 1;
      if (!b.expiry_date) return -1;
      return b.expiry_date.getTime() - a.expiry_date.getTime();
    });
}

/**
 * Get the best credential (longest-to-expire active credential).
 * Always excludes RESERVED_CREDENTIALS.  Optionally exclude additional
 * usernames (e.g. credentials already assigned to other channels).
 */
function getBestCredential(excludeUsernames = []) {
  const excludeSet = new Set([...excludeUsernames, ...RESERVED_CREDENTIALS]);
  const active = getActiveCredentials().filter(c => !excludeSet.has(c.username));
  return active.length > 0 ? active[0] : null;
}

function addCatalogNameIndexEntry(name, streamId, nameIndex = catalogNameIndex) {
  const normalized = normalizeName(name);
  if (!normalized) return;
  const existing = nameIndex.get(normalized);
  if (existing) {
    if (!existing.includes(streamId)) existing.push(streamId);
    return;
  }
  nameIndex.set(normalized, [streamId]);
}

// ---------------------------------------------------------------------------
// Channel Catalog Sync
// ---------------------------------------------------------------------------

function loadCatalogCache() {
  try {
    if (fs.existsSync(CATALOG_FILE)) {
      const raw = fs.readFileSync(CATALOG_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        let skippedInvalid = 0;
        for (const entry of data) {
          const streamId = parsePositiveStreamId(entry.stream_id);
          if (!streamId) {
            skippedInvalid++;
            continue;
          }
          entry.stream_id = streamId;
          catalog.set(streamId, entry);
          addCatalogNameIndexEntry(entry.name, streamId);
        }
        log(`Loaded cached catalog: ${catalog.size} streams${skippedInvalid > 0 ? ` (skipped ${skippedInvalid} invalid entries)` : ''}`);
      }
    }
  } catch (e) {
    warn(`Failed to load catalog cache: ${e.message}`);
  }
}

async function syncCatalog() {
  const best = getBestCredential();
  if (!best) {
    error('No active credentials available to sync catalog');
    return false;
  }

  try {
    log(`Fetching live stream catalog using credential ${best.username}...`);
    const { response: streams, port: apiPort } = await fetchPlayerApiWithPortFallback({
      server: providerConfig.server,
      username: best.username,
      password: best.password,
      action: 'get_live_streams',
      preferredPort: preferredApiPort,
      defaultPort: providerConfig.default_port,
      discoveredPorts: getDiscoveredApiPorts(),
      probePorts: API_PORT_PROBE_PORTS,
      timeoutMs: 30000
    });
    updatePreferredApiPort(apiPort, 'catalog sync');

    if (!Array.isArray(streams)) {
      error('Catalog response is not an array');
      return false;
    }

    const prevCatalog = new Map(catalog);
    catalog.clear();
    catalogNameIndex.clear();

    let skippedInvalid = 0;
    for (const stream of streams) {
      const streamId = parsePositiveStreamId(stream.stream_id);
      if (!streamId) {
        skippedInvalid++;
        continue;
      }
      const entry = {
        stream_id: streamId,
        name: stream.name,
        stream_icon: stream.stream_icon || '',
        category_id: stream.category_id || ''
      };
      catalog.set(streamId, entry);
      addCatalogNameIndexEntry(stream.name, streamId);
    }

    log(`Catalog synced: ${catalog.size} live streams${skippedInvalid > 0 ? ` (skipped ${skippedInvalid} invalid entries)` : ''}`);

    // Detect changes
    let newStreams = 0, removedStreams = 0;
    for (const [id] of catalog) {
      if (!prevCatalog.has(id)) newStreams++;
    }
    for (const [id] of prevCatalog) {
      if (!catalog.has(id)) removedStreams++;
    }
    if (newStreams > 0 || removedStreams > 0) {
      log(`Catalog changes: +${newStreams} new, -${removedStreams} removed`);
    }

    // Save cache
    atomicWriteFileSync(CATALOG_FILE, JSON.stringify([...catalog.values()], null, 2));

    return true;
  } catch (e) {
    error(`Failed to sync catalog: ${e.message}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Ayyadonline Provider Functions
// ---------------------------------------------------------------------------

function loadAyyadonlineCredentials() {
  if (!fs.existsSync(AYYADONLINE_CREDENTIALS_FILE)) {
    warn(`Ayyadonline credentials file not found: ${AYYADONLINE_CREDENTIALS_FILE}`);
    return false;
  }
  try {
    ayyadonlineConfig = loadProviderConfigFile(AYYADONLINE_CREDENTIALS_FILE, CHANNELS_DIR);
    ayyadonlineCredentialPool.clear();
    for (const cred of ayyadonlineConfig.credentials) {
      ayyadonlineCredentialPool.set(cred.username, {
        username: cred.username,
        password: cred.password
      });
    }
    log(`Loaded ${ayyadonlineConfig.credentials.length} ayyadonline credentials for ${ayyadonlineConfig.server}`);
    return true;
  } catch (e) {
    warn(`Failed to load ayyadonline credentials: ${e.message}`);
    return false;
  }
}

async function syncAyyadonlineCatalog() {
  if (!ayyadonlineConfig || ayyadonlineCredentialPool.size === 0) {
    return false;
  }
  const cred = ayyadonlineCredentialPool.values().next().value;
  if (!cred) return false;

  try {
    log(`Fetching ayyadonline catalog using credential ${cred.username}...`);
    const url = buildPlayerApiUrl(
      ayyadonlineConfig.server,
      ayyadonlineConfig.default_port,
      cred.username,
      cred.password,
      'get_live_streams'
    );
    const streams = await httpGetJson(url, 30000);
    if (!Array.isArray(streams)) {
      warn('Ayyadonline catalog response is not an array');
      return false;
    }

    ayyadonlineCatalog.clear();
    let count = 0;
    for (const stream of streams) {
      const streamId = parsePositiveStreamId(stream.stream_id);
      if (!streamId) continue;
      ayyadonlineCatalog.set(streamId, {
        stream_id: streamId,
        name: stream.name || ''
      });
      count++;
    }
    log(`Ayyadonline catalog synced: ${count} live streams`);

    // Save cache
    atomicWriteFileSync(
      AYYADONLINE_CATALOG_FILE,
      JSON.stringify([...ayyadonlineCatalog.values()], null, 2)
    );
    return true;
  } catch (e) {
    warn(`Ayyadonline catalog sync failed: ${e.message}`);
    return false;
  }
}

/**
 * Build an ayyadonline backup URL for a channel if mapped.
 * Reads from registry metadata first (ayyadonline_stream_id / ayyadonline_credential),
 * then falls back to hardcoded AYYADONLINE_CHANNEL_MAP for migration.
 * Returns the URL string or null.
 */
function buildAyyadonlineBackupUrl(channelId, channelEntry) {
  if (!ayyadonlineConfig) return null;

  // Prefer registry-stored metadata (data-driven)
  let streamId = null;
  let credentialUsername = null;
  if (channelEntry) {
    streamId = parsePositiveStreamId(channelEntry.ayyadonline_stream_id);
    credentialUsername = channelEntry.ayyadonline_credential || null;
  }

  // Fallback to hardcoded map during migration
  if (!streamId || !credentialUsername) {
    const mapping = AYYADONLINE_CHANNEL_MAP[channelId];
    if (!mapping) return null;
    streamId = streamId || mapping.stream_id;
    credentialUsername = credentialUsername || mapping.credential;
  }

  if (!streamId || !credentialUsername) return null;
  const cred = ayyadonlineCredentialPool.get(credentialUsername);
  if (!cred) return null;

  return `http://${ayyadonlineConfig.server}:${ayyadonlineConfig.default_port}/${cred.username}/${cred.password}/${streamId}`;
}

// ---------------------------------------------------------------------------
// Name-Based Channel Matching
// ---------------------------------------------------------------------------

function findExactCatalogMatch(matchNames, channelConfig, catalogMap, catalogNameIndexMap, channelKey, logWarning = warn) {
  for (const name of matchNames) {
    const normalized = normalizeName(name);
    if (!normalized) continue;

    const candidates = catalogNameIndexMap.get(normalized) || [];
    if (candidates.length === 1) {
      const streamId = candidates[0];
      const entry = catalogMap.get(streamId);
      if (entry) {
        return { stream_id: streamId, provider_name: entry.name, method: 'exact' };
      }
      continue;
    }

    if (candidates.length > 1) {
      if (channelConfig.stream_id && candidates.includes(channelConfig.stream_id)) {
        const existingEntry = catalogMap.get(channelConfig.stream_id);
        if (existingEntry) {
          return {
            stream_id: channelConfig.stream_id,
            provider_name: existingEntry.name,
            method: 'exact_current'
          };
        }
      }

      logWarning(
        `Ambiguous exact match for "${channelKey}" using "${name}" -> candidates [${candidates.join(', ')}], skipping exact-name remap`
      );
    }
  }

  return null;
}

function findFuzzyCatalogMatch(matchNames, channelConfig, catalogMap, catalogNameIndexMap, channelKey, logWarning = warn) {
  let bestScore = -1;
  const bestByStreamId = new Map();

  // Token-based fuzzy match.
  // Accept:
  //  - subset matches (all meaningful search tokens appear in the catalog name), allowing a small number of extra tokens
  //  - near-identical matches by Jaccard similarity
  const MAX_EXTRA_TOKENS = 2;

  for (const name of matchNames) {
    const normalizedSearch = normalizeName(name);
    if (!normalizedSearch) continue;

    const searchTokens = tokenizeNormalizedName(normalizedSearch);
    if (searchTokens.length < 2) continue; // avoid matching on overly generic single tokens

    for (const [normalizedCatalog, streamIds] of catalogNameIndexMap) {
      const catalogTokens = tokenizeNormalizedName(normalizedCatalog);
      if (catalogTokens.length === 0) continue;

      const stats = tokenOverlapStats(searchTokens, catalogTokens);
      if (stats.common < 2) continue;

      const isSubsetMatch = stats.coverage >= 1 && stats.extra <= MAX_EXTRA_TOKENS;
      const isNearIdentical = stats.jaccard >= 0.9;
      if (!isSubsetMatch && !isNearIdentical) continue;

      // Deterministic integer scoring to avoid float-equality edge cases.
      const coverageScaled = Math.round(stats.coverage * 1000); // 0..1000
      const jaccardScaled = Math.round(stats.jaccard * 1000);   // 0..1000
      const score = coverageScaled * 1000000 + jaccardScaled * 1000 - stats.extra;

      if (score > bestScore) {
        bestScore = score;
        bestByStreamId.clear();
      }

      if (score === bestScore) {
        for (const streamId of streamIds) {
          const entry = catalogMap.get(streamId);
          if (!entry) continue;
          if (!bestByStreamId.has(streamId)) {
            bestByStreamId.set(streamId, {
              stream_id: streamId,
              provider_name: entry.name,
              method: isSubsetMatch ? 'fuzzy_subset' : 'fuzzy',
              score,
              coverage: coverageScaled,
              jaccard: jaccardScaled,
              extra_tokens: stats.extra,
            });
          }
        }
      }
    }
  }

  if (bestByStreamId.size === 1) {
    const match = [...bestByStreamId.values()][0];
    logWarning(
      `Fuzzy match for "${channelKey}": "${match.provider_name}" ` +
      `(coverage ${match.coverage}/1000, jaccard ${match.jaccard}/1000, extra ${match.extra_tokens})`
    );
    return match;
  }

  if (bestByStreamId.size > 1 && channelConfig.stream_id && bestByStreamId.has(channelConfig.stream_id)) {
    const match = bestByStreamId.get(channelConfig.stream_id);
    return {
      stream_id: match.stream_id,
      provider_name: match.provider_name,
      method: 'fuzzy_current',
      score: match.score,
      coverage: match.coverage,
      jaccard: match.jaccard,
      extra_tokens: match.extra_tokens,
    };
  }

  if (bestByStreamId.size > 1) {
    const candidates = [...bestByStreamId.values()]
      .map(m => `${m.stream_id}:${m.provider_name}`)
      .join(', ');
    logWarning(`Ambiguous fuzzy match for "${channelKey}" (score ${bestScore}): ${candidates}`);
  }

  return null;
}

/**
 * Find stream_id for a channel by its match_names.
 * Returns { stream_id, provider_name, method } or null.
 */
function matchChannelInCatalogWithIndexes(
  channelKey,
  channelConfig,
  catalogMap,
  catalogNameIndexMap,
  logWarning = warn
) {
  const matchNames = channelConfig.match_names || [];

  // 1. Exact normalized name match
  const exactMatch = findExactCatalogMatch(
    matchNames,
    channelConfig,
    catalogMap,
    catalogNameIndexMap,
    channelKey,
    logWarning
  );
  if (exactMatch) return exactMatch;

  // 2. Direct stream_id lookup (if catalog still has it)
  if (channelConfig.stream_id && catalogMap.has(channelConfig.stream_id)) {
    const entry = catalogMap.get(channelConfig.stream_id);
    return { stream_id: channelConfig.stream_id, provider_name: entry.name, method: 'stream_id' };
  }

  // 3. Fuzzy match with ambiguity protection
  return findFuzzyCatalogMatch(
    matchNames,
    channelConfig,
    catalogMap,
    catalogNameIndexMap,
    channelKey,
    logWarning
  );
}

function matchChannelInCatalog(channelKey, channelConfig) {
  return matchChannelInCatalogWithIndexes(channelKey, channelConfig, catalog, catalogNameIndex);
}

// ---------------------------------------------------------------------------
// Channel Registry
// ---------------------------------------------------------------------------

function loadRegistry() {
  try {
    if (fs.existsSync(REGISTRY_FILE)) {
      const raw = fs.readFileSync(REGISTRY_FILE, 'utf8');
      const data = JSON.parse(raw);
      const sanitized = sanitizeRegistryData(data, `registry:${REGISTRY_FILE}`);
      registry = sanitized.registry;
      for (const warningMessage of sanitized.warnings) {
        warn(warningMessage);
      }
      log(`Loaded registry: ${Object.keys(registry.channels).length} channels`);
    } else {
      registry = { channels: {} };
      warn(`Registry file not found at ${REGISTRY_FILE}, starting fresh`);
    }
  } catch (e) {
    warn(`Failed to load registry: ${e.message}`);
    registry = { channels: {} };
  }
}

function saveRegistry() {
  // Clean-on-write safety net: strip any Seenshow/KwikMotion tokens from
  // non_vlc_backups before persisting.  This prevents token churn even if
  // an upstream code path accidentally passes tokenized URLs.
  for (const ch of Object.values(registry.channels)) {
    if (Array.isArray(ch.non_vlc_backups)) {
      ch.non_vlc_backups = ch.non_vlc_backups.map(stripSeenshowToken);
    }
  }
  atomicWriteFileSync(REGISTRY_FILE, JSON.stringify(registry, null, 2));
}

/**
 * Bootstrap registry from existing channel_*.sh config files.
 * Scans channel configs and builds initial mappings.
 * Supports channels where vlc.news is primary OR backup (vlc_as_backup=true).
 */
function extractBootstrapChannelEntry(content, file, catalogMap = catalog) {
  if (typeof content !== 'string' || content.trim() === '') return null;
  if (typeof file !== 'string' || file.trim() === '') return null;

  const urlMatch = content.match(/^stream_url="([^"]+)"/m);
  if (!urlMatch || !urlMatch[1]) return null;

  const streamUrl = urlMatch[1].trim();
  const backup1Match = content.match(/^stream_url_backup1="([^"]*)"/m);
  const backup2Match = content.match(/^stream_url_backup2="([^"]*)"/m);
  const backup1 = backup1Match ? backup1Match[1].trim() : '';
  const backup2 = backup2Match ? backup2Match[1].trim() : '';

  const primaryVlc = parseVlcNewsUrl(streamUrl);
  const backupVlcCandidates = [backup1, backup2]
    .map(parseVlcNewsUrl)
    .filter(Boolean);
  const selectedVlc = primaryVlc || backupVlcCandidates[0] || null;
  if (!selectedVlc) return null;

  const rtmpMatch = content.match(/^rtmp_url="\/var\/www\/html\/stream\/hls\/([^/]+)\/master\.m3u8"/m);
  if (!rtmpMatch || !rtmpMatch[1]) return null;
  const channelId = rtmpMatch[1];

  const scaleMatch = content.match(/^scale=(\d+)/m);
  const scale = scaleMatch ? parseInt(scaleMatch[1], 10) : 0;
  const streamId = selectedVlc.streamId;
  const vlcAsBackup = !primaryVlc;

  const nonVlcBackups = [];
  const seenNonVlc = new Set();
  const addNonVlc = (urlValue) => {
    if (typeof urlValue !== 'string') return;
    const trimmed = urlValue.trim();
    if (!trimmed || parseVlcNewsUrl(trimmed) || seenNonVlc.has(trimmed)) return;
    seenNonVlc.add(trimmed);
    nonVlcBackups.push(trimmed);
  };

  if (vlcAsBackup) {
    addNonVlc(streamUrl);
  }
  addNonVlc(backup1);
  addNonVlc(backup2);

  const providerName = catalogMap.has(streamId) ? catalogMap.get(streamId).name : '';
  const matchNames = [];
  if (providerName) {
    matchNames.push(providerName);
  }

  return {
    channelId,
    streamId,
    preferredCredential: selectedVlc.username,
    scale,
    nonVlcBackups,
    vlcAsBackup,
    providerName,
    matchNames,
  };
}

function bootstrapRegistry() {
  log('Bootstrapping registry from existing channel configs...');

  const files = fs.readdirSync(CHANNELS_DIR)
    .filter(f => f.startsWith('channel_') && f.endsWith('.sh'))
    .filter(f => f !== 'channel_status.sh' && f !== 'channel_youtube_example.sh');

  for (const file of files) {
    const filePath = path.join(CHANNELS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf8');
    const entry = extractBootstrapChannelEntry(content, file, catalog);
    if (!entry) continue;
    const {
      channelId,
      streamId,
      preferredCredential,
      scale,
      nonVlcBackups,
      vlcAsBackup,
      providerName,
      matchNames,
    } = entry;

    // Skip if already in registry
    if (registry.channels[channelId]) {
      // Update config_file if needed
      registry.channels[channelId].config_file = file;
      if (registry.channels[channelId].vlc_as_backup !== true && vlcAsBackup) {
        registry.channels[channelId].vlc_as_backup = true;
      }
      continue;
    }

    registry.channels[channelId] = {
      stream_id: streamId,
      match_names: matchNames,
      config_file: file,
      provider_name: providerName,
      preferred_credential: preferredCredential,
      scale: scale,
      non_vlc_backups: nonVlcBackups,
      vlc_as_backup: vlcAsBackup,
      last_updated: new Date().toISOString()
    };

    log(`  Registered: ${channelId} → stream_id ${streamId} (${file})`);
  }

  saveRegistry();
  log(`Registry bootstrap complete: ${Object.keys(registry.channels).length} channels`);
}

/**
 * Populate match_names for channels that don't have any yet,
 * using the M3U playlists in the playlists/ directory.
 */
function populateMatchNamesFromPlaylists() {
  const playlistsDir = path.join(CHANNELS_DIR, '..', 'playlists');
  if (!fs.existsSync(playlistsDir)) {
    warn('No playlists directory found, skipping match_names population');
    return;
  }

  // Build stream_id → name mapping from any playlist file
  const streamIdNames = new Map();
  const playlistFiles = fs.readdirSync(playlistsDir).filter(f => f.endsWith('.m3u'));

  if (playlistFiles.length === 0) return;

  // Read just one playlist file (they all have the same channel names)
  const playlistPath = path.join(playlistsDir, playlistFiles[0]);
  const content = fs.readFileSync(playlistPath, 'utf8');
  const lines = content.split('\n');

  for (let i = 0; i < lines.length - 1; i++) {
    const extMatch = lines[i].match(/^#EXTINF:[^,]*,(.+)$/);
    if (extMatch) {
      const urlLine = lines[i + 1];
      const idMatch = urlLine && urlLine.match(/\/(\d+)\s*$/);
      if (idMatch) {
        const id = parseInt(idMatch[1], 10);
        streamIdNames.set(id, extMatch[1].trim());
      }
    }
  }

  log(`Loaded ${streamIdNames.size} stream names from playlists`);

  // Populate match_names for channels missing them
  let updated = 0;
  for (const [channelId, ch] of Object.entries(registry.channels)) {
    if (ch.match_names.length === 0 && streamIdNames.has(ch.stream_id)) {
      const name = streamIdNames.get(ch.stream_id);
      ch.match_names.push(name);
      ch.provider_name = ch.provider_name || name;
      updated++;
      log(`  Added match_name for ${channelId}: "${name}"`);
    }
  }

  if (updated > 0) {
    saveRegistry();
    log(`Updated match_names for ${updated} channels`);
  }
}

// ---------------------------------------------------------------------------
// Channel Config Updater
// ---------------------------------------------------------------------------

/**
 * Build a vlc.news URL from credential and stream_id.
 */
function buildStreamUrl(cred, streamId) {
  return `${cred.server_protocol}://${cred.server_url}:${cred.server_port}/${cred.username}/${cred.password}/${streamId}`;
}

function appendUniqueUrl(urls, seen, url) {
  if (typeof url !== 'string') return;
  const trimmed = url.trim();
  if (!trimmed || seen.has(trimmed)) return;
  seen.add(trimmed);
  urls.push(trimmed);
}

/**
 * Compose primary + backup URLs for a channel deterministically.
 * 1:1 credential policy: each channel gets at most ONE vlc.news credential.
 * backupCredentials is accepted for API compatibility but should be empty ([]).
 * Policy:
 *  - If primaryCredential is null, use non-vlc backups only.
 *  - Preserve configured non-vlc backups first.
 *  - For vlc_as_backup channels, keep non-vlc as primary and place vlc URL in backups.
 */
function planChannelUrls(channel, resolvedStreamId, primaryCredential, backupCredentials = []) {
  const nonVlcBackups = Array.isArray(channel.non_vlc_backups)
    ? channel.non_vlc_backups
    : [];

  // No vlc credential — use non-vlc backups only
  if (!primaryCredential) {
    const valid = nonVlcBackups.filter(u => typeof u === 'string' && u.trim());
    return {
      primaryUrl: valid[0] || '',
      backup1: valid[1] || '',
      backup2: valid[2] || '',
      backup3: valid[3] || '',
      vlcPrimaryUrl: ''
    };
  }

  const vlcPrimaryUrl = buildStreamUrl(primaryCredential, resolvedStreamId);
  const vlcBackupUrls = backupCredentials
    .filter(Boolean)
    .map((cred) => buildStreamUrl(cred, resolvedStreamId));

  let primaryUrl = vlcPrimaryUrl;
  const backups = [];
  const seenBackups = new Set();

  if (channel.vlc_as_backup) {
    const nonVlcPrimary = nonVlcBackups.find((url) => typeof url === 'string' && url.trim() !== '');
    if (nonVlcPrimary) {
      primaryUrl = nonVlcPrimary.trim();
    }

    if (vlcPrimaryUrl !== primaryUrl) {
      appendUniqueUrl(backups, seenBackups, vlcPrimaryUrl);
    }
    for (const backupUrl of vlcBackupUrls) {
      if (backupUrl === primaryUrl) continue;
      appendUniqueUrl(backups, seenBackups, backupUrl);
      if (backups.length >= 3) break;
    }
  } else {
    for (const backupUrl of nonVlcBackups) {
      appendUniqueUrl(backups, seenBackups, backupUrl);
      if (backups.length >= 3) break;
    }
    if (backups.length < 3) {
      for (const backupUrl of vlcBackupUrls) {
        if (backupUrl === primaryUrl) continue;
        appendUniqueUrl(backups, seenBackups, backupUrl);
        if (backups.length >= 3) break;
      }
    }
  }

  return {
    primaryUrl,
    backup1: backups[0] || '',
    backup2: backups[1] || '',
    backup3: backups[2] || '',
    vlcPrimaryUrl
  };
}

/**
 * Parse config content string to extract current URLs.
 */
function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getShellVarMatches(content, varName) {
  const escapedVarName = escapeRegex(varName);
  const pattern = new RegExp(
    `^(${escapedVarName}=)"((?:[^"\\\\]|\\\\.)*)"([ \\t]*(?:#.*)?)$`,
    'gm'
  );
  return [...content.matchAll(pattern)];
}

function unescapeShellDoubleQuoted(value) {
  return String(value).replace(/\\(["\\$`])/g, '$1');
}

function escapeShellDoubleQuoted(value, varName = 'value') {
  if (typeof value !== 'string') {
    throw new Error(`${varName} must be a string`);
  }
  if (/[\r\n]/.test(value)) {
    throw new Error(`${varName} must not contain newlines`);
  }
  return value.replace(/["\\$`]/g, '\\$&');
}

function parseRequiredShellVar(content, varName) {
  const matches = getShellVarMatches(content, varName);
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one ${varName} assignment, found ${matches.length}`);
  }
  return unescapeShellDoubleQuoted(matches[0][2]);
}

function parseOptionalShellVar(content, varName) {
  const matches = getShellVarMatches(content, varName);
  if (matches.length === 0) return null;
  if (matches.length !== 1) {
    throw new Error(`Expected at most one ${varName} assignment, found ${matches.length}`);
  }
  return unescapeShellDoubleQuoted(matches[0][2]);
}

function parseConfigContent(content) {
  return {
    stream_url: parseRequiredShellVar(content, 'stream_url'),
    stream_url_backup1: parseRequiredShellVar(content, 'stream_url_backup1'),
    stream_url_backup2: parseRequiredShellVar(content, 'stream_url_backup2'),
    stream_url_backup3: parseOptionalShellVar(content, 'stream_url_backup3')
  };
}

/**
 * Replace a shell variable assignment in content.
 * Uses function replacer to avoid regex $ injection in replacement strings.
 */
function replaceShellVar(content, varName, newValue) {
  const matches = getShellVarMatches(content, varName);
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one ${varName} assignment, found ${matches.length}`);
  }

  const escapedValue = escapeShellDoubleQuoted(newValue, varName);
  const [fullMatch, prefix, , suffix = ''] = matches[0];
  return content.replace(fullMatch, () => `${prefix}"${escapedValue}"${suffix}`);
}

/**
 * Update a channel_*.sh config file with new URLs.
 * Preserves all other content. Uses atomic write.
 * Returns { primaryChanged, backupsChanged }.
 */
function updateConfigFile(filePath, newStreamUrl, newBackup1, newBackup2, newBackup3 = '') {
  const content = fs.readFileSync(filePath, 'utf8');
  const current = parseConfigContent(content);

  const hasBackup3Var = current.stream_url_backup3 !== null;
  const primaryChanged = current.stream_url !== newStreamUrl;
  const backupsChanged = current.stream_url_backup1 !== newBackup1 ||
                         current.stream_url_backup2 !== newBackup2 ||
                         (hasBackup3Var && current.stream_url_backup3 !== newBackup3);

  if (!primaryChanged && !backupsChanged) {
    return { primaryChanged: false, backupsChanged: false };
  }

  let updated = content;

  if (primaryChanged) {
    updated = replaceShellVar(updated, 'stream_url', newStreamUrl);
    // Also update stream_name if it was in credential/stream_id format
    const nameMatch = updated.match(/^stream_name="(\d{12}\/\d{12}\/\d+)"/m);
    if (nameMatch) {
      const urlParts = newStreamUrl.match(/\/(\d{12})\/(\d{12})\/(\d+)$/);
      if (urlParts) {
        updated = replaceShellVar(updated, 'stream_name', `${urlParts[1]}/${urlParts[2]}/${urlParts[3]}`);
      }
    }
  }

  if (backupsChanged) {
    updated = replaceShellVar(updated, 'stream_url_backup1', newBackup1);
    updated = replaceShellVar(updated, 'stream_url_backup2', newBackup2);
    if (hasBackup3Var) {
      updated = replaceShellVar(updated, 'stream_url_backup3', newBackup3);
    }
  }

  const persisted = parseConfigContent(updated);
  if (persisted.stream_url !== newStreamUrl ||
      persisted.stream_url_backup1 !== newBackup1 ||
      persisted.stream_url_backup2 !== newBackup2 ||
      (hasBackup3Var && persisted.stream_url_backup3 !== newBackup3)) {
    throw new Error(`Failed to persist URL updates in ${filePath}`);
  }

  atomicWriteFileSync(filePath, updated);
  return { primaryChanged, backupsChanged };
}

/**
 * Trigger graceful restart for a channel.
 */
async function triggerGracefulRestart(channelId, options = {}) {
  const scriptPath = options.scriptPath || GRACEFUL_RESTART_SCRIPT;
  const restartCwd = options.cwd || CHANNELS_DIR;
  const execImpl = typeof options.execFile === 'function' ? options.execFile : execFile;
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : GRACEFUL_RESTART_TIMEOUT_MS;

  if (typeof channelId !== 'string' || channelId.trim() === '') {
    return { ok: false, error: new Error('channelId must be a non-empty string') };
  }

  if (!fs.existsSync(scriptPath)) {
    warn(`graceful_restart.sh not found at ${scriptPath}`);
    return { ok: false, error: new Error(`graceful_restart.sh not found at ${scriptPath}`) };
  }

  log(`Triggering graceful restart for channel: ${channelId}`);
  const env = Object.assign({}, process.env, {
    SUDO_ASKPASS: path.join(os.homedir(), '.sudo_pass.sh'),
  });

  return new Promise((resolve) => {
    execImpl('sudo', ['-A', scriptPath, channelId], { cwd: restartCwd, env, timeout: timeoutMs }, (err, stdout, stderr) => {
      if (err) {
        error(`Graceful restart failed for ${channelId}: ${err.message}`);
        if (stderr) error(`  stderr: ${stderr.slice(0, 500)}`);
        resolve({ ok: false, error: err, stdout: stdout || '', stderr: stderr || '' });
        return;
      }

      log(`Graceful restart completed for ${channelId}`);
      if (stdout) log(`  stdout: ${stdout.slice(0, 500)}`);
      resolve({ ok: true, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

/**
 * Apply config update and ensure primary URL changes are only kept when
 * graceful restart succeeds.
 */
async function applyConfigUpdateAndRestartIfNeeded(configPath, channelId, primaryUrl, backup1, backup2, backup3 = '', options = {}) {
  // Fail closed: never write an empty primary stream URL — it would break the channel.
  if (typeof primaryUrl !== 'string' || primaryUrl.trim() === '') {
    throw new Error(`Refusing to write empty stream_url for ${channelId}`);
  }
  const restartFn = typeof options.restartFn === 'function'
    ? options.restartFn
    : (id) => triggerGracefulRestart(id, options.restartOptions || {});

  const previousContent = fs.readFileSync(configPath, 'utf8');
  const result = updateConfigFile(configPath, primaryUrl, backup1, backup2, backup3);

  if (!result.primaryChanged) {
    return result;
  }

  const restartResult = await restartFn(channelId);
  if (restartResult && restartResult.ok) {
    return result;
  }

  // Keep URL/state transitions atomic: if restart fails, revert file so the
  // next sync retries the same primary move instead of silently drifting.
  atomicWriteFileSync(configPath, previousContent);
  const restartErr = restartResult && restartResult.error
    ? restartResult.error
    : new Error('graceful restart returned failure');
  throw new Error(`Graceful restart failed for ${channelId}; config rolled back: ${restartErr.message}`);
}

// ---------------------------------------------------------------------------
// Main Sync Loop
// ---------------------------------------------------------------------------

async function runSync() {
  if (syncInProgress) {
    warn('Sync already in progress, skipping');
    return;
  }

  syncInProgress = true;
  const startTime = Date.now();
  log('=== Starting provider sync ===');

  try {
    // 1. Check all credentials
    await checkAllCredentials();

    // 2. Sync catalog from provider
    const catalogOk = await syncCatalog();
    if (!catalogOk) {
      warn('Catalog sync failed, using cached data');
    }

    // 2b. Sync ayyadonline catalog
    if (ayyadonlineConfig) {
      const ayyadOk = await syncAyyadonlineCatalog();
      if (!ayyadOk) {
        warn('Ayyadonline catalog sync failed');
      }
    }

    // 3. Load/bootstrap registry
    loadRegistry();
    if (Object.keys(registry.channels).length === 0) {
      bootstrapRegistry();
      populateMatchNamesFromPlaylists();
    }

    // 4. Update each channel
    const activeCredentials = getActiveCredentials();
    if (activeCredentials.length === 0) {
      error('No active credentials available! Cannot update channels.');
      return; // finally block handles syncInProgress = false
    }

    let updatedPrimary = 0;
    let updatedBackups = 0;
    let streamIdChanges = 0;
    let matchFailures = 0;
    let invalidChannels = 0;
    let channelErrors = 0;
    let seenshowTokenRefreshes = 0;
    let seenshowTokenFailures = 0;
    const seenshowResolveCache = new Map();
    // Track credentials already assigned during this sync cycle to prevent
    // the fallback path from re-using another channel's credential.
    // Map<credential_username, channelId> for duplicate detection.
    const usedCredentials = new Map();
    // Channels whose credentials were cleared and need a fallback assignment.
    const needsFallbackCred = [];
    // Sort channel IDs for deterministic credential assignment across sync cycles.
    // Without sorting, JSON property insertion order could vary between bootstrap
    // runs, causing different channels to receive different fallback credentials.
    const sortedChannelIds = Object.keys(registry.channels).sort();
    for (const chId of sortedChannelIds) {
      const ch = registry.channels[chId];
      if (ch && ch.preferred_credential) {
        const cred = ch.preferred_credential;
        if (RESERVED_CREDENTIALS.has(cred)) {
          warn(`Channel "${chId}" uses reserved credential ${cred} — clearing assignment`);
          ch.preferred_credential = '';
          needsFallbackCred.push(chId);
        } else if (usedCredentials.has(cred)) {
          warn(`Credential ${cred} claimed by both "${usedCredentials.get(cred)}" and "${chId}" — clearing duplicate from "${chId}"`);
          ch.preferred_credential = '';
          needsFallbackCred.push(chId);
        } else {
          usedCredentials.set(cred, chId);
        }
      }
    }
    // Attempt fallback credential assignment for cleared channels.
    // Channels that are explicitly non-vlc-only (vlc_as_backup=true with
    // non-vlc backups) can safely remain without a credential.
    for (const chId of needsFallbackCred) {
      const ch = registry.channels[chId];
      const hasNonVlcBackups = Array.isArray(ch.non_vlc_backups) &&
        ch.non_vlc_backups.some(u => typeof u === 'string' && u.trim());
      if (ch.vlc_as_backup && hasNonVlcBackups) {
        // Non-vlc-only channel — safe to leave without credential
        continue;
      }
      const fallback = getBestCredential([...usedCredentials.keys()]);
      if (fallback) {
        warn(`Assigning fallback credential ${fallback.username} to "${chId}"`);
        ch.preferred_credential = fallback.username;
        usedCredentials.set(fallback.username, chId);
      } else if (!hasNonVlcBackups) {
        error(`FAIL-CLOSED: Channel "${chId}" has no credential and no non-vlc backups — will skip`);
      }
    }

    for (const channelId of sortedChannelIds) {
      const rawChannel = registry.channels[channelId];
      let ch;
      try {
        ch = sanitizeRegistryChannel(channelId, rawChannel);
        registry.channels[channelId] = ch;
      } catch (e) {
        invalidChannels++;
        warn(`Skipping invalid registry channel "${channelId}": ${e.message}`);
        continue;
      }

      try {
        const configPath = resolveChannelConfigPath(ch.config_file);
        if (!fs.existsSync(configPath)) {
          warn(`Config file not found for ${channelId}: ${ch.config_file}`);
          continue;
        }

        let resolvedStreamId = ch.stream_id;
        let resolvedProviderName = ch.provider_name;
        const resolvedMatchNames = [...ch.match_names];

        // Match channel in catalog by name. Only persist match-derived changes
        // after the channel config update succeeds (prevents registry drift).
        if (catalog.size > 0) {
          const match = matchChannelInCatalog(channelId, ch);
          if (match) {
            if (match.stream_id !== ch.stream_id) {
              log(`STREAM_ID CHANGE for ${channelId}: ${ch.stream_id} → ${match.stream_id} (matched by ${match.method}: "${match.provider_name}")`);
              resolvedStreamId = match.stream_id;
            }
            resolvedProviderName = match.provider_name;
            if (!resolvedMatchNames.includes(match.provider_name)) {
              resolvedMatchNames.push(match.provider_name);
            }
          } else {
            matchFailures++;
            warn(`Could not match channel "${channelId}" in catalog (stream_id: ${ch.stream_id})`);
          }
        }

        // Refresh Seenshow backup URLs via resolver on each sync cycle.
        const seenshowResult = await refreshSeenshowBackups(ch.non_vlc_backups, {
          cache: seenshowResolveCache,
        });
        seenshowTokenRefreshes += seenshowResult.refreshedCount;
        seenshowTokenFailures += seenshowResult.failedCount;
        // Compare clean (token-stripped) URLs to detect real base-path changes,
        // not just token expiry differences.
        const cleanedBackups = seenshowResult.backups.map(stripSeenshowToken);

        // Append ayyadonline backup URL if mapped (and not already present)
        const ayyadonlineUrl = buildAyyadonlineBackupUrl(channelId, ch);
        if (ayyadonlineUrl) {
          const alreadyPresent = cleanedBackups.some(u => u === ayyadonlineUrl);
          if (!alreadyPresent) {
            cleanedBackups.push(ayyadonlineUrl);
          }
        }

        const nonVlcBackupsChanged = !arraysEqual(ch.non_vlc_backups, cleanedBackups);
        if (nonVlcBackupsChanged) {
          log(`Updated non-vlc backup URLs for ${channelId}`);
        }

        // Pick credential for primary URL (1:1 policy — no backup credentials)
        // Channels without preferred_credential run on non-vlc sources only.
        // Reserved credentials are never assigned; duplicates were cleared above.
        let bestCred = null;
        if (ch.preferred_credential) {
          if (RESERVED_CREDENTIALS.has(ch.preferred_credential)) {
            warn(`Channel "${channelId}" preferred_credential ${ch.preferred_credential} is reserved — clearing`);
            ch.preferred_credential = '';
          } else if (credentialPool.has(ch.preferred_credential)) {
            const preferred = credentialPool.get(ch.preferred_credential);
            if (preferred.status === 'Active') {
              bestCred = preferred;
            }
          }
          if (!bestCred && ch.preferred_credential) {
            bestCred = getBestCredential([...usedCredentials.keys()]);
            if (bestCred) {
              warn(`Preferred credential for ${channelId} unavailable, falling back to ${bestCred.username}`);
              usedCredentials.set(bestCred.username, channelId);
            }
          }
          if (!bestCred && ch.preferred_credential) {
            warn(`No active credential for ${channelId}, skipping`);
            channelErrors++;
            continue;
          }
        }
        // bestCred is null for channels with no preferred_credential — that's OK

        const plannedUrls = planChannelUrls(
          {
            ...ch,
            non_vlc_backups: cleanedBackups
          },
          resolvedStreamId,
          bestCred,
          []
        );
        const { primaryUrl, backup1, backup2, backup3 } = plannedUrls;

        const streamIdChanged = resolvedStreamId !== ch.stream_id;
        const providerNameChanged = resolvedProviderName !== ch.provider_name;
        const matchNamesChanged = !arraysEqual(resolvedMatchNames, ch.match_names);
        const preferredCredentialChanged = bestCred
          ? ch.preferred_credential !== bestCred.username
          : false;

        // Update config file
        const result = await applyConfigUpdateAndRestartIfNeeded(
          configPath,
          channelId,
          primaryUrl,
          backup1,
          backup2,
          backup3
        );

        if (result.primaryChanged) {
          updatedPrimary++;
          log(`PRIMARY URL CHANGED for ${channelId}: ${redactUrlCredentials(primaryUrl)}`);
          // Stagger restarts to avoid overwhelming the provider with concurrent connections
          await sleep(3000);
        }

        if (result.backupsChanged) {
          updatedBackups++;
          log(`Backup URLs updated for ${channelId}`);
        }

        if (streamIdChanged) {
          ch.stream_id = resolvedStreamId;
          streamIdChanges++;
        }
        if (providerNameChanged) {
          ch.provider_name = resolvedProviderName;
        }
        if (matchNamesChanged) {
          ch.match_names = resolvedMatchNames;
        }
        if (nonVlcBackupsChanged) {
          ch.non_vlc_backups = cleanedBackups;
        }

        // Keep preferred credential synchronized with the primary stream URL source.
        if (preferredCredentialChanged) {
          ch.preferred_credential = bestCred.username;
          usedCredentials.set(bestCred.username, channelId);
        }

        if (
          result.primaryChanged ||
          result.backupsChanged ||
          streamIdChanged ||
          providerNameChanged ||
          matchNamesChanged ||
          nonVlcBackupsChanged ||
          preferredCredentialChanged
        ) {
          ch.last_updated = new Date().toISOString();
        }
      } catch (e) {
        channelErrors++;
        warn(`Channel "${channelId}" sync failed: ${e.message}`);
      }
    }

    saveRegistry();
    lastSyncTime = new Date();

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    log(`=== Sync complete in ${elapsed}s: ${updatedPrimary} primary changes, ${updatedBackups} backup changes, ${streamIdChanges} stream_id changes, ${seenshowTokenRefreshes} Seenshow token refreshes, ${seenshowTokenFailures} Seenshow token failures, ${matchFailures} match failures, ${invalidChannels} invalid channels skipped, ${channelErrors} channel errors ===`);

  } catch (e) {
    error(`Sync failed: ${e.message}`);
    error(e.stack);
  } finally {
    syncInProgress = false;
  }
}

// ---------------------------------------------------------------------------
// HTTP API Server
// ---------------------------------------------------------------------------

function handleHealth(req, res) {
  const active = [...credentialPool.values()].filter(c => c.status === 'Active').length;
  const expired = [...credentialPool.values()].filter(c => c.status === 'Expired').length;
  const errors = [...credentialPool.values()].filter(c => c.status === 'error').length;
  const status = computeServiceStatus({
    credentialTotal: credentialPool.size,
    activeCredentials: active,
    errorCredentials: errors,
    lastSync: lastSyncTime
  });

  const body = {
    status,
    uptime_seconds: Math.floor(process.uptime()),
    credentials: {
      total: credentialPool.size,
      active,
      expired,
      errors
    },
    channels: {
      total: Object.keys(registry.channels).length,
      synced: Object.values(registry.channels).filter(c => c.last_updated).length
    },
    catalog_size: catalog.size,
    last_sync: lastSyncTime ? lastSyncTime.toISOString() : null,
    sync_in_progress: syncInProgress
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
}

function handleCredentials(req, res) {
  const creds = [...credentialPool.values()].map(c => ({
    username: c.username,
    password: redactSecretForApi(c.password),
    status: c.status,
    server_url: c.server_url,
    server_port: c.server_port,
    expiry_date: c.expiry_date ? c.expiry_date.toISOString() : null,
    last_check: c.last_check ? c.last_check.toISOString() : null,
    error: c.error
  }));

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(creds, null, 2));
}

function handleCatalog(req, res) {
  const entries = [...catalog.values()];
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(entries, null, 2));
}

function handleResolve(req, res, channelId) {
  const rawChannel = registry.channels[channelId];
  if (!rawChannel) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Channel "${channelId}" not found in registry` }));
    return;
  }

  let ch;
  try {
    ch = sanitizeRegistryChannel(channelId, rawChannel);
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Channel "${channelId}" is misconfigured: ${e.message}` }));
    return;
  }

  const activeCredentials = getActiveCredentials();
  if (activeCredentials.length === 0) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'No active credentials available' }));
    return;
  }

  const urls = activeCredentials.map(cred => buildStreamUrl(cred, ch.stream_id));
  const exposeRawUrls = process.env.PROVIDER_SYNC_EXPOSE_RAW_URLS === '1';
  const responseUrls = exposeRawUrls
    ? urls
    : urls.map(redactUrlCredentials);

  const body = {
    channel_id: channelId,
    stream_id: ch.stream_id,
    provider_name: ch.provider_name,
    primary_url: responseUrls[0],
    backup_urls: responseUrls.slice(1, 5),
    non_vlc_backups: (ch.non_vlc_backups || []).map(redactUrlCredentials),
    total_available: urls.length
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
}

async function handleSync(req, res) {
  if (syncInProgress) {
    res.writeHead(409, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Sync already in progress' }));
    return;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ status: 'sync_started' }));

  // Run sync asynchronously
  runSync().catch(e => error(`Manual sync failed: ${e.message}`));
}

function handleRegistry(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(registry, null, 2));
}

function handleRequest(req, res) {
  let pathname;
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Bad request' }));
    return;
  }

  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  if (pathname === '/health') return handleHealth(req, res);
  if (pathname === '/credentials') return handleCredentials(req, res);
  if (pathname === '/catalog') return handleCatalog(req, res);
  if (pathname === '/sync') return handleSync(req, res);
  if (pathname === '/registry') return handleRegistry(req, res);

  // /resolve/:channel_id
  const resolveMatch = pathname.match(/^\/resolve\/([a-z0-9_-]+)$/i);
  if (resolveMatch) return handleResolve(req, res, resolveMatch[1]);

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', endpoints: ['/health', '/credentials', '/catalog', '/sync', '/registry', '/resolve/:channel_id'] }));
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function main() {
  log('Starting IPTV Provider Sync Service...');
  log(`  Port: ${PORT}, Host: ${HOST}`);
  log(`  Sync interval: ${SYNC_INTERVAL_MS / 1000}s (${SYNC_INTERVAL_MS / 60000} min)`);
  log(`  API port probes: ${API_PORT_PROBE_PORTS.join(', ')} (timeout ${API_PORT_PROBE_TIMEOUT_MS}ms)`);
  log(`  Channels dir: ${CHANNELS_DIR}`);
  log(`  Credentials file: ${CREDENTIALS_FILE}`);
  log(`  Seenshow resolver: ${SEENSHOW_ENABLE_RESOLVER ? `${SEENSHOW_RESOLVER_URL} (${SEENSHOW_RESOLVER_TIMEOUT_MS}ms timeout)` : 'disabled'}`);

  // Load configuration
  loadCredentials();
  loadAyyadonlineCredentials();
  loadCatalogCache();
  loadRegistry();

  // Start HTTP server
  const server = http.createServer(handleRequest);
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
      error(`Port ${PORT} already in use. Is another instance running?`);
    } else {
      error(`Server error: ${e.message}`);
    }
    process.exit(1);
  });
  server.listen(PORT, HOST, () => {
    log(`HTTP server listening on ${HOST}:${PORT}`);
  });

  // Handle graceful shutdown
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`Received ${signal}, shutting down...`);
    if (syncTimer) clearInterval(syncTimer);
    server.close(() => {
      log('HTTP server closed');
      process.exit(0);
    });
    // Force exit after 5s if server.close() hangs
    setTimeout(() => process.exit(0), 5000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Run initial sync
  if (SKIP_INITIAL_SYNC) {
    warn('Skipping initial sync because PROVIDER_SYNC_SKIP_INITIAL_SYNC=1');
  } else {
    log('Running initial sync...');
    await runSync();
  }

  if (EXIT_AFTER_INITIAL_SYNC) {
    log('Exiting after initial sync because PROVIDER_SYNC_EXIT_AFTER_INITIAL_SYNC=1');
    process.exit(0);
  }

  // Schedule periodic sync
  syncTimer = setInterval(() => {
    runSync().catch(e => error(`Scheduled sync failed: ${e.message}`));
  }, SYNC_INTERVAL_MS);

  log('Provider sync service ready');
}

if (require.main === module) {
  main().catch(e => {
    error(`Fatal error: ${e.message}`);
    error(e.stack);
    process.exit(1);
  });
}

/**
 * Test-only helper to populate the in-memory credentialPool.
 * Allows unit tests to verify getBestCredential against a real pool
 * (including RESERVED_CREDENTIALS exclusion).
 * @param {Array<{username: string, password?: string, status?: string, expiry_date?: Date|null}>} entries
 */
function _testSetCredentialPool(entries) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_testSetCredentialPool must not be called in production');
  }
  if (!Array.isArray(entries)) return;
  credentialPool.clear();
  for (const entry of entries) {
    credentialPool.set(entry.username, {
      username: entry.username,
      password: entry.password || '',
      status: entry.status || 'Active',
      server_url: entry.server_url || 'vlc.news',
      server_port: entry.server_port || 80,
      server_protocol: entry.server_protocol || 'http',
      expiry_date: entry.expiry_date !== undefined ? entry.expiry_date : new Date('2027-01-02'),
      last_check: new Date(),
      error: null
    });
  }
}

module.exports = {
  applyConfigUpdateAndRestartIfNeeded,
  assertValidChannelConfigFilename,
  buildPlayerApiUrl,
  buildApiPortCandidates,
  computeServiceStatus,
  fetchPlayerApiWithPortFallback,
  loadProviderConfigFile,
  matchChannelInCatalogWithIndexes,
  parseBoundedInt,
  parsePositiveStreamId,
  parsePortList,
  parsePortValue,
  parseConfigContent,
  isSeenshowUrl,
  stripSeenshowToken,
  parseSeenshowHlsPath,
  resolveSeenshowTokenUrl,
  refreshSeenshowBackups,
  redactSecretForApi,
  replaceShellVar,
  resolvePathFromBase,
  resolveChannelConfigPath,
  sanitizeRegistryChannel,
  sanitizeRegistryData,
  parseVlcNewsUrl,
  extractBootstrapChannelEntry,
  planChannelUrls,
  triggerGracefulRestart,
  updateConfigFile,
  validateCredentialFilePermissions,
  validateProviderConfigShape,
  RESERVED_CREDENTIALS,
  getBestCredential,
  buildAyyadonlineBackupUrl,
  parseOptionalShellVar,
  _testSetCredentialPool,
};
