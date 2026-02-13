'use strict';

const DEFAULT_SEGMENT_HOST_SUFFIXES = Object.freeze([
  'googlevideo.com',
  'youtube.com',
  'youtube-nocookie.com',
  'ytimg.com',
  'googleusercontent.com',
  'gvt1.com'
]);

function hostnameMatchesAllowedSuffix(hostname, allowedSuffixes) {
  if (!hostname || !Array.isArray(allowedSuffixes)) return false;
  const normalizedHost = hostname.toLowerCase();
  return allowedSuffixes.some((suffix) => {
    if (typeof suffix !== 'string' || suffix.trim() === '') {
      return false;
    }
    const normalizedSuffix = suffix.toLowerCase();
    return normalizedHost === normalizedSuffix || normalizedHost.endsWith(`.${normalizedSuffix}`);
  });
}

function parseRequestUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return {
      ok: false,
      status: 400,
      error: 'bad request: missing URL'
    };
  }

  try {
    const parsed = new URL(rawUrl, 'http://localhost');
    try {
      // Reject malformed percent-encoding so handlers don't process broken paths.
      decodeURIComponent(parsed.pathname);
    } catch (decodeErr) {
      return {
        ok: false,
        status: 400,
        error: `bad request: malformed URL (${decodeErr.message})`
      };
    }
    return {
      ok: true,
      url: parsed
    };
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: `bad request: malformed URL (${err.message})`
    };
  }
}

function decodeSegmentUrl(encodedUrl) {
  if (typeof encodedUrl !== 'string' || encodedUrl.length === 0) {
    return {
      ok: false,
      status: 400,
      error: 'missing encoded segment URL'
    };
  }

  try {
    const decoded = decodeURIComponent(encodedUrl);
    if (decoded.trim() === '') {
      return {
        ok: false,
        status: 400,
        error: 'missing encoded segment URL'
      };
    }
    return {
      ok: true,
      url: decoded
    };
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: `bad request: malformed segment URL encoding (${err.message})`
    };
  }
}

function validateSegmentProxyUrl(rawUrl, allowedHostSuffixes = DEFAULT_SEGMENT_HOST_SUFFIXES) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return {
      ok: false,
      status: 400,
      error: 'missing segment URL'
    };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: `bad request: malformed segment URL (${err.message})`
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      ok: false,
      status: 400,
      error: 'bad request: unsupported segment URL protocol'
    };
  }

  if (parsed.username || parsed.password) {
    return {
      ok: false,
      status: 400,
      error: 'bad request: segment URL must not contain credentials'
    };
  }

  if (!hostnameMatchesAllowedSuffix(parsed.hostname, allowedHostSuffixes)) {
    return {
      ok: false,
      status: 403,
      error: `segment host is not allowed: ${parsed.hostname}`
    };
  }

  return {
    ok: true,
    url: parsed.toString()
  };
}

function normalizeProxyOrigin(proxyOrigin) {
  if (typeof proxyOrigin !== 'string' || proxyOrigin.trim() === '') {
    throw new Error('proxyOrigin must be a non-empty string');
  }
  return proxyOrigin.replace(/\/+$/, '');
}

function buildSegmentProxyUrl(proxyOrigin, sessionId, targetUrl) {
  const normalizedOrigin = normalizeProxyOrigin(proxyOrigin);
  const normalizedSessionId = String(sessionId ?? '').trim();
  if (!normalizedSessionId) {
    throw new Error('sessionId must be provided');
  }
  const normalizedTarget = String(targetUrl ?? '').trim();
  if (!normalizedTarget) {
    throw new Error('targetUrl must be provided');
  }

  const segmentPrefix = `${normalizedOrigin}/hls/${normalizedSessionId}/segment/`;
  if (normalizedTarget.startsWith(segmentPrefix)) {
    return normalizedTarget;
  }

  return `${segmentPrefix}${encodeURIComponent(normalizedTarget)}`;
}

function resolveManifestUri(rawUri, baseManifestUrl = '') {
  if (typeof rawUri !== 'string') return null;
  const candidate = rawUri.trim();
  if (!candidate) return null;

  let parsed;
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
      parsed = new URL(candidate);
    } else if (typeof baseManifestUrl === 'string' && baseManifestUrl.trim() !== '') {
      parsed = new URL(candidate, baseManifestUrl);
    } else {
      return null;
    }
  } catch (_err) {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }
  return parsed.toString();
}

function rewriteManifest(manifest, sessionId, proxyOrigin, baseManifestUrl = '') {
  if (typeof manifest !== 'string' || manifest.length === 0) return '';
  const normalizedOrigin = normalizeProxyOrigin(proxyOrigin);
  const normalizedSessionId = String(sessionId ?? '').trim();
  if (!normalizedSessionId) {
    throw new Error('sessionId must be provided');
  }
  const proxiedPrefix = `${normalizedOrigin}/hls/${normalizedSessionId}/segment/`;

  const rewriteUri = (uriValue) => {
    const resolved = resolveManifestUri(uriValue, baseManifestUrl);
    if (!resolved) return null;
    if (resolved.startsWith(proxiedPrefix)) return resolved;
    return buildSegmentProxyUrl(normalizedOrigin, normalizedSessionId, resolved);
  };

  return manifest
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return line;
      }

      if (trimmed.startsWith('#')) {
        return line.replace(/URI="([^"]+)"/g, (fullMatch, uriValue) => {
          const rewritten = rewriteUri(uriValue);
          if (!rewritten) return fullMatch;
          return `URI="${rewritten}"`;
        });
      }

      const rewritten = rewriteUri(trimmed);
      return rewritten || line;
    })
    .join('\n');
}

module.exports = {
  DEFAULT_SEGMENT_HOST_SUFFIXES,
  buildSegmentProxyUrl,
  hostnameMatchesAllowedSuffix,
  parseRequestUrl,
  decodeSegmentUrl,
  resolveManifestUri,
  rewriteManifest,
  validateSegmentProxyUrl
};
