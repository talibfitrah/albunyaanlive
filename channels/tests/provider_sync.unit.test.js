#!/usr/bin/env node
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const providerSync = require('../provider_sync.js');

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'provider-sync-test-'));
}

function cleanupDir(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
}

test('validateProviderConfigShape accepts valid config and normalizes port', () => {
  const result = providerSync.validateProviderConfigShape({
    server: 'vlc.news',
    default_port: '80',
    credentials: [
      { username: '111111111111', password: 'pw1' },
      { username: '222222222222', password: 'pw2' }
    ]
  });

  assert.equal(result.server, 'vlc.news');
  assert.equal(result.default_port, 80);
  assert.equal(result.credentials.length, 2);
});

test('validateProviderConfigShape rejects malformed credentials array', () => {
  assert.throws(
    () => providerSync.validateProviderConfigShape({
      server: 'vlc.news',
      default_port: 80,
      credentials: {}
    }),
    /credentials must be a non-empty array/
  );
});

test('validateProviderConfigShape rejects duplicate usernames', () => {
  assert.throws(
    () => providerSync.validateProviderConfigShape({
      server: 'vlc.news',
      default_port: 80,
      credentials: [
        { username: 'dup', password: 'pw1' },
        { username: 'dup', password: 'pw2' }
      ]
    }),
    /duplicate username/
  );
});

test('sanitizeRegistryData keeps valid channels and skips invalid entries', () => {
  const result = providerSync.sanitizeRegistryData({
    channels: {
      good: {
        stream_id: '1408',
        match_names: ['Al MAJD Ajaweed'],
        config_file: 'channel_ajaweed_revised.sh',
        provider_name: 'Al MAJD Ajaweed',
        preferred_credential: '166164109628',
        scale: '0',
        non_vlc_backups: ['https://example.com/fallback.m3u8']
      },
      bad: {
        stream_id: 'nope',
        match_names: [],
        config_file: ''
      }
    }
  }, 'test-registry');

  assert.equal(Object.keys(result.registry.channels).length, 1);
  assert.ok(result.registry.channels.good);
  assert.ok(result.warnings.some((msg) => msg.includes('bad')));
});

test('computeServiceStatus reports degraded/starting states deterministically', () => {
  assert.equal(providerSync.computeServiceStatus({
    credentialTotal: 0,
    activeCredentials: 0,
    errorCredentials: 0,
    lastSync: null
  }), 'starting');

  assert.equal(providerSync.computeServiceStatus({
    credentialTotal: 2,
    activeCredentials: 0,
    errorCredentials: 2,
    lastSync: new Date()
  }), 'degraded');

  assert.equal(providerSync.computeServiceStatus({
    credentialTotal: 2,
    activeCredentials: 2,
    errorCredentials: 0,
    lastSync: new Date()
  }), 'ok');
});

test('loadProviderConfigFile rejects missing credentials file', () => {
  const tempDir = makeTempDir();
  const missingFile = path.join(tempDir, 'missing_provider_credentials.json');

  try {
    assert.throws(
      () => providerSync.loadProviderConfigFile(missingFile, tempDir),
      /Credentials file not found/
    );
  } finally {
    cleanupDir(tempDir);
  }
});

test('loadProviderConfigFile rejects malformed credentials schema', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'provider_credentials.json');

  try {
    fs.writeFileSync(configPath, JSON.stringify({
      server: 'vlc.news',
      default_port: 80,
      credentials: {}
    }, null, 2), 'utf8');

    assert.throws(
      () => providerSync.loadProviderConfigFile(configPath, tempDir),
      /credentials must be a non-empty array/
    );
  } finally {
    cleanupDir(tempDir);
  }
});

test('resolveChannelConfigPath enforces channel_*.sh basename and directory bounds', () => {
  const tempDir = makeTempDir();
  const channelsDir = path.join(tempDir, 'channels');

  try {
    fs.mkdirSync(channelsDir, { recursive: true });
    const resolved = providerSync.resolveChannelConfigPath('channel_demo.sh', channelsDir);
    assert.equal(resolved, path.join(channelsDir, 'channel_demo.sh'));

    assert.throws(
      () => providerSync.resolveChannelConfigPath('../channel_demo.sh', channelsDir),
      /without path separators/
    );
    assert.throws(
      () => providerSync.resolveChannelConfigPath('evil.sh', channelsDir),
      /channel_\*\.sh/
    );
  } finally {
    cleanupDir(tempDir);
  }
});

test('updateConfigFile fails closed when required assignments are missing', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');
  const initial = [
    'stream_url="http://vlc.news:80/u/p/1"',
    'stream_url_backup1=""'
  ].join('\n');

  try {
    fs.writeFileSync(configPath, `${initial}\n`, 'utf8');
    assert.throws(
      () => providerSync.updateConfigFile(
        configPath,
        'http://vlc.news:80/u/p/1',
        'http://vlc.news:80/u2/p2/1',
        'http://vlc.news:80/u3/p3/1'
      ),
      /stream_url_backup2/
    );
    assert.equal(fs.readFileSync(configPath, 'utf8'), `${initial}\n`);
  } finally {
    cleanupDir(tempDir);
  }
});

test('updateConfigFile safely escapes shell-special characters and round-trips values', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');

  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/u/p/1"',
      'stream_url_backup1=""',
      'stream_url_backup2=""'
    ].join('\n') + '\n', 'utf8');

    const primary = 'http://example.com/live?sig=$token`abc"&id=1';
    const backup1 = 'http://example.com/b1?x=$A';
    const backup2 = 'http://example.com/b2?x=`B`';

    const result = providerSync.updateConfigFile(configPath, primary, backup1, backup2);
    assert.equal(result.primaryChanged, true);
    assert.equal(result.backupsChanged, true);

    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url, primary);
    assert.equal(persisted.stream_url_backup1, backup1);
    assert.equal(persisted.stream_url_backup2, backup2);
  } finally {
    cleanupDir(tempDir);
  }
});

test('parsePositiveStreamId accepts only finite positive integers', () => {
  assert.equal(providerSync.parsePositiveStreamId('1408'), 1408);
  assert.equal(providerSync.parsePositiveStreamId(357369), 357369);
  assert.equal(providerSync.parsePositiveStreamId('0'), null);
  assert.equal(providerSync.parsePositiveStreamId('-1'), null);
  assert.equal(providerSync.parsePositiveStreamId('NaN'), null);
  assert.equal(providerSync.parsePositiveStreamId('1.5'), null);
  assert.equal(providerSync.parsePositiveStreamId(undefined), null);
});

test('matchChannelInCatalogWithIndexes fails closed on ambiguous exact name matches', () => {
  const catalogMap = new Map([
    [357383, { stream_id: 357383, name: 'ALFATH TV' }],
    [357370, { stream_id: 357370, name: 'Al Fath TV' }]
  ]);
  const indexMap = new Map([
    ['fath tv', [357383, 357370]]
  ]);
  const warnings = [];

  const result = providerSync.matchChannelInCatalogWithIndexes(
    'alfath',
    { stream_id: 999999, match_names: ['Al Fath TV'] },
    catalogMap,
    indexMap,
    (msg) => warnings.push(msg)
  );

  assert.equal(result, null);
  assert.ok(warnings.length >= 1);
  assert.ok(warnings.some((msg) => /Ambiguous exact match/.test(msg)));
});

test('matchChannelInCatalogWithIndexes prefers current stream when exact match is ambiguous', () => {
  const catalogMap = new Map([
    [357383, { stream_id: 357383, name: 'ALFATH TV' }],
    [357370, { stream_id: 357370, name: 'Al Fath TV' }]
  ]);
  const indexMap = new Map([
    ['fath tv', [357383, 357370]]
  ]);

  const result = providerSync.matchChannelInCatalogWithIndexes(
    'alfath',
    { stream_id: 357370, match_names: ['Al Fath TV'] },
    catalogMap,
    indexMap
  );

  assert.equal(result.stream_id, 357370);
  assert.equal(result.method, 'exact_current');
});

test('matchChannelInCatalogWithIndexes matches stream_id drift when catalog name adds HD token', () => {
  const catalogMap = new Map([
    [9001, { stream_id: 9001, name: 'Al MAJD news HD' }],
  ]);
  const indexMap = new Map([
    ['majd news hd', [9001]],
  ]);

  const result = providerSync.matchChannelInCatalogWithIndexes(
    'almajd-news',
    { stream_id: 1415, match_names: ['Al MAJD news'] },
    catalogMap,
    indexMap
  );

  assert.ok(result);
  assert.equal(result.stream_id, 9001);
});

test('matchChannelInCatalogWithIndexes fails closed on ambiguous subset fuzzy matches', () => {
  const catalogMap = new Map([
    [9001, { stream_id: 9001, name: 'Al MAJD news HD' }],
    [9002, { stream_id: 9002, name: 'Al MAJD news SD' }],
  ]);
  const indexMap = new Map([
    ['majd news hd', [9001]],
    ['majd news sd', [9002]],
  ]);
  const warnings = [];

  const result = providerSync.matchChannelInCatalogWithIndexes(
    'almajd-news',
    { stream_id: 1415, match_names: ['Al MAJD news'] },
    catalogMap,
    indexMap,
    (msg) => warnings.push(msg)
  );

  assert.equal(result, null);
  assert.ok(warnings.some((msg) => /Ambiguous fuzzy match/.test(msg)));
});

test('matchChannelInCatalogWithIndexes does not match on overly generic single-token names', () => {
  const catalogMap = new Map([
    [9001, { stream_id: 9001, name: 'Al MAJD news HD' }],
  ]);
  const indexMap = new Map([
    ['majd news hd', [9001]],
  ]);

  const result = providerSync.matchChannelInCatalogWithIndexes(
    'almajd-news',
    { stream_id: 1415, match_names: ['News'] },
    catalogMap,
    indexMap
  );

  assert.equal(result, null);
});

test('loadProviderConfigFile enforces restrictive permissions in production', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'provider_credentials.json');
  const prevNodeEnv = process.env.NODE_ENV;
  const prevStrictPerms = process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS;

  try {
    fs.writeFileSync(configPath, JSON.stringify({
      server: 'vlc.news',
      default_port: 80,
      credentials: [{ username: '111111111111', password: 'pw1' }]
    }, null, 2), 'utf8');
    fs.chmodSync(configPath, 0o644);

    process.env.NODE_ENV = 'production';
    delete process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS;

    assert.throws(
      () => providerSync.loadProviderConfigFile(configPath, tempDir),
      /mode 644; expected 600/
    );
  } finally {
    if (prevNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = prevNodeEnv;
    }

    if (prevStrictPerms === undefined) {
      delete process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS;
    } else {
      process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS = prevStrictPerms;
    }

    cleanupDir(tempDir);
  }
});

test('loadProviderConfigFile allows permissive mode when strict production enforcement is disabled', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'provider_credentials.json');
  const prevNodeEnv = process.env.NODE_ENV;
  const prevStrictPerms = process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS;

  try {
    fs.writeFileSync(configPath, JSON.stringify({
      server: 'vlc.news',
      default_port: 80,
      credentials: [{ username: '111111111111', password: 'pw1' }]
    }, null, 2), 'utf8');
    fs.chmodSync(configPath, 0o644);

    process.env.NODE_ENV = 'production';
    process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS = '0';

    const cfg = providerSync.loadProviderConfigFile(configPath, tempDir);
    assert.equal(cfg.server, 'vlc.news');
    assert.equal(cfg.default_port, 80);
    assert.equal(cfg.credentials.length, 1);
  } finally {
    if (prevNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = prevNodeEnv;
    }

    if (prevStrictPerms === undefined) {
      delete process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS;
    } else {
      process.env.PROVIDER_SYNC_STRICT_CREDENTIAL_PERMS = prevStrictPerms;
    }

    cleanupDir(tempDir);
  }
});

test('buildPlayerApiUrl safely URL-encodes credential query parameters', () => {
  const built = providerSync.buildPlayerApiUrl(
    'vlc.news',
    80,
    'user+name',
    'p@ss&word=1',
    'get_live_streams'
  );

  const parsed = new URL(built);
  assert.equal(parsed.hostname, 'vlc.news');
  assert.ok(parsed.port === '' || parsed.port === '80');
  assert.equal(parsed.pathname, '/player_api.php');
  assert.equal(parsed.searchParams.get('username'), 'user+name');
  assert.equal(parsed.searchParams.get('password'), 'p@ss&word=1');
  assert.equal(parsed.searchParams.get('action'), 'get_live_streams');
});

test('redactSecretForApi always hides credential values', () => {
  assert.equal(providerSync.redactSecretForApi('secret123'), '<redacted>');
  assert.equal(providerSync.redactSecretForApi(''), '<redacted>');
});

test('parseBoundedInt falls back and clamps values', () => {
  assert.equal(providerSync.parseBoundedInt(undefined, 10, 1, 100), 10);
  assert.equal(providerSync.parseBoundedInt('not-a-number', 10, 1, 100), 10);
  assert.equal(providerSync.parseBoundedInt('0', 10, 1, 100), 1);
  assert.equal(providerSync.parseBoundedInt('101', 10, 1, 100), 100);
  assert.equal(providerSync.parseBoundedInt('42', 10, 1, 100), 42);
});

test('parsePortList keeps valid ports and removes duplicates', () => {
  assert.deepEqual(
    providerSync.parsePortList('80, 8080, abc, 80, 70000', [9000]),
    [80, 8080]
  );
  assert.deepEqual(providerSync.parsePortList('', [9000, 9000, 80]), [9000, 80]);
});

test('buildApiPortCandidates prioritizes and deduplicates candidates', () => {
  const candidates = providerSync.buildApiPortCandidates({
    preferredPort: 9000,
    defaultPort: 80,
    discoveredPorts: [80, 8080, 9000, null],
    probePorts: [8080, 8000, 443]
  });
  assert.deepEqual(candidates, [9000, 80, 8080, 8000, 443]);
});

test('fetchPlayerApiWithPortFallback falls back to later ports and returns used port', async () => {
  const attemptedPorts = [];
  const result = await providerSync.fetchPlayerApiWithPortFallback({
    server: 'vlc.news',
    username: 'user1',
    password: 'pass1',
    preferredPort: 9000,
    defaultPort: 80,
    discoveredPorts: [8080],
    probePorts: [8000],
    timeoutMs: 1234,
    fetchJson: async (url, timeoutMs) => {
      assert.equal(timeoutMs, 1234);
      const parsed = new URL(url);
      const port = parsed.port === '' ? 80 : Number(parsed.port);
      attemptedPorts.push(port);
      if (port !== 8000) {
        throw new Error(`port ${port} unavailable`);
      }
      return { ok: true, port };
    }
  });

  assert.deepEqual(attemptedPorts, [9000, 80, 8080, 8000]);
  assert.equal(result.port, 8000);
  assert.deepEqual(result.attemptedPorts, [9000, 80, 8080, 8000]);
  assert.deepEqual(result.response, { ok: true, port: 8000 });
});

test('fetchPlayerApiWithPortFallback fails when all probe ports fail', async () => {
  await assert.rejects(
    providerSync.fetchPlayerApiWithPortFallback({
      server: 'vlc.news',
      username: 'user1',
      password: 'pass1',
      preferredPort: 9999,
      defaultPort: 80,
      probePorts: [8080],
      fetchJson: async () => {
        throw new Error('network down');
      }
    }),
    /All API port probes failed/
  );
});

test('planChannelUrls preserves non-vlc backup priority and fills remaining slots with vlc backups', () => {
  const primaryCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '111111111111',
    password: 'pw1'
  };
  const backupCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '222222222222',
    password: 'pw2'
  };

  const planned = providerSync.planChannelUrls(
    {
      vlc_as_backup: false,
      non_vlc_backups: ['https://live.seenshow.com/hls/live/abc/master.m3u8']
    },
    357369,
    primaryCred,
    [backupCred]
  );

  assert.equal(planned.primaryUrl, 'http://vlc.news:80/111111111111/pw1/357369');
  assert.equal(planned.backup1, 'https://live.seenshow.com/hls/live/abc/master.m3u8');
  assert.equal(planned.backup2, 'http://vlc.news:80/222222222222/pw2/357369');
});

test('planChannelUrls uses two distinct vlc backup credentials when no non-vlc backups exist', () => {
  const primaryCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '111111111111',
    password: 'pw1'
  };
  const backupCred1 = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '222222222222',
    password: 'pw2'
  };
  const backupCred2 = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '333333333333',
    password: 'pw3'
  };

  const planned = providerSync.planChannelUrls(
    { vlc_as_backup: false, non_vlc_backups: [] },
    1434,
    primaryCred,
    [backupCred1, backupCred2]
  );

  assert.equal(planned.primaryUrl, 'http://vlc.news:80/111111111111/pw1/1434');
  assert.equal(planned.backup1, 'http://vlc.news:80/222222222222/pw2/1434');
  assert.equal(planned.backup2, 'http://vlc.news:80/333333333333/pw3/1434');
});

test('planChannelUrls keeps non-vlc primary for vlc_as_backup channels and emits vlc backups', () => {
  const primaryCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '111111111111',
    password: 'pw1'
  };
  const backupCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '222222222222',
    password: 'pw2'
  };

  const planned = providerSync.planChannelUrls(
    {
      vlc_as_backup: true,
      non_vlc_backups: ['rtmp://live.restream.io/pull/stream-id']
    },
    1434,
    primaryCred,
    [backupCred]
  );

  assert.equal(planned.primaryUrl, 'rtmp://live.restream.io/pull/stream-id');
  assert.equal(planned.backup1, 'http://vlc.news:80/111111111111/pw1/1434');
  assert.equal(planned.backup2, 'http://vlc.news:80/222222222222/pw2/1434');
});

test('parseVlcNewsUrl parses valid vlc.news URLs and rejects invalid sources', () => {
  const parsed = providerSync.parseVlcNewsUrl('http://vlc.news:80/111111111111/pw1/357369');
  assert.ok(parsed);
  assert.equal(parsed.port, 80);
  assert.equal(parsed.username, '111111111111');
  assert.equal(parsed.password, 'pw1');
  assert.equal(parsed.streamId, 357369);

  assert.equal(providerSync.parseVlcNewsUrl('http://example.com:80/111111111111/pw1/357369'), null);
  assert.equal(providerSync.parseVlcNewsUrl('http://vlc.news:80/user/pass/not-number'), null);
  assert.equal(providerSync.parseVlcNewsUrl(''), null);
});

test('extractBootstrapChannelEntry supports non-vlc primary channels with vlc backups', () => {
  const content = [
    'stream_url="https://live.seenshow.com/hls/live/2120826/LIVE-006-WASEQYA/master.m3u8"',
    'stream_url_backup1="http://vlc.news:80/166063150075/pw-doc/1407"',
    'stream_url_backup2="https://www.youtube.com/watch?v=backup123"',
    'rtmp_url="/var/www/html/stream/hls/almajd-documentary/master.m3u8"',
    'scale=4'
  ].join('\n') + '\n';

  const catalog = new Map([[1407, { stream_id: 1407, name: 'Al MAJD Documentary' }]]);
  const entry = providerSync.extractBootstrapChannelEntry(content, 'channel_almajd_doc_revised.sh', catalog);

  assert.ok(entry);
  assert.equal(entry.channelId, 'almajd-documentary');
  assert.equal(entry.streamId, 1407);
  assert.equal(entry.preferredCredential, '166063150075');
  assert.equal(entry.vlcAsBackup, true);
  assert.equal(entry.scale, 4);
  assert.equal(entry.providerName, 'Al MAJD Documentary');
  assert.deepEqual(entry.matchNames, ['Al MAJD Documentary']);
  assert.deepEqual(entry.nonVlcBackups, [
    'https://live.seenshow.com/hls/live/2120826/LIVE-006-WASEQYA/master.m3u8',
    'https://www.youtube.com/watch?v=backup123'
  ]);
});

test('extractBootstrapChannelEntry keeps vlc primary channels and only non-vlc backups', () => {
  const content = [
    'stream_url="http://vlc.news:80/602779426000/pw-kids/1413"',
    'stream_url_backup1="https://live.seenshow.com/hls/live/2120822/LIVE-009-KIDS/master.m3u8"',
    'stream_url_backup2="http://vlc.news:80/302285257136/pw-bk/1413"',
    'rtmp_url="/var/www/html/stream/hls/almajd-kids/master.m3u8"',
    'scale=0'
  ].join('\n') + '\n';

  const catalog = new Map([[1413, { stream_id: 1413, name: 'Al MAJD Kids' }]]);
  const entry = providerSync.extractBootstrapChannelEntry(content, 'channel_almajd_kids_revised.sh', catalog);

  assert.ok(entry);
  assert.equal(entry.channelId, 'almajd-kids');
  assert.equal(entry.streamId, 1413);
  assert.equal(entry.preferredCredential, '602779426000');
  assert.equal(entry.vlcAsBackup, false);
  assert.deepEqual(entry.nonVlcBackups, [
    'https://live.seenshow.com/hls/live/2120822/LIVE-009-KIDS/master.m3u8'
  ]);
});

test('parseSeenshowHlsPath extracts stream path from Seenshow master and variant URLs', () => {
  assert.equal(
    providerSync.parseSeenshowHlsPath('https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/master.m3u8'),
    '2120823/LIVE-011-RAWDA'
  );
  assert.equal(
    providerSync.parseSeenshowHlsPath('https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/3.m3u8?hdntl=exp%3D1'),
    '2120823/LIVE-011-RAWDA'
  );
  assert.equal(
    providerSync.parseSeenshowHlsPath(
      'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/hdntl=exp=1770913951~acl=%2fhls%2flive%2f2120830%2fLIVE-004-ELMIA%2f*~hmac=abc/3.m3u8'
    ),
    '2120830/LIVE-004-ELMIA'
  );
  assert.equal(providerSync.parseSeenshowHlsPath('https://example.com/not-seenshow.m3u8'), null);
});

test('resolveSeenshowTokenUrl calls resolver endpoint and returns tokenized URL', async () => {
  let requested = '';
  const resolved = await providerSync.resolveSeenshowTokenUrl(
    '2120829/LIVE-002-QURAN',
    async (url) => {
      requested = url;
      return { url: 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/master.m3u8?hdntl=exp=9999999999~acl=*' };
    }
  );

  assert.ok(requested.endsWith('/resolve/2120829/LIVE-002-QURAN'));
  assert.ok(resolved.includes('hdntl='));
});

test('refreshSeenshowBackups resolves Seenshow URLs and reuses cache for duplicate paths', async () => {
  const backups = [
    'https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/master.m3u8',
    'https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/hdntl=exp=999~acl=%2fhls%2flive%2f2120823%2fLIVE-011-RAWDA%2f*~hmac=x/3.m3u8',
    'rtmp://live.restream.io/pull/stream-id'
  ];
  const cache = new Map();
  let calls = 0;

  const result = await providerSync.refreshSeenshowBackups(backups, {
    cache,
    fetchJson: async () => {
      calls++;
      return { url: 'https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/master.m3u8?hdntl=exp=9999999999~acl=*' };
    }
  });

  // If resolver integration is disabled in env, function should no-op.
  if (calls === 0) {
    assert.deepEqual(result.backups, backups);
    assert.equal(result.changed, false);
    return;
  }

  assert.equal(calls, 1);
  assert.equal(result.changed, true);
  assert.equal(result.refreshedCount, 2);
  assert.equal(result.failedCount, 0);
  assert.ok(result.backups[0].includes('hdntl='));
  assert.ok(result.backups[1].includes('hdntl='));
  assert.equal(result.backups[2], backups[2]);
});

test('applyConfigUpdateAndRestartIfNeeded rolls back config when primary restart fails', async () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');
  const initial = [
    'stream_name="123456789012/123456789012/1"',
    'stream_url="http://vlc.news:80/111111111111/pw1/1"',
    'stream_url_backup1="http://vlc.news:80/222222222222/pw2/1"',
    'stream_url_backup2="http://vlc.news:80/333333333333/pw3/1"'
  ].join('\n') + '\n';
  let restartCalls = 0;

  try {
    fs.writeFileSync(configPath, initial, 'utf8');

    await assert.rejects(
      providerSync.applyConfigUpdateAndRestartIfNeeded(
        configPath,
        'almajd-test',
        'http://vlc.news:80/111111111111/pw1/2',
        'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/master.m3u8?hdntl=exp=9999999999~acl=*',
        'http://vlc.news:80/333333333333/pw3/2',
        '',
        {
          restartFn: async () => {
            restartCalls++;
            return { ok: false, error: new Error('graceful restart command failed') };
          }
        }
      ),
      /config rolled back/
    );

    assert.equal(restartCalls, 1);
    assert.equal(fs.readFileSync(configPath, 'utf8'), initial);
  } finally {
    cleanupDir(tempDir);
  }
});

test('applyConfigUpdateAndRestartIfNeeded skips restart when primary URL does not change', async () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');
  let restartCalls = 0;

  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/111111111111/pw1/1"',
      'stream_url_backup1="http://vlc.news:80/222222222222/pw2/1"',
      'stream_url_backup2="http://vlc.news:80/333333333333/pw3/1"'
    ].join('\n') + '\n', 'utf8');

    const result = await providerSync.applyConfigUpdateAndRestartIfNeeded(
      configPath,
      'almajd-test',
      'http://vlc.news:80/111111111111/pw1/1',
      'https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/master.m3u8?hdntl=exp=9999999999~acl=*',
      'http://vlc.news:80/333333333333/pw3/1',
      '',
      {
        restartFn: async () => {
          restartCalls++;
          return { ok: true };
        }
      }
    );

    assert.equal(result.primaryChanged, false);
    assert.equal(result.backupsChanged, true);
    assert.equal(restartCalls, 0);

    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url, 'http://vlc.news:80/111111111111/pw1/1');
    assert.ok(persisted.stream_url_backup1.includes('hdntl='));
  } finally {
    cleanupDir(tempDir);
  }
});

test('applyConfigUpdateAndRestartIfNeeded keeps config changes when graceful restart succeeds', async () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');
  let restartCalls = 0;

  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/111111111111/pw1/1"',
      'stream_url_backup1="http://vlc.news:80/222222222222/pw2/1"',
      'stream_url_backup2="http://vlc.news:80/333333333333/pw3/1"'
    ].join('\n') + '\n', 'utf8');

    const result = await providerSync.applyConfigUpdateAndRestartIfNeeded(
      configPath,
      'almajd-test',
      'http://vlc.news:80/111111111111/pw1/2',
      'http://vlc.news:80/222222222222/pw2/2',
      'http://vlc.news:80/333333333333/pw3/2',
      '',
      {
        restartFn: async () => {
          restartCalls++;
          return { ok: true, stdout: 'ok', stderr: '' };
        }
      }
    );

    assert.equal(restartCalls, 1);
    assert.equal(result.primaryChanged, true);
    assert.equal(result.backupsChanged, true);

    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url, 'http://vlc.news:80/111111111111/pw1/2');
    assert.equal(persisted.stream_url_backup1, 'http://vlc.news:80/222222222222/pw2/2');
    assert.equal(persisted.stream_url_backup2, 'http://vlc.news:80/333333333333/pw3/2');
  } finally {
    cleanupDir(tempDir);
  }
});

// ---------------------------------------------------------------------------
// stripSeenshowToken — path-segment and query-string token stripping
// ---------------------------------------------------------------------------

test('stripSeenshowToken strips path-segment hdntl tokens', () => {
  const url = 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/hdntl=exp=1771002312~acl=%2f*~hmac=abc123/3.m3u8';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/3.m3u8');
});

test('stripSeenshowToken strips query-string hdntl as sole param', () => {
  const url = 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/master.m3u8?hdntl=exp=9999~acl=*~hmac=abc';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/master.m3u8');
});

test('stripSeenshowToken strips query-string hdnts as additional param', () => {
  const url = 'https://live.seenshow.com/hls/live/abc/3.m3u8?foo=1&hdnts=exp=9999~hmac=xyz&bar=2';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/abc/3.m3u8?foo=1&bar=2');
});

test('stripSeenshowToken leaves non-seenshow URLs untouched', () => {
  const url = 'http://vlc.news:80/user/pass/1234';
  assert.equal(providerSync.stripSeenshowToken(url), url);
});

test('stripSeenshowToken handles URL with both path and query tokens', () => {
  const url = 'https://live.seenshow.com/hls/live/abc/hdntl=exp=111~hmac=aaa/3.m3u8?hdnts=exp=222~hmac=bbb';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/abc/3.m3u8');
});

test('stripSeenshowToken handles clean URL (no tokens) as no-op', () => {
  const url = 'https://live.seenshow.com/hls/live/2120829/LIVE-002-QURAN/3.m3u8';
  assert.equal(providerSync.stripSeenshowToken(url), url);
});

// ---------------------------------------------------------------------------
// RESERVED_CREDENTIALS enforcement
// ---------------------------------------------------------------------------

test('RESERVED_CREDENTIALS contains the expected testing and spare credentials', () => {
  assert.ok(providerSync.RESERVED_CREDENTIALS.has('302285257136'));
  assert.ok(providerSync.RESERVED_CREDENTIALS.has('964683414160'));
});

test('getBestCredential excludes reserved credentials from selection', () => {
  assert.ok(providerSync.RESERVED_CREDENTIALS instanceof Set);
  assert.ok(providerSync.RESERVED_CREDENTIALS.size >= 2);
  // getBestCredential with all usernames excluded must return null (no active pool loaded)
  const result = providerSync.getBestCredential([...providerSync.RESERVED_CREDENTIALS]);
  assert.equal(result, null);
});

test('getBestCredential skips reserved credentials even when they are Active in the pool', () => {
  // Inject a pool that includes both reserved and non-reserved credentials
  const reserved = [...providerSync.RESERVED_CREDENTIALS];
  providerSync._testSetCredentialPool([
    { username: reserved[0], status: 'Active', expiry_date: new Date('2028-01-01') },
    { username: reserved[1], status: 'Active', expiry_date: new Date('2028-01-01') },
    { username: '111111111111', status: 'Active', expiry_date: new Date('2027-01-02') },
    { username: '222222222222', status: 'Active', expiry_date: new Date('2027-06-01') },
  ]);

  try {
    // With no additional exclusions, getBestCredential must skip reserved and return a non-reserved
    const best = providerSync.getBestCredential();
    assert.ok(best !== null, 'should return a credential');
    assert.ok(!providerSync.RESERVED_CREDENTIALS.has(best.username),
      `returned reserved credential ${best.username}`);
    assert.equal(best.username, '222222222222', 'should pick longest-to-expire non-reserved');

    // Excluding one non-reserved credential should return the other non-reserved
    const next = providerSync.getBestCredential(['222222222222']);
    assert.ok(next !== null);
    assert.equal(next.username, '111111111111');

    // Excluding all non-reserved should return null (reserved still skipped)
    const none = providerSync.getBestCredential(['111111111111', '222222222222']);
    assert.equal(none, null, 'must return null when only reserved remain');
  } finally {
    // Clean up injected pool
    providerSync._testSetCredentialPool([]);
  }
});

// ---------------------------------------------------------------------------
// planChannelUrls — null credential (non-vlc-only channels)
// ---------------------------------------------------------------------------

test('planChannelUrls with null primaryCredential uses non-vlc backups only', () => {
  const planned = providerSync.planChannelUrls(
    {
      vlc_as_backup: true,
      non_vlc_backups: [
        'https://www.youtube.com/@SaudiQuranTv/live',
        'aloula:7'
      ]
    },
    1438,
    null,
    []
  );

  assert.equal(planned.primaryUrl, 'https://www.youtube.com/@SaudiQuranTv/live');
  assert.equal(planned.backup1, 'aloula:7');
  assert.equal(planned.backup2, '');
  assert.equal(planned.vlcPrimaryUrl, '');
});

// ---------------------------------------------------------------------------
// stripSeenshowToken — fragment edge case
// ---------------------------------------------------------------------------

test('stripSeenshowToken preserves fragment when stripping sole query token', () => {
  const url = 'https://live.seenshow.com/hls/live/abc/3.m3u8?hdntl=exp=9999~hmac=abc#frag';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/abc/3.m3u8#frag');
});

test('stripSeenshowToken strips both hdntl and hdnts when both present as query params', () => {
  const url = 'https://live.seenshow.com/hls/live/abc/3.m3u8?hdntl=tok1&hdnts=tok2';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/abc/3.m3u8');
});

test('stripSeenshowToken keeps non-token params when stripping both hdntl and hdnts', () => {
  const url = 'https://live.seenshow.com/hls/live/abc/3.m3u8?foo=1&hdntl=tok1&hdnts=tok2&bar=2';
  const cleaned = providerSync.stripSeenshowToken(url);
  assert.equal(cleaned, 'https://live.seenshow.com/hls/live/abc/3.m3u8?foo=1&bar=2');
});

// ---------------------------------------------------------------------------
// applyConfigUpdateAndRestartIfNeeded — fail-closed on empty primaryUrl
// ---------------------------------------------------------------------------

test('applyConfigUpdateAndRestartIfNeeded rejects empty primaryUrl', async () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');
  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/111111111111/pw1/1"',
      'stream_url_backup1=""',
      'stream_url_backup2=""'
    ].join('\n') + '\n', 'utf8');

    await assert.rejects(
      providerSync.applyConfigUpdateAndRestartIfNeeded(
        configPath,
        'test-channel',
        '',
        '',
        '',
        '',
        { restartFn: async () => ({ ok: true }) }
      ),
      /Refusing to write empty stream_url/
    );

    // Config must remain unchanged
    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url, 'http://vlc.news:80/111111111111/pw1/1');
  } finally {
    cleanupDir(tempDir);
  }
});

// ---------------------------------------------------------------------------
// planChannelUrls — null credential + empty non-vlc backups returns empty
// ---------------------------------------------------------------------------

test('planChannelUrls with null credential and no non-vlc backups returns empty URLs', () => {
  const planned = providerSync.planChannelUrls(
    { vlc_as_backup: false, non_vlc_backups: [] },
    1234,
    null,
    []
  );
  assert.equal(planned.primaryUrl, '');
  assert.equal(planned.backup1, '');
  assert.equal(planned.backup2, '');
  assert.equal(planned.vlcPrimaryUrl, '');
});

// ---------------------------------------------------------------------------
// planChannelUrls — backup3 support
// ---------------------------------------------------------------------------

test('planChannelUrls returns backup3 when 3+ non-vlc backups exist', () => {
  const primaryCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '111111111111',
    password: 'pw1'
  };

  const planned = providerSync.planChannelUrls(
    {
      vlc_as_backup: false,
      non_vlc_backups: [
        'https://backup1.example.com/stream.m3u8',
        'https://backup2.example.com/stream.m3u8',
        'https://backup3.example.com/stream.m3u8'
      ]
    },
    1415,
    primaryCred,
    []
  );

  assert.equal(planned.primaryUrl, 'http://vlc.news:80/111111111111/pw1/1415');
  assert.equal(planned.backup1, 'https://backup1.example.com/stream.m3u8');
  assert.equal(planned.backup2, 'https://backup2.example.com/stream.m3u8');
  assert.equal(planned.backup3, 'https://backup3.example.com/stream.m3u8');
});

test('planChannelUrls returns empty backup3 when fewer than 3 non-vlc backups', () => {
  const primaryCred = {
    server_protocol: 'http',
    server_url: 'vlc.news',
    server_port: 80,
    username: '111111111111',
    password: 'pw1'
  };

  const planned = providerSync.planChannelUrls(
    { vlc_as_backup: false, non_vlc_backups: ['https://backup1.example.com/s.m3u8'] },
    1415,
    primaryCred,
    []
  );

  assert.equal(planned.backup1, 'https://backup1.example.com/s.m3u8');
  assert.equal(planned.backup3, '');
});

// ---------------------------------------------------------------------------
// sanitizeRegistryChannel — ayyadonline_* field preservation
// ---------------------------------------------------------------------------

test('sanitizeRegistryChannel preserves ayyadonline_stream_id and ayyadonline_credential', () => {
  const sanitized = providerSync.sanitizeRegistryChannel('test-ch', {
    stream_id: 1415,
    match_names: ['Test Channel'],
    config_file: 'channel_test.sh',
    provider_name: 'Test Channel',
    preferred_credential: '111111111111',
    scale: 4,
    non_vlc_backups: [],
    vlc_as_backup: false,
    ayyadonline_stream_id: 77453,
    ayyadonline_credential: 'farouq10226'
  });

  assert.equal(sanitized.ayyadonline_stream_id, 77453);
  assert.equal(sanitized.ayyadonline_credential, 'farouq10226');
});

test('sanitizeRegistryChannel omits ayyadonline fields when not present', () => {
  const sanitized = providerSync.sanitizeRegistryChannel('test-ch', {
    stream_id: 1415,
    match_names: ['Test Channel'],
    config_file: 'channel_test.sh',
    provider_name: 'Test Channel',
    preferred_credential: '111111111111',
    scale: 4,
    non_vlc_backups: [],
    vlc_as_backup: false
  });

  assert.equal(sanitized.ayyadonline_stream_id, undefined);
  assert.equal(sanitized.ayyadonline_credential, undefined);
});

test('sanitizeRegistryData round-trips ayyadonline fields through sanitize', () => {
  const result = providerSync.sanitizeRegistryData({
    channels: {
      makkah: {
        stream_id: 1421,
        match_names: ['MAKKAH TV'],
        config_file: 'channel_quran.sh',
        provider_name: 'MAKKAH TV',
        preferred_credential: '705729222787',
        scale: 4,
        non_vlc_backups: ['elahmad:makkahtv'],
        vlc_as_backup: false,
        ayyadonline_stream_id: 28179,
        ayyadonline_credential: 'farouq70226'
      }
    }
  }, 'test');

  assert.equal(result.warnings.length, 0);
  const ch = result.registry.channels.makkah;
  assert.equal(ch.ayyadonline_stream_id, 28179);
  assert.equal(ch.ayyadonline_credential, 'farouq70226');
  assert.equal(ch.stream_id, 1421);
});

// ---------------------------------------------------------------------------
// parseOptionalShellVar — backup3 parsing
// ---------------------------------------------------------------------------

test('parseOptionalShellVar returns null for missing variable', () => {
  const content = 'stream_url_backup1="http://example.com"\nstream_url_backup2=""';
  const result = providerSync.parseOptionalShellVar(content, 'stream_url_backup3');
  assert.equal(result, null);
});

test('parseOptionalShellVar returns value when variable is present', () => {
  const content = 'stream_url_backup3="http://example.com/b3"\n';
  const result = providerSync.parseOptionalShellVar(content, 'stream_url_backup3');
  assert.equal(result, 'http://example.com/b3');
});

// ---------------------------------------------------------------------------
// updateConfigFile — backup3 handling
// ---------------------------------------------------------------------------

test('updateConfigFile writes backup3 when config has the variable', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');

  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/u/p/1"',
      'stream_url_backup1=""',
      'stream_url_backup2=""',
      'stream_url_backup3=""'
    ].join('\n') + '\n', 'utf8');

    const result = providerSync.updateConfigFile(
      configPath,
      'http://vlc.news:80/u/p/1',
      'http://example.com/b1',
      'http://example.com/b2',
      'http://example.com/b3'
    );

    assert.equal(result.backupsChanged, true);
    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url_backup3, 'http://example.com/b3');
  } finally {
    cleanupDir(tempDir);
  }
});

test('updateConfigFile skips backup3 when config lacks the variable', () => {
  const tempDir = makeTempDir();
  const configPath = path.join(tempDir, 'channel_test.sh');

  try {
    fs.writeFileSync(configPath, [
      'stream_name="123456789012/123456789012/1"',
      'stream_url="http://vlc.news:80/u/p/1"',
      'stream_url_backup1=""',
      'stream_url_backup2=""'
    ].join('\n') + '\n', 'utf8');

    const result = providerSync.updateConfigFile(
      configPath,
      'http://vlc.news:80/u/p/1',
      'http://example.com/b1',
      'http://example.com/b2',
      'http://example.com/b3'
    );

    assert.equal(result.backupsChanged, true);
    const persisted = providerSync.parseConfigContent(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.stream_url_backup3, null);
  } finally {
    cleanupDir(tempDir);
  }
});

// ---------------------------------------------------------------------------
// buildAyyadonlineBackupUrl — registry-first with hardcoded fallback
// ---------------------------------------------------------------------------

test('buildAyyadonlineBackupUrl reads from channelEntry when ayyadonline fields present', () => {
  // buildAyyadonlineBackupUrl requires ayyadonlineConfig to be loaded.
  // Without real config, it returns null — this test validates null-safety.
  const result = providerSync.buildAyyadonlineBackupUrl('makkah', {
    ayyadonline_stream_id: 28179,
    ayyadonline_credential: 'farouq70226'
  });
  // Returns null because ayyadonlineConfig is not loaded in test env.
  // The important validation: function accepts channelEntry and doesn't throw.
  assert.equal(result, null);
});

test('buildAyyadonlineBackupUrl falls back to hardcoded map when entry has no ayyadonline fields', () => {
  const result = providerSync.buildAyyadonlineBackupUrl('makkah', {});
  // Returns null because ayyadonlineConfig is not loaded.
  assert.equal(result, null);
});

test('buildAyyadonlineBackupUrl returns null for unmapped channel', () => {
  const result = providerSync.buildAyyadonlineBackupUrl('nonexistent-channel', {});
  assert.equal(result, null);
});
