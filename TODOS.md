# TODOS

## Follow-up from 2026-04-13 refactor session

### Session A — `/proxy/hls/*` integration test harness (~1 hour)
Build a live test harness in `channels/tests/` that:
- Allocates an ephemeral port (retry on EADDRINUSE)
- PATH-prepends a fake `curl` (shell script in temp dir) that emits canned headers + body from fixtures
- Spawns `seenshow_resolver.js` with `SEENSHOW_HEADLESS=true` and test env, waits for `listen()` log line
- Sends HTTP requests via `curl` (the real one, outside the prepended PATH) to the resolver

Four tests against this harness:
1. **SSRF reject** — `GET /proxy/../etc/passwd` → 400 with `Only /hls/ paths are proxied`
2. **Host-header isolation** — `GET /proxy/hls/live/x/master.m3u8` with `Host: evil.com`, fake curl returns an m3u8 containing `https://live.seenshow.com/hls/foo.ts`. Assert response body contains `http://127.0.0.1:<port>/proxy/` and NOT `evil.com`.
3. **curl-close-before-headers** — fake curl exits 6 with no stdout. Assert 502 within ~16s (no hang).
4. **HEAD pass-through** — `HEAD /proxy/hls/live/x/master.m3u8`, fake curl emits 200 + Content-Type. Assert resolver returns 200 + Content-Type, empty body.

Static guards added in this session cover deletion of safety code; these cover semantic regressions.

### Session B — curl→HTTP fallback attempts-loop refactor (~30 min)
File: `channels/seenshow_resolver.js`, `promoteHdntsToHdntl` function (~line 860-890).
Current shape: nested try/catch where inner catch shadows outer as `err2`, both branches build the same `payload` shape with different log strings ("Promotion via curl" vs "Promotion via HTTP fallback").
Target shape:
```js
const attempts = [
  ['curl',          () => curlGetText(url, timeoutMs)],
  ['HTTP fallback', () => httpGetText(url, timeoutMs)],
];
for (const [label, fn] of attempts) {
  try { payload = await fn(); log(`Promotion via ${label}`); break; }
  catch (err) { log(`  ${label} failed: ${err.message}`); }
}
if (!payload) return null;
```
Safety net: integration tests from Session A.

### Session C — Extract `/proxy/` handler to named function (~1 hour)
File: `channels/seenshow_resolver.js`, inside `http.createServer` (~line 1667-1810).
Target: `async function handleProxyRequest(req, res, pathname, fullParsed)` at module scope, with internal helpers:
- `spawnProxyCurl({ url, mode })` — returns child process
- `parseHeadersFromStream(child)` — returns `{ upstreamStatus, upstreamHeaders, bodyStart }` promise
- `pipeBodyToResponse({ res, child, contentType, isPlaylist, playlistRewriteBase })` — handles playlist buffering OR binary streaming

Replaces the two-layered-listener pattern (`headersParsed` / `bodyHandlerInstalled` flags) with a cleaner state flow. Prerequisite: Session A integration tests must exist and pass before starting.

### Not doing — `emit_gpu_or_copy_encoder` helper
The scale 4/9/12 branches in `try_start_stream.sh` (~line 4030-4108) have 3-way conditionals for `force_copy_mode` / no-GPU / GPU-encode. Extracting to a helper is a ~80-line diff with a wide parameter surface (bitrate, preset, tune, rc, CQ, filter graph all vary). Without runtime encoder-output fixtures to compare before/after, a "refactor" that silently swaps two NVENC flags produces streams that decode but look subtly wrong. The current duplication is auditable by eye. Leave as-is unless a fourth scale appears.

## Pre-existing (unrelated to 2026-04-13 session, flagged for awareness)

### Move secrets out of `/home/msa/Development/hlsextractor/hls_url_updater.js`
Hardcoded at lines 17-22, 83-84: MySQL password, login email, login password. If that repo has a public or shared remote, these leak. Move to env vars or a `.gitignore`d config file.

### Add Puppeteer `waitForNavigation` timeout in `hls_url_updater.js:93`
Since self-scheduling was removed (2026-04-13), a hang during login now hangs the entire cron-invoked process until the next cron fire. Wrap with `{ timeout: 30000 }` or `Promise.race`.
