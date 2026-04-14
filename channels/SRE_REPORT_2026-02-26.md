# SRE Monitoring Report — 5-Hour Mission
## 20:56 CET Feb 26 → 01:50 CET Feb 27, 2026

---

## Health Sweep Log (44 sweeps, every 5 min)

| Sweep | Time  | Healthy | Stale Channels        | Alerts (FILTER_CRASH etc)     | Load  |
|-------|-------|---------|----------------------|-------------------------------|-------|
| #1    | 21:06 | 22/22   | —                    | —                             | —     |
| #2    | 21:11 | 22/22   | —                    | —                             | —     |
| #3    | 21:16 | 21/22   | saad (53s)           | —                             | —     |
| #4    | 21:24 | 22/22   | —                    | —                             | 4.28  |
| #5    | 21:29 | 22/22   | —                    | —                             | 7.33  |
| #6    | 21:34 | 21/22   | saad (40s)           | —                             | 7.86  |
| #7    | 21:41 | 22/22   | —                    | —                             | 5.81  |
| #8    | 21:46 | 22/22   | —                    | —                             | 6.28  |
| #9    | 21:51 | 22/22   | —                    | —                             | 6.04  |
| #10   | 22:17 | 22/22   | —                    | uthaymeen                     | 4.01  |
| #11   | 22:22 | 22/22   | —                    | —                             | 6.47  |
| #12   | 22:27 | 22/22   | —                    | —                             | 5.69  |
| #13   | 22:35 | 22/22   | —                    | uthaymeen                     | 2.90  |
| #14   | 22:40 | 22/22   | —                    | almajd-3aamah                 | 2.99  |
| #15   | 22:45 | 22/22   | —                    | —                             | 3.92  |
| #16   | 22:50 | 21/22   | almajd-3aamah (80s)  | —                             | 4.39  |
| #17   | 22:55 | 22/22   | —                    | almajd-3aamah                 | 4.64  |
| #18   | 23:00 | 22/22   | —                    | almajd-documentary            | 4.25  |
| #19   | 23:34 | 22/22   | —                    | almajd-documentary            | 3.87  |
| #20   | 23:39 | 22/22   | —                    | almajd-3aamah                 | 3.24  |
| #21   | 23:44 | 22/22   | —                    | almajd-documentary            | 4.24  |
| #22   | 23:49 | 22/22   | —                    | almajd-documentary            | 5.93  |
| #23   | 23:54 | 22/22   | —                    | almajd-3aamah                 | 6.17  |
| #24   | 23:59 | 22/22   | —                    | almajd-documentary            | 6.99  |
| #25   | 00:04 | 22/22   | —                    | almajd-3aamah                 | 9.49  |
| #26   | 00:09 | 22/22   | —                    | almajd-3aamah                 | 14.56 |
| #27   | 00:14 | 22/22   | —                    | —                             | 7.20  |
| #28   | 00:19 | 22/22   | —                    | uthaymeen                     | 3.59  |
| #29   | 00:24 | 22/22   | —                    | almajd-3aamah                 | 4.84  |
| #30   | 00:29 | 21/22   | anees (60s)          | —                             | 3.77  |
| #31   | 00:45 | 22/22   | —                    | —                             | 3.49  |
| #32   | 00:50 | 22/22   | —                    | —                             | 3.47  |
| #33   | 00:55 | 22/22   | —                    | —                             | 3.85  |
| #34   | 01:00 | 22/22   | —                    | —                             | 4.43  |
| #35   | 01:05 | 22/22   | —                    | —                             | 3.89  |
| #36   | 01:10 | 22/22   | —                    | —                             | 2.42  |
| #37   | 01:15 | 22/22   | —                    | —                             | 3.24  |
| #38   | 01:20 | 22/22   | —                    | —                             | 3.47  |
| #39   | 01:25 | 22/22   | —                    | —                             | 5.56  |
| #40   | 01:30 | 22/22   | —                    | —                             | 4.07  |
| #41   | 01:35 | 22/22   | —                    | —                             | 3.24  |
| #42   | 01:40 | 22/22   | —                    | —                             | 3.60  |
| #43   | 01:45 | 22/22   | —                    | —                             | 3.78  |
| #44   | 01:50 | 22/22   | —                    | —                             | 3.60  |

**Result: 40/44 sweeps at 22/22 (91%). 4 sweeps had 1 channel stale (<80s each). Zero channels fully lost.**

---

## Incident Timeline

| Time  | Channel              | Symptom                          | Root Cause                                  | Action                          | Result           |
|-------|----------------------|----------------------------------|---------------------------------------------|---------------------------------|------------------|
| 20:56 | almajd-documentary   | Dead (no process, 28min stale)   | Stale lock — DUPLICATE_DETECTED false positive | Cleaned lock, restarted         | Recovered 20:59  |
| 20:56 | almajd-islamic-sci   | Dead (no process, 28min stale)   | Same as above                               | Cleaned lock, restarted         | Recovered 20:59  |
| 20:56 | hadith-almajd        | Dead (no process, 27min stale)   | Same as above                               | Cleaned lock, restarted         | Recovered 20:59  |
| 20:53 | basmah               | Seenshow proxy validation 404    | Proxy only handled GET, not HEAD            | Added HEAD support to /proxy    | Fixed, deployed   |
| 21:15 | almajd-documentary   | vlc.news I/O errors every 80s    | vlc.news stream 1407 unstable               | Auto-failover to seenshow proxy | Stable since      |
| 21:16 | saad                 | 53s stale                        | ssadtv.ddns.net segment 404                 | Auto: slate→feeder restart      | Recovered 21:17  |
| 21:19 | basmah               | FILTER_CRASH + restart           | GPU filter + config revert to vlc.news      | Auto-restart on vlc.news        | OK (intended)    |
| 21:34 | saad                 | 40s stale                        | ssadtv.ddns.net segment 404 (2nd time)      | Auto: slate→feeder restart      | Recovered 21:35  |
| 22:00 | uthaymeen            | FILTER_CRASH                     | hwupload_cuda format change                 | Auto-restart                    | Recovered        |
| 22:50 | almajd-3aamah        | 80s stale + FILTER_CRASH         | hwupload_cuda format change                 | Auto-restart                    | Recovered        |
| 23:00+ | almajd-doc, 3aamah  | Recurring FILTER_CRASH (~25min)  | hwupload_cuda format change                 | Auto-restart each time          | Always recovers  |
| 00:09 | (system)             | Load spike to 14.56              | Multiple simultaneous FILTER_CRASH restarts | Self-resolved                   | Load → 3.5       |
| 00:29 | anees                | 60s stale                        | vlc.news feeder died                        | Auto: slate→feeder restart      | Recovered        |

---

## 5 Pain Points to Eliminate (ranked by impact)

### PAIN 1: GPU FILTER_CRASH — hwupload_cuda format change failure
**What happens:** When vlc.news (or any source) changes video resolution or pixel format mid-stream, FFmpeg's `hwupload_cuda` filter crashes with "Impossible to convert between formats". The encoder dies, slate covers for 30-80s, encoder restarts.
**How often:** ~45 total crashes in logs. During this session: almajd-documentary (10x), almajd-3aamah (5x), uthaymeen (6x), basmah (10x), makkah (7x), arrahmah (5x). The two worst channels (almajd-doc, almajd-3aamah) crash every ~25 min.
**Impact:** 30-80s stream gap per crash. Clients see slate or freeze.
**Current filter chain:** `scale=1920:1080:flags=fast_bilinear,format=nv12,hwupload_cuda` → `h264_nvenc`
**Root cause:** The GPU upload can't handle format transitions from the source. When vlc.news switches between different input formats (e.g., logo overlay changes, ad insertion), the hwupload_cuda filter fails.
**Fix options:**
  - A) Replace `hwupload_cuda` with CPU-only `scale` — eliminates crash but uses more CPU
  - B) Add `format=nv12` before `hwupload_cuda` to normalize input — may prevent some crashes
  - C) Use `scale_cuda` instead of CPU scale + hwupload — keeps GPU acceleration but needs format detection
  - D) Catch the FILTER_CRASH and restart only the filter graph, not the entire encoder

### PAIN 2: Stale Lock / DUPLICATE_DETECTED False Positive
**What happens:** When channels are killed externally (kill -9, health monitor restart, etc.), the lock dir `/tmp/stream_${channel}.lock` and PID file remain. When a new instance starts, it checks for an existing FFmpeg PID, finds the stale PID, and exits saying "Another instance is already streaming."
**How often:** 3 channels dead for 28 min at mission start.
**Impact:** Channel stays dead until manual cleanup.
**Root cause:** The duplicate detection checks if a PID exists in `/proc` but doesn't verify it's actually a relevant FFmpeg process for this channel.
**Fix:** Before declaring DUPLICATE_DETECTED, verify:
  1. The PID is actually alive: `kill -0 $pid 2>/dev/null`
  2. The PID is actually an FFmpeg process: check `/proc/$pid/cmdline`
  3. The PID is actually writing to this channel's output dir

### PAIN 3: saad Upstream Instability (no backup)
**What happens:** ssadtv.ddns.net periodically returns 404 for TS segments while the playlist remains accessible. The stream goes stale until the upstream recovers.
**How often:** 2063 historical stale events. 2 incidents during this 5h session.
**Impact:** Stream gaps until upstream recovers. No failover possible.
**Root cause:** External dependency — the saad DDNS server is unreliable.
**Fix options:**
  - A) Find an alternative source for saad content (another provider, YouTube stream?)
  - B) Increase streamlink retry tolerance so it doesn't exit on transient 404s
  - C) Accept as external dependency and improve slate quality for these gaps

### PAIN 4: Seenshow Proxy HEAD Validation (FIXED)
**What happens:** The `/proxy` endpoint in seenshow_resolver.js only handled GET requests. The URL validator in try_start_stream.sh uses `curl -I` (HEAD). HEAD requests fell through to the 404 catch-all, causing seenshow URLs to always fail validation and fall back to vlc.news.
**Status:** FIXED during this session. HEAD support added to proxy endpoint.
**File:** `channels/seenshow_resolver.js` lines 1666-1770

### PAIN 5: vlc.news Per-Stream Instability
**What happens:** Some vlc.news streams (notably stream 1407 / almajd-documentary) drop with I/O errors after ~80s of playback, while other streams on the same server are stable.
**How often:** Continuous for almajd-documentary on vlc.news during this session.
**Impact:** Repeated feeder restarts until max-restart failover to seenshow.
**Root cause:** Provider-side issue. The IPTV panel may have intermittent issues on specific stream IDs.
**Fix:** Ensure seenshow backup is configured for all affected channels. The auto-failover mechanism works but takes multiple restart cycles.

---

## Seenshow Coverage Gap

Channels WITHOUT seenshow backup (12/22):
- `ajaweed` — could add seenshow if available
- `almajd-news` — could add seenshow if available
- `arrahmah` — could add seenshow if available
- `hadith-almajd` — could add seenshow if available
- `uthaymeen` — could add seenshow if available
- `nada` — different provider (eagtop.vip)
- `anees` — has YouTube backup already
- `mecca-quran` — YouTube-based primary
- `sunnah` — YouTube-based primary
- `saad` — own DDNS, seenshow N/A
- `zaad` — restream.io, seenshow N/A
- `quran` — needs investigation

Channels WITH seenshow backup (10/22):
almajd-3aamah, almajd-documentary, almajd-kids, almajd-quran,
almajd-science, basmah, daal, maassah, natural, rawdah

---

## System State at End of Mission

| Metric     | Value                          |
|------------|--------------------------------|
| Channels   | 22/22 healthy                  |
| RAM        | 24Gi/62Gi (37Gi available)     |
| Swap       | 2.0/2.0 Gi (full, stable)     |
| GPU        | 11%, 62°C, 2993 MiB           |
| Load       | 3.60                           |
| VPN tun1   | UP, routes intact              |
| Seenshow   | 10/10 tokens valid (~21h left) |

---

## Code Change Diff

**File:** `channels/seenshow_resolver.js`

```diff
-    if (method === 'GET' && pathname.startsWith('/proxy/')) {
-      const remotePath = pathname.slice('/proxy'.length);
-      const fullParsed = new URL(req.url, 'http://localhost');
-      const remoteUrl = `https://live.seenshow.com${remotePath}${fullParsed.search || ''}`;
-      try {
-        const child = require('child_process').spawn('curl', [
-          '-sS',
-          '--interface', 'tun1',
-          '--max-time', '15',
-          '-D', '-',
-          remoteUrl,
-        ], { stdio: ['ignore', 'pipe', 'pipe'] });
+    if ((method === 'GET' || method === 'HEAD') && pathname.startsWith('/proxy/')) {
+      const isHead = method === 'HEAD';
+      const remotePath = pathname.slice('/proxy'.length);
+      const fullParsed = new URL(req.url, 'http://localhost');
+      const remoteUrl = `https://live.seenshow.com${remotePath}${fullParsed.search || ''}`;
+      try {
+        const curlArgs = ['-sS', '--interface', 'tun1', '--max-time', '15'];
+        if (isHead) { curlArgs.push('--head'); }
+        else { curlArgs.push('-D', '-'); }
+        curlArgs.push(remoteUrl);
+        const child = require('child_process').spawn('curl', curlArgs,
+          { stdio: ['ignore', 'pipe', 'pipe'] });
```

Additionally: HEAD-specific response handling (return status only, no body), and fallback close handler for HEAD when `\r\n\r\n` not found in headers.
