# Channel Troubleshooting Playbook

Diagnostic flow for viewer-reported issues. Built from real incidents — each section names the symptom as the viewer describes it, then the steps that distinguish upstream (broadcaster) from pipeline (our infra) causes.

## Viewer reports "stuttering every 2–3 seconds"

The two realistic causes are upstream frame starvation and pipeline encoder crashes. Distinguish them in this order.

### 1. Is the pipeline producing segments on time?

```bash
ls -lt --time-style='+%H:%M:%S' /var/www/html/stream/hls/<channel>/*.ts | head -10
cat /var/www/html/stream/hls/<channel>/master.m3u8 | head -40
```

- Irregular `#EXTINF` durations (e.g. 10s, 2.7s, 1.6s, 10s) → feeder/encoder thrashing.
- Uniform `#EXTINF` (e.g. every segment exactly 6.000 or 7.200) → pipeline is healthy; problem is in segment *content*.

### 2. Count frames per segment

The output target is `hls_time × fps`. E.g. 6s @ 25fps should be 150 frames, 6s @ 30fps should be 180.

```bash
LATEST=$(ls -t /var/www/html/stream/hls/<channel>/*.ts | head -1)
ffprobe -v error -count_frames -select_streams v:0 \
  -show_entries stream=nb_read_frames,r_frame_rate \
  -show_entries format=duration -of default=nw=1 "$LATEST"
```

If frame count matches expected → segments are frame-complete, encoder is OK.

### 3. Probe the source directly for 12s

Same flags as the feeder to get a like-for-like read:

```bash
timeout 18 ffmpeg -hide_banner -loglevel error \
  -i "<primary_url>" -t 12 -c copy -f mpegts /tmp/src_test.ts
ffprobe -v error -count_frames -select_streams v:0 \
  -show_entries stream=nb_read_frames,r_frame_rate \
  -show_entries format=duration -of default=nw=1 /tmp/src_test.ts
```

- Expected for 12s @ 25fps = 300 frames, @ 30fps = 360 frames.
- If source delivers **significantly fewer** frames than expected (e.g. 144/300 on a 25fps channel) → **upstream frame starvation**. The broadcaster is sending a sub-rate stream and the encoder is padding with frozen frames to hit the declared fps. The viewer sees this as 2–3 second freezes.
- Repeat for each backup URL to find a clean one.

### 4. If upstream is the cause — swap primary

Edit `channel_<name>_revised.sh`: move a clean backup into `stream_url`, push the bad one to `stream_url_backup2`. Config hot-reload detects the mtime change within 60s, but it does not restart the currently-active feeder. To apply immediately, use `graceful_restart.sh <channel>`. **Warning: `graceful_restart.sh` has left orphaned ffmpeg processes on failures; if the new stream manager logs `DUPLICATE_DETECTED` and exits, kill the `PPID=1` ffmpeg writing to the channel's master.m3u8, then relaunch the channel script manually.**

### 5. Confirm the swap worked

Wait 30–60s for the new feeder to produce segments. Re-run the frame-count probe from step 2 on new segments. Compare rate against expected.

### 6. If pipeline is the cause

Look at `logs/<channel>.error.log` for these signatures:

- `Impossible to convert between the formats supported by the filter 'Parsed_hwupload_cuda_2'` → NVENC filter reinit failure when source pixel format shifts mid-stream. Workaround: prepend `format=yuv420p,` to the `-vf` chain in `try_start_stream.sh` to normalize input before scale+upload.
- `Error during demuxing: Input/output error` → feeder lost its TCP/RTMP connection. Benign if feeder swap recovers quickly; concerning if repeated within minutes.
- `FEEDER_MONITOR: Max restarts (10) on current URL. Switching.` spamming in cycles → all backup URLs failing (DNS dead, geo-blocked, auth expired). Test each with `curl -sI` and `ffprobe`.

## Viewer reports "no stream at all"

1. Check if anything is writing to `master.m3u8`:
   ```bash
   stat /var/www/html/stream/hls/<channel>/master.m3u8
   ```
   Stale mtime (> 60s old) means production has stopped.

2. Check the ffmpeg processes:
   ```bash
   ps -ef | grep <channel> | grep -v grep
   ```
   Look for orphaned PPID=1 processes from failed graceful restarts — these can hold the `master.m3u8` path and block the new stream manager from starting.

3. Probe each URL. If all three backups fail, the channel is dead at the network level — likely DNS (`eeijvvut.qastertv.xyz` was one real case), expired auth, or upstream shutdown.

4. If the source is deliberately private/blocked by the broadcaster (user has confirmed this for anees — colleague hid the upstream), the pipeline cannot fix it. Document and move on.

## Known-good expected rates

Record the canonical frame rate per channel here as incidents surface them, so future comparisons are fast:

| Channel | Source | Expected fps | Resolution |
|---------|--------|--------------|------------|
| zaad    | YouTube `@ZadTVchannel/live` | 30 | 1920x1080 |
| zaad    | ayyadonline backup | 50 | 720x576 (SD) |
| anees   | vlc.news primary | 25 | 1280x720 |

## Incident log

### 2026-04-13 — zaad primary source frame starvation
Viewer reported 2–3 second freezes. Direct probe of `rtmp://live.restream.io/pull/play_4504673_…` delivered 144 frames in 12s (expected 300 @ 25fps). YouTube backup delivered full-rate. Promoted YouTube to primary; restream.io demoted to backup2. Confirmed post-swap with 180 frames per 6s segment (30fps exact). Graceful restart left two orphaned ffmpeg processes (`PPID=1`) that had to be killed manually before the new stream manager could start.
