# Albunyaan v4 24/7 Operator — Build State

Source of truth for ongoing work to implement the v4 operator system prompt.
**Pick this up in a new session by reading this file first (entirely).**

---

## RESUME CHECKLIST (run these first, in order)

```bash
# 1. What shipped since last context you had
git log --oneline -20

# 2. Are the long-running services alive?
systemctl status albunyaan-watcher albunyaan-brain.timer \
  albunyaan-security-cso.timer albunyaan-security-health.timer --no-pager

# 3. What does the brain believe about the world?
cat channels/brain/state.json | python3 -m json.tool

# 4. What wakes have completed?
cat channels/brain/wake.log

# 5. Is the watcher reporting fresh state?
python3 -c 'import json,time; d=json.load(open("/tmp/albunyaan-watcher-state.json")); print("state age:", int(time.time())-d["unix"], "s; unhealthy:", [c for c in d["channels"] if c["status"]!="healthy"])'

# 6. Any recent stalls, alerts, or anomalies?
tail -60 channels/logs/reflex_watcher.log
```

After this, read the "CURRENT STATE" section below, then decide from
"OPEN WORK" what to do next.

---

## CURRENT STATE (as of 2026-04-14 02:07 CEST)

### Running and armed

- **`albunyaan-watcher.service`** — Phase 1a reflex watcher, 3s loop,
  emits `/tmp/albunyaan-watcher-state.json`. Now also posts
  **direct Telegram alerts** on status transitions (plain Arabic),
  with debounce (2 obs), per-kind cooldown (10min), and 15s startup
  grace so cold-starts don't announce pre-existing stalls.
- **`albunyaan-brain.timer`** — Phase 3 brain loop, 30min cadence.
  Wake 1 completed successfully 2026-04-14 01:45:55 (8min 20s).
  Hardened after wake 1 findings (MemoryMax=4G, CPUQuota=80%,
  ProtectSystem=strict, ReadWritePaths whitelist, ProtectKernel*).
  Next wake: ~02:07:47 CEST (will validate hardening + refined
  sub-agent contract).
- **`albunyaan-security-cso.timer`** — weekly /cso audit. First
  fire: Sunday 2026-04-19 03:08 CEST.
- **`albunyaan-security-health.timer`** — monthly /health audit.
  First fire: 2026-05-01 03:11 CEST.

### Open incident tracked by brain

- `anees-slate-20260414T0138` — upstream maintenance slate confirmed
  via visual identity (confidence 1.0). Segments flow (watcher
  can't see it), only visual probe catches it. Known condition per
  `channels/identity_manifest.json`. Brain will escalate if
  persists past 3 consecutive wakes (~1.5h).

### All commits landed this session (newest last)

```
8879671 Promote ayyadonline as zaad primary source
3792039 Reap orphan ffmpeg in graceful_restart cleanup paths
956ebe0 Add Phase 5 security cadence prototype (/cso weekly) + Phase 3/5 design
325d90c Strip --max-budget-usd from headless audit wrapper
2e36c94 Add Phase 3 brain loop prototype (30min comprehensive wake)
d2018c0 Brain wrapper: fix three blocking issues found in self-review
c0acc5a Brain wrapper: fix three remaining self-review issues
4dc7ae8 Reflex watcher: direct Telegram alerts on status transitions
1bfe924 Add /health monthly security cadence timer
5ec012d Act on brain wake 1 findings: systemd hardening + sub-agent contract
```

### Memory rules added/updated this session

- `feedback_telegram_tone.md` — **Arabic is now the DEFAULT for all
  Telegram output** (not just mirror-user-language). English is
  fallback only.
- `project_channel_swap_workflow.md` — Telegram colleague requesting
  a channel replacement = retire old + create new (new folder under
  `/var/www/html/stream/hls/`). Reply with
  `https://stream.edratech.nl/<folder_name>/master.m3u8` once
  healthy. Folder name drives the URL exactly.
- `feedback_telegram_url_disambiguation.md` — ALWAYS ask in Arabic
  whether an incoming URL belongs to the channel being discussed
  or a different one, and confirm its intended role (primary /
  backup / replacement). Prevents wrong-content-under-channel-name
  bugs.

---

## OPEN WORK (priority order)

### Blocked until later today (~20:11 CEST)

- **Phase 1b — slate override action layer.** Watcher currently
  observe-only; on stall detection it should force slate within one
  segment cycle. Blocked on Phase 1a baseline data (~24h from the
  watcher's 2026-04-13 20:11 start). Needs: sentinel-file protocol
  (so watcher doesn't race `try_start_stream.sh` on master.m3u8
  writes), slate transcode pipeline or reuse of FEEDER_SLATE,
  recovery swap-back policy. Design notes in
  `V4_PHASE3_PHASE5_DESIGN.md` are for Phase 3/5 only — Phase 1b
  design still pending.
- Estimate: 4-8 focused hours AFTER baseline matures.

### Ready now (independent work)

- **Two-way Telegram bridge.** Brain currently only pushes; user
  can't interrupt/query mid-incident. Two options: piggyback the
  existing `plugin:telegram:telegram` plugin (already runs, already
  authenticated) vs build a tiny webhook listener. Piggyback is
  probably right — less moving parts. ~2-4 hours.
- **Phase 4b — threshold enforcement actions.** Currently brain
  proposes `graceful_restart` and `extra_disk_cleanup`; wrapper
  logs but doesn't execute. Move to auto-execute ONLY after safety
  guards designed (don't restart a channel whose only sin is being
  on a slow upstream). ~2-4 hours.

### Small loose ends (under 30 min each)

- `channels/TROUBLESHOOTING.md` entry the brain itself proposed:
  "channel healthy by segment age but showing upstream slate —
  visual probe required." See
  `channels/brain/raw/wake_20260414T013735.log` `troubleshooting_updates`.
- Investigate whether Seenshow slot-limit rejections when multiple
  channels fail over simultaneously (observed 2026-04-14 ~01:29)
  warrant pre-allocating runner slots or increasing the resolver's
  cap. Not urgent — slate fallback handled it.
- Watch: wake 2 should show reduced false-positive mismatches after
  the sub-agent contract refinement. If not, iterate on PROMPT.md
  step 6.

---

## Key architectural decisions recorded

- **Headless claude via systemd timers, NOT cloud `/schedule`.** The
  cloud remote-trigger model can't reach `/tmp/albunyaan-watcher-state.json`
  or the local Telegram bridge. All operator loops run locally.
- **Subscription auth works headless** (`claude -p` under User=msa,
  verified end-to-end via systemd-run with stripped env). No DBus/
  keyring needed; OAuth credentials live under $HOME.
- **Fast alerts stay in the watcher (no LLM).** Brain does the smart
  work (visual identity, code review, incident bookkeeping); the
  watcher handles dumb transition alerts directly via curl. 10x
  less subscription quota for the same operator behavior.
- **Wrapper owns all writes. Brain is observe/recommend only for now.**
  Only `restart_watcher` is auto-executed. `graceful_restart` and
  `extra_disk_cleanup` are proposed, logged, NOT applied.
- **Prompt injection defended with per-wake random delimiters + scoped
  Bash allowlist.** A compromised brain still cannot mutate the
  system.

---

---

## Reference: v4 operator prompt

The full v4 operator prompt (English + Arabic) was sent by the user via
Telegram on 2026-04-13. It defines a two-layer architecture:

1. **Reflex watcher** — lightweight always-on systemd service, sub-second
   slate failover, cheap probes every few seconds.
2. **Brain in a loop** — Claude in a `/loop` (or `ScheduleWakeup`-driven
   cadence ~2–5 min normal, faster on incidents), reads watcher state,
   does deep checks, dispatches sub-agents, pushes Telegram updates.

Goals: zero viewer-perceived downtime; no wrong content under a channel's
name; daily 08:00 Europe/Amsterdam Telegram report.

---

## Phase status

### Phase 1a — Reflex watcher (DONE, committed in 629e219)

Files (all under `channels/`):
- `reflex_watcher.sh` — observe-only daemon. 3s loop, per-channel HLS
  segment freshness + system resources (RAM, CPU 5-min load, GPU memory,
  disk root, disk HLS). Emits versioned JSON state to
  `/tmp/albunyaan-watcher-state.json`. Schema field = 1.
- `albunyaan-watcher.service` — systemd unit. User=msa, CPUQuota=10%,
  MemoryMax=128M, Restart=always.
- `rotate_logs.sh` — extended to rotate `channels/logs/*.log` with 7-day
  retention.

State file shape:
```
{ "schema":1, "ts":"...", "unix":..., "thresholds":{...},
  "system":{ "mem_pct","mem_status","cpu_pct","cpu_status",
             "gpu_mem_pct","gpu_status","disk_root_pct",
             "disk_root_status","disk_hls_pct","disk_hls_status" },
  "channels":[ { "id","segment_age_s","status" }, ... ] }
```

Status classifications: `healthy`, `warn`, `stalled`, `critical`,
`no_segments`, `unknown`.

Thresholds (from v4):
- Stall: warn at 2× segment duration (12s), crit at 4× (24s)
- Mem: warn 75, crit 90
- CPU: warn 70 (5-min avg), crit 90
- GPU mem: warn 75, crit 90
- Disk: warn 80, crit 90

Verify it's running: `systemctl status albunyaan-watcher` and
`cat /tmp/albunyaan-watcher-state.json`.

**Decision: Phase 1a is observe-only.** No playlist writes, no feeder
control. Action layer (Phase 1b) waits for baseline data to validate
detection reliability. Started 2026-04-13 ~20:00 local — let it gather
~24h before designing Phase 1b thresholds and action policy.

### Phase 2 — Content-identity sampler (DONE, committed in 629e219)

Files:
- `channels/sample_thumbnails.sh` — extracts one frame per channel from
  newest HLS `.ts` to `/tmp/albunyaan-thumbs/thumb_<id>.png` (640px wide).
  Run on demand; brain loop will invoke each wake.
- `channels/identity_manifest.json` — 22 channels seeded from
  channel_registry + `saad`. Each entry has `provider_name`,
  `match_names`, `source_hints`, `expected_content_genre`,
  `expected_logo_description`, `baseline_thumb_path`, `notes`.
- `channels/baselines/thumb_<id>.png` — 22 baseline thumbnails captured
  at build time. ~5.6 MB total.

**Open finding from baseline capture**: `anees` was serving an upstream
maintenance slate ("البث سيعود بعد قليل إن شاء الله / Stream will return
shortly") at capture time. Watcher rated it healthy because segments
flow. This is the v4-warned silent-swap blind spot. Manifest `anees.notes`
documents how to recognize the slate.

`hadith-almajd` baseline was captured from a washed-out frame. Re-sample
when channel is showing typical content.

### Phase 1b — Slate override action layer (TODO)

Goal: when watcher detects stall, force the affected channel's HLS
playlist to serve slate within one segment cycle.

Design questions to resolve before coding:
1. **Coordination with existing slate logic.** `try_start_stream.sh`
   already has SLATE/FEEDER_SLATE/SWAP_SLATE functions
   (lines 3607, 3674, 3699, 4664). Watcher acting independently risks
   race on `master.m3u8` writes. Options:
   - **Option A (recommended)**: watcher writes a sentinel file
     (`/tmp/albunyaan-watcher-slate-request/<channel>`) and lets
     try_start_stream's existing SWAP_SLATE pick it up. Cleanest separation.
   - **Option B**: watcher rewrites playlist directly. Faster but conflicts
     with try_start_stream still trying to publish segments.
2. **Slate delivery format.** Slate is `slate_loop.mp4` at
   `/var/www/html/stream/hls/slate/`. To serve via HLS we need a slate
   transcode producing `.ts` segments matching the channel's profile, OR
   reuse try_start_stream's existing FEEDER_SLATE pipeline.
3. **Recovery**: when stall clears, who decides to swap back to live?
   Watcher (cheap), or brain (smarter)?
4. **Action threshold**: `stalled` (24s+) is too lenient if seconds
   matter to viewers. Consider acting at 12s (`warn`) on second
   consecutive observation.

After ~24h of Phase 1a baseline data, review state file history (or
tail the watcher log) to understand normal segment-age variance per
channel. Tune thresholds before writing action code.

### Phase 3 — Brain loop (DESIGNED 2026-04-13, see V4_PHASE3_PHASE5_DESIGN.md)

Goal: continuous Claude operation via `/loop` (or ScheduleWakeup
cadence) that reads watcher state, runs sampler, dispatches per-channel
visual sub-agents, and pushes Telegram updates.

Each wake (per v4):
1. Segment production check (already in watcher state)
2. Frame integrity (`ffprobe -count_frames` per channel)
3. Content identity (sample thumbs + sub-agent verify against manifest)
4. Slate correctness (if slate active: confirm rotating, swap-back ASAP)
5. Resource trends (compare against thresholds, flag rising)
6. Incident follow-through (read state file; finish what's open)
7. Report and sleep

Sub-agent dispatch shape: one Claude sub-agent per channel with
`{thumbnail_path, expected_genre, expected_logo}` returning `{verdict,
confidence, reasoning}`. Embarrassingly parallel.

Cadence:
- First 2 weeks: every 2 min, all checks
- After stable: visual identity hourly, full sweep every 10 min

Watcher self-heartbeat check: brain must check `state.unix` age. If >30s,
watcher is stuck. Restart watcher and alert.

State file consumption format is stable (schema=1).

### Phase 4 — Daily report + threshold enforcement (TODO)

Two parts:

**4a — 08:00 Europe/Amsterdam daily report via Telegram.** One-page
summary in plain Arabic (per Telegram tone memory): incidents, root
causes, fixes, anything still degraded, resource trends, content-identity
anomalies. No padding.

Implementation options:
- gstack `/schedule` skill creating a remote-trigger cron
- systemd timer that triggers a Claude headless invocation
- Cron + script that gathers stats and posts via Telegram bot API

**4b — Enforce thresholds.** Today the watcher only logs when status
breaches warn/crit. Phase 4b acts: trim disk, kill runaway feeders,
restart services, etc. Each action needs a safety guard (don't kill the
zaad process if its only sin is being on a slow segment).

### Phase 5 — Scheduled security cadence (DESIGNED 2026-04-13, see V4_PHASE3_PHASE5_DESIGN.md — 3 open decisions)

Schedule the gstack security suite:
- `/cso` — full infra security audit weekly
- `/review` — before every code change lands
- `/health` — composite code-quality dashboard monthly
- `/devex-review` — quarterly DX/docs audit

Mechanism: cron triggers + remote-trigger agents. Findings logged in
`TODOS.md` (currently empty).

---

## Open issues found during build (worth fixing in dedicated commits)

### Telegram tone

End-user on Telegram is non-technical (~17yo home-user level). All
Telegram replies — including daily reports, alerts, status pings —
must be plain Arabic/English, no jargon. See
`~/.claude/projects/-home-msa-Development-scripts-albunyaan/memory/feedback_telegram_tone.md`.

### graceful_restart.sh fragility (FIXED 2026-04-13, commit 3792039)

Was: when the temp stream's primary URL failed validation (e.g.
ayyadonline returning 502), `graceful_restart.sh` killed the spawned
try_start_stream with SIGTERM but the ffmpeg child reparented to PID 1
and survived. Every subsequent retry hit `DUPLICATE_DETECTED`
(`try_start_stream.sh:4350`) and exited.

Fix: added `reap_temp_ffmpeg` helper that pgrep/pkill-matches the
cmdline path (resolvable even after the temp dir is unlinked), TERM
with a bounded wait, then SIGKILL. Wired into both the EXIT trap
(safety net for every exit path) and the failure-path explicit cleanup.
Also tightened the failure-path `NEW_STREAM_PID` kill to a proper
wait+escalate instead of a single 2-second sleep.

The live orphan from 2026-04-13 20:26 (`PID 486331`) was reaped
manually before commit; verified the new pattern matches it.

### Zaad config history

User asked to swap zaad primary to ayyadonline 2026-04-13 ~18:18
Telegram time. Ayyadonline was returning 502 at the time. A background
poller ran (`/tmp/zaad_ayyad_swap.log`, `/tmp/zaad_ayyad_swap.done`)
that retried every 2 min and succeeded at 20:27:11 once ayyadonline
recovered. User notified via auto Telegram message. The poller exited.

Earlier in the day there was a comment-vs-code mismatch in
`channel_zaad_revised.sh`: comment said ayyadonline was promoted but
`stream_url=` was still restream.io. This commit (uncommitted in this
session) corrects it.

### TODOS.md

Actively populated (refactor follow-ups from the seenshow_resolver
session, plus pre-existing security/timeout flags). Phase 5 will add
a `## Security` section to it. The earlier "currently empty" note was
incorrect.

### makkah vs mekkah-quran

Both are valid separate channels (MAKKAH TV vs SAUDI QURAN). Both in
registry, both have HLS dirs and baseline thumbs. No action needed.

---

## Files referenced in this build

Repo (committed in 629e219):
- `channels/reflex_watcher.sh`
- `channels/albunyaan-watcher.service`
- `channels/sample_thumbnails.sh`
- `channels/identity_manifest.json`
- `channels/baselines/*.png`
- `channels/rotate_logs.sh` (modified)

Memory (`~/.claude/projects/-home-msa-Development-scripts-albunyaan/memory/`):
- `feedback_telegram_tone.md`
- `feedback_telegram_env_format.md` (older session)
- `project_stutter_diagnostic_workflow.md` (older session)

Live runtime:
- systemd: `albunyaan-watcher.service` (active since 2026-04-13 ~20:00)
- state file: `/tmp/albunyaan-watcher-state.json`
- thumbnails: `/tmp/albunyaan-thumbs/`
- baselines: `channels/baselines/`

---

## How to resume in a new session

1. Read this file.
2. `git log --oneline -5` to see if anything new landed since `629e219`.
3. `systemctl status albunyaan-watcher` to confirm Phase 1a is still
   running. `cat /tmp/albunyaan-watcher-state.json | python3 -m json.tool | head -40`.
4. Decide which phase to tackle next based on Phase 1a baseline data
   maturity: if 24h+ has passed since 2026-04-13 20:00, Phase 1b is
   ready to design; otherwise start Phase 3 or Phase 5 (independent).
5. Telegram tone rule: any reply via the Telegram MCP must be plain
   language for a non-technical user. Daily reports also go via Telegram
   in simplified form.

---

## Session log

### 2026-04-13 evening (commit 629e219)

- Built and committed Phase 1a + 2.
- Code review pass before commit caught: log rotation gap, missing
  nullglob, no schema version, control-char json escape, 1-min vs 5-min
  cpu avg, no nvidia-smi timeout. All fixed.
- User-driven Zaad source swap incident:
  - User asked via Telegram to swap zaad primary to ayyadonline.
  - Ayyadonline returning 502 at the time.
  - First graceful_restart attempt as `msa` failed (permission denied
    on root-owned HLS dir).
  - Retried as root via SUDO_ASKPASS — temp ffmpeg orphaned because
    SIGTERM was insufficient. `DUPLICATE_DETECTED` blocked all
    subsequent attempts. Cleared with SIGKILL.
  - Set up background poller (`/tmp/zaad_ayyad_swap.{log,done}`) that
    probed every 2 min, succeeded at 20:27:11 once ayyadonline
    recovered, ran graceful_restart, posted Telegram confirmation
    directly via bot API. Poller exited cleanly.
  - Zaad now serves from ayyadonline. Config edit
    (`channel_zaad_revised.sh` setting ayyadonline as primary) is
    UNCOMMITTED — review and commit if appropriate.
- Two memory rules saved this session:
  - `feedback_telegram_tone.md` — non-technical tone; daily reports too.
  - `feedback_context_checkpointing.md` — proactive checkpoint + /clear.
- Phase 1a watcher still running. Phase 1a baseline data target:
  ~24h from start (~2026-04-14 20:00 local).

### Open work for next session

In priority order:
1. ~~Commit the uncommitted `channel_zaad_revised.sh` edit~~ — DONE
   (commit 8879671, 2026-04-13 22:08).
2. ~~Harden `graceful_restart.sh` cleanup path~~ — DONE
   (commit 3792039, 2026-04-13 22:11). Live orphan also reaped.
3. Wait for Phase 1a baseline (~24h), then design Phase 1b with the
   real per-channel segment-age variance numbers in hand. Watcher
   started 2026-04-13 20:11; baseline target ~2026-04-14 20:00.
4. Phase 5 (security cadence) is independent of Phase 1a baseline —
   can start anytime.
5. Phase 3 (brain loop) once Phase 1b is on its way.

### 2026-04-13 late evening (commits 8879671, 3792039)

- Verified watcher still healthy (~1h52m uptime at session start).
- Committed zaad ayyadonline-primary config (8879671). Live process
  confirmed running on ayyadonline before commit.
- Found the predicted graceful_restart orphan still alive in
  production (`PID 486331`, parent=1, 1h38m old, 208MB RSS, writing
  to deleted `/var/www/html/stream/hls/zaad/.graceful_zaad/`).
- Hardened `graceful_restart.sh` (3792039): added `reap_temp_ffmpeg`
  helper, wired into EXIT trap and failure-path cleanup, tightened
  failure-path NEW_STREAM_PID kill escalation. Pattern smoke-tested
  against the live orphan before fix.
- Reaped PID 486331 manually (sudo SIGKILL).

### PreCompact checkpoint 2026-04-13T22:00:39+02:00

- branch: main
- last 3 commits:
  - 629e219 Add reflex watcher and content-identity sampler
  - b97ff43 Promote zaad YouTube source to primary; add stutter-diagnosis playbook
  - 44505b1 Fix NVENC filter crashes by replacing scale_npp with resilient CPU-scale pipeline
- git status --short:
   M CLAUDE.md
   M channels/channel_almajd_hadith.sh
   M channels/channel_almajd_news.sh
   M channels/channel_basmah_revised.sh
   M channels/channel_registry.json
   M channels/channel_saad_revised.sh
   M channels/channel_uthaymeen_revised.sh
   M channels/channel_zaad_revised.sh
   M channels/seenshow_resolver.js
   M channels/tests/run_tests.sh
   M channels/try_start_stream.sh
  ?? TODOS.md
  ?? V4_OPERATOR_BUILD.md
  ?? channels/SRE_REPORT_2026-02-26.md
  ?? channels/reap_orphan_streamlinks.sh
  ?? channels/seenshow-vpn-routes.service
  ?? channels/seenshow-vpn-routes.sh
  ?? channels/whisper_transcribe.py
- (harness compacted here — context was summarized at this point)
