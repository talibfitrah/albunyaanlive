# Reflex Loop Design

**Date:** 2026-04-15
**Scope:** Priority items 1–3 of the autonomous reliability work:
1. Fix watcher staleness detection (`.ts` file mtime, not playlist mtime).
2. Wire `swap_to_slate_feeder()` into the failure path (automatic slate-on-source-death).
3. Backup auto-swap on identity mismatch.

## 1. Summary

Today the system has periodic observation plus a watcher that reports false-healthy for stale channels. There is no autonomous reflex loop — when a source dies, a human must intervene. This spec closes that gap: detection → slate → backup probe → backup swap → recovery to primary, all running in `reflex_watcher.sh` at 5 s cadence with no new processes or systemd units.

## 2. Mission alignment

Mission: 24/7 Islamic TV channels with zero viewer-perceived downtime; never a black screen, never wrong content under a channel's name.

Rule 1 (no viewer downtime): satisfied — slate engages within ≤15 s of source death; backup swap follows in the next ≤5 s cycle.
Rule 2 (no wrong content): partially satisfied — detection window is bounded by brain wake cadence (3 h, rate-limit-conserved). Once detected, remediation is ≤15 s. Re-verify after swap is ≤3 h.

## 3. Scope

**In scope:**
- Staleness detection fix in `reflex_watcher.sh`.
- State-file-driven state machine per channel (LIVE / SLATE / BACKUP / DEGRADED).
- Automatic slate engagement, backup walk, and recovery-to-primary with exponential backoff.
- Brain → watcher handoff for identity mismatches via shared state file.
- Unit, integration, and E2E tests for the above.

**Out of scope (separate future plans):**
- Playability probe (PTS alignment, codec, audio level).
- Daily 08:00 report generator.
- Rate-limit resilience for brain + security audits (task #10 — immediate next plan).
- Cheaper between-wake identity signals (audio fingerprint, frame hash).
- Per-channel slate branding.
- FFmpeg-death detection beyond what staleness already catches.

## 4. Decisions locked during brainstorming

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| Q1 | Slate primitive | **Shared slate** for all channels | Fastest to ship; rule 1 literally ("slate on screen, not black"); per-channel slate maintenance cost not justified |
| Q2 | Slate-swap latency budget | **≤15 s** (poll every 5 s, fire after 10 s of no-new-`.ts`) | Matches HLS cadence (~6 s segments), gives upstream one segment of grace, keeps viewer-perceived downtime under viewer tolerance (~10 s) |
| Q3 | Where reflex logic lives | **Extend `reflex_watcher.sh`** | One bounded component (CPU ≤10 %, RAM ≤128 M); avoids signaling race modes; avoids per-channel-supervisor fragmentation |
| Q4 | Primary recovery policy | **Watcher-managed probe** every 5 min while in backup state, exponential backoff after 3 misses (5→15→30→60 min cap), swap-back after 2 consecutive healthy probes | Keeps logic in the watcher; prevents hammering dead primaries; faster restoration than brain-wake-aligned |

## 5. Architecture + State Machine

**Components (no new processes, no new systemd units):**

- `reflex_watcher.sh` — **extended.** Owns detection and all state transitions.
- `try_start_stream.sh` — unchanged core. Exposes two primitives as subcommands:
  - `swap_to_slate_feeder <channel_id>` — exists today; wrap as invokable subcommand.
  - `swap_to_source <channel_id> <url>` — new; extract from existing try-stream logic.
- `brain_loop/wake.sh` — unchanged cadence (3 h). On identity mismatch, writes signal to the channel state file instead of only logging.
- `/var/run/albunyaan/state/<channel_id>.json` — **new.** One state file per channel. Watcher owns most fields; brain owns identity fields.

**Per-channel state machine:**

```
LIVE ──(stale ≥10 s  OR  brain-written identity_status=mismatch)──▶ SLATE
SLATE ──(backup probe passes)──────────────────────────────────────▶ BACKUP
SLATE ──(all backups fail)──────────────────▶ SLATE  [probe loop with backoff]
BACKUP ──(current backup stale)────────────────────────────────────▶ SLATE
BACKUP ──(primary healthy × 2 probes)──────────────────────────────▶ LIVE
any   ──(>5 transitions in 2 min)──────────────────────────────────▶ DEGRADED
```

Every transition is logged to the state file and syslog via `logger`.

**Watcher cycle (every 5 s):**

1. Read config and state for each channel.
2. Dispatch on state:
   - LIVE → check `.ts` mtime staleness.
   - SLATE → probe primary (per backoff), then probe one backup (round-robin).
   - BACKUP → check current backup health; probe primary if backoff allows.
3. On transition: call swap primitive, update state file (atomically via temp-file + rename under flock), log.

**Viewer-experience guarantees:**

- Source dies at t=0 → staleness detected ≤10 s → slate on-air ≤15 s. *Rule 1.*
- Healthy backup found within ≤5 s next cycle → backup on-air ~t=20 s.
- No healthy backup → slate indefinite, never dead stream.
- Brain-detected identity mismatch → same flow within ≤15 s of brain writing the flag. *Rule 2 (within the 3 h detection window).*

## 6. Detection Algorithm (staleness fix)

**Root cause of current bug:** `reflex_watcher.sh` checks `.m3u8` playlist mtime. The slate feeder regenerates the playlist with stale segment references, so playlist mtime advances while `.ts` segments do not. Watcher reports healthy while viewer sees frozen content.

**Fix:**

```bash
is_output_fresh() {
  local hls_dir="$1"                  # /var/www/html/stream/hls/<channel_id>
  local threshold_sec="${2:-10}"
  [[ -d "$hls_dir" ]] || return 2     # 2 = no-dir (distinct from stale)
  local fresh_count
  fresh_count=$(find "$hls_dir" -maxdepth 1 -name '*.ts' \
                     -newermt "-${threshold_sec} seconds" 2>/dev/null | wc -l)
  (( fresh_count > 0 ))               # 0 = fresh, 1 = stale
}
```

Return codes: `0` fresh, `1` stale, `2` HLS dir missing (structural failure — stay in current state and alert).

**Why `find -newermt`:** filesystem-native, no wall-clock arithmetic, single-digit-ms runtime per channel even with hundreds of segments. Stable under clock skew.

**Grace period on state transitions:** on entry to LIVE or BACKUP, set `grace_until = now + 30 s` in state file. Staleness check is skipped while `now < grace_until`. Boot grace is 60 s to cover slow-start channels.

## 7. Action Path

**LIVE → SLATE transition:**

```
IF is_output_fresh(hls_dir, 10) == stale
   AND state == LIVE
   AND now > grace_until:
  swap_to_slate_feeder <channel_id>
  state := SLATE
  current_source_url := null; current_source_role := null
  primary_probe.next_attempt_after := now + 5 min
  log transition (reason: "staleness" or "identity_mismatch")
```

**SLATE-state action per cycle:**

```
IF state == SLATE:
  # 1. Try primary (respecting backoff)
  IF now >= primary_probe.next_attempt_after:
    IF probe_url(primary_url, 2s):
      consecutive_successes++
      IF consecutive_successes >= 2:
        swap_to_source <channel_id> <primary_url>
        state := LIVE; grace_until := now + 30s
        reset primary_probe; return
    ELSE:
      consecutive_failures++
      next_attempt_after := now + backoff(failures)
      consecutive_successes := 0

  # 2. Walk one backup per cycle (round-robin to cap per-cycle cost)
  backup := channel.backup_urls[backup_walk_cursor]
  backup_walk_cursor := (backup_walk_cursor + 1) % len(backup_urls)
  IF backup NOT IN excluded_backups AND probe_url(backup, 2s):
    swap_to_source <channel_id> <backup>
    state := BACKUP
    current_source_url := backup; current_source_role := "backup"
    grace_until := now + 30s
    log transition; return

  # 3. Nothing healthy — stay in SLATE
```

**BACKUP-state action per cycle:**

```
IF state == BACKUP:
  # 1. Current backup still delivering?
  IF is_output_fresh(hls_dir, 10) == stale AND now > grace_until:
    swap_to_slate_feeder <channel_id>
    excluded_backups += current_source_url
    state := SLATE
    current_source_url := null; current_source_role := null
    log transition; return

  # 2. Primary upgrade attempt (respecting backoff)
  IF now >= primary_probe.next_attempt_after:
    ... same probe + 2-of-2 logic as SLATE case ...
```

**Primary-probe backoff schedule:**

| Consecutive failures | Next probe delay |
|---|---|
| 0 | (reset) |
| 1 | 5 min |
| 2 | 5 min |
| 3 | 15 min |
| 4 | 30 min |
| 5+ | 60 min (cap) |

Reset to 0 on any successful probe.

**`probe_url(url, timeout)`:**

- HTTP(S) `.m3u8`: `curl -sI --max-time 2 <url>` and verify `200 OK` + `Content-Type` hints HLS.
- Non-HTTP (rtmp/rtsp): `ffprobe -timeout 2000000 -i <url> -select_streams v:0 -show_entries stream=codec_type -of csv` with 2 s timeout.
- YouTube-resolved URLs: hit the resolver cache directly to avoid re-resolution cost.

**Probes are serial, round-robin one backup per cycle.** Per-cycle cost bounded at ~2 s of probing worst case.

**State file schema** — `/var/run/albunyaan/state/<channel_id>.json`:

```json
{
  "channel_id": "sunnah",
  "state": "LIVE | SLATE | BACKUP | DEGRADED",
  "current_source_url": "<primary_url> | <backup_url> | null",
  "current_source_role": "primary | backup | null",
  "last_transition": "2026-04-15T10:58:00Z",
  "grace_until": "2026-04-15T10:58:30Z",

  "identity_status": "unknown | verified | mismatch",
  "identity_checked_at": "2026-04-15T10:30:00Z",
  "reverify_requested": false,

  "primary_probe": {
    "last_attempt": "2026-04-15T10:55:00Z",
    "consecutive_failures": 3,
    "consecutive_successes": 0,
    "next_attempt_after": "2026-04-15T11:10:00Z"
  },

  "backup_walk_cursor": 0,
  "excluded_backups": [],

  "transition_history": [
    { "at": "...", "from": "LIVE", "to": "SLATE", "reason": "..." }
  ]
  // transition_history is capped at 50 entries (FIFO eviction) to bound file size.
  // excluded_backups is cleared on any successful transition to LIVE
  //   (primary is healthy again, restart backup walk from clean slate).
}
```

**Ownership (single-writer-per-field):**

| Field | Writer | Cleared by |
|-------|--------|-----------|
| `state`, `current_source_url`, `current_source_role`, `grace_until`, `primary_probe.*`, `backup_walk_cursor`, `excluded_backups`, `transition_history`, `slate_retry_count` | watcher | watcher |
| `identity_status`, `identity_checked_at` | brain | brain |
| `reverify_requested` | watcher (sets `true` on identity-driven swap) | brain (on next successful check) |

Cross-writer serialization via `flock` on a sidecar lockfile.

## 8. Identity-Mismatch Remediation

**Current brain behavior (unchanged in this plan):** visual sub-agents on ≤4 channels per wake, compare against `identity_manifest.json`. On mismatch, previously logged to `wake_summary` only.

**Change:** on mismatch, brain also writes `identity_status: "mismatch"` + `identity_checked_at: <now>` to the channel's state file.

**Brain wake flow (modified):**

```
# Priority ordering
candidates = channels sorted by:
  (identity_status == "mismatch") DESC,
  (reverify_requested == true) DESC,
  (identity_checked_at ASC)

selected = candidates[:visual_sub_agent_cap]   # currently 4

FOR channel in selected:
  IF channel.state != LIVE:
    # Skip — checking SLATE/BACKUP would spuriously flag slate/backup content
    continue
  result = visual_sub_agent.check(channel)
  lock_and_update(channel.state_file):
    IF result.matches_expected:
      identity_status := "verified"
      reverify_requested := false
    ELSE:
      identity_status := "mismatch"
    identity_checked_at := now
```

**Watcher flow (addition to Section 7):**

```
IF state IN {LIVE, BACKUP} AND identity_status == "mismatch" AND now > grace_until:
  swap_to_slate_feeder <channel_id>
  IF state == BACKUP:
    excluded_backups += current_source_url    # bad backup — skip on next walk
  # (when state == LIVE, primary is not in the backup list; nothing to exclude.
  #  primary_probe's own backoff will govern when we try primary again.)
  reverify_requested := true
  state := SLATE
  current_source_url := null; current_source_role := null
  log transition reason := "identity_mismatch"
```

When watcher then swaps to a backup, `reverify_requested` stays `true` on the new state file until brain verifies the new source. When watcher successfully returns to LIVE (primary healthy × 2 probes), `excluded_backups` is cleared.

**Brain skips identity checks for channels not in LIVE state.** Rationale: checking a SLATE or BACKUP channel would flag slate/backup content as "mismatch" (of course — it's not the real channel content). Avoids spurious flag cascades during remediation.

**The 3 h re-verify latency (honest trade-off):**

- Remediation (slate + backup swap) fires ≤15 s after brain writes `mismatch`.
- Re-verification of the new source is ≤3 h (next brain wake).
- If backup also has wrong content, viewer sees wrong content up to 3 h before next flag + swap cycle.
- Baseline today: mismatch → no remediation, ever. Worst case here is 3 h; worst case today is forever. Strict improvement.
- When it becomes unacceptable: frequent mismatches + frequently-wrong backups, or a 3 h wrong-content window is mission-breaking. Mitigation = cheaper non-LLM identity signal in watcher. Future plan, not here.
- If brain is rate-limited on the re-verify wake, window stretches to ≤6 h. This is why task #10 (rate-limit resilience) is the immediate next plan.

## 9. Error Handling + Edge Cases

**Critical invariants:**

1. Viewer never sees a dead stream — SLATE is the fallback for every detection-triggered failure.
2. State file is never torn — atomic temp-file + rename, `flock` on concurrent writers.
3. Watcher never crashes on malformed state — unparseable JSON treated as missing, defaults rebuild.
4. Slate video existence is a startup precondition. Watcher refuses to start if `/var/www/html/stream/hls/slate/slate_loop.mp4` is missing.

**Failure-mode handling:**

| Failure | Detection | Response |
|---------|-----------|----------|
| `swap_to_slate_feeder` non-zero exit | exit code | log, syslog alert, retry on next cycle (state stays at previous value). After 3 consecutive failed retries: `DEGRADED`. Retry counter lives in state file as `slate_retry_count`; resets on any success. |
| `swap_to_source` non-zero exit | exit code | log, exclude that URL for this SLATE episode, continue backup walk. |
| HLS output dir missing | `[[ ! -d ]]` | log (rate-limited), stay in current state, alert. Channel supervisor is supposed to create it. |
| State file missing | file not exists | initialize `{ state: "LIVE", grace_until: now + 60s }`. |
| State file corrupt JSON | `jq` parse fail | rename to `.broken.<ts>`, reinitialize. |
| All backup probes fail | no URL passes | stay SLATE, keep probing (primary + backups) per backoff. |
| Slate video missing | startup check | exit non-zero; systemd retries; syslog alerts. Will not run blind. |
| Watcher crashes | systemd | `Restart=always`; on restart load state files, resume. In-flight transitions re-evaluated on next cycle. |
| FFmpeg dies | output freshness stale | standard LIVE → SLATE path. No special case. |
| Config added/removed mid-run | watcher re-reads config every 60 s (12 cycles) | picked up without restart; stale state files reaped. |
| Clock jumps backward | probe timestamps in the future | next probe fires once wall clock crosses `next_attempt_after`. Bounded impact. |

**Flapping circuit breaker:**

If a channel transitions >5 times in 2 min → `state := DEGRADED`. Watcher stops auto-swapping for that channel. Logs loudly. Manual `reflex_watcher.sh reset <channel_id>` clears it.

**Single watcher instance enforcement:** PID-file lock at `/var/run/albunyaan/reflex_watcher.pid`. Second instance exits with clear error.

**Startup:**

1. Pre-flight: slate video exists, state dir writable, systemd unit valid.
2. Load config; enumerate channels.
3. For each: load or initialize state file; `grace_until := now + 60 s` (boot grace).
4. Enter main loop.

**Shutdown:**

- SIGTERM → finish current cycle, flush state, exit.
- No mid-swap shutdown; let swap complete.
- ffmpegs left in whatever state they were in — orderly shutdown persists state as-is.

**Explicit non-goals / accepted trade-offs:**

- No attempt to fix FFmpeg crashes inside the reflex loop — relies on systemd + staleness detector.
- Identity false positives cost one slate blip + backup swap — acceptable; brain should be high-confidence before flagging. No 2-of-N consensus (would double latency to 6 h).
- Grace period abuse during rapid cycling is caught by the flapping circuit breaker, not by per-cycle freshness suppression.
- No automatic re-try of failed slate-swap beyond 3 retries — `DEGRADED` is a deliberate "stop and call a human" state.

## 10. Testing Strategy

Tests live under `channels/tests/reflex/`; executed via existing `channels/run_tests.sh`.

**Unit tests** (pure functions, no process side-effects):

| Target | Cases |
|--------|-------|
| `is_output_fresh()` | fresh / stale / no-dir / empty-dir / malformed filenames / simultaneous-second mtime collision |
| `probe_url()` | 200 / 4xx / 5xx / timeout / DNS fail / HTTPS cert invalid / redirect chain |
| `backoff_delay(n)` | 0→5, 1→5, 2→5, 3→15, 4→30, 5→60, 99→60 (cap) |
| state file R/M/W | atomic rename / flock serialization / corrupt-file recovery / missing-file init |

**State-machine integration tests** (feed state file + stub primitives, assert next state):

| Start | Input | Expected |
|-------|-------|----------|
| LIVE | stale ≥10 s, grace expired | → SLATE |
| LIVE | stale, grace active | stay LIVE |
| LIVE | `identity_status=mismatch` | → SLATE, primary excluded |
| SLATE | backup1 probe passes | → BACKUP on backup1 |
| SLATE | all backups fail | stay SLATE, backoff advances |
| SLATE | primary probe passes once | stay SLATE, successes=1 |
| SLATE | primary probe passes twice | → LIVE |
| BACKUP | current backup stale | → SLATE, current excluded |
| BACKUP | primary probe passes twice | → LIVE |
| any | corrupt state file | reinit + log, no crash |
| any | 6 transitions in 2 min | → DEGRADED |

Swap primitives mocked; tests assert the right args were passed.

**E2E on a dedicated test channel** (`test_channel` with a controlled nginx upstream):

1. Happy path: upstream up → kill → slate ≤15 s → start backup1 → BACKUP ≤5 s of backup1 up → restore primary → return to LIVE after 2 × 5 min probes.
2. All dead: kill upstream + all backups → SLATE holds indefinitely, no thrashing.
3. Backup dies mid-serve: BACKUP, kill current backup → SLATE → walk to next backup.
4. Identity handoff: manually write `identity_status=mismatch` → watcher swaps ≤15 s.
5. Flapping: rapid upstream up/down cycle → DEGRADED triggers at 6th transition.

E2E tests never touch production channels.

**Pre-flight checks** (via `reflex_watcher.sh --preflight`, called from systemd `ExecStartPre=`):

- Slate video exists and is readable.
- State-file directory writable.
- All configured channels parse.
- systemd unit files pass `systemd-analyze verify`.

**Regression canary** — `tests/unit/test_freshness_no_false_healthy.sh`:

1. Synthetic HLS dir: all `.ts` mtime = now − 600 s.
2. Drop `master.m3u8` with mtime = now (simulating slate feeder).
3. `is_output_fresh(dir, 10)` must return **stale**.

This is the single test that guards against the exact bug being fixed. If it ever passes as "fresh," the regression is back.

**Not tested here:**

- FFmpeg quality / codec issues (future playability-probe plan).
- Rate-limit behavior of brain (task #10 plan).
- Actual Claude / LLM identity checks (expensive + flaky; tested via mocks).
- Multi-watcher concurrency (prevented structurally; tested as "second watcher exits cleanly").

**Test execution cadence:**

- Unit + integration: on every change via `run_tests.sh`. Target runtime <30 s.
- E2E: manually before landing the PR, and on demand. Runtime ~5 min (includes deliberate timeout waits).
- Pre-flight: every watcher startup.

## 11. Follow-up work (out of this plan)

After this reflex loop ships, the immediate next plans in order:

1. **Task #10 — rate-limit resilience.** Exponential backoff on 429/5xx in `wake.sh` + `run_audit.sh`; rate-limit header logging; tiered priority + circuit breaker; cross-session token budget in `/var/run/albunyaan/`; shell-only fallback health pass when LLM is unavailable; evaluate Batch API for cso/health.
2. **08:00 daily report content generator** (rule 5). This session generates content; other session (dedicated Telegram) delivers.
3. **Disk growth alerts + stale HLS cleanup** (rules 3 + 4 completion). Alert if HLS or log dirs grow >2 GB/day; periodic cleanup of orphan segment directories.
4. **`/review` per-commit + `/devex` quarterly** (rule 6 completion).
5. **Polish:** orphan reaper → systemd timer; sub-agent wiring into watcher cycle; cadence auto-tuning from `wake_summary` recommendation.

Longer-horizon (separate spec rounds):

- Cheaper between-wake identity signals (audio fingerprint, frame hash) — closes the 3 h re-verify window.
- Playability probe (PTS alignment / codec / audio level) — closes gaps the `.ts` mtime check doesn't catch (healthy pipeline serving broken content).

## 12. Coordination with the dedicated Telegram session

This session never sends Telegram messages (see `feedback_no_telegram_outbound.md`). All operator-facing changes land via:

- **Durable state:** project memory (`MEMORY.md` + `memory/*.md`).
- **Time-sensitive handoffs:** `SESSION_HANDOFF.md` at project root (append-only log).

When this plan ships, the Telegram session will see the new `reverify_requested` field and the `DEGRADED` state in channel state files. If those should surface in the daily 08:00 report or operator alerts, that's the Telegram session's responsibility and lives in the follow-up 08:00 report plan.
