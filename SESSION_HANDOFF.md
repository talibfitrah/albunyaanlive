# Session Handoff Log

Append-only coordination log between the SRE/dev session and the dedicated Telegram session.

## Convention

- New entries go at the bottom, newest last.
- Format: `## YYYY-MM-DD HH:MM TZ — <topic>`
- Body: what changed; what (if anything) the Telegram session needs to do.
- Status tags (optional, at end): `[NEW]`, `[ACK]` (other session has read), `[DONE]` (other session has acted), `[OBSOLETE]`.

## Log

## 2026-04-15 — Reflex loop plan started

Implementation plan for the autonomous reflex loop is at `docs/superpowers/plans/2026-04-15-reflex-loop.md`. Will land in phases 1–8; each phase ends with a handoff entry summarizing what the Telegram session may see (new state-file fields, new alert shapes, etc.). [NEW]

## 2026-04-15 — Reflex watcher now runs in dry-run mode

`reflex_watcher.sh` loads the new `channels/reflex/*.sh` modules and runs
the state-machine each cycle. Output: `reflex(dry-run) SIGNAL:...` lines
in the watcher log. No signals are dispatched yet; the action layer is
gated by `REFLEX_DRY_RUN=0` (Phase 5). New state files appear at
`/var/run/albunyaan/state/<channel_id>.json`. [NEW]

## 2026-04-15 — Phases 0–5 + 8.1 landed; activation ready for operator

**11 commits on main** since plan landed:
`0507feb` SESSION_HANDOFF · `c3c5686` state.sh · `b1832cc` freshness+canary · `d02bc9a` backoff · `05b9194` probe · `99231f6` transitions · `25e7760` watcher dry-run wiring · `57017c8` try_start_stream PID+signals · `c496e16` try_start_stream fix (EXIT trap) · `aeb75e9` signals.sh+dispatch · `77323fc` signals.sh fix (PID validation) · `3149601` preflight+RuntimeDirectory

**Dry-run validated on production:** 6 stale-detection events + 1 swap-to-backup event, state machine correct, no false positives.

**Still pending (next session):**
- Phase 6: brain → watcher identity handoff (wake.sh + PROMPT.md)
- Phase 7: E2E fixture + scenarios
- Phase 8.2: reflex tests in run_tests.sh
- Review pipeline (code-reviewer, cso, review, simplify, verification)

### ACTIVATION CHECKLIST — operator must do these in order when ready

Viewer-visible cost: each channel restart is a brief (a few seconds) black frame / buffer underrun for viewers on THAT channel. Plan accordingly (off-peak hours recommended).

**Step A — apply the new unit file + preflight dir creation:**
```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl daemon-reload
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
systemctl status albunyaan-watcher --no-pager | head -20
# Expected: active, "preflight OK" in log, /var/run/albunyaan now owned by systemd's RuntimeDirectory
ls -la /var/run/albunyaan/
```

**Step B — restart channel supervisors ONE AT A TIME so they pick up new try_start_stream.sh (PID file + SIGUSR1/2 handlers):**
```bash
# Example for a single channel — adapt to each channel's unit name.
# List channel units first:
systemctl list-units 'albunyaan-channel-*' --no-pager
# Then restart one, wait ~30s, verify PID file appears, confirm stream healthy, move to next.
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-channel-<ch>.service
sleep 30
ls /var/run/albunyaan/pid/<ch>.pid && cat /var/run/albunyaan/pid/<ch>.pid
curl -sI http://stream.edratech.nl/<ch>/master.m3u8 | head -1   # expect 200
```

If channels are launched via something other than per-channel systemd units (tmux, raw `run_all_channels.sh`, etc.), find that launcher and restart channels through it — the only requirement is that `try_start_stream.sh` processes are freshly started after commit `57017c8`.

**Step C — after all channels have PID files, flip REFLEX_DRY_RUN=0:**
```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl edit albunyaan-watcher
# In the override editor, add:
# [Service]
# Environment="REFLEX_DRY_RUN=0"
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl daemon-reload
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
# Watch the first few minutes — look for "reflex SIGNAL:" lines (without "dry-run") and confirm dispatches don't log "dispatch FAILED":
tail -F /home/msa/Development/scripts/albunyaan/channels/logs/reflex_watcher.log | grep -E "reflex |reflex_enabled|dispatch FAILED"
```

**Rollback (if activation goes wrong):**
```bash
# Undo the systemd override:
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl revert albunyaan-watcher
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
# Back to dry-run mode; channels unaffected by watcher itself.
```

**What the dedicated Telegram session should know:**
- New per-channel state files at `/var/run/albunyaan/state/<ch>.json` include `state`, `current_source_url`, `identity_status`, `reverify_requested`, `transition_history`, `excluded_backups`. These will start mutating once activation happens.
- `DEGRADED` state on any channel = circuit breaker tripped (>5 transitions in 2 min); that's a "call a human" signal.
- No new alert shapes landed yet; existing `tg_alert` calls in the watcher are unchanged.

[NEW]

## 2026-04-15 — Phase 6 landed: brain → watcher identity handoff

Two commits: `665597e` wake.sh applies identity_updates; `948d086` PROMPT.md §6a + JSON schema.

**What the brain now emits:** top-level `identity_updates` array in each wake's JSON, e.g. `[{"channel_id":"anees","identity_status":"mismatch"}]`. Only `verified` / `mismatch` are honored; `slate`/`blackframe`/`unknown` are informational only.

**What the wake wrapper now does:** after brain returns, writes `identity_status` + `identity_checked_at` into `/var/run/albunyaan/state/<ch>.json` under flock. On `verified`, clears `reverify_requested`. Missing state files are skipped silently — safe during cold-start before any channels are under reflex management.

**Brain prioritization change:** visual sub-agents now rank mismatch + reverify_requested channels first and **skip non-LIVE channels** (avoids flagging slate/backup content as mismatch — would cascade the reflex loop).

**Deviation from plan:** fixed a plan bug in the Python invocation — the planned `echo $JSON | python3 - arg <<PYEOF` pattern is broken because bash heredoc clobbers the pipe's stdin (json.load sees empty stream). Switched to `python3 -c "$(cat <<PYEOF ... PYEOF)" arg`, which keeps stdin free for the JSON. Confirmed via repro before the fix.

**Telegram session:** no user-visible change yet. The `identity_updates` field is a new key in the brain's JSON — non-breaking for existing consumers. DEGRADED → "call a human" signal is still the only action cue.

[NEW]

## 2026-04-15 — Reflex loop landed end-to-end

All phases 1–8 merged. Per-channel state files at
`/var/run/albunyaan/state/<id>.json` now carry:
- `state` ∈ {LIVE, SLATE, BACKUP, DEGRADED}
- `identity_status` ∈ {unknown, verified, mismatch}
- `reverify_requested` (boolean — brain sets on mismatch, watcher
  clears when brain returns verified)
- `transition_history` (FIFO, capped at 50)
- `excluded_backups` (URLs the watcher probed and found dead during
  the current slate episode)

Phase 6 brain handoff: the wake wrapper now consumes an
`identity_updates` array from the brain's JSON and writes
`identity_status` + `identity_checked_at` into each state file under
flock. The brain's prompt (§6a) tells it to emit those entries and to
skip non-LIVE channels when doing visual checks.

Phase 7 E2E: `channels/tests/reflex/e2e/reflex_e2e.sh` runs five
scenarios (`happy_path`, `all_dead`, `backup_dies`, `identity_handoff`,
`flapping`) against an isolated `/tmp/reflex-e2e/` fixture. Uses a stub
supervisor to avoid spawning real ffmpeg pipelines on the production
box. All five pass on this host.

Phase 8: systemd preflight + RuntimeDirectory (commit `3149601`) already
active in production dry-run mode since earlier today. Reflex unit +
integration tests are now part of `run_tests.sh`.

**What the dedicated Telegram session may want to do next:**
- Surface `state != LIVE` in the daily 08:00 report.
- Surface `identity_status == mismatch` until brain clears it.
- Watch for `state == DEGRADED` — that's a "call a human" signal
  (>5 transitions in 120 s, circuit breaker tripped).

**Operator's activation deploy gate is unchanged** — see the earlier
"ACTIVATION CHECKLIST" entry in this log. Steps B (restart channel
supervisors) and C (flip REFLEX_DRY_RUN=0) are still pending.

Rate-limit resilience, playability probe, and the 08:00 report are
explicitly out of scope for this plan — they're spec §11 follow-ups.

[NEW]

## 2026-04-15 — /review pipeline landed 7 fixes, 2 memory-flagged bugs

Ran gstack /review (code-reviewer + security + testing specialists +
Claude adversarial subagent). Codex passes deferred due to the auth
timeouts the user flagged. 6 commits on main since reflex-complete:

| Commit    | Fix |
|-----------|-----|
| f164ab3   | wake.sh channel_id regex (path traversal); jq --arg everywhere in transitions.sh (6 injection sites closed); _push_transition latent injection; RuntimeDirectoryMode 0755→0750 (auth token leak); PID cmdline guard requires channel_id match |
| 57cd5e8   | **Hyphenated channel glob** — 9/22 channels were silently inert. Registry.json lookup now primary, with glob + hyphen→underscore fallback |
| 94fbc09   | probe_url 3-state return code; rc=2 for resolver schemes (elahmad:/aloula:/seenshow:/youtube:) and RFC1918/loopback; transitions.sh primary-probe sites handle rc=2 as "no info, advance timer" |
| bd45373   | **Circuit-breaker persistence** — /var/lib/albunyaan sticky sidecar via systemd StateDirectory; state_init rehydrates DEGRADED on first-create (24h TTL); survives tmpfs wipe + crash loops |
| ec16a20   | test_signals.sh (6 tests, decoy-PID harness); 3 new state.sh edge-case tests; state_init now uses `[[ -s ]]` + explicit type-check (uncovered an actual bug on zero-byte files) |

**Two bugs surfaced via memory updates (not by the review pipeline itself):**
- `feedback_reflex_channel_id_glob` — 9 channels silently excluded from state machine; fixed by 57cd5e8.
- `feedback_probe_url_http_only` — Makkah primary elahmad:makkahtv climbed `consecutive_failures=9` while the real pipeline was fine; fixed by 94fbc09.

**Deferred (documented in-code or as comments, not blocking):**
- Bash signal-trap queuing behind foreground ffmpeg (red-team, conf 7) — architectural; needs ack mechanism; grace windows mostly absorb the lag today.
- Signal overwrite race on rapid back-to-back swaps (red-team, conf 7) — latest-wins IS correct for state targeting; doc comment added in signals.sh.
- wake.sh identity_updates unit test; transitions.sh integration gaps (BACKUP→LIVE, excluded-skip, backoff); try_start_stream.sh reflex handler runtime test.

**Operator's deploy gate unchanged** — Steps B (restart supervisors) and C (flip REFLEX_DRY_RUN=0) still pending.

[NEW]

## 2026-04-15 23:30 CEST — Step A + privilege bridge + Step B all landed

All three gates before `REFLEX_DRY_RUN=0`:
- Step A (19:02): new unit file in /etc, /var/run/albunyaan 0750, /var/lib/albunyaan created by StateDirectory=, preflight OK.
- Privilege bridge (23:09): /usr/local/bin/albunyaan-signal installed root:root 0755; /etc/sudoers.d/albunyaan-reflex scoped to USR1/USR2 only; signals.sh falls back to sudo wrapper on EPERM. Repo copy at `channels/reflex/albunyaan-signal`. Commit `546b8a2`.
- Step B (23:30): `sudo bash restart.sh` executed. 22/22 PID files within 45 s; ~20/22 channels producing fresh segments. 24 ffmpegs running (2 transient during ramp-up). Watcher NRestarts=1.
- Arrahmah post-restart: state=LIVE, consecutive_failures=0 (was SLATE with 9 failures pre-fix). The 302-redirect probe fix holds.

**Caveat before Step C:** 12 channels show `state=SLATE` in /var/run/albunyaan/state because the restart's 30-40 s ffmpeg-restart window tripped freshness.is_output_fresh. These are dry-run-only entries — no real supervisor signal was delivered. They'll reconcile back to LIVE as the primary-probe loop succeeds (~5–10 min after probes come off backoff).

**Do NOT flip REFLEX_DRY_RUN=0 until states reconcile** — otherwise SIGNAL:swap fires at supervisors that are already on primary URL. No-op on the supervisor side but noisy on the watcher side.

Operational facts discovered tonight that the original deploy plan didn't capture are in `docs/reflex-deploy-notes.md` (privilege model, PGID trap in restart, Step C checklist, rollback).

[NEW]

## 2026-04-16 00:00 CEST — REFLEX LOOP LIVE (REFLEX_DRY_RUN=0)

All four gates complete:
- Step A (unit + dirs) ✅
- Privilege bridge ✅
- Step B (fleet restart + PID files) ✅
- **Step C (dispatch live) ✅** via drop-in `/etc/systemd/system/albunyaan-watcher.service.d/reflex-dispatch.conf`

Pre-flip fix needed: probe retry (commit `38ee592`). The 2 s single-shot HTTP probe hit ~5% transient failure against vlc.news and was causing a persistent ~3/22 channels to oscillate in spurious SLATE. Retry-once stabilized the flap; post-retry soak showed 22/22 LIVE and zero dispatches (fleet is actually healthy).

At `T+90s` post-flip:
- state_distribution: 22 LIVE
- signals dispatched: 0
- dispatch failures: 0
- watcher NRestarts: 0
- fleet fresh (<15s): 22/22

Next real stale event will trigger actual `kill -USR1`/`-USR2` delivery through the sudo bridge. No supervisor signal has fired yet in production.

**Rollback if anything goes wrong:**
```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl revert albunyaan-watcher
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
```
Channels continue running independently; only dispatch stops.

[NEW]
