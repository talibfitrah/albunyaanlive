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
