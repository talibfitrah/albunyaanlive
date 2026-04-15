# Resume Pointer — Albunyaan Reflex Loop

**One-document handoff for picking up this project in a fresh session.** Read this first; then `SESSION_HANDOFF.md` for chronological history if you need more context.

**Last updated:** 2026-04-16 01:15 CEST.

---

## TL;DR

Autonomous reflex watcher is LIVE in production. `REFLEX_DRY_RUN=0`. All 22 HLS channels are under state-machine management. End-to-end dispatch chain is verified. Origin/main is synced.

One restart isn't going to break anything. One bug fix isn't urgent. The immediate operational concern: the spurious-SLATE rate from probe timing sensitivity (mitigated by 1-retry but not eliminated). Remaining work is backlog, not fires.

---

## How to verify health right now

```bash
# Watcher is active, dry_run=0, few restarts.
systemctl is-active albunyaan-watcher
systemctl show albunyaan-watcher -p Environment -p NRestarts --value

# All 22 channels tracked; most LIVE; tiny tail of SLATE/BACKUP is normal.
for f in /var/run/albunyaan/state/*.json; do jq -r '.state' "$f"; done | sort | uniq -c

# Recent dispatches (real — no "(dry-run)" prefix since 00:00:31 on 2026-04-16).
# Look for SIGNAL:slate:<ch> or SIGNAL:swap:<ch>:<url>. `dispatch FAILED` is bad.
tail -50 /home/msa/Development/scripts/albunyaan/channels/logs/reflex_watcher.log | grep -E 'SIGNAL:|dispatch'

# Privilege bridge actively firing (sudo-wrapped USR1/USR2 delivery to root supervisors).
journalctl -u albunyaan-watcher --since '30 minutes ago' --no-pager | grep albunyaan-signal | tail
```

---

## Architecture pointers

| Concern | File / path |
|---|---|
| Watcher main loop | `channels/reflex_watcher.sh` |
| State machine transitions | `channels/reflex/transitions.sh` |
| State file I/O (flock'd) | `channels/reflex/state.sh` |
| Probe (HTTP + rtmp/rtsp via ffprobe) | `channels/reflex/probe.sh` |
| Output-freshness detector | `channels/reflex/freshness.sh` |
| Signal dispatch (kill + sudo fallback) | `channels/reflex/signals.sh` |
| Privilege bridge helper (root-owned) | `/usr/local/bin/albunyaan-signal` (source: `channels/reflex/albunyaan-signal`) |
| Sudoers rule | `/etc/sudoers.d/albunyaan-reflex` (NOPASSWD, argv-whitelisted) |
| Systemd unit | `/etc/systemd/system/albunyaan-watcher.service` |
| DRY_RUN=0 drop-in | `/etc/systemd/system/albunyaan-watcher.service.d/reflex-dispatch.conf` |
| Per-channel state (runtime) | `/var/run/albunyaan/state/<ch>.json` |
| Supervisor PID files (runtime, preserved) | `/var/run/albunyaan/pid/<ch>.pid` |
| Swap-target cmd files (runtime) | `/var/run/albunyaan/cmd/<ch>.target_url` |
| Sticky DEGRADED (persistent, 24h TTL) | `/var/lib/albunyaan/<ch>.sticky.json` |

---

## Key runtime facts (easy to get wrong)

- **Channel supervisors run as root** (launched by `restart.sh` from root's crontab every 8h at :00 / 02:00 / 10:00 / 18:00 CEST).
- **Watcher runs as user `msa`** (systemd). User `msa` cannot signal root processes directly — hence the sudo-gated privilege helper.
- **PGID trap:** all 22 channel supervisors share the same PGID (inherited from `run_all_channels.sh`). Never `kill -TERM -<PGID>` on a channel's PGID — it kills the whole fleet. Target individual PIDs.
- **tmpfs wipe:** `/var/run/albunyaan` is tmpfs. `RuntimeDirectoryPreserve=yes` (unit directive) preserves it across watcher restart but NOT reboot. Sticky DEGRADED is in `/var/lib/albunyaan` (StateDirectory) to survive reboot.
- **Channel-ID → script-file mapping is messy.** Use `channel_registry.json` (`channels[<ch>].config_file`) — many channels have no obvious name↔file relationship (e.g. `makkah` → `channel_quran.sh`; `natural` → `channel_almajd_nature_revised.sh`). `_resolve_channel_script` in `reflex_watcher.sh` does the lookup.
- **probe_url return codes:** `0` = healthy, `1` = unhealthy, `2` = unknown-skip (resolver schemes like `elahmad:`, `aloula:`, `seenshow:`, `youtube:`, OR blocklisted addresses). rc=2 does NOT change probe counters.
- **Retries:** probe_url retries once on HTTP transient failure (commit `38ee592`). Absorbs WAN jitter that was pushing channels into spurious SLATE.
- **HTTP probe accepts 2xx / 3xx / 405.** vlc.news Xtream Codes returns 302 to CDN; strict 200-only trapped all vlc.news channels. Commit `1766b5a`.

---

## Verified end-to-end tonight (2026-04-15/16)

| Gate | Evidence |
|---|---|
| Dispatch delivery (SIGUSR2 swap) | `SIGNAL:swap:zaad:https://...@ZadTVchannel/live` at 00:09:05 → supervisor log `REFLEX: SIGUSR2 received` at 00:09:06 → fresh YouTube segments |
| Privilege bridge under load | journalctl: `msa : COMMAND=/usr/local/bin/albunyaan-signal USR2 2317117 natural` delivered cleanly |
| Sticky DEGRADED round-trip | basmah test: 6 seeded transitions → DEGRADED in 4s → `/var/lib/albunyaan/basmah.sticky.json` written → watcher restart → state rehydrated to DEGRADED → manually cleared |
| RuntimeDirectoryPreserve | Controlled watcher restart at 01:04:25 preserved all 22 PID files and 22 state files |
| Full test suite | All reflex unit + integration + 5 E2E scenarios pass |

---

## Pending / deferred (not blocking, not urgent)

These were surfaced by the second review pipeline pass (commit `b06824b`). All are design-level, not bugs:

| Priority | Item | Effort | Notes |
|---|---|---|---|
| Low-Medium | TOCTOU between `/proc/cmdline` read and `exec kill` | 1-2 days | Needs pidfd_send_signal migration; wrapper is bash |
| Low-Medium | Clock-skew / NTP-jump robustness in probe schedule | ~1 day | Refactor next_attempt_after from ISO8601 to epoch int |
| Low-Medium | DEGRADED auto-recovery window | Design | Currently requires manual sticky deletion after 24h TTL |
| Low | Probe retry regression test (transient-fail → success) | 30 min | Fixture server that counts attempts |
| Low | `_resolve_channel_script` regression test | 30 min | Fake registry + temp script_dir |
| Low | Extra HTTP code coverage (301, 307, 308, 405 positive; 500, 503 negative) | 15 min | Parametrize existing fixture |
| Low | Observe natural organic SLATE→BACKUP→LIVE cycle | Passive wait | First real vlc.news blip >12s triggers it; monitor log |

---

## Operational runbook

### Safely restart the watcher (no-op for viewers)

```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
# PID + state files preserved via RuntimeDirectoryPreserve=yes.
# Supervisors unaffected.
```

### Rollback dispatch (back to dry-run)

```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl revert albunyaan-watcher
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
```

Removes the `REFLEX_DRY_RUN=0` drop-in; signals go back to log-only.

### Reset a stuck channel

```bash
CH=<channel_id>
# If stuck in DEGRADED (sticky):
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A rm /var/lib/albunyaan/$CH.sticky.json
# Reset state machine view:
jq '.state = "LIVE" | .primary_probe = {last_attempt:null, consecutive_failures:0, consecutive_successes:0, next_attempt_after:(now|todate)}' \
    /var/run/albunyaan/state/$CH.json | sponge /var/run/albunyaan/state/$CH.json
```

### Restart a single channel (viewer-visible black for ~5-10s)

No per-channel systemd unit exists. The pattern:

```bash
CH=<channel_id>
# Find and kill the channel's top-level script (channel_<foo>.sh), NOT the PGID.
SCRIPT=$(jq -r --arg c "$CH" '.channels[$c].config_file' channels/channel_registry.json)
PID=$(ps -eo pid,cmd --no-headers | awk -v s="$SCRIPT" '$0 ~ s {print $1; exit}')
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A pkill -TERM -P "$PID"   # children first
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A kill -TERM "$PID"
# Wait for cleanup, then manually relaunch.
sleep 3
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A nohup bash /home/msa/Development/scripts/albunyaan/channels/$SCRIPT </dev/null >/dev/null 2>&1 &
disown
```

For a full-fleet restart, `sudo bash /home/msa/Development/scripts/albunyaan/channels/restart.sh` (20-40s viewer disruption across the fleet; prefer off-peak, KSA 03:00-05:00).

### Push to GitHub

`~/.ssh/id_rsa` is NOT the authorized key. Working key lives in persistent ssh-agent sockets:

```bash
for _s in /tmp/ssh-XXXXXX*/agent.*; do
    [ -S "$_s" ] || continue
    SSH_AUTH_SOCK="$_s" ssh-add -l >/dev/null 2>&1 && { export SSH_AUTH_SOCK="$_s"; break; }
done
git push origin main
```

---

## Memory index (auto-loaded)

Key entries in `~/.claude/projects/-home-msa-Development-scripts-albunyaan/memory/MEMORY.md`:

- `project_reflex_loop.md` — current state snapshot (mirrors this doc's TL;DR).
- `reference_git_push_ssh_agent.md` — the ssh-agent-socket trick above.
- `project_arrahmah_false_slate.md` — why vlc.news 302 was tripping the probe.
- `feedback_reflex_channel_id_glob.md` — channel_id → script mapping pitfall (now solved by registry resolver).
- `feedback_probe_url_http_only.md` — resolver schemes + probe rc=2 context.
- `feedback_heredoc_pipe_stdin_bug.md` — `python3 - <<EOF | …` stdin hazard in wake.sh.

## Spec + plan (don't change without reason)

- `docs/superpowers/specs/2026-04-15-reflex-loop-design.md` — design spec.
- `docs/superpowers/plans/2026-04-15-reflex-loop.md` — implementation plan (now fully executed).
