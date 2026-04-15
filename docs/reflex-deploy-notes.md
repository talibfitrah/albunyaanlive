# Reflex Deploy Notes

Operational facts discovered during activation that SESSION_HANDOFF.md's
original checklist didn't anticipate. Read before running Step B or C.

## Privilege model

- Channel supervisors run as **root** (launched by `restart.sh` from
  root's crontab).
- Reflex watcher runs as **user msa** (via `albunyaan-watcher.service`).
- User msa cannot signal root processes → direct `kill -USR1` returns
  `Operation not permitted`.

### Bridge

- `/usr/local/bin/albunyaan-signal` — root-owned wrapper (0755) that
  re-validates args and cmdline before signalling. Source in
  `channels/reflex/albunyaan-signal`.
- `/etc/sudoers.d/albunyaan-reflex` — narrow NOPASSWD rule: msa may
  invoke the wrapper with USR1/USR2 only, with numeric PID and
  `[A-Za-z0-9_-]+` channel_id. `Defaults !requiretty` for systemd
  contexts.
- `signals.sh` calls direct `kill` first (cheap, works msa→msa in tests
  and in any future refactor); falls back to `sudo -n wrapper` on EPERM.

Verify after a reinstall:
```bash
ls -la /usr/local/bin/albunyaan-signal        # root:root 0755
ls -la /etc/sudoers.d/albunyaan-reflex        # root:root 0440
sudo visudo -c                                # parsed OK
```

## Channel restart mechanics

There are **no per-channel systemd units** on this box. Channels are
launched by `run_all_channels.sh` as root from `hls_background_job.sh`,
triggered by root's cron at `0 2-23/8 * * *` (02:00 / 10:00 / 18:00 CEST)
via `restart.sh`.

Implications:
- `restart.sh` is an all-or-nothing fleet restart. It runs `stop_all.sh`
  (kills every `start_stream`/`ffmpeg`/`hls_background_job` process
  AND deletes most channel HLS output dirs) then `start_all_streams.sh`
  (relaunches the whole fleet). Total viewer-visible disruption window
  is 20–60 s per channel during the ramp-up.
- **Do NOT send `kill -TERM -<PGID>` to a channel's PGID.** All 22
  channels share the same PGID (inherited from `run_all_channels.sh`),
  so a PGID-kill takes down the whole fleet.
- To restart a single channel, kill its specific PIDs (not the PGID),
  wait for cleanup, then `sudo nohup bash channel_<name>.sh &`.

## Step-by-step activation state (2026-04-15)

- [x] Step A: new unit file installed + daemon-reload + restart. watcher
      0750 on /var/run/albunyaan, StateDirectory creates /var/lib/albunyaan,
      preflight OK.
- [x] Privilege bridge installed.
- [x] Step B: fleet restart executed at 23:30 CEST. 22/22 PID files
      written, ~20/22 channels producing fresh segments within 45 s.
- [ ] **Step C pending.** Before flipping `REFLEX_DRY_RUN=0`:
      - Confirm all channels back to `state=LIVE` in state files (the
        restart transient leaves channels in SLATE; primary-probe
        reconciliation takes ~5–10 min).
      - Tail `reflex_watcher.log` for the `SIGNAL:slate`/`SIGNAL:swap`
        cadence. Noisy = state is out of sync with reality; calm = ok
        to flip.

## Flipping to live (Step C)

```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl edit albunyaan-watcher
# In the editor:
#   [Service]
#   Environment="REFLEX_DRY_RUN=0"
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl daemon-reload
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
tail -F /home/msa/Development/scripts/albunyaan/channels/logs/reflex_watcher.log | \
  grep -E 'reflex SIGNAL:|dispatch FAILED'
```

Rollback: `sudo systemctl revert albunyaan-watcher` + restart.

## Rollback of the whole deploy

If reflex misbehaves:
1. `sudo systemctl stop albunyaan-watcher` — stops dispatch immediately
   (dry-run or live, doesn't matter).
2. Channel supervisors continue running independently; viewers unaffected.
3. If PID files accumulate stale entries: `sudo rm /var/run/albunyaan/pid/*.pid`.
4. To revert signal handlers in the supervisors themselves, wait for
   the next `restart.sh` cron (max 8 h) — they'll relaunch with whatever
   try_start_stream.sh is current on disk.
