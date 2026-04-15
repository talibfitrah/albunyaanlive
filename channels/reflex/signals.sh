#!/bin/bash
# channels/reflex/signals.sh
# Send reflex control signals to a channel's try_start_stream.sh supervisor.
#
# Production note: channel supervisors run as root (launched by
# restart.sh from root's crontab), while the reflex watcher runs as
# user msa. User msa cannot signal root processes (EPERM). To bridge
# that gap, a small privileged helper at /usr/local/bin/albunyaan-signal
# is invoked via sudoers NOPASSWD (see /etc/sudoers.d/albunyaan-reflex).
# The helper re-validates cmdline inside the privileged context so it
# can't be abused to signal arbitrary root processes.
#
# _deliver_signal() tries direct kill first — that path stays zero-cost
# when the supervisor and watcher share a UID (E2E tests, future refactor
# where supervisors drop privilege). Falls back to the sudo wrapper only
# on EPERM.

REFLEX_PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"
REFLEX_CMD_DIR="${REFLEX_CMD_DIR:-/var/run/albunyaan/cmd}"
REFLEX_PRIV_HELPER="${REFLEX_PRIV_HELPER:-/usr/local/bin/albunyaan-signal}"

# _pid_for <channel_id>
_pid_for() {
    local pf="$REFLEX_PID_DIR/$1.pid"
    [[ -r "$pf" ]] || return 1
    cat "$pf"
}

# _pid_is_try_start_stream <pid> <channel_id>
# Returns 0 iff the PID is running a try_start_stream supervisor for the
# given channel_id. The channel_id match MUST be anchored to the
# supervisor's argv tokens (`-d .../<ch>/master.m3u8` or `-n <ch>`);
# a bare substring check would let the guard pass for any supervisor
# whose cmdline contains "$ch" as a substring — e.g. a hypothetical
# channel called "almajd" would match any of almajd-kids, hadith-almajd,
# almajd-3aamah, mekkah-quran (contains "quran"), etc. (review round 2,
# 2026-04-16 security + red-team, conf 9).
_pid_is_try_start_stream() {
    local pid="$1" ch="$2" cmdline_file="/proc/$1/cmdline"
    [[ -r "$cmdline_file" ]] || return 1
    local cmdline
    cmdline=$(tr '\0' ' ' < "$cmdline_file" 2>/dev/null) || return 1
    [[ "$cmdline" == *try_start_stream* ]] || return 1
    # Anchor to argv tokens. try_start_stream.sh always receives both
    # -d .../<ch>/master.m3u8 AND -n <ch>; either anchor is sufficient.
    [[ "$cmdline" == *"/hls/$ch/master.m3u8"* || "$cmdline" == *" -n $ch "* ]] || return 1
    return 0
}

# _deliver_signal <signal> <pid> <channel_id>
# Tries `kill` directly first; if EPERM (UID mismatch: watcher is msa,
# supervisor is root), falls back to the sudo-gated privilege helper.
# Returns 0 on success, 1 on any failure.
#
# Prints a one-line diagnostic to stderr per boot (not per call) when
# the privilege helper is missing — operator otherwise sees generic
# "dispatch FAILED" and spends time chasing the wrong cause.
_deliver_signal() {
    local sig="$1" pid="$2" ch="$3"
    # Direct path: works when caller and target share a UID.
    if kill "-$sig" "$pid" 2>/dev/null; then
        return 0
    fi
    # Fallback: privilege bridge. sudo -n fails fast if the rule is
    # missing rather than prompting; the helper re-validates cmdline.
    if [[ -x "$REFLEX_PRIV_HELPER" ]]; then
        sudo -n "$REFLEX_PRIV_HELPER" "$sig" "$pid" "$ch" 2>/dev/null
        return $?
    fi
    if [[ "${_REFLEX_HELPER_MISSING_WARNED:-0}" != "1" ]]; then
        echo "reflex: privilege helper not executable: $REFLEX_PRIV_HELPER" >&2
        _REFLEX_HELPER_MISSING_WARNED=1
    fi
    return 1
}

# send_slate_signal <channel_id>    → SIGUSR1 (enter slate)
send_slate_signal() {
    local ch="$1" pid
    pid=$(_pid_for "$ch") || return 1
    _pid_is_try_start_stream "$pid" "$ch" || return 1
    _deliver_signal USR1 "$pid" "$ch"
}

# send_resume_signal <channel_id> <target_url>
# Writes the target URL to a per-channel command file, then sends SIGUSR2.
# try_start_stream.sh reads the file in its SIGUSR2 handler and switches
# to exactly that URL (not whichever happens to be next in rotation).
#
# Known trade-off: rapid back-to-back swaps overwrite the cmd file
# before the supervisor processes the first. Supervisor ends up on the
# LATEST target URL, which is semantically correct for state-machine
# targeting but loses the intermediate URLs from any audit trail. The
# state machine's grace windows (30s after BACKUP, 300s+ backoff on
# primary probe) make the race window effectively unreachable under
# normal operation. Acknowledged at commit time; revisit if needed.
send_resume_signal() {
    local ch="$1" target_url="$2" pid
    pid=$(_pid_for "$ch") || return 1
    _pid_is_try_start_stream "$pid" "$ch" || return 1
    mkdir -p "$REFLEX_CMD_DIR" 2>/dev/null || true
    local tmp="$REFLEX_CMD_DIR/$ch.target_url.tmp"
    local dst="$REFLEX_CMD_DIR/$ch.target_url"
    printf '%s\n' "$target_url" > "$tmp" && mv -f "$tmp" "$dst"
    _deliver_signal USR2 "$pid" "$ch"
}

# dispatch_signal <SIGNAL line from transitions.sh>
# Parses "SIGNAL:slate:<ch>" or "SIGNAL:swap:<ch>:<url>" and invokes
# the corresponding signal. Returns 0 on success, 1 on PID missing,
# 2 on malformed line.
dispatch_signal() {
    local line="$1"
    case "$line" in
        SIGNAL:slate:*)
            local ch="${line#SIGNAL:slate:}"
            send_slate_signal "$ch" ;;
        SIGNAL:swap:*)
            # Strip prefix, then channel is up to the next ':', URL is the rest
            local rest="${line#SIGNAL:swap:}"
            local ch="${rest%%:*}"
            local url="${rest#*:}"
            [[ -n "$ch" && -n "$url" && "$url" != "$rest" ]] || return 2
            send_resume_signal "$ch" "$url" ;;
        *) return 2 ;;
    esac
}
