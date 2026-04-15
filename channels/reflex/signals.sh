#!/bin/bash
# channels/reflex/signals.sh
# Send reflex control signals to a channel's try_start_stream.sh supervisor.

REFLEX_PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"
REFLEX_CMD_DIR="${REFLEX_CMD_DIR:-/var/run/albunyaan/cmd}"

# _pid_for <channel_id>
_pid_for() {
    local pf="$REFLEX_PID_DIR/$1.pid"
    [[ -r "$pf" ]] || return 1
    cat "$pf"
}

# send_slate_signal <channel_id>    → SIGUSR1 (enter slate)
send_slate_signal() {
    local pid; pid=$(_pid_for "$1") || return 1
    kill -USR1 "$pid" 2>/dev/null
}

# send_resume_signal <channel_id> <target_url>
# Writes the target URL to a per-channel command file, then sends SIGUSR2.
# try_start_stream.sh reads the file in its SIGUSR2 handler and switches
# to exactly that URL (not whichever happens to be next in rotation).
send_resume_signal() {
    local ch="$1" target_url="$2" pid
    pid=$(_pid_for "$ch") || return 1
    mkdir -p "$REFLEX_CMD_DIR" 2>/dev/null || true
    local tmp="$REFLEX_CMD_DIR/$ch.target_url.tmp"
    local dst="$REFLEX_CMD_DIR/$ch.target_url"
    printf '%s\n' "$target_url" > "$tmp" && mv -f "$tmp" "$dst"
    kill -USR2 "$pid" 2>/dev/null
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
            send_resume_signal "$ch" "$url" ;;
        *) return 2 ;;
    esac
}
