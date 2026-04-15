#!/bin/bash
# channels/reflex/preflight.sh
# Runs before the watcher starts. Refuses to run blind: slate video must
# exist and state directory must be writable.
set -u

SLATE_VIDEO="${SLATE_VIDEO:-/var/www/html/stream/hls/slate/slate_loop.mp4}"
STATE_DIR="${STATE_DIR:-/var/run/albunyaan/state}"
PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"
CMD_DIR="${REFLEX_CMD_DIR:-/var/run/albunyaan/cmd}"

fail() { echo "PREFLIGHT FAIL: $*" >&2; exit 1; }

[[ -f "$SLATE_VIDEO" && -r "$SLATE_VIDEO" ]] || fail "slate video missing or unreadable: $SLATE_VIDEO"
mkdir -p "$STATE_DIR" "$PID_DIR" "$CMD_DIR" || fail "cannot create runtime dirs under /var/run/albunyaan"
[[ -w "$STATE_DIR" && -w "$PID_DIR" && -w "$CMD_DIR" ]] || fail "runtime dirs not writable"
echo "preflight OK"
