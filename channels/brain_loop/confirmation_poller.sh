#!/bin/bash
# Telegram confirmation poller — pending-expire + (disabled) getUpdates.
#
# IMPORTANT — current state (2026-04-17 post review):
# ---------------------------------------------------
# The Telegram MCP plugin
# (`~/.claude/plugins/cache/claude-plugins-official/telegram/...`) holds
# an exclusive long-poll getUpdates session on the colleague bot token.
# Telegram only allows ONE getUpdates consumer per token, so any second
# poller — including this script — receives
#   { "ok": false,
#     "description": "Conflict: terminated by other getUpdates request" }
# for EVERY call. A code review on 2026-04-17 caught the first version of
# this script hitting 12/12 Conflict errors in 24 minutes of runtime.
#
# Rather than fight the plugin (and break incoming messages to the MCP
# session if we win the race), this script now runs in "expire-only"
# mode: it still executes `pending-expire` every 2 minutes so stale
# confirmation rows get cleaned up, but it does NOT call getUpdates.
#
# Automatic confirmation capture is therefore a DESIGN GAP right now.
# The pending_confirmations rows that wake.sh creates after severe
# alerts have to be resolved MANUALLY:
#   channels/brain_loop/lessons.sh pending-list
#   channels/brain_loop/lessons.sh pending-resolve --id N --outcome … --by operator
#
# To close the loop automatically, the right fix is to patch the MCP
# plugin (there is already a `patch-server.sh` in the plugin dir) so it
# also fans incoming text messages out to a sidecar file. Left for the
# operator to decide when the time is right — don't do it under time
# pressure.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_DIR="${CONFIRMATION_STATE_DIR:-$REPO_ROOT/channels/brain}"
LOG_FILE="$STATE_DIR/confirmation_poller.log"
LOCK_FILE="$STATE_DIR/confirmation_poller.lock"
LESSONS_CLI="$SCRIPT_DIR/lessons.sh"

mkdir -p "$STATE_DIR"

log() { echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"; }

# Concurrency guard: systemd timer can race a slow previous run.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "another run in progress (lock held); skipping"
    exit 0
fi

# Expire-only run. pending-expire is idempotent and cheap — touches
# rows that have crossed expires_at.
"$LESSONS_CLI" pending-expire >>"$LOG_FILE" 2>&1
log "pending-expire complete (getUpdates disabled — see script header for why)"

# Rotate log at 5 MB. NB: this must remain the LAST step of the script —
# any log() call after the rotation would write to a now-unexpected path
# if the rotation has just occurred (the logger re-opens $LOG_FILE each
# call, so new writes go to a fresh file, but the message the
# maintainer intended to write before rotation would be lost).
if [[ -f "$LOG_FILE" ]] && [[ "$(stat -c %s "$LOG_FILE")" -gt 5242880 ]]; then
    mv "$LOG_FILE" "$LOG_FILE.1"
fi
