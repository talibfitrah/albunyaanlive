#!/bin/bash
# wake_reminder.sh — T-30min and T-15min reminders before each brain wake.
#
# Why: pending confirmations (lessons.sh pending-record) close the
# self-improvement loop for the brain. The MCP plugin holds the only
# allowed getUpdates long-poll, so the confirmation_poller can't auto-
# capture replies. A human needs to resolve them via `lessons.sh
# pending-resolve` before the next wake, or the feedback is lost.
#
# This script fires every 5 min (systemd timer) and sends an operator
# Telegram at T-30min and T-15min of the next brain wake, but only if
# there are unresolved pendings. Idempotent per cycle: each phase is
# sent at most once per wake.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

STATE_DIR="${RUNTIME_DIR:-/run/albunyaan}"
STATE_FILE="$STATE_DIR/brain_reminder.state.json"
LESSONS_SH="$REPO_ROOT/channels/brain_loop/lessons.sh"
LOG_PREFIX="[wake_reminder $(date -Iseconds)]"

log()  { echo "$LOG_PREFIX $*" >&2; }

TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
if [[ -f "$TELEGRAM_ENV" ]]; then
    set -a; source "$TELEGRAM_ENV"; set +a
fi
# shellcheck source=../tg_alert.sh
source "$REPO_ROOT/channels/tg_alert.sh"

_next_wake_epoch() {
    local line ts_str
    line=$(systemctl list-timers albunyaan-brain.timer --no-pager --no-legend 2>/dev/null | head -1)
    [[ -z "$line" ]] && return 1
    ts_str=$(awk '{print $1" "$2" "$3" "$4}' <<<"$line")
    date -d "$ts_str" +%s 2>/dev/null
}

_pending_count() {
    local out
    out=$("$LESSONS_SH" pending-list 2>/dev/null || true)
    [[ "$out" == "(no rows)" || -z "$out" ]] && { echo 0; return; }
    grep -cE '^[[:space:]]*[0-9]+' <<<"$out" 2>/dev/null || echo 0
}

_state_get() {
    local key="$1"
    [[ -r "$STATE_FILE" ]] || { echo ""; return; }
    jq -r --arg k "$key" '.[$k] // ""' "$STATE_FILE" 2>/dev/null || echo ""
}

_state_set() {
    local key="$1" val="$2" tmp
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
    tmp=$(mktemp "${STATE_FILE}.XXXXXX")
    if [[ -r "$STATE_FILE" ]]; then
        jq --arg k "$key" --arg v "$val" '.[$k] = $v' "$STATE_FILE" >"$tmp"
    else
        jq -n --arg k "$key" --arg v "$val" '{($k): $v}' >"$tmp"
    fi
    mv -f "$tmp" "$STATE_FILE"
}

next_wake=$(_next_wake_epoch) || { log "ERR: cannot read next wake time"; exit 1; }
now=$(date +%s)
# round to nearest minute
minutes_until=$(( (next_wake - now + 30) / 60 ))

cycle_id="$next_wake"
phase=""
if (( minutes_until >= 28 && minutes_until <= 32 )); then
    [[ "$(_state_get t30_cycle)" != "$cycle_id" ]] && phase="30"
elif (( minutes_until >= 13 && minutes_until <= 17 )); then
    [[ "$(_state_get t15_cycle)" != "$cycle_id" ]] && phase="15"
fi

if [[ -z "$phase" ]]; then
    log "no action: minutes_until=$minutes_until"
    exit 0
fi

pending_count=$(_pending_count)
pending_count="${pending_count//[^0-9]/}"
: "${pending_count:=0}"

if (( pending_count == 0 )); then
    log "quiet: T-${phase}min, 0 pending (marking cycle sent)"
    _state_set "t${phase}_cycle" "$cycle_id"
    exit 0
fi

wake_time_human=$(date -d "@$next_wake" +"%H:%M %Z")
msg="Brain wake in ~${phase} min (${wake_time_human}). ${pending_count} pending confirmation(s) waiting for your outcome.

Resolve with:
  channels/brain_loop/lessons.sh pending-list
  channels/brain_loop/lessons.sh pending-resolve --id N --outcome {prevented_fp|confirmed_flag|no_effect|wrong} --by operator

Why it matters: unresolved pendings = the brain can't learn whether its rule-firings were right. Outcomes close the self-improvement loop."

if tg_alert "info" "$msg"; then
    log "sent: T-${phase}min, pending=$pending_count"
    _state_set "t${phase}_cycle" "$cycle_id"
else
    log "ERR: tg_alert failed; will retry next tick"
    exit 1
fi
