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
#
# Reliability invariants (review 2026-04-20):
#   R1. Next-wake epoch is read from systemd's machine-stable property
#       (NextElapseUSecRealtime), NOT from the humanized `list-timers`
#       columns — those vary by locale and systemd version.
#   R2. Pending count comes from `lessons.sh pending-count`, which exits
#       non-zero on DB error. Silent "0 pending" on a locked/corrupt DB
#       would defeat the whole point of this script.
#   R3. Per-cycle "already sent" markers are persisted ONLY after
#       tg_alert returns 0 — i.e. after a real HTTP 200. A dropped
#       Telegram stays unmarked and is retried on the next tick.
#   R4. State writes are flock'd so two overlapping timer fires can't
#       corrupt the JSON or lose a phase marker.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

STATE_DIR="${RUNTIME_DIR:-/run/albunyaan}"
STATE_FILE="$STATE_DIR/brain_reminder.state.json"
STATE_LOCK="$STATE_DIR/brain_reminder.state.lock"
LESSONS_SH="$REPO_ROOT/channels/brain_loop/lessons.sh"
LOG_PREFIX="[wake_reminder $(date -Iseconds)]"

log()  { echo "$LOG_PREFIX $*" >&2; }

TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
if [[ -f "$TELEGRAM_ENV" ]]; then
    set -a; source "$TELEGRAM_ENV"; set +a
fi
# shellcheck source=../tg_alert.sh
source "$REPO_ROOT/channels/tg_alert.sh"

# R1: parse `list-timers --output=json`. The `.next` field is microseconds
# since epoch — a stable machine-readable number, regardless of locale or
# systemd's list-timers column layout. (We avoid `show -p
# NextElapseUSecRealtime` because monotonic timers like
# OnUnitActiveSec/OnBootSec leave that property empty — the brain timer
# is monotonic.)
_next_wake_epoch() {
    local usec
    usec=$(systemctl list-timers albunyaan-brain.timer \
             --no-pager --output=json 2>/dev/null \
           | jq -r '.[0].next // empty' 2>/dev/null || true)
    [[ -n "$usec" ]] || return 1
    [[ "$usec" =~ ^[0-9]+$ ]] || return 1
    echo $(( usec / 1000000 ))
}

# R2: pending-count exits non-zero on DB error; we propagate the error
# instead of treating it as "0 pending" and silently skipping the reminder.
_pending_count() {
    "$LESSONS_SH" pending-count --status sent 2>/dev/null
}

_state_get() {
    local key="$1"
    [[ -r "$STATE_FILE" ]] || { echo ""; return; }
    jq -r --arg k "$key" '.[$k] // ""' "$STATE_FILE" 2>/dev/null || echo ""
}

# R4: flock'd write. Two overlapping timer fires serialize; the second one
# sees the updated state rather than a stale read+write merge.
_state_set() {
    local key="$1" val="$2" tmp
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
    # Open fd 9 on the lock file and hold an exclusive lock for this block.
    exec 9>"$STATE_LOCK"
    flock -x 9
    tmp=$(mktemp "${STATE_FILE}.XXXXXX")
    if [[ -r "$STATE_FILE" ]]; then
        jq --arg k "$key" --arg v "$val" '.[$k] = $v' "$STATE_FILE" >"$tmp"
    else
        jq -n --arg k "$key" --arg v "$val" '{($k): $v}' >"$tmp"
    fi
    mv -f "$tmp" "$STATE_FILE"
    exec 9>&-
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

# R2: pending_count call fails loud on DB error — we exit non-zero so the
# next tick retries, rather than silently marking the cycle sent.
if ! pending_count=$(_pending_count); then
    log "ERR: lessons.sh pending-count failed; will retry next tick"
    exit 1
fi
# Defensive: must be a pure integer. If lessons.sh ever returns non-numeric,
# fail loud rather than coerce to 0.
[[ "$pending_count" =~ ^[0-9]+$ ]] || {
    log "ERR: pending-count returned non-integer: '$pending_count'; will retry next tick"
    exit 1
}

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

# R3: only mark the cycle sent on a real HTTP 200 from tg_alert. A
# silently-dropped send (no creds, non-200, network error) keeps the
# cycle unmarked and retries on the next tick.
if tg_alert "info" "$msg"; then
    log "sent: T-${phase}min, pending=$pending_count"
    _state_set "t${phase}_cycle" "$cycle_id"
else
    log "ERR: tg_alert failed; will retry next tick"
    exit 1
fi
