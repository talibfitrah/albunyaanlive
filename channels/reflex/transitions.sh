#!/bin/bash
# channels/reflex/transitions.sh
# Pure state-machine. Given (channel_cfg_json, current_state_json, now_unix),
# updates the state file in place via state_modify and emits action lines
# on stdout for the caller to handle:
#   SIGNAL:slate:<channel_id>
#   SIGNAL:swap:<channel_id>:<url>
# Does not fork ffmpeg, does not call curl directly (uses probe_url,
# which the caller may stub).
#
# Depends on: state.sh, freshness.sh, backoff.sh, probe.sh

# Helper used by tests to locate the state file path
state_path_for() { echo "${STATE_DIR:-/var/run/albunyaan/state}/$1.json"; }

# _count_recent_transitions <channel_id> <now_unix> <window_sec>
# Returns count of transitions in the last <window_sec> seconds.
_count_recent_transitions() {
    local ch="$1" now="$2" window="$3"
    local cutoff=$(( now - window ))
    state_read_field "$ch" "[.transition_history[] | select((.at|tonumber) >= $cutoff)] | length" 2>/dev/null || echo 0
}

# _push_transition <channel_id> <from> <to> <reason>
_push_transition() {
    local ch="$1" from="$2" to="$3" reason="$4"
    local now; now=$(date +%s)
    state_modify "$ch" "
      .transition_history += [{at: \"$now\", from: \"$from\", to: \"$to\", reason: \"$reason\"}]
      | .transition_history |= (if length > 50 then .[-50:] else . end)
      | .last_transition = \"$(date -Iseconds)\"
    "
}

# _iso_plus <seconds>   → now + N seconds in ISO8601
_iso_plus() { date -Iseconds -d "@$(( $(date +%s) + $1 ))"; }

# Main dispatcher — emits SIGNAL lines and returns.
next_state() {
    local cfg_json="$1" state_json="$2" now_unix="$3"
    local ch; ch=$(jq -r '.channel_id' <<<"$cfg_json")
    local hls_dir; hls_dir=$(jq -r '.hls_dir' <<<"$cfg_json")
    local primary_url; primary_url=$(jq -r '.primary_url' <<<"$cfg_json")
    local backups; backups=$(jq -c '.backup_urls' <<<"$cfg_json")
    local cur_state; cur_state=$(jq -r '.state' <<<"$state_json")
    local grace_until; grace_until=$(jq -r '.grace_until' <<<"$state_json")
    local identity_status; identity_status=$(jq -r '.identity_status' <<<"$state_json")
    local grace_unix; grace_unix=$(date -d "$grace_until" +%s 2>/dev/null || echo 0)
    local in_grace=0
    (( now_unix < grace_unix )) && in_grace=1

    # Circuit breaker check — applies from any state
    if [[ "$cur_state" != "DEGRADED" ]]; then
        local rc; rc=$(_count_recent_transitions "$ch" "$now_unix" 120)
        if (( rc > 5 )); then
            _push_transition "$ch" "$cur_state" "DEGRADED" "flapping"
            state_write_field "$ch" ".state" '"DEGRADED"'
            return
        fi
    fi

    case "$cur_state" in
        LIVE)    _handle_live    "$ch" "$hls_dir" "$state_json" "$cfg_json" "$in_grace" "$identity_status" "$now_unix" ;;
        SLATE)   _handle_slate   "$ch" "$state_json" "$cfg_json" "$primary_url" "$backups" "$now_unix" ;;
        BACKUP)  _handle_backup  "$ch" "$hls_dir" "$state_json" "$cfg_json" "$primary_url" "$in_grace" "$now_unix" ;;
        DEGRADED) : ;;   # no auto action
    esac
}

_handle_live() {
    local ch="$1" hls_dir="$2" state_json="$3" cfg_json="$4" in_grace="$5" identity_status="$6" now_unix="$7"

    # Identity-mismatch short-circuit (takes precedence over staleness)
    if [[ "$identity_status" == "mismatch" && "$in_grace" == "0" ]]; then
        _push_transition "$ch" "LIVE" "SLATE" "identity_mismatch"
        state_modify "$ch" '
          .state = "SLATE"
          | .current_source_url = null
          | .current_source_role = null
          | .reverify_requested = true
          | .slate_retry_count = 0
        '
        echo "SIGNAL:slate:$ch"
        return
    fi

    [[ "$in_grace" == "1" ]] && return

    is_output_fresh "$hls_dir" 10
    case $? in
        0) return ;;   # fresh — stay
        1)             # stale — slate
            _push_transition "$ch" "LIVE" "SLATE" "staleness"
            state_modify "$ch" '
              .state = "SLATE"
              | .current_source_url = null
              | .current_source_role = null
              | .slate_retry_count = 0
              | .primary_probe.next_attempt_after = "'"$(_iso_plus 300)"'"
            '
            echo "SIGNAL:slate:$ch" ;;
        2) return ;;   # no dir — log, stay. Caller handles.
    esac
}

_handle_slate() {
    local ch="$1" state_json="$2" cfg_json="$3" primary_url="$4" backups="$5" now_unix="$6"

    # 1. Primary probe (respecting backoff)
    local next_after; next_after=$(jq -r '.primary_probe.next_attempt_after' <<<"$state_json")
    local next_after_u; next_after_u=$(date -d "$next_after" +%s 2>/dev/null || echo 0)
    if (( now_unix >= next_after_u )); then
        if probe_url "$primary_url" 2; then
            local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
            succ=$(( succ + 1 ))
            if (( succ >= 2 )); then
                _push_transition "$ch" "SLATE" "LIVE" "primary_recovered"
                state_modify "$ch" '
                  .state = "LIVE"
                  | .current_source_url = "'"$primary_url"'"
                  | .current_source_role = "primary"
                  | .grace_until = "'"$(_iso_plus 30)"'"
                  | .primary_probe = {last_attempt:"'"$(_iso_plus 0)"'",consecutive_failures:0,consecutive_successes:0,next_attempt_after:"'"$(_iso_plus 0)"'"}
                  | .excluded_backups = []
                  | .reverify_requested = false
                '
                echo "SIGNAL:swap:$ch:$primary_url"
                return
            else
                state_modify "$ch" ".primary_probe.consecutive_successes = $succ | .primary_probe.last_attempt = \"$(_iso_plus 0)\""
            fi
        else
            local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
            fail=$(( fail + 1 ))
            local delay; delay=$(backoff_delay "$fail")
            state_modify "$ch" "
              .primary_probe.consecutive_failures = $fail
              | .primary_probe.consecutive_successes = 0
              | .primary_probe.last_attempt = \"$(_iso_plus 0)\"
              | .primary_probe.next_attempt_after = \"$(_iso_plus $delay)\"
            "
        fi
    fi

    # 2. Walk one backup per cycle (round-robin)
    local total; total=$(jq -r 'length' <<<"$backups")
    (( total == 0 )) && return
    local cursor; cursor=$(jq -r '.backup_walk_cursor' <<<"$state_json")
    local idx=$(( cursor % total ))
    local url; url=$(jq -r ".[$idx]" <<<"$backups")
    state_modify "$ch" ".backup_walk_cursor = $(( (idx + 1) % total ))"
    # Skip if excluded
    if jq -e --arg u "$url" '.excluded_backups | index($u)' <<<"$state_json" >/dev/null; then
        return
    fi
    if probe_url "$url" 2; then
        _push_transition "$ch" "SLATE" "BACKUP" "backup_probe_ok"
        state_modify "$ch" '
          .state = "BACKUP"
          | .current_source_url = "'"$url"'"
          | .current_source_role = "backup"
          | .grace_until = "'"$(_iso_plus 30)"'"
          | .slate_retry_count = 0
        '
        echo "SIGNAL:swap:$ch:$url"
    fi
}

_handle_backup() {
    local ch="$1" hls_dir="$2" state_json="$3" cfg_json="$4" primary_url="$5" in_grace="$6" now_unix="$7"
    local identity_status; identity_status=$(jq -r '.identity_status' <<<"$state_json")
    local cur_url; cur_url=$(jq -r '.current_source_url' <<<"$state_json")

    # Identity mismatch on the current BACKUP → exclude it, slate
    if [[ "$identity_status" == "mismatch" && "$in_grace" == "0" ]]; then
        _push_transition "$ch" "BACKUP" "SLATE" "identity_mismatch"
        state_modify "$ch" "
          .state = \"SLATE\"
          | .excluded_backups += [\"$cur_url\"]
          | .current_source_url = null
          | .current_source_role = null
          | .reverify_requested = true
          | .slate_retry_count = 0
        "
        echo "SIGNAL:slate:$ch"
        return
    fi

    if [[ "$in_grace" == "0" ]]; then
        is_output_fresh "$hls_dir" 10
        if [[ $? -eq 1 ]]; then
            _push_transition "$ch" "BACKUP" "SLATE" "backup_stale"
            state_modify "$ch" "
              .state = \"SLATE\"
              | .excluded_backups += [\"$cur_url\"]
              | .current_source_url = null
              | .current_source_role = null
              | .slate_retry_count = 0
            "
            echo "SIGNAL:slate:$ch"
            return
        fi
    fi

    # Primary-return probe (same logic as SLATE's primary probe, minus backup walk)
    local next_after; next_after=$(jq -r '.primary_probe.next_attempt_after' <<<"$state_json")
    local next_after_u; next_after_u=$(date -d "$next_after" +%s 2>/dev/null || echo 0)
    if (( now_unix >= next_after_u )); then
        if probe_url "$primary_url" 2; then
            local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
            succ=$(( succ + 1 ))
            if (( succ >= 2 )); then
                _push_transition "$ch" "BACKUP" "LIVE" "primary_recovered"
                state_modify "$ch" '
                  .state = "LIVE"
                  | .current_source_url = "'"$primary_url"'"
                  | .current_source_role = "primary"
                  | .grace_until = "'"$(_iso_plus 30)"'"
                  | .primary_probe = {last_attempt:"'"$(_iso_plus 0)"'",consecutive_failures:0,consecutive_successes:0,next_attempt_after:"'"$(_iso_plus 0)"'"}
                  | .excluded_backups = []
                  | .reverify_requested = false
                '
                echo "SIGNAL:swap:$ch:$primary_url"
            else
                state_modify "$ch" ".primary_probe.consecutive_successes = $succ | .primary_probe.last_attempt = \"$(_iso_plus 0)\""
            fi
        else
            local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
            fail=$(( fail + 1 ))
            local delay; delay=$(backoff_delay "$fail")
            state_modify "$ch" "
              .primary_probe.consecutive_failures = $fail
              | .primary_probe.consecutive_successes = 0
              | .primary_probe.last_attempt = \"$(_iso_plus 0)\"
              | .primary_probe.next_attempt_after = \"$(_iso_plus $delay)\"
            "
        fi
    fi
}
