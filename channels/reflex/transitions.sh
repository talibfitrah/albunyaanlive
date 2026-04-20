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
    local now last; now=$(date +%s); last=$(date -Iseconds)
    state_modify "$ch" '
      .transition_history += [{at: $at, from: $from, to: $to, reason: $reason}]
      | .transition_history |= (if length > 50 then .[-50:] else . end)
      | .last_transition = $last
    ' --arg at "$now" --arg from "$from" --arg to "$to" --arg reason "$reason" --arg last "$last"
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
            # Persist DEGRADED to disk (non-tmpfs) so a systemd crash
            # loop doesn't silently reset the breaker on every restart.
            state_write_sticky "$ch" '.state = "DEGRADED"'
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

    # Threshold must exceed try_start_stream.sh's own SEGMENT_STALE_THRESHOLD (90s)
    # so reflex acts as a safety net *after* the supervisor's self-heal window,
    # not a racing competitor. Lowering this below ~100s reintroduces the
    # 2026-04-15→-20 flap storm where reflex tripped SIGUSR1 every ~60s on
    # transient jitter that ffmpeg would have absorbed on its own.
    # Env override REFLEX_STALENESS_SEC exists so the e2e fixture can use a
    # smaller value (10s) without waiting 100+ s per scenario.
    is_output_fresh "$hls_dir" "${REFLEX_STALENESS_SEC:-100}"
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
        probe_url "$primary_url" 2
        local _probe_rc=$?
        case "$_probe_rc" in
            0)
                local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
                succ=$(( succ + 1 ))
                if (( succ >= 2 )); then
                    _push_transition "$ch" "SLATE" "LIVE" "primary_recovered"
                    local now_iso grace_iso
                    now_iso=$(_iso_plus 0); grace_iso=$(_iso_plus 30)
                    state_modify "$ch" '
                      .state = "LIVE"
                      | .current_source_url = $url
                      | .current_source_role = "primary"
                      | .grace_until = $grace
                      | .primary_probe = {last_attempt:$now, consecutive_failures:0, consecutive_successes:0, next_attempt_after:$now}
                      | .excluded_backups = []
                      | .reverify_requested = false
                    ' --arg url "$primary_url" --arg grace "$grace_iso" --arg now "$now_iso"
                    echo "SIGNAL:swap:$ch:$primary_url"
                    return
                else
                    local now_iso; now_iso=$(_iso_plus 0)
                    state_modify "$ch" '
                      .primary_probe.consecutive_successes = ($n | tonumber)
                      | .primary_probe.last_attempt = $now
                    ' --arg n "$succ" --arg now "$now_iso"
                fi ;;
            1)
                local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
                fail=$(( fail + 1 ))
                local delay; delay=$(backoff_delay "$fail")
                local now_iso next_iso; now_iso=$(_iso_plus 0); next_iso=$(_iso_plus "$delay")
                state_modify "$ch" '
                  .primary_probe.consecutive_failures = ($f | tonumber)
                  | .primary_probe.consecutive_successes = 0
                  | .primary_probe.last_attempt = $now
                  | .primary_probe.next_attempt_after = $next
                ' --arg f "$fail" --arg now "$now_iso" --arg next "$next_iso" ;;
            2)
                # Unprobeable (resolver scheme / blocklisted). Don't
                # touch counters; just push next_attempt forward so we
                # don't hot-loop. Recovery path for these channels is
                # out of scope — handled by supervisor internally.
                local now_iso next_iso; now_iso=$(_iso_plus 0); next_iso=$(_iso_plus 300)
                state_modify "$ch" '
                  .primary_probe.last_attempt = $now
                  | .primary_probe.next_attempt_after = $next
                ' --arg now "$now_iso" --arg next "$next_iso" ;;
        esac
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
        local grace_iso; grace_iso=$(_iso_plus 30)
        state_modify "$ch" '
          .state = "BACKUP"
          | .current_source_url = $url
          | .current_source_role = "backup"
          | .grace_until = $grace
          | .slate_retry_count = 0
        ' --arg url "$url" --arg grace "$grace_iso"
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
        state_modify "$ch" '
          .state = "SLATE"
          | .excluded_backups += [$cur]
          | .current_source_url = null
          | .current_source_role = null
          | .reverify_requested = true
          | .slate_retry_count = 0
        ' --arg cur "$cur_url"
        echo "SIGNAL:slate:$ch"
        return
    fi

    if [[ "$in_grace" == "0" ]]; then
        # Same 100s threshold as LIVE handler — see comment above for rationale.
        is_output_fresh "$hls_dir" "${REFLEX_STALENESS_SEC:-100}"
        if [[ $? -eq 1 ]]; then
            _push_transition "$ch" "BACKUP" "SLATE" "backup_stale"
            state_modify "$ch" '
              .state = "SLATE"
              | .excluded_backups += [$cur]
              | .current_source_url = null
              | .current_source_role = null
              | .slate_retry_count = 0
            ' --arg cur "$cur_url"
            echo "SIGNAL:slate:$ch"
            return
        fi
    fi

    # Primary-return probe (same logic as SLATE's primary probe, minus backup walk)
    local next_after; next_after=$(jq -r '.primary_probe.next_attempt_after' <<<"$state_json")
    local next_after_u; next_after_u=$(date -d "$next_after" +%s 2>/dev/null || echo 0)
    if (( now_unix >= next_after_u )); then
        probe_url "$primary_url" 2
        local _probe_rc=$?
        case "$_probe_rc" in
            0)
                local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
                succ=$(( succ + 1 ))
                if (( succ >= 2 )); then
                    _push_transition "$ch" "BACKUP" "LIVE" "primary_recovered"
                    local now_iso grace_iso
                    now_iso=$(_iso_plus 0); grace_iso=$(_iso_plus 30)
                    state_modify "$ch" '
                      .state = "LIVE"
                      | .current_source_url = $url
                      | .current_source_role = "primary"
                      | .grace_until = $grace
                      | .primary_probe = {last_attempt:$now, consecutive_failures:0, consecutive_successes:0, next_attempt_after:$now}
                      | .excluded_backups = []
                      | .reverify_requested = false
                    ' --arg url "$primary_url" --arg grace "$grace_iso" --arg now "$now_iso"
                    echo "SIGNAL:swap:$ch:$primary_url"
                else
                    local now_iso; now_iso=$(_iso_plus 0)
                    state_modify "$ch" '
                      .primary_probe.consecutive_successes = ($n | tonumber)
                      | .primary_probe.last_attempt = $now
                    ' --arg n "$succ" --arg now "$now_iso"
                fi ;;
            2)
                # Unprobeable primary (resolver scheme / blocklisted).
                # Don't touch counters; push next_attempt forward.
                local now_iso next_iso; now_iso=$(_iso_plus 0); next_iso=$(_iso_plus 300)
                state_modify "$ch" '
                  .primary_probe.last_attempt = $now
                  | .primary_probe.next_attempt_after = $next
                ' --arg now "$now_iso" --arg next "$next_iso" ;;
            1)
                local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
                fail=$(( fail + 1 ))
                local delay; delay=$(backoff_delay "$fail")
                local now_iso next_iso; now_iso=$(_iso_plus 0); next_iso=$(_iso_plus "$delay")
                state_modify "$ch" '
                  .primary_probe.consecutive_failures = ($f | tonumber)
                  | .primary_probe.consecutive_successes = 0
                  | .primary_probe.last_attempt = $now
                  | .primary_probe.next_attempt_after = $next
                ' --arg f "$fail" --arg now "$now_iso" --arg next "$next_iso" ;;
        esac
    fi
}
