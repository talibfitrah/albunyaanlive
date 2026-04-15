#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/state.sh"
source "$REFLEX_DIR/freshness.sh"
source "$REFLEX_DIR/backoff.sh"
source "$REFLEX_DIR/transitions.sh"

# Stub the probe function with a configurable result table.
# Tests set PROBE_RESULTS[url]=0|1 before calling.
declare -A PROBE_RESULTS
probe_url() {
    local url="$1"
    [[ "${PROBE_RESULTS[$url]:-1}" == "0" ]]
}

# Helper: construct a minimal channel config
make_channel_cfg() {
    local ch="$1" primary="$2"
    shift 2
    local backups_json="[]"
    if [[ $# -gt 0 ]]; then
        backups_json=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
    fi
    jq -n --arg id "$ch" --arg p "$primary" --argjson b "$backups_json" \
        '{channel_id:$id, primary_url:$p, backup_urls:$b, hls_dir:env.CH_DIR}'
}

test_live_stale_transitions_to_slate() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    : > "$CH_DIR/seg0.ts"; touch -d "-30 seconds" "$CH_DIR/seg0.ts"
    state_init "$ch"
    state_modify "$ch" '.grace_until = "1970-01-01T00:00:00Z"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8")
    local actions
    actions=$(next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)")
    echo "$actions" | grep -q "^SIGNAL:slate:$ch$" || { echo "missing slate signal"; return 1; }
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "SLATE" "LIVE+stale → SLATE" || return 1
}

test_live_stale_in_grace_stays_live() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    : > "$CH_DIR/seg0.ts"; touch -d "-30 seconds" "$CH_DIR/seg0.ts"
    state_init "$ch"
    state_modify "$ch" '.grace_until = "2099-01-01T00:00:00Z"'  # far future
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8")
    next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)" >/dev/null
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "LIVE" "grace active → stay LIVE" || return 1
}

test_slate_finds_healthy_backup() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    state_init "$ch"
    state_modify "$ch" '.state = "SLATE"'
    state_modify "$ch" '.grace_until = "1970-01-01T00:00:00Z"'
    state_modify "$ch" '.primary_probe.next_attempt_after = "2099-01-01T00:00:00Z"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8" "http://b1.test/m.m3u8")
    PROBE_RESULTS["http://b1.test/m.m3u8"]=0
    local actions; actions=$(next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)")
    echo "$actions" | grep -q "^SIGNAL:swap:$ch:http://b1.test/m.m3u8$" || { echo "missing swap signal"; return 1; }
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "BACKUP" "SLATE + healthy backup → BACKUP" || return 1
}

test_slate_all_backups_dead_stays_slate() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    state_init "$ch"
    state_modify "$ch" '.state = "SLATE"'
    state_modify "$ch" '.primary_probe.next_attempt_after = "2099-01-01T00:00:00Z"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8" "http://b1.test/m.m3u8")
    PROBE_RESULTS["http://b1.test/m.m3u8"]=1
    next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)" >/dev/null
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "SLATE" "all dead → stay SLATE" || return 1
}

test_slate_primary_twice_returns_live() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    state_init "$ch"
    state_modify "$ch" '.state = "SLATE"'
    state_modify "$ch" '.primary_probe.consecutive_successes = 1'
    state_modify "$ch" '.primary_probe.next_attempt_after = "1970-01-01T00:00:00Z"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8")
    PROBE_RESULTS["http://p.test/m.m3u8"]=0
    local actions; actions=$(next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)")
    echo "$actions" | grep -q "^SIGNAL:swap:$ch:http://p.test/m.m3u8$" || { echo "missing primary-return swap"; return 1; }
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "LIVE" "primary ×2 → LIVE" || return 1
}

test_identity_mismatch_triggers_slate() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    : > "$CH_DIR/seg0.ts"; touch -d "-1 second" "$CH_DIR/seg0.ts"   # output fresh
    state_init "$ch"
    state_modify "$ch" '.grace_until = "1970-01-01T00:00:00Z"'
    state_modify "$ch" '.identity_status = "mismatch"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8")
    local actions; actions=$(next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$(date +%s)")
    echo "$actions" | grep -q "^SIGNAL:slate:$ch$" || { echo "identity path didn't slate"; return 1; }
    local rv; rv=$(state_read_field "$ch" ".reverify_requested")
    th_assert_eq "$rv" "true" "reverify_requested set" || return 1
}

test_flapping_triggers_degraded() {
    local ch="chan_a"; export CH_DIR="$TEST_TMPDIR/ch"; mkdir -p "$CH_DIR"
    state_init "$ch"
    local now; now=$(date +%s)
    # Seed 6 recent transitions
    local hist
    hist=$(jq -n --argjson n "$now" '[
      {at:($n-100|tostring), from:"LIVE",to:"SLATE",reason:"stale"},
      {at:($n-90|tostring),  from:"SLATE",to:"BACKUP",reason:"probe"},
      {at:($n-80|tostring),  from:"BACKUP",to:"SLATE",reason:"stale"},
      {at:($n-60|tostring),  from:"SLATE",to:"BACKUP",reason:"probe"},
      {at:($n-40|tostring),  from:"BACKUP",to:"SLATE",reason:"stale"},
      {at:($n-20|tostring),  from:"SLATE",to:"BACKUP",reason:"probe"}
    ]')
    state_modify "$ch" ".transition_history = $hist"
    state_modify "$ch" '.state = "BACKUP"'
    local cfg; cfg=$(make_channel_cfg "$ch" "http://p.test/m.m3u8" "http://b1.test/m.m3u8")
    : > "$CH_DIR/seg0.ts"; touch -d "-30 seconds" "$CH_DIR/seg0.ts"   # stale
    state_modify "$ch" '.grace_until = "1970-01-01T00:00:00Z"'
    next_state "$cfg" "$(cat $(state_path_for "$ch"))" "$now" >/dev/null
    local new_state; new_state=$(state_read_field "$ch" ".state")
    th_assert_eq "$new_state" "DEGRADED" ">5 transitions in 2min → DEGRADED" || return 1
}

th_run "LIVE+stale → SLATE"               test_live_stale_transitions_to_slate || exit 1
th_run "LIVE+stale+grace → stay LIVE"     test_live_stale_in_grace_stays_live  || exit 1
th_run "SLATE+healthy backup → BACKUP"    test_slate_finds_healthy_backup      || exit 1
th_run "SLATE+all dead → stay SLATE"      test_slate_all_backups_dead_stays_slate || exit 1
th_run "SLATE+primary ×2 → LIVE"          test_slate_primary_twice_returns_live   || exit 1
th_run "identity mismatch → SLATE + reverify" test_identity_mismatch_triggers_slate || exit 1
th_run "flapping → DEGRADED"              test_flapping_triggers_degraded      || exit 1
echo "transitions tests: all PASS"
