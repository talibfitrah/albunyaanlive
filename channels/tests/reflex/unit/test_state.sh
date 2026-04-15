#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/state.sh"

test_init_creates_default() {
    state_init "chan_a"
    th_assert_file_exists "$STATE_DIR/chan_a.json" || return 1
    local s; s=$(jq -r '.state' "$STATE_DIR/chan_a.json")
    th_assert_eq "$s" "LIVE" "initial state" || return 1
}

test_write_read_roundtrip() {
    state_init "chan_a"
    state_write_field "chan_a" ".state" '"SLATE"'
    local s; s=$(state_read_field "chan_a" ".state")
    th_assert_eq "$s" "SLATE" "state after write" || return 1
}

test_corrupt_file_reinits() {
    echo "not json {" > "$STATE_DIR/chan_a.json"
    state_init "chan_a"   # should detect and reinit
    local s; s=$(state_read_field "chan_a" ".state")
    th_assert_eq "$s" "LIVE" "state after corrupt reinit" || return 1
    # verify quarantine
    ls "$STATE_DIR"/*.broken.* >/dev/null 2>&1 || { echo "FAIL: expected .broken quarantine"; return 1; }
}

test_concurrent_writes_dont_lose() {
    state_init "chan_a"
    # Two concurrent writers incrementing a counter
    (for _ in {1..20}; do
        state_modify "chan_a" '.counter = ((.counter // 0) + 1)'
     done) &
    (for _ in {1..20}; do
        state_modify "chan_a" '.counter = ((.counter // 0) + 1)'
     done) &
    wait
    local c; c=$(state_read_field "chan_a" ".counter")
    th_assert_eq "$c" "40" "counter after concurrent writes" || return 1
}

th_run "state_init creates default"       test_init_creates_default       || exit 1
th_run "state write/read roundtrip"       test_write_read_roundtrip       || exit 1
th_run "corrupt state reinits"            test_corrupt_file_reinits       || exit 1
th_run "concurrent writes don't lose"     test_concurrent_writes_dont_lose || exit 1
echo "state tests: all PASS"
