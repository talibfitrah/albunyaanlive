#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/backoff.sh"

test_schedule() {
    th_assert_eq "$(backoff_delay 0)" "300"  "0 → 5min"   || return 1
    th_assert_eq "$(backoff_delay 1)" "300"  "1 → 5min"   || return 1
    th_assert_eq "$(backoff_delay 2)" "300"  "2 → 5min"   || return 1
    th_assert_eq "$(backoff_delay 3)" "900"  "3 → 15min"  || return 1
    th_assert_eq "$(backoff_delay 4)" "1800" "4 → 30min"  || return 1
    th_assert_eq "$(backoff_delay 5)" "3600" "5 → 60min"  || return 1
    th_assert_eq "$(backoff_delay 99)" "3600" "cap at 60min" || return 1
}

th_run "backoff schedule matches spec" test_schedule || exit 1
echo "backoff tests: all PASS"
