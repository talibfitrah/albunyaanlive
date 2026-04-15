#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/freshness.sh"

test_fresh_ts_within_threshold() {
    local d="$TEST_TMPDIR/ch"; mkdir -p "$d"
    : > "$d/seg0.ts"
    is_output_fresh "$d" 10
    local rc=$?
    th_assert_eq "$rc" "0" "fresh returns 0" || return 1
}

test_stale_ts_older_than_threshold() {
    local d="$TEST_TMPDIR/ch"; mkdir -p "$d"
    : > "$d/seg0.ts"
    touch -d "-30 seconds" "$d/seg0.ts"
    is_output_fresh "$d" 10
    local rc=$?
    th_assert_eq "$rc" "1" "stale returns 1" || return 1
}

test_missing_dir_returns_2() {
    is_output_fresh "$TEST_TMPDIR/nonexistent" 10
    local rc=$?
    th_assert_eq "$rc" "2" "no-dir returns 2" || return 1
}

test_empty_dir_returns_stale() {
    local d="$TEST_TMPDIR/ch"; mkdir -p "$d"
    is_output_fresh "$d" 10
    local rc=$?
    th_assert_eq "$rc" "1" "empty dir returns stale" || return 1
}

th_run "fresh .ts within threshold"   test_fresh_ts_within_threshold || exit 1
th_run "stale .ts older than threshold" test_stale_ts_older_than_threshold || exit 1
th_run "missing dir returns 2"        test_missing_dir_returns_2 || exit 1
th_run "empty dir returns stale"      test_empty_dir_returns_stale || exit 1
echo "freshness tests: all PASS"
