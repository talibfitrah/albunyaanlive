#!/bin/bash
# Shared helpers for reflex unit tests.

TEST_TMPDIR=""

th_setup() {
    TEST_TMPDIR=$(mktemp -d -t reflex-test.XXXXXX)
    export STATE_DIR="$TEST_TMPDIR/state"
    mkdir -p "$STATE_DIR"
}

th_teardown() {
    [[ -n "$TEST_TMPDIR" && -d "$TEST_TMPDIR" ]] && rm -rf "$TEST_TMPDIR"
    TEST_TMPDIR=""
}

th_assert_eq() {
    local actual="$1" expected="$2" label="${3:-}"
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL ${label}: expected '$expected', got '$actual'" >&2
        return 1
    fi
}

th_assert_file_exists() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "FAIL: expected file $path" >&2
        return 1
    fi
}

th_run() {
    local name="$1"; shift
    echo "TEST: $name"
    th_setup
    if "$@"; then
        echo "  PASS"
    else
        echo "  FAIL"
        th_teardown
        return 1
    fi
    th_teardown
}
