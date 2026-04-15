#!/bin/bash
# REGRESSION CANARY: Watcher must not report healthy when .ts files are
# stale even if master.m3u8 has been regenerated recently (e.g., by an
# upstream-slate feeder). If this ever passes as "fresh", the bug is back.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/freshness.sh"

test_stale_ts_fresh_playlist_is_stale() {
    local d="$TEST_TMPDIR/ch"; mkdir -p "$d"
    # Stale .ts files — all 10 minutes old
    for i in 0 1 2 3; do
        : > "$d/seg${i}.ts"
        touch -d "-600 seconds" "$d/seg${i}.ts"
    done
    # Freshly regenerated playlist (simulates slate feeder re-writing m3u8)
    : > "$d/master.m3u8"
    touch -d "now" "$d/master.m3u8"
    is_output_fresh "$d" 10
    local rc=$?
    th_assert_eq "$rc" "1" "stale .ts + fresh m3u8 MUST return stale" || return 1
}

th_run "REGRESSION: stale .ts + fresh m3u8 is stale" test_stale_ts_fresh_playlist_is_stale || exit 1
echo "false-healthy regression canary: PASS"
