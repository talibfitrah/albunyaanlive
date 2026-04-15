#!/bin/bash
# channels/tests/reflex/unit/test_signals.sh
# Unit tests for channels/reflex/signals.sh — dispatch parser, PID guard,
# cmd-file atomic rename. Important surface because:
#   - signals.sh is the bridge between the state machine and real
#     channel supervisors. A regression here silently breaks dispatch.
#   - The PID-cmdline guard (_pid_is_try_start_stream) has a security
#     role: mis-firing across channels causes the wrong channel to go
#     to slate. Explicit tests for PID-reuse misfire protect this.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Override pid/cmd dirs into TEST_TMPDIR via test_helpers' th_setup.
# signals.sh reads them on source via env vars — source LATE.
_test_signals_setup() {
    export REFLEX_PID_DIR="$TEST_TMPDIR/pid"
    export REFLEX_CMD_DIR="$TEST_TMPDIR/cmd"
    mkdir -p "$REFLEX_PID_DIR" "$REFLEX_CMD_DIR"
    source "$REFLEX_DIR/signals.sh"
}

# Decoy helpers --------------------------------------------------------
# Spawn a process whose /proc/PID/cmdline contains the given substring,
# so we can exercise the cmdline guard without starting a real supervisor.
# Uses `bash -c "exec -a NAME sleep N"` which sets argv[0] to NAME.
# Waits briefly for the exec to settle so /proc/PID/cmdline reflects the
# sleep argv, not the bash wrapper's.
_spawn_decoy() {
    # Caller MUST pass a "pid_out" shell variable name — we set it in the
    # caller's scope. Avoids the $(subshell) pattern where the spawned
    # background process becomes orphaned / receives SIGHUP when the
    # subshell exits, which caused flaky tests.
    local name="$1" ttl="${2:-30}" pid_var="$3"
    setsid bash -c "exec -a '$name' sleep $ttl" </dev/null &
    local _p=$!
    for _ in {1..20}; do
        [[ -r "/proc/$_p/cmdline" ]] && \
          tr '\0' ' ' <"/proc/$_p/cmdline" 2>/dev/null | grep -q "$name" && break
        sleep 0.05
    done
    printf -v "$pid_var" '%s' "$_p"
}

# ---------------------------------------------------------------------

test_dispatch_slate_signals_correct_pid() {
    _test_signals_setup
    local pid; _spawn_decoy "try_start_stream_chan_a" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "0" "slate dispatch success" || return 1
}

test_dispatch_swap_writes_cmd_file_and_signals() {
    _test_signals_setup
    local pid; _spawn_decoy "try_start_stream_chan_a" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"
    dispatch_signal "SIGNAL:swap:chan_a:http://cdn.example:18080/master.m3u8"
    local rc=$?
    local written=""
    [[ -f "$REFLEX_CMD_DIR/chan_a.target_url" ]] && written=$(cat "$REFLEX_CMD_DIR/chan_a.target_url")
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "0" "swap dispatch success" || return 1
    th_assert_eq "$written" "http://cdn.example:18080/master.m3u8" \
        "target_url preserves colons in URL" || return 1
}

test_dispatch_rejects_malformed_line() {
    _test_signals_setup
    dispatch_signal "NOT_A_SIGNAL"
    th_assert_eq "$?" "2" "malformed line → rc=2" || return 1
    dispatch_signal "SIGNAL:unknown:chan_a"
    th_assert_eq "$?" "2" "unknown verb → rc=2" || return 1
    dispatch_signal "SIGNAL:swap:chan_a:"
    th_assert_eq "$?" "2" "swap missing URL → rc=2" || return 1
}

test_dispatch_missing_pid_file_returns_1() {
    _test_signals_setup
    rm -f "$REFLEX_PID_DIR/ghost.pid"
    dispatch_signal "SIGNAL:slate:ghost"
    th_assert_eq "$?" "1" "missing pid → rc=1" || return 1
}

test_pid_guard_rejects_non_supervisor_process() {
    _test_signals_setup
    # Spawn a decoy whose cmdline does NOT contain "try_start_stream".
    local pid; _spawn_decoy "random_innocent_proc" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "1" "non-supervisor PID rejected" || return 1
}

test_pid_guard_rejects_cross_channel_reuse() {
    # CRITICAL regression guard: if channel A's PID was recycled to
    # channel B's try_start_stream, signals for A must NOT fire on B.
    # Guard is: cmdline must contain BOTH "try_start_stream" AND the
    # channel_id we're signaling.
    _test_signals_setup
    local pid; _spawn_decoy "try_start_stream_chan_b" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"   # stale pid file for A
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "1" "cross-channel PID reuse rejected" || return 1
}

th_run "slate dispatch delivers"           test_dispatch_slate_signals_correct_pid || exit 1
th_run "swap writes cmd file atomically"   test_dispatch_swap_writes_cmd_file_and_signals || exit 1
th_run "malformed lines rejected"          test_dispatch_rejects_malformed_line || exit 1
th_run "missing pid file → rc=1"           test_dispatch_missing_pid_file_returns_1 || exit 1
th_run "non-supervisor PID rejected"       test_pid_guard_rejects_non_supervisor_process || exit 1
th_run "cross-channel PID reuse rejected"  test_pid_guard_rejects_cross_channel_reuse || exit 1
echo "signals tests: all PASS"
