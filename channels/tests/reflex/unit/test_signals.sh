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
    #
    # <name> describes the kind of decoy:
    #   "supervisor:<ch>"  — a fake try_start_stream for <ch> (cmdline
    #                       anchored to argv tokens -n <ch> -d .../hls/<ch>/master.m3u8)
    #   "supervisor-only" — a try_start_stream-named process without any channel_id
    #                       (to test the channel-id guard rejects it)
    #   "innocent"        — an unrelated process whose cmdline must not match
    local name="$1" ttl="${2:-30}" pid_var="$3" ch=""
    case "$name" in
        supervisor:*) ch="${name#supervisor:}" ;;
    esac
    local _p fake_bin
    # Fake supervisor: the script body just sleeps (long enough for any test);
    # the argv carries the tokens that the anchored cmdline guard looks for.
    # Filename contains "try_start_stream" so the supervisor-presence check
    # (separate from the channel-id anchor) passes.
    fake_bin="$TEST_TMPDIR/fake_try_start_stream.sh"
    if [[ ! -x "$fake_bin" ]]; then
        cat > "$fake_bin" <<'EOF'
#!/bin/bash
# Ignores all args; they're in /proc/$$/cmdline for the test's cmdline guard.
sleep 600
EOF
        chmod +x "$fake_bin"
    fi
    if [[ -n "$ch" ]]; then
        setsid "$fake_bin" -n "$ch" -d "/var/www/html/stream/hls/$ch/master.m3u8" </dev/null &
        _p=$!
    elif [[ "$name" == supervisor-only ]]; then
        # Anchored guard expects an argv token; supervisor-only has none,
        # so the channel-id check must fail.
        setsid "$fake_bin" </dev/null &
        _p=$!
    else
        # "innocent" — unrelated process that must not match the guard at all.
        setsid bash -c "exec -a '$name' sleep 600" </dev/null &
        _p=$!
    fi
    for _ in {1..20}; do
        if [[ -r "/proc/$_p/cmdline" ]]; then
            local cl; cl=$(tr '\0' ' ' <"/proc/$_p/cmdline" 2>/dev/null)
            [[ -n "$cl" ]] && break
        fi
        sleep 0.05
    done
    printf -v "$pid_var" '%s' "$_p"
}

# ---------------------------------------------------------------------

test_dispatch_slate_signals_correct_pid() {
    _test_signals_setup
    local pid; _spawn_decoy "supervisor:chan_a" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "0" "slate dispatch success" || return 1
}

test_dispatch_swap_writes_cmd_file_and_signals() {
    _test_signals_setup
    local pid; _spawn_decoy "supervisor:chan_a" 30 pid
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

test_dispatch_rejects_substring_channel_id_collision() {
    # REGRESSION GUARD: channel_id "almajd" must NOT match the cmdline of
    # supervisor "almajd-kids". The old bare substring match would have
    # passed this and mis-fired SIGUSR1 to the wrong channel.
    _test_signals_setup
    local pid; _spawn_decoy "supervisor:almajd-kids" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/almajd.pid"
    dispatch_signal "SIGNAL:slate:almajd"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "1" "substring collision rejected" || return 1
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
    local pid; _spawn_decoy "innocent" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "1" "non-supervisor PID rejected" || return 1
}

test_pid_guard_rejects_cross_channel_reuse() {
    # CRITICAL regression guard: if channel A's PID was recycled to
    # channel B's try_start_stream, signals for A must NOT fire on B.
    # Guard anchors the channel_id match to argv tokens (-n ch or
    # /hls/ch/master.m3u8).
    _test_signals_setup
    local pid; _spawn_decoy "supervisor:chan_b" 30 pid
    echo "$pid" > "$REFLEX_PID_DIR/chan_a.pid"   # stale pid file for A
    dispatch_signal "SIGNAL:slate:chan_a"
    local rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    th_assert_eq "$rc" "1" "cross-channel PID reuse rejected" || return 1
}

th_run "slate dispatch delivers"               test_dispatch_slate_signals_correct_pid || exit 1
th_run "swap writes cmd file atomically"       test_dispatch_swap_writes_cmd_file_and_signals || exit 1
th_run "substring ch-id collision rejected"    test_dispatch_rejects_substring_channel_id_collision || exit 1
th_run "malformed lines rejected"              test_dispatch_rejects_malformed_line || exit 1
th_run "missing pid file → rc=1"               test_dispatch_missing_pid_file_returns_1 || exit 1
th_run "non-supervisor PID rejected"           test_pid_guard_rejects_non_supervisor_process || exit 1
th_run "cross-channel PID reuse rejected"      test_pid_guard_rejects_cross_channel_reuse || exit 1
echo "signals tests: all PASS"
