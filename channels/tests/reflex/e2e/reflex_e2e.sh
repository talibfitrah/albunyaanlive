#!/bin/bash
# Reflex E2E scenario runner.
# Usage: reflex_e2e.sh <scenario>
#   happy_path | all_dead | backup_dies | identity_handoff | flapping
#
# Uses a stub supervisor (fixtures/stub_try_start_stream.sh) in place of
# the real try_start_stream.sh so the test doesn't spawn ffmpeg/streamlink
# pipelines that would compete with production for CPU/NVENC on this host.
# The stub mimics the surface that reflex_watcher.sh + signals.sh actually
# observe: PID file location, "try_start_stream" in cmdline (for
# _pid_is_try_start_stream), and SIGUSR1/SIGUSR2 handlers.
#
# Everything runs inside /tmp/reflex-e2e/ — the production watcher (running
# against /var/run/albunyaan/ + /var/www/html/stream/hls/) is unaffected.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
CHANNELS="$ROOT_DIR/channels"
FIX_DIR="$SCRIPT_DIR/fixtures"

# Isolated env — override every reflex path so the test watcher only sees
# our test_channel and never touches production state.
export HLS_ROOT=/tmp/reflex-e2e/hls
export STATE_DIR=/tmp/reflex-e2e/state
export REFLEX_PID_DIR=/tmp/reflex-e2e/pid
export REFLEX_CMD_DIR=/tmp/reflex-e2e/cmd
export LOG_FILE=/tmp/reflex-e2e/logs/watcher.log
export CHANNEL_CONFIG_DIR="$FIX_DIR"
export INTERVAL=1
export REFLEX_DRY_RUN=0
export REFLEX_ENABLED=1
# Aggressive stall thresholds so the test doesn't need to wait 60+ s.
export STALL_WARN=3
export STALL_CRIT=6

CH=test_channel
PRIMARY_URL="http://127.0.0.1:18080/master.m3u8"
BACKUP_URL="http://127.0.0.1:18081/master.m3u8"
SIG_LOG=/tmp/reflex-e2e/logs/stub.${CH}.signals.log

scenario="${1:-happy_path}"

die()  { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

current_state() {
    jq -r '.state // "NONE"' "$STATE_DIR/$CH.json" 2>/dev/null || echo "NONE"
}

current_source_url() {
    jq -r '.current_source_url // ""' "$STATE_DIR/$CH.json" 2>/dev/null
}

STUB_PID=""
WPID=""

setup() {
    bash "$SCRIPT_DIR/setup_fixture.sh" >/tmp/reflex-e2e-setup.out 2>&1 \
        || { cat /tmp/reflex-e2e-setup.out >&2; die "fixture failed to come up"; }
    # setsid gives the stub its own session + process group so teardown can
    # TERM/KILL the whole tree. Note: `$!` points at the setsid wrapper,
    # not the stub — read the real PID from the PID file the stub writes.
    setsid bash "$FIX_DIR/stub_try_start_stream.sh" "$CH" "$PRIMARY_URL" \
        </dev/null >/tmp/reflex-e2e/logs/stub.out 2>&1 &
    local waited=0
    while (( waited < 20 )); do
        [[ -f "$REFLEX_PID_DIR/$CH.pid" ]] && \
        ls "$HLS_ROOT/$CH"/*.ts >/dev/null 2>&1 && break
        sleep 0.25; waited=$((waited+1))
    done
    STUB_PID=$(cat "$REFLEX_PID_DIR/$CH.pid" 2>/dev/null || echo "")
    [[ -n "$STUB_PID" ]] || die "stub never wrote pid file (see /tmp/reflex-e2e/logs/stub.out)"
    ls "$HLS_ROOT/$CH"/*.ts >/dev/null 2>&1 \
        || die "stub never produced segments (see /tmp/reflex-e2e/logs/stub.out)"
}

teardown() {
    if [[ -n "$WPID" ]]; then
        kill -TERM -"$WPID" 2>/dev/null || kill "$WPID" 2>/dev/null || true
        wait "$WPID" 2>/dev/null || true
    fi
    if [[ -n "$STUB_PID" ]]; then
        kill -TERM -"$STUB_PID" 2>/dev/null || kill "$STUB_PID" 2>/dev/null || true
        sleep 0.3
        kill -KILL -"$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
    bash "$SCRIPT_DIR/teardown_fixture.sh" >/dev/null 2>&1 || true
}
trap teardown EXIT

start_watcher() {
    setsid bash "$CHANNELS/reflex_watcher.sh" </dev/null \
        >/tmp/reflex-e2e/logs/watcher-wrapper.log 2>&1 &
    WPID=$!
}

kill_primary() {
    local pid; pid=$(cat /tmp/reflex-e2e/primary.pid 2>/dev/null) || return 0
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    # Wait for the socket to fully release.
    for _ in {1..20}; do
        ss -tln 2>/dev/null | grep -q '127.0.0.1:18080 ' || return 0
        sleep 0.1
    done
}

# wait_for_signal <keyword> <timeout_sec>  — grep SIG_LOG each second
wait_for_signal() {
    local kw="$1" tmo="$2" elapsed=0
    while (( elapsed < tmo )); do
        grep -q "$kw" "$SIG_LOG" 2>/dev/null && return 0
        sleep 1; elapsed=$((elapsed+1))
    done
    return 1
}

wait_for_state() {
    local tmo="$1"; shift
    local elapsed=0 s=""
    while (( elapsed < tmo )); do
        s=$(current_state)
        for want in "$@"; do [[ "$s" == "$want" ]] && { echo "$s"; return 0; }; done
        sleep 1; elapsed=$((elapsed+1))
    done
    echo "TIMEOUT(last=$s want=$*)"
    return 1
}

case "$scenario" in
    happy_path)
        setup
        start_watcher
        got=$(wait_for_state 10 LIVE) || die "initial state never LIVE ($got)"
        pass "initial state=$got"
        kill_primary
        echo "primary killed at $(date +%s.%N); waiting for slate signal..."
        wait_for_signal "signal=slate" 20 || die "stub never got SIGUSR1 (see $SIG_LOG)"
        pass "stub received SIGUSR1 (slate)"
        wait_for_signal "signal=swap target=.*18081" 25 \
            || die "stub never got SIGUSR2 with backup URL (see $SIG_LOG)"
        pass "stub received SIGUSR2 with backup URL"
        got=$(wait_for_state 10 BACKUP) || die "state never reached BACKUP ($got)"
        url=$(current_source_url)
        [[ "$url" == *":18081/"* ]] || die "current_source_url not backup1 ($url)"
        pass "happy_path — state=$got url=$url"
        ;;
    *)
        echo "unknown scenario: $scenario" >&2
        echo "available: happy_path" >&2
        exit 2 ;;
esac
