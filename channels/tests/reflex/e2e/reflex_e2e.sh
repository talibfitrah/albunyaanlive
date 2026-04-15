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
    if [[ "${REFLEX_E2E_NO_TEARDOWN:-0}" == "1" ]]; then
        echo "--- teardown skipped (REFLEX_E2E_NO_TEARDOWN=1) ---" >&2
        echo "    state:  $STATE_DIR/$CH.json" >&2
        echo "    sig:    $SIG_LOG" >&2
        echo "    watcher: $LOG_FILE" >&2
        return 0
    fi
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
    rm -f /tmp/reflex-e2e/primary.pid
    for _ in {1..20}; do
        ss -tln 2>/dev/null | grep -q '127.0.0.1:18080 ' || return 0
        sleep 0.1
    done
}

kill_backup1() {
    local pid; pid=$(cat /tmp/reflex-e2e/backup1.pid 2>/dev/null) || return 0
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -f /tmp/reflex-e2e/backup1.pid
    for _ in {1..20}; do
        ss -tln 2>/dev/null | grep -q '127.0.0.1:18081 ' || return 0
        sleep 0.1
    done
}

start_primary() {
    # Restart only the primary server (upstream files still on disk).
    python3 -m http.server --bind 127.0.0.1 \
        --directory /tmp/reflex-e2e/upstream/primary 18080 \
        >>/tmp/reflex-e2e/logs/primary.log 2>&1 &
    echo $! >/tmp/reflex-e2e/primary.pid
    for _ in {1..20}; do
        curl -sf -o /dev/null http://127.0.0.1:18080/master.m3u8 && return 0
        sleep 0.2
    done
    return 1
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
    all_dead)
        setup
        start_watcher
        got=$(wait_for_state 10 LIVE) || die "initial state never LIVE ($got)"
        kill_primary
        kill_backup1
        wait_for_signal "signal=slate" 25 || die "stub never got SIGUSR1 after kill-both"
        pass "stub received SIGUSR1 (slate) after killing both upstreams"
        # The watcher has nothing to swap to: probe of backup1 fails, so
        # transitions.sh excludes it and stays in SLATE. No swap signals.
        # Hold for 30 s and verify no swap was dispatched and state stayed
        # either SLATE or DEGRADED (not thrashing between SLATE↔BACKUP).
        sleep 30
        swap_count=$(grep -c 'signal=swap' "$SIG_LOG" || true)
        (( swap_count == 0 )) || die "unexpected swap signals (count=$swap_count)"
        got=$(current_state)
        [[ "$got" == "SLATE" || "$got" == "DEGRADED" ]] \
            || die "state drifted to $got (expected SLATE or DEGRADED)"
        pass "all_dead — held in $got for 30 s, zero swap attempts"
        ;;

    backup_dies)
        setup
        start_watcher
        got=$(wait_for_state 10 LIVE) || die "initial state never LIVE ($got)"
        # Force the first LIVE→BACKUP transition.
        kill_primary
        wait_for_signal 'signal=swap target=.*18081' 30 \
            || die "stub never got swap to backup1"
        got=$(wait_for_state 10 BACKUP) || die "state never BACKUP ($got)"
        pass "reached BACKUP on backup1"
        # Now kill backup1 too. The stub (which is now probing backup1) will
        # stop touching segments → watcher sees stale → slate. Watcher then
        # probes backup1, fails, adds it to excluded_backups; no primary
        # available → stays in SLATE.
        slate_count_before=$(grep -c 'signal=slate' "$SIG_LOG" || true)
        kill_backup1
        # Wait for the second slate signal (caused by backup1 dying).
        # Budget: 30 s BACKUP-grace + 10 s stale threshold + 10 s slack = 50 s.
        for _ in {1..50}; do
            current_slate=$(grep -c 'signal=slate' "$SIG_LOG" || echo 0)
            (( current_slate > slate_count_before )) && break
            sleep 1
        done
        (( current_slate > slate_count_before )) \
            || die "stub never got 2nd slate signal after killing backup1"
        pass "stub received 2nd SIGUSR1 after backup1 died"
        # Give the watcher a cycle or two to add backup1 to excluded_backups.
        sleep 4
        excluded=$(jq -r '.excluded_backups[]? // empty' "$STATE_DIR/$CH.json")
        [[ "$excluded" == *"18081"* ]] \
            || die "backup1 URL not in excluded_backups: [$excluded]"
        got=$(current_state)
        [[ "$got" == "SLATE" || "$got" == "DEGRADED" ]] \
            || die "final state=$got (expected SLATE)"
        pass "backup_dies — excluded_backups contains 18081; final state=$got"
        ;;

    identity_handoff)
        setup
        start_watcher
        got=$(wait_for_state 10 LIVE) || die "initial state never LIVE ($got)"
        # Simulate brain writing identity_status=mismatch via wake.sh.
        # We emulate the file write that Phase 6.1's wake.sh wrapper does,
        # under flock, to keep byte-for-byte faithful to real production.
        python3 -c "
import json, fcntl, sys, os
path = '$STATE_DIR/$CH.json'
lock = '$STATE_DIR/$CH.lock'
with open(lock, 'w') as lf:
    fcntl.flock(lf, fcntl.LOCK_EX)
    with open(path) as f: s = json.load(f)
    s['identity_status'] = 'mismatch'
    s['reverify_requested'] = True
    tmp = path + '.tmp'
    with open(tmp, 'w') as f: json.dump(s, f, indent=2)
    os.replace(tmp, path)
"
        # Watcher's next cycle should emit slate.
        wait_for_signal 'signal=slate' 15 \
            || die "stub never got slate after identity_status=mismatch"
        pass "identity mismatch → slate within 15 s"
        got=$(wait_for_state 10 SLATE BACKUP) \
            || die "state never left LIVE ($got)"
        # reverify_requested remains true until brain flips it back.
        rv=$(jq -r '.reverify_requested' "$STATE_DIR/$CH.json")
        [[ "$rv" == "true" ]] || die "reverify_requested=$rv (expected true)"
        pass "identity_handoff — state=$got reverify_requested=true"
        ;;

    flapping)
        setup
        start_watcher
        got=$(wait_for_state 10 LIVE) || die "initial state never LIVE ($got)"
        # Seed 6 rapid transitions within the last 60 seconds. The primary
        # probe backoff is 300 s minimum, so the production state machine
        # can't physically flap the LIVE↔BACKUP loop inside the 120 s
        # circuit-breaker window on its own. The breaker's job is to fire
        # when it *sees* many transitions in that window — this scenario
        # exercises that logic directly, not the (slower) physical
        # conditions that produce it.
        now=$(date +%s)
        python3 -c "
import json, fcntl, sys, os
path = '$STATE_DIR/$CH.json'
lock = '$STATE_DIR/$CH.lock'
now = $now
with open(lock, 'w') as lf:
    fcntl.flock(lf, fcntl.LOCK_EX)
    with open(path) as f: s = json.load(f)
    hist = s.get('transition_history', [])
    for i in range(6):
        hist.append({'at': str(now - (6 - i) * 5),
                     'from': 'LIVE' if i % 2 == 0 else 'BACKUP',
                     'to':   'BACKUP' if i % 2 == 0 else 'LIVE',
                     'reason': 'seeded_flap'})
    s['transition_history'] = hist
    tmp = path + '.tmp'
    with open(tmp, 'w') as f: json.dump(s, f, indent=2)
    os.replace(tmp, path)
"
        got=$(wait_for_state 15 DEGRADED) \
            || die "circuit breaker never tripped after seeded flapping ($got)"
        pass "reached DEGRADED after seeded flap"
        # In DEGRADED, watcher should stop dispatching any new signals.
        slate_before=$(grep -c 'signal=slate' "$SIG_LOG" || true)
        swap_before=$(grep -c 'signal=swap'  "$SIG_LOG" || true)
        sleep 8
        slate_after=$(grep -c 'signal=slate' "$SIG_LOG" || true)
        swap_after=$(grep -c 'signal=swap'  "$SIG_LOG" || true)
        (( slate_after == slate_before )) || die "new slate signals while DEGRADED (before=$slate_before after=$slate_after)"
        (( swap_after  == swap_before  )) || die "new swap  signals while DEGRADED (before=$swap_before  after=$swap_after)"
        pass "flapping — DEGRADED state holds, zero new signals dispatched"
        ;;

    *)
        echo "unknown scenario: $scenario" >&2
        echo "available: happy_path | all_dead | backup_dies | identity_handoff | flapping" >&2
        exit 2 ;;
esac
