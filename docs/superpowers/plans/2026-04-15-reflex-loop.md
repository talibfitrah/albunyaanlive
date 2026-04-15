# Reflex Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the observe-only reflex watcher into an autonomous reflex loop that detects stale sources, engages a shared slate within ≤15 s, walks backup URLs, and returns to primary with exponential-backoff probing — with a brain → watcher handoff for identity mismatches.

**Architecture:** Extend `reflex_watcher.sh` as the single reflex component (no new processes or systemd units). Pure functions in small modules under `channels/reflex/` for testability. Per-channel state files at `/var/run/albunyaan/state/<channel_id>.json`. `try_start_stream.sh` gains PID-file + SIGUSR1/SIGUSR2 signal handlers so the watcher can instruct a channel supervisor to enter/leave slate mode. Brain writes `identity_status` to state files; watcher reads on next 5 s cycle.

**Tech Stack:** Bash, `jq`, `flock`, `find -newermt`, `curl`, `ffprobe`, systemd. No new language dependencies.

**Reference spec:** `docs/superpowers/specs/2026-04-15-reflex-loop-design.md` (commit `c2e0ef9`).

---

## Coordination with the dedicated Telegram session

This session does not send Telegram messages. Durable state changes propagate via shared project memory (`MEMORY.md` + `memory/*.md`). After each phase lands, append a one-line entry to `SESSION_HANDOFF.md` (to be created in Task 0) summarizing what changed, so the Telegram session's next wake picks up the delta. Existing `tg_alert()` calls in `reflex_watcher.sh` are unchanged — those are operational alerts that the watcher already owns; the constraint is this session, not the watcher process.

---

## File structure

**New files:**

```
channels/reflex/
  state.sh              — state file read/write, flock, atomic temp+rename
  freshness.sh          — is_output_fresh() thin wrapper over existing logic
  backoff.sh            — backoff_delay(n) for primary-probe schedule
  probe.sh              — probe_url(url, timeout)
  transitions.sh        — pure state-machine: (channel_state, signals) → (new_state, actions)
  signals.sh            — send_slate_signal(), send_resume_signal(), send_swap_signal() wrappers

channels/tests/reflex/
  lib/test_helpers.sh              — shared harness (tmpdir setup, assertions)
  lib/mock_try_start_stream.sh     — stub PID that captures signals for assertions
  unit/test_state.sh
  unit/test_freshness.sh
  unit/test_freshness_no_false_healthy.sh   — regression canary
  unit/test_backoff.sh
  unit/test_probe.sh
  integration/test_transitions.sh
  e2e/reflex_e2e.sh                — runs against a controlled test_channel fixture
  e2e/fixtures/nginx_upstream.conf — test upstream config
  e2e/fixtures/test_channel.sh     — channel config for the test fixture

/var/run/albunyaan/state/          — runtime state (created by systemd ExecStartPre)
/var/run/albunyaan/pid/            — try_start_stream PIDs (created by systemd ExecStartPre)

SESSION_HANDOFF.md                 — coordination log with the Telegram session
```

**Modified files:**

```
channels/reflex_watcher.sh         — add state-machine dispatch, action layer
channels/try_start_stream.sh       — add PID file write, SIGUSR1/SIGUSR2 handlers
channels/brain_loop/wake.sh        — read per-channel state file; brain writes identity_status
channels/brain_loop/PROMPT.md      — priority ordering for flagged channels; skip non-LIVE
channels/tests/run_tests.sh        — invoke tests/reflex/** suites
channels/albunyaan-watcher.service — add ExecStartPre preflight + /var/run/albunyaan creation
```

---

## Phasing

- **Phase 0** — prerequisites (one-time).
- **Phase 1** — utility modules (pure functions, no production effect).
- **Phase 2** — state machine (pure function, no production effect).
- **Phase 3** — watcher dry-run (computes transitions, logs them, does not act — lets us validate detection on real data safely).
- **Phase 4** — `try_start_stream.sh` signal handlers + PID file (does not activate anything yet).
- **Phase 5** — activate the reflex (watcher sends signals for real).
- **Phase 6** — brain handoff.
- **Phase 7** — E2E tests against a controlled fixture.
- **Phase 8** — operational integration (systemd preflight, test harness wiring).

Each phase is landable and reversible on its own. Phases 1–4 introduce zero behavior change in production.

---

## Phase 0 — Prerequisites

### Task 0: Create SESSION_HANDOFF.md

**Files:**
- Create: `SESSION_HANDOFF.md`

- [ ] **Step 1: Create the file**

Write to `/home/msa/Development/scripts/albunyaan/SESSION_HANDOFF.md`:

```markdown
# Session Handoff Log

Append-only coordination log between the SRE/dev session and the dedicated Telegram session.

## Convention

- New entries go at the bottom, newest last.
- Format: `## YYYY-MM-DD HH:MM TZ — <topic>`
- Body: what changed; what (if anything) the Telegram session needs to do.
- Status tags (optional, at end): `[NEW]`, `[ACK]` (other session has read), `[DONE]` (other session has acted), `[OBSOLETE]`.

## Log

## 2026-04-15 — Reflex loop plan started

Implementation plan for the autonomous reflex loop is at `docs/superpowers/plans/2026-04-15-reflex-loop.md`. Will land in phases 1–8; each phase ends with a handoff entry summarizing what the Telegram session may see (new state-file fields, new alert shapes, etc.). [NEW]
```

- [ ] **Step 2: Commit**

```bash
git add SESSION_HANDOFF.md
git commit -m "chore: add SESSION_HANDOFF.md for cross-session coordination"
```

---

## Phase 1 — Utility modules

### Task 1.1: `state.sh` — state file I/O

**Files:**
- Create: `channels/reflex/state.sh`
- Create: `channels/tests/reflex/lib/test_helpers.sh`
- Create: `channels/tests/reflex/unit/test_state.sh`

- [ ] **Step 1: Write the failing test**

Create `channels/tests/reflex/lib/test_helpers.sh`:

```bash
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
```

Create `channels/tests/reflex/unit/test_state.sh`:

```bash
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
```

- [ ] **Step 2: Run test — verify it fails**

```bash
bash channels/tests/reflex/unit/test_state.sh
```
Expected: error (file `reflex/state.sh` does not exist).

- [ ] **Step 3: Implement `channels/reflex/state.sh`**

```bash
#!/bin/bash
# channels/reflex/state.sh
# Per-channel state file I/O with atomic writes + flock serialization.
# State files live at $STATE_DIR/<channel_id>.json (default /var/run/albunyaan/state).

STATE_DIR="${STATE_DIR:-/var/run/albunyaan/state}"

_state_path()  { echo "$STATE_DIR/$1.json"; }
_state_lock()  { echo "$STATE_DIR/$1.lock"; }

_state_default_json() {
    local ch="$1" now; now=$(date -Iseconds)
    cat <<EOF
{
  "channel_id": "$ch",
  "state": "LIVE",
  "current_source_url": null,
  "current_source_role": null,
  "last_transition": "$now",
  "grace_until": "$now",
  "identity_status": "unknown",
  "identity_checked_at": null,
  "reverify_requested": false,
  "primary_probe": {
    "last_attempt": null,
    "consecutive_failures": 0,
    "consecutive_successes": 0,
    "next_attempt_after": "$now"
  },
  "backup_walk_cursor": 0,
  "excluded_backups": [],
  "slate_retry_count": 0,
  "transition_history": []
}
EOF
}

# state_init <channel_id>
# Ensures a valid state file exists. If the file is missing OR unparseable,
# (re-)creates it with defaults. Corrupt files are quarantined as .broken.<ts>.
state_init() {
    local ch="$1" path; path=$(_state_path "$ch")
    mkdir -p "$STATE_DIR"
    if [[ -f "$path" ]]; then
        if jq -e . "$path" >/dev/null 2>&1; then
            return 0
        fi
        local ts; ts=$(date +%s)
        mv "$path" "${path}.broken.${ts}"
    fi
    local tmp="${path}.tmp.$$"
    _state_default_json "$ch" > "$tmp"
    mv -f "$tmp" "$path"
}

# state_read_field <channel_id> <jq_expr>
# Returns the field as a plain string (jq -r).
state_read_field() {
    local ch="$1" expr="$2" path; path=$(_state_path "$ch")
    [[ -f "$path" ]] || { echo ""; return 1; }
    jq -r "$expr" "$path" 2>/dev/null
}

# state_modify <channel_id> <jq_expr>
# Applies the jq expression to the state file under flock. Atomic via
# temp-file-then-rename.
state_modify() {
    local ch="$1" expr="$2" path lock tmp
    path=$(_state_path "$ch"); lock=$(_state_lock "$ch")
    mkdir -p "$STATE_DIR"
    exec 200>"$lock"
    flock -x 200
    [[ -f "$path" ]] || _state_default_json "$ch" > "$path"
    tmp="${path}.tmp.$$"
    if ! jq "$expr" "$path" > "$tmp"; then
        rm -f "$tmp"
        exec 200>&-
        return 1
    fi
    mv -f "$tmp" "$path"
    exec 200>&-
}

# state_write_field <channel_id> <jq_expr_path> <jq_value_expr>
# Convenience wrapper: state_write_field ch ".state" '"SLATE"'
state_write_field() {
    local ch="$1" jpath="$2" jvalue="$3"
    state_modify "$ch" "${jpath} = ${jvalue}"
}
```

- [ ] **Step 4: Run test — verify it passes**

```bash
bash channels/tests/reflex/unit/test_state.sh
```
Expected: `state tests: all PASS`.

- [ ] **Step 5: Commit**

```bash
git add channels/reflex/state.sh channels/tests/reflex/lib/test_helpers.sh channels/tests/reflex/unit/test_state.sh
git commit -m "feat(reflex): add state.sh — per-channel state file I/O with flock

New module in channels/reflex/ with atomic read/modify/write for
/var/run/albunyaan/state/<channel_id>.json. Corrupt files are
quarantined as .broken.<ts> and reinitialized. Covered by
unit/test_state.sh including concurrent-writer test.

Pure addition — no production code wired to it yet."
```

---

### Task 1.2: `freshness.sh` — output freshness check (+ regression canary)

**Files:**
- Create: `channels/reflex/freshness.sh`
- Create: `channels/tests/reflex/unit/test_freshness.sh`
- Create: `channels/tests/reflex/unit/test_freshness_no_false_healthy.sh`

- [ ] **Step 1: Write failing tests**

Create `channels/tests/reflex/unit/test_freshness.sh`:

```bash
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
```

Create `channels/tests/reflex/unit/test_freshness_no_false_healthy.sh` (regression canary for the bug the spec names):

```bash
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
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
bash channels/tests/reflex/unit/test_freshness.sh
bash channels/tests/reflex/unit/test_freshness_no_false_healthy.sh
```
Expected: errors (file does not exist).

- [ ] **Step 3: Implement `channels/reflex/freshness.sh`**

```bash
#!/bin/bash
# channels/reflex/freshness.sh
# Output-freshness check: is any .ts segment in the channel's HLS dir
# fresher than the threshold? Returns 0=fresh, 1=stale, 2=no-dir.

# is_output_fresh <hls_dir> [threshold_seconds]
is_output_fresh() {
    local hls_dir="$1"
    local threshold_sec="${2:-10}"
    [[ -d "$hls_dir" ]] || return 2
    local fresh_count
    fresh_count=$(find "$hls_dir" -maxdepth 1 -name '*.ts' \
                       -newermt "-${threshold_sec} seconds" 2>/dev/null | wc -l)
    (( fresh_count > 0 ))
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
bash channels/tests/reflex/unit/test_freshness.sh
bash channels/tests/reflex/unit/test_freshness_no_false_healthy.sh
```
Expected: `freshness tests: all PASS` and `false-healthy regression canary: PASS`.

- [ ] **Step 5: Commit**

```bash
git add channels/reflex/freshness.sh channels/tests/reflex/unit/test_freshness.sh channels/tests/reflex/unit/test_freshness_no_false_healthy.sh
git commit -m "feat(reflex): add freshness.sh + regression canary

is_output_fresh() returns 0=fresh, 1=stale, 2=no-dir via find -newermt
against .ts files. Regression test covers the spec's named failure
mode: stale .ts with freshly-regenerated master.m3u8 must still
report stale."
```

---

### Task 1.3: `backoff.sh` — primary-probe backoff schedule

**Files:**
- Create: `channels/reflex/backoff.sh`
- Create: `channels/tests/reflex/unit/test_backoff.sh`

- [ ] **Step 1: Write failing test**

Create `channels/tests/reflex/unit/test_backoff.sh`:

```bash
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
```

- [ ] **Step 2: Run test — verify it fails**

```bash
bash channels/tests/reflex/unit/test_backoff.sh
```

- [ ] **Step 3: Implement `channels/reflex/backoff.sh`**

```bash
#!/bin/bash
# channels/reflex/backoff.sh
# Primary-probe backoff schedule (seconds).
# 0-2 failures → 5 min; 3 → 15 min; 4 → 30 min; 5+ → 60 min (cap).

backoff_delay() {
    local n="$1"
    case "$n" in
        0|1|2) echo 300 ;;
        3)     echo 900 ;;
        4)     echo 1800 ;;
        *)     echo 3600 ;;
    esac
}
```

- [ ] **Step 4: Run test — verify it passes**

```bash
bash channels/tests/reflex/unit/test_backoff.sh
```

- [ ] **Step 5: Commit**

```bash
git add channels/reflex/backoff.sh channels/tests/reflex/unit/test_backoff.sh
git commit -m "feat(reflex): add backoff.sh — primary-probe schedule per spec §7"
```

---

### Task 1.4: `probe.sh` — lightweight URL health probe

**Files:**
- Create: `channels/reflex/probe.sh`
- Create: `channels/tests/reflex/unit/test_probe.sh`

- [ ] **Step 1: Write failing test**

Create `channels/tests/reflex/unit/test_probe.sh`:

```bash
#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/probe.sh"

# Spin up a throwaway HTTP server in bash using python3 one-liner.
PY_PORT=18089

start_fixture_server() {
    python3 -c "
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == '/ok.m3u8':
            self.send_response(200); self.send_header('Content-Type', 'application/vnd.apple.mpegurl'); self.end_headers()
        elif self.path == '/notfound.m3u8':
            self.send_response(404); self.end_headers()
        else:
            self.send_response(500); self.end_headers()
    def do_GET(self): self.do_HEAD()
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('127.0.0.1', $PY_PORT), H) as s:
    s.serve_forever()
" &
    FIXTURE_PID=$!
    # Wait briefly for the server to bind
    for _ in {1..20}; do
        curl -sI "http://127.0.0.1:$PY_PORT/ok.m3u8" >/dev/null 2>&1 && break
        sleep 0.1
    done
}

stop_fixture_server() {
    [[ -n "${FIXTURE_PID:-}" ]] && kill "$FIXTURE_PID" 2>/dev/null && wait "$FIXTURE_PID" 2>/dev/null
}

trap stop_fixture_server EXIT

test_probe_200_passes() {
    start_fixture_server
    probe_url "http://127.0.0.1:$PY_PORT/ok.m3u8" 2
    local rc=$?
    stop_fixture_server
    th_assert_eq "$rc" "0" "200 → pass" || return 1
}

test_probe_404_fails() {
    start_fixture_server
    probe_url "http://127.0.0.1:$PY_PORT/notfound.m3u8" 2
    local rc=$?
    stop_fixture_server
    th_assert_eq "$rc" "1" "404 → fail" || return 1
}

test_probe_timeout_fails() {
    # Hit an unrouted address to force timeout
    probe_url "http://192.0.2.1/never.m3u8" 1
    local rc=$?
    th_assert_eq "$rc" "1" "timeout → fail" || return 1
}

th_run "probe 200 passes"    test_probe_200_passes   || exit 1
th_run "probe 404 fails"     test_probe_404_fails    || exit 1
th_run "probe timeout fails" test_probe_timeout_fails || exit 1
echo "probe tests: all PASS"
```

- [ ] **Step 2: Run test — verify it fails**

```bash
bash channels/tests/reflex/unit/test_probe.sh
```

- [ ] **Step 3: Implement `channels/reflex/probe.sh`**

```bash
#!/bin/bash
# channels/reflex/probe.sh
# Lightweight URL health check for primary/backup sources.
# Returns 0 if the URL responds acceptably within <timeout> seconds, else 1.
# HTTP(S): HEAD → 200 OK.
# Non-HTTP (rtmp/rtsp/etc.): ffprobe with hard timeout.

probe_url() {
    local url="$1" timeout="${2:-2}"
    if [[ "$url" =~ ^https?:// ]]; then
        local code
        code=$(curl -sI --max-time "$timeout" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")
        [[ "$code" == "200" ]]
    else
        # ffprobe -timeout takes microseconds
        local us=$(( timeout * 1000000 ))
        ffprobe -v error -timeout "$us" -i "$url" \
                -select_streams v:0 -show_entries stream=codec_type -of csv=p=0 \
                >/dev/null 2>&1
    fi
}
```

- [ ] **Step 4: Run test — verify it passes**

```bash
bash channels/tests/reflex/unit/test_probe.sh
```

- [ ] **Step 5: Commit**

```bash
git add channels/reflex/probe.sh channels/tests/reflex/unit/test_probe.sh
git commit -m "feat(reflex): add probe.sh — HEAD/ffprobe URL health check"
```

---

## Phase 2 — State machine (pure function)

### Task 2.1: `transitions.sh` — pure state-machine

Design: one function `next_state(channel_config_json, state_json, now_unix)` reads current state + freshness + probe results, returns a new state JSON + list of side-effect actions (as lines on stdout). No direct I/O inside the function — callers supply inputs and handle outputs. This makes it trivially testable.

**Files:**
- Create: `channels/reflex/transitions.sh`
- Create: `channels/tests/reflex/integration/test_transitions.sh`

- [ ] **Step 1: Write failing test**

Create `channels/tests/reflex/integration/test_transitions.sh`:

```bash
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
```

- [ ] **Step 2: Run test — verify it fails**

```bash
bash channels/tests/reflex/integration/test_transitions.sh
```

- [ ] **Step 3: Implement `channels/reflex/transitions.sh`**

```bash
#!/bin/bash
# channels/reflex/transitions.sh
# Pure state-machine. Given (channel_cfg_json, current_state_json, now_unix),
# updates the state file in place via state_modify and emits action lines
# on stdout for the caller to handle:
#   SIGNAL:slate:<channel_id>
#   SIGNAL:swap:<channel_id>:<url>
# Does not fork ffmpeg, does not call curl directly (uses probe_url,
# which the caller may stub).
#
# Depends on: state.sh, freshness.sh, backoff.sh, probe.sh

# Helper used by tests to locate the state file path
state_path_for() { echo "${STATE_DIR:-/var/run/albunyaan/state}/$1.json"; }

# _count_recent_transitions <channel_id> <now_unix> <window_sec>
# Returns count of transitions in the last <window_sec> seconds.
_count_recent_transitions() {
    local ch="$1" now="$2" window="$3"
    local cutoff=$(( now - window ))
    state_read_field "$ch" "[.transition_history[] | select((.at|tonumber) >= $cutoff)] | length" 2>/dev/null || echo 0
}

# _push_transition <channel_id> <from> <to> <reason>
_push_transition() {
    local ch="$1" from="$2" to="$3" reason="$4"
    local now; now=$(date +%s)
    state_modify "$ch" "
      .transition_history += [{at: \"$now\", from: \"$from\", to: \"$to\", reason: \"$reason\"}]
      | .transition_history |= (if length > 50 then .[-50:] else . end)
      | .last_transition = \"$(date -Iseconds)\"
    "
}

# _iso_plus <seconds>   → now + N seconds in ISO8601
_iso_plus() { date -Iseconds -d "@$(( $(date +%s) + $1 ))"; }

# Main dispatcher — emits SIGNAL lines and returns.
next_state() {
    local cfg_json="$1" state_json="$2" now_unix="$3"
    local ch; ch=$(jq -r '.channel_id' <<<"$cfg_json")
    local hls_dir; hls_dir=$(jq -r '.hls_dir' <<<"$cfg_json")
    local primary_url; primary_url=$(jq -r '.primary_url' <<<"$cfg_json")
    local backups; backups=$(jq -c '.backup_urls' <<<"$cfg_json")
    local cur_state; cur_state=$(jq -r '.state' <<<"$state_json")
    local grace_until; grace_until=$(jq -r '.grace_until' <<<"$state_json")
    local identity_status; identity_status=$(jq -r '.identity_status' <<<"$state_json")
    local grace_unix; grace_unix=$(date -d "$grace_until" +%s 2>/dev/null || echo 0)
    local in_grace=0
    (( now_unix < grace_unix )) && in_grace=1

    # Circuit breaker check — applies from any state
    if [[ "$cur_state" != "DEGRADED" ]]; then
        local rc; rc=$(_count_recent_transitions "$ch" "$now_unix" 120)
        if (( rc > 5 )); then
            _push_transition "$ch" "$cur_state" "DEGRADED" "flapping"
            state_write_field "$ch" ".state" '"DEGRADED"'
            return
        fi
    fi

    case "$cur_state" in
        LIVE)    _handle_live    "$ch" "$hls_dir" "$state_json" "$cfg_json" "$in_grace" "$identity_status" "$now_unix" ;;
        SLATE)   _handle_slate   "$ch" "$state_json" "$cfg_json" "$primary_url" "$backups" "$now_unix" ;;
        BACKUP)  _handle_backup  "$ch" "$hls_dir" "$state_json" "$cfg_json" "$primary_url" "$in_grace" "$now_unix" ;;
        DEGRADED) : ;;   # no auto action
    esac
}

_handle_live() {
    local ch="$1" hls_dir="$2" state_json="$3" cfg_json="$4" in_grace="$5" identity_status="$6" now_unix="$7"

    # Identity-mismatch short-circuit (takes precedence over staleness)
    if [[ "$identity_status" == "mismatch" && "$in_grace" == "0" ]]; then
        _push_transition "$ch" "LIVE" "SLATE" "identity_mismatch"
        state_modify "$ch" '
          .state = "SLATE"
          | .current_source_url = null
          | .current_source_role = null
          | .reverify_requested = true
          | .slate_retry_count = 0
        '
        echo "SIGNAL:slate:$ch"
        return
    fi

    [[ "$in_grace" == "1" ]] && return

    is_output_fresh "$hls_dir" 10
    case $? in
        0) return ;;   # fresh — stay
        1)             # stale — slate
            _push_transition "$ch" "LIVE" "SLATE" "staleness"
            state_modify "$ch" '
              .state = "SLATE"
              | .current_source_url = null
              | .current_source_role = null
              | .slate_retry_count = 0
              | .primary_probe.next_attempt_after = "'"$(_iso_plus 300)"'"
            '
            echo "SIGNAL:slate:$ch" ;;
        2) return ;;   # no dir — log, stay. Caller handles.
    esac
}

_handle_slate() {
    local ch="$1" state_json="$2" cfg_json="$3" primary_url="$4" backups="$5" now_unix="$6"

    # 1. Primary probe (respecting backoff)
    local next_after; next_after=$(jq -r '.primary_probe.next_attempt_after' <<<"$state_json")
    local next_after_u; next_after_u=$(date -d "$next_after" +%s 2>/dev/null || echo 0)
    if (( now_unix >= next_after_u )); then
        if probe_url "$primary_url" 2; then
            local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
            succ=$(( succ + 1 ))
            if (( succ >= 2 )); then
                _push_transition "$ch" "SLATE" "LIVE" "primary_recovered"
                state_modify "$ch" '
                  .state = "LIVE"
                  | .current_source_url = "'"$primary_url"'"
                  | .current_source_role = "primary"
                  | .grace_until = "'"$(_iso_plus 30)"'"
                  | .primary_probe = {last_attempt:"'"$(_iso_plus 0)"'", consecutive_failures:0, consecutive_successes:0, next_attempt_after:"'"$(_iso_plus 0)"'"}
                  | .excluded_backups = []
                  | .reverify_requested = false
                '
                echo "SIGNAL:swap:$ch:$primary_url"
                return
            else
                state_modify "$ch" ".primary_probe.consecutive_successes = $succ | .primary_probe.last_attempt = \"$(_iso_plus 0)\""
            fi
        else
            local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
            fail=$(( fail + 1 ))
            local delay; delay=$(backoff_delay "$fail")
            state_modify "$ch" "
              .primary_probe.consecutive_failures = $fail
              | .primary_probe.consecutive_successes = 0
              | .primary_probe.last_attempt = \"$(_iso_plus 0)\"
              | .primary_probe.next_attempt_after = \"$(_iso_plus $delay)\"
            "
        fi
    fi

    # 2. Walk one backup per cycle (round-robin)
    local total; total=$(jq -r 'length' <<<"$backups")
    (( total == 0 )) && return
    local cursor; cursor=$(jq -r '.backup_walk_cursor' <<<"$state_json")
    local idx=$(( cursor % total ))
    local url; url=$(jq -r ".[$idx]" <<<"$backups")
    state_modify "$ch" ".backup_walk_cursor = $(( (idx + 1) % total ))"
    # Skip if excluded
    if jq -e --arg u "$url" '.excluded_backups | index($u)' <<<"$state_json" >/dev/null; then
        return
    fi
    if probe_url "$url" 2; then
        _push_transition "$ch" "SLATE" "BACKUP" "backup_probe_ok"
        state_modify "$ch" '
          .state = "BACKUP"
          | .current_source_url = "'"$url"'"
          | .current_source_role = "backup"
          | .grace_until = "'"$(_iso_plus 30)"'"
          | .slate_retry_count = 0
        '
        echo "SIGNAL:swap:$ch:$url"
    fi
}

_handle_backup() {
    local ch="$1" hls_dir="$2" state_json="$3" cfg_json="$4" primary_url="$5" in_grace="$6" now_unix="$7"
    local identity_status; identity_status=$(jq -r '.identity_status' <<<"$state_json")
    local cur_url; cur_url=$(jq -r '.current_source_url' <<<"$state_json")

    # Identity mismatch on the current BACKUP → exclude it, slate
    if [[ "$identity_status" == "mismatch" && "$in_grace" == "0" ]]; then
        _push_transition "$ch" "BACKUP" "SLATE" "identity_mismatch"
        state_modify "$ch" "
          .state = \"SLATE\"
          | .excluded_backups += [\"$cur_url\"]
          | .current_source_url = null
          | .current_source_role = null
          | .reverify_requested = true
          | .slate_retry_count = 0
        "
        echo "SIGNAL:slate:$ch"
        return
    fi

    if [[ "$in_grace" == "0" ]]; then
        is_output_fresh "$hls_dir" 10
        if [[ $? -eq 1 ]]; then
            _push_transition "$ch" "BACKUP" "SLATE" "backup_stale"
            state_modify "$ch" "
              .state = \"SLATE\"
              | .excluded_backups += [\"$cur_url\"]
              | .current_source_url = null
              | .current_source_role = null
              | .slate_retry_count = 0
            "
            echo "SIGNAL:slate:$ch"
            return
        fi
    fi

    # Primary-return probe (same logic as SLATE's primary probe, minus backup walk)
    local next_after; next_after=$(jq -r '.primary_probe.next_attempt_after' <<<"$state_json")
    local next_after_u; next_after_u=$(date -d "$next_after" +%s 2>/dev/null || echo 0)
    if (( now_unix >= next_after_u )); then
        if probe_url "$primary_url" 2; then
            local succ; succ=$(jq -r '.primary_probe.consecutive_successes' <<<"$state_json")
            succ=$(( succ + 1 ))
            if (( succ >= 2 )); then
                _push_transition "$ch" "BACKUP" "LIVE" "primary_recovered"
                state_modify "$ch" '
                  .state = "LIVE"
                  | .current_source_url = "'"$primary_url"'"
                  | .current_source_role = "primary"
                  | .grace_until = "'"$(_iso_plus 30)"'"
                  | .primary_probe = {last_attempt:"'"$(_iso_plus 0)"'", consecutive_failures:0, consecutive_successes:0, next_attempt_after:"'"$(_iso_plus 0)"'"}
                  | .excluded_backups = []
                  | .reverify_requested = false
                '
                echo "SIGNAL:swap:$ch:$primary_url"
            else
                state_modify "$ch" ".primary_probe.consecutive_successes = $succ | .primary_probe.last_attempt = \"$(_iso_plus 0)\""
            fi
        else
            local fail; fail=$(jq -r '.primary_probe.consecutive_failures' <<<"$state_json")
            fail=$(( fail + 1 ))
            local delay; delay=$(backoff_delay "$fail")
            state_modify "$ch" "
              .primary_probe.consecutive_failures = $fail
              | .primary_probe.consecutive_successes = 0
              | .primary_probe.last_attempt = \"$(_iso_plus 0)\"
              | .primary_probe.next_attempt_after = \"$(_iso_plus $delay)\"
            "
        fi
    fi
}
```

- [ ] **Step 4: Run test — verify it passes**

```bash
bash channels/tests/reflex/integration/test_transitions.sh
```

- [ ] **Step 5: Commit**

```bash
git add channels/reflex/transitions.sh channels/tests/reflex/integration/test_transitions.sh
git commit -m "feat(reflex): add transitions.sh — pure state-machine

Emits SIGNAL: lines for slate/swap; caller handles dispatch. State file
updates are confined here via state_modify. Seven integration tests
cover the state matrix from spec §7 + identity mismatch + flapping.

Pure addition — not wired to the watcher yet."
```

---

## Phase 3 — Watcher dry-run

### Task 3.1: Dry-run dispatch in `reflex_watcher.sh`

Add a new mode controlled by env `REFLEX_DRY_RUN=1` (default). When set, the watcher computes next-state transitions and logs the SIGNAL lines instead of dispatching them. This lets us land the integration in production and watch the log for a day to validate detection against real data before turning on the action layer.

**Files:**
- Modify: `channels/reflex_watcher.sh`

- [ ] **Step 1: Extend watcher with dry-run dispatch**

Edit `channels/reflex_watcher.sh`. After the existing `trap 'log "reflex_watcher stopping"; exit 0' INT TERM` line (near the end of the file), replace the main `while true` loop with:

```bash
# ---------------------------------------------------------------------------
# Reflex loop — Phase 3 dry-run mode.
# When REFLEX_DRY_RUN=1 (default during rollout), the state machine runs
# but signals are logged only, not dispatched to try_start_stream.
# ---------------------------------------------------------------------------

REFLEX_DRY_RUN="${REFLEX_DRY_RUN:-1}"
REFLEX_LIB_DIR="$(dirname "${BASH_SOURCE[0]}")/reflex"
if [[ -d "$REFLEX_LIB_DIR" ]]; then
    # shellcheck source=reflex/state.sh
    source "$REFLEX_LIB_DIR/state.sh"
    # shellcheck source=reflex/freshness.sh
    source "$REFLEX_LIB_DIR/freshness.sh"
    # shellcheck source=reflex/backoff.sh
    source "$REFLEX_LIB_DIR/backoff.sh"
    # shellcheck source=reflex/probe.sh
    source "$REFLEX_LIB_DIR/probe.sh"
    # shellcheck source=reflex/transitions.sh
    source "$REFLEX_LIB_DIR/transitions.sh"
    REFLEX_ENABLED=1
else
    REFLEX_ENABLED=0
fi

# Build channel config JSON once per cycle.
# Today's channel configs live in channels/channel_*.sh and export
# stream_url, stream_url_backup{1,2,3}. We mine them without sourcing
# (scripts invoke generic_channel.sh at end).
_channel_cfg_json() {
    local ch="$1" script_dir="$2"
    local script; script=$(ls "$script_dir"/channel_"$ch"*.sh 2>/dev/null | head -1)
    [[ -z "$script" ]] && { echo ""; return; }
    local primary backups=()
    primary=$(grep -E '^stream_url=' "$script" | head -1 | sed -E 's/^stream_url="([^"]*)".*/\1/')
    for i in 1 2 3; do
        local v
        v=$(grep -E "^stream_url_backup${i}=" "$script" | head -1 | sed -E 's/^[^=]+="([^"]*)".*/\1/')
        [[ -n "$v" ]] && backups+=("$v")
    done
    local backups_json="[]"
    if (( ${#backups[@]} > 0 )); then
        backups_json=$(printf '%s\n' "${backups[@]}" | jq -R . | jq -sc .)
    fi
    jq -n \
        --arg id "$ch" \
        --arg p "$primary" \
        --argjson b "$backups_json" \
        --arg d "$HLS_ROOT/$ch" \
        '{channel_id:$id, primary_url:$p, backup_urls:$b, hls_dir:$d}'
}

_reflex_cycle() {
    [[ "$REFLEX_ENABLED" == "1" ]] || return 0
    mkdir -p "$STATE_DIR"
    local script_dir; script_dir="$(dirname "${BASH_SOURCE[0]}")"
    local now; now=$(date +%s)
    for dir in "$HLS_ROOT"/*/; do
        local ch; ch=$(basename "$dir")
        [[ "$ch" == "slate" ]] && continue
        local cfg; cfg=$(_channel_cfg_json "$ch" "$script_dir")
        [[ -z "$cfg" ]] && continue
        state_init "$ch"
        local state_blob; state_blob=$(cat "$(state_path_for "$ch")")
        local actions; actions=$(next_state "$cfg" "$state_blob" "$now")
        if [[ -n "$actions" ]]; then
            while IFS= read -r line; do
                if [[ "$REFLEX_DRY_RUN" == "1" ]]; then
                    log "reflex(dry-run) $line"
                else
                    log "reflex $line"
                    # Phase 5 will wire real dispatch here.
                fi
            done <<<"$actions"
        fi
    done
}

STATE_DIR="${STATE_DIR:-/var/run/albunyaan/state}"

log "reflex_watcher started (interval=${INTERVAL}s, stall_warn=${STALL_WARN}s, stall_crit=${STALL_CRIT}s, reflex_enabled=$REFLEX_ENABLED, dry_run=$REFLEX_DRY_RUN)"

while true; do
    emit_state
    log_anomalies
    check_alerts
    _reflex_cycle
    TICK_COUNT=$((TICK_COUNT + 1))
    sleep "$INTERVAL"
done
```

- [ ] **Step 2: Syntax check**

```bash
bash -n channels/reflex_watcher.sh
```
Expected: exit 0, no output.

- [ ] **Step 3: Local smoke test (dry-run)**

```bash
# Run the watcher briefly against a scratch state dir — should log dry-run lines without exiting
STATE_DIR=/tmp/reflex-smoke-$$/state \
HLS_ROOT=/var/www/html/stream/hls \
LOG_FILE=/tmp/reflex-smoke-$$.log \
INTERVAL=1 \
REFLEX_DRY_RUN=1 \
timeout 3 bash channels/reflex_watcher.sh || true
grep -c "reflex(dry-run)" /tmp/reflex-smoke-$$.log
```
Expected: a positive integer (at least one dry-run line per channel per cycle).

- [ ] **Step 4: Append SESSION_HANDOFF entry**

```bash
cat >> SESSION_HANDOFF.md <<'EOF'

## 2026-04-15 — Reflex watcher now runs in dry-run mode

`reflex_watcher.sh` loads the new `channels/reflex/*.sh` modules and runs
the state-machine each cycle. Output: `reflex(dry-run) SIGNAL:...` lines
in the watcher log. No signals are dispatched yet; the action layer is
gated by `REFLEX_DRY_RUN=0` (Phase 5). New state files appear at
`/var/run/albunyaan/state/<channel_id>.json`. [NEW]
EOF
```

- [ ] **Step 5: Commit**

```bash
git add channels/reflex_watcher.sh SESSION_HANDOFF.md
git commit -m "feat(reflex): wire state machine into watcher (dry-run mode)

Watcher now loads channels/reflex/*.sh and runs the state machine each
cycle. Actions are logged as 'reflex(dry-run) SIGNAL:...' lines but not
dispatched. Controlled by REFLEX_DRY_RUN=1 (default). State files land
at /var/run/albunyaan/state/<channel_id>.json.

No production behavior change yet."
```

- [ ] **Step 6: Deploy and observe for ≥1 hour**

```bash
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
# After ~1 hour:
tail -200 channels/logs/reflex_watcher.log | grep "reflex(dry-run)" | head -30
```

Expected: dry-run lines align with reality — channels the existing alerter flags as stalled should show `SIGNAL:slate:<ch>` lines; healthy channels should show no SIGNAL lines. If dry-run flags healthy channels, investigate before proceeding to Phase 4.

---

## Phase 4 — `try_start_stream.sh` signal handlers

### Task 4.1: Add PID file + signal handlers

**Files:**
- Modify: `channels/try_start_stream.sh`

- [ ] **Step 1: Add PID write near start**

In `channels/try_start_stream.sh`, locate the line `channel_id=$(basename "$(dirname "$destination")")` (~line 265 based on Phase 3 audit; `grep -n` to confirm). Immediately after the `if [[ -z "$channel_name" ]]; then channel_name="$channel_id"; fi` block, add:

```bash
# =============================================================================
# PID file for external signal dispatch (reflex watcher uses this).
# =============================================================================
REFLEX_PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"
mkdir -p "$REFLEX_PID_DIR" 2>/dev/null || true
REFLEX_PID_FILE="$REFLEX_PID_DIR/${channel_id}.pid"
echo $$ > "$REFLEX_PID_FILE" 2>/dev/null || log_error "Could not write PID file $REFLEX_PID_FILE"
trap 'rm -f "$REFLEX_PID_FILE"' EXIT

# =============================================================================
# Reflex signal handlers — watcher may send SIGUSR1 (enter slate) or
# SIGUSR2 (leave slate + switch to next URL).
# =============================================================================
reflex_force_slate=0
reflex_target_url=""
REFLEX_CMD_DIR="${REFLEX_CMD_DIR:-/var/run/albunyaan/cmd}"

_read_reflex_target_url() {
    local f="$REFLEX_CMD_DIR/${channel_id}.target_url"
    [[ -r "$f" ]] || { echo ""; return; }
    local url; url=$(head -1 "$f" 2>/dev/null)
    echo "$url"
}

trap 'reflex_force_slate=1; log "REFLEX: SIGUSR1 received — will enter slate on next loop iteration"' USR1
trap 'reflex_force_slate=0; reflex_target_url=$(_read_reflex_target_url); log "REFLEX: SIGUSR2 received — will switch to URL: $reflex_target_url"' USR2
```

- [ ] **Step 2: Make the main loop respect reflex signals**

In the main URL-cycling loop (the `while true` near the end of `try_start_stream.sh`), find the place where a new FFmpeg iteration is about to start. Add at the TOP of the loop body:

```bash
    # Reflex handover: if watcher signalled slate, switch to slate stream
    # for as long as the flag is held.
    if (( reflex_force_slate == 1 )); then
        if [[ -z "$slate_ffmpeg_pid" ]] || ! kill -0 "$slate_ffmpeg_pid" 2>$DEVNULL; then
            kill_feeder 2>/dev/null || true
            if start_slate_stream; then
                log "REFLEX: slate stream engaged under external signal"
            else
                log "REFLEX: failed to start slate (slate video missing?)"
            fi
        fi
        sleep 1
        continue
    fi

    # Reflex handover: if watcher signalled a specific target URL, stop
    # slate, locate that URL in the url_array, jump to it.
    if [[ -n "$reflex_target_url" ]]; then
        stop_slate_stream
        local target="$reflex_target_url"
        reflex_target_url=""
        local found=-1
        for i in "${!url_array[@]}"; do
            if [[ "${url_array[$i]}" == "$target" ]]; then
                found="$i"; break
            fi
        done
        if [[ "$found" -ge 0 ]]; then
            current_url_index="$found"
            reset_url_retries
            log "REFLEX: URL-swap to index $found ($target)"
        else
            log "REFLEX: target URL not in url_array, advancing normally: $target"
            switch_to_next_url "reflex_signal"
        fi
    fi
```

- [ ] **Step 3: Syntax check + existing test suite**

```bash
bash -n channels/try_start_stream.sh
bash channels/tests/run_tests.sh
```
Expected: no errors; existing tests still green.

- [ ] **Step 4: Manual smoke test**

```bash
# Pick an unused channel HLS dir
test_ch=test_reflex_$$
dest=/tmp/$test_ch
mkdir -p "$dest"
# Start try_start_stream in background with a dummy valid URL (will fail to fetch but the PID file + signals still work)
bash channels/try_start_stream.sh -u "http://127.0.0.1:9/nonexistent.m3u8" -d "$dest" -n "$test_ch" &
sleep 2
pid=$(cat /var/run/albunyaan/pid/${test_ch}.pid)
echo "PID: $pid"
kill -USR1 "$pid"; sleep 2
grep "SIGUSR1 received" /tmp/try_start_stream_*.log | tail -1
kill "$pid"; wait "$pid" 2>/dev/null || true
rm -rf "$dest"
```
Expected: log line confirming the SIGUSR1 handler fired.

- [ ] **Step 5: Commit**

```bash
git add channels/try_start_stream.sh
git commit -m "feat(try_start_stream): PID file + SIGUSR1/SIGUSR2 reflex handlers

Each channel supervisor writes its PID to /var/run/albunyaan/pid/<ch>.pid.
SIGUSR1 engages the slate stream; SIGUSR2 leaves slate and advances to
the next backup URL. Watcher will use these in Phase 5.

Zero behavior change until the watcher sends signals."
```

---

## Phase 5 — Activate the reflex

### Task 5.1: `signals.sh` and watcher live dispatch

**Files:**
- Create: `channels/reflex/signals.sh`
- Modify: `channels/reflex_watcher.sh`

- [ ] **Step 1: Create the signals module**

```bash
#!/bin/bash
# channels/reflex/signals.sh
# Send reflex control signals to a channel's try_start_stream.sh supervisor.

REFLEX_PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"

# _pid_for <channel_id>
_pid_for() {
    local pf="$REFLEX_PID_DIR/$1.pid"
    [[ -r "$pf" ]] || return 1
    cat "$pf"
}

# send_slate_signal <channel_id>    → SIGUSR1 (enter slate)
send_slate_signal() {
    local pid; pid=$(_pid_for "$1") || return 1
    kill -USR1 "$pid" 2>/dev/null
}

# send_resume_signal <channel_id> <target_url>
# Writes the target URL to a per-channel command file, then sends SIGUSR2.
# try_start_stream.sh reads the file in its SIGUSR2 handler and switches
# to exactly that URL (not whichever happens to be next in rotation).
REFLEX_CMD_DIR="${REFLEX_CMD_DIR:-/var/run/albunyaan/cmd}"
send_resume_signal() {
    local ch="$1" target_url="$2" pid
    pid=$(_pid_for "$ch") || return 1
    mkdir -p "$REFLEX_CMD_DIR" 2>/dev/null || true
    local tmp="$REFLEX_CMD_DIR/$ch.target_url.tmp"
    local dst="$REFLEX_CMD_DIR/$ch.target_url"
    printf '%s\n' "$target_url" > "$tmp" && mv -f "$tmp" "$dst"
    kill -USR2 "$pid" 2>/dev/null
}

# dispatch_signal <SIGNAL line from transitions.sh>
# Parses "SIGNAL:slate:<ch>" or "SIGNAL:swap:<ch>:<url>" and invokes
# the corresponding signal. Returns 0 on success, non-zero if no PID.
dispatch_signal() {
    local line="$1"
    case "$line" in
        SIGNAL:slate:*)
            local ch="${line#SIGNAL:slate:}"
            send_slate_signal "$ch" ;;
        SIGNAL:swap:*)
            # Strip prefix, then channel is up to the next ':', URL is the rest
            local rest="${line#SIGNAL:swap:}"
            local ch="${rest%%:*}"
            local url="${rest#*:}"
            send_resume_signal "$ch" "$url" ;;
        *) return 2 ;;
    esac
}
```

- [ ] **Step 2: Wire real dispatch into the watcher**

Edit `channels/reflex_watcher.sh`. In the `_reflex_cycle` function (added in Task 3.1), replace the dry-run branch with real dispatch. Find this block:

```bash
                if [[ "$REFLEX_DRY_RUN" == "1" ]]; then
                    log "reflex(dry-run) $line"
                else
                    log "reflex $line"
                    # Phase 5 will wire real dispatch here.
                fi
```

Replace with:

```bash
                if [[ "$REFLEX_DRY_RUN" == "1" ]]; then
                    log "reflex(dry-run) $line"
                else
                    log "reflex $line"
                    if ! dispatch_signal "$line"; then
                        log "reflex: dispatch FAILED for $line (PID file missing?)"
                    fi
                fi
```

Also source the new module alongside the others:

```bash
    # shellcheck source=reflex/signals.sh
    source "$REFLEX_LIB_DIR/signals.sh"
```

- [ ] **Step 3: Bash syntax check**

```bash
bash -n channels/reflex_watcher.sh channels/reflex/signals.sh
```

- [ ] **Step 4: Switch to live mode (controlled rollout)**

Edit `channels/albunyaan-watcher.service` environment to override the default:

Find the `[Service]` section and add (or modify):

```
Environment="REFLEX_DRY_RUN=0"
```

(Leave it in dry-run in the unit file if you prefer gradual rollout; flip to 0 channel-by-channel via systemd override at operator discretion.)

- [ ] **Step 5: Append handoff + commit**

```bash
cat >> SESSION_HANDOFF.md <<'EOF'

## 2026-04-15 — Reflex action layer active

`REFLEX_DRY_RUN=0` enabled in the watcher unit. Slate and backup-swap
signals now fire to try_start_stream.sh via SIGUSR1/SIGUSR2.
Expect: on a stalled source, a channel will show SLATE in its state
file within ≤15s and a healthy backup within the next cycle. [NEW]
EOF
```

```bash
git add channels/reflex/signals.sh channels/reflex_watcher.sh channels/albunyaan-watcher.service SESSION_HANDOFF.md
git commit -m "feat(reflex): activate action layer — watcher dispatches signals live

signals.sh translates SIGNAL: lines from transitions.sh into SIGUSR1/
SIGUSR2 to the per-channel try_start_stream.sh PID. Unit env flips
REFLEX_DRY_RUN=0. This is the phase that makes the reflex loop real."
```

---

## Phase 6 — Brain handoff

### Task 6.1: Brain writes `identity_status` to state files

**Files:**
- Modify: `channels/brain_loop/wake.sh`

- [ ] **Step 1: Teach the wake wrapper to apply `identity_updates`**

In `channels/brain_loop/wake.sh`, immediately after the `# --- act on the response ---` section header (right before the telegram-message dispatch block), insert:

```bash
# Apply any identity_updates the brain returned. Brain owns the
# `identity_status` and `identity_checked_at` fields of each per-channel
# state file; watcher reads them each cycle (see reflex/state.sh).
REFLEX_STATE_DIR="${REFLEX_STATE_DIR:-/var/run/albunyaan/state}"
echo "$JSON_DOC" | python3 - "$REFLEX_STATE_DIR" <<'PYEOF' || log_line "WARN identity_updates apply failed"
import json, sys, os, time, fcntl

state_dir = sys.argv[1]
if not os.path.isdir(state_dir):
    sys.exit(0)
d = json.load(sys.stdin)
updates = (d.get("identity_updates") or [])
if not isinstance(updates, list):
    sys.exit(0)

now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
for u in updates:
    ch = u.get("channel_id")
    status = u.get("identity_status")
    if not ch or status not in ("verified", "mismatch"):
        continue
    path = os.path.join(state_dir, f"{ch}.json")
    lock = os.path.join(state_dir, f"{ch}.lock")
    if not os.path.exists(path):
        continue
    with open(lock, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            with open(path) as f:
                s = json.load(f)
            s["identity_status"] = status
            s["identity_checked_at"] = now_iso
            if status == "verified":
                s["reverify_requested"] = False
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(s, f, indent=2)
            os.replace(tmp, path)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
PYEOF
```

- [ ] **Step 2: Syntax check**

```bash
bash -n channels/brain_loop/wake.sh
```

- [ ] **Step 3: Dry-run once with a fake state file**

```bash
mkdir -p /tmp/reflex-brain-smoke && cp /dev/null /tmp/reflex-brain-smoke/chan_a.lock
cat > /tmp/reflex-brain-smoke/chan_a.json <<'EOF'
{"channel_id":"chan_a","state":"LIVE","identity_status":"unknown","reverify_requested":false}
EOF
JSON='{"ok":true,"identity_updates":[{"channel_id":"chan_a","identity_status":"mismatch"}]}'
REFLEX_STATE_DIR=/tmp/reflex-brain-smoke python3 -c "
import json, sys, os, time, fcntl
state_dir='/tmp/reflex-brain-smoke'
d=json.loads('$JSON')
updates = (d.get('identity_updates') or [])
now_iso = time.strftime('%Y-%m-%dT%H:%M:%S%z')
for u in updates:
    ch=u.get('channel_id'); status=u.get('identity_status')
    path=os.path.join(state_dir,f'{ch}.json')
    with open(path) as f: s=json.load(f)
    s['identity_status']=status
    s['identity_checked_at']=now_iso
    with open(path,'w') as f: json.dump(s,f,indent=2)
"
jq .identity_status /tmp/reflex-brain-smoke/chan_a.json
```
Expected: `"mismatch"`.

- [ ] **Step 4: Commit**

```bash
git add channels/brain_loop/wake.sh
git commit -m "feat(brain): apply identity_updates to per-channel state files

wake.sh now consumes an 'identity_updates' list from the brain's JSON
response and writes identity_status + identity_checked_at into each
/var/run/albunyaan/state/<channel>.json under flock. The reflex watcher
reads these fields each cycle for the identity-mismatch → slate path."
```

---

### Task 6.2: Teach the brain to populate `identity_updates`

**Files:**
- Modify: `channels/brain_loop/PROMPT.md`

- [ ] **Step 1: Amend PROMPT.md §6 (visual identity sweep)**

In `channels/brain_loop/PROMPT.md`, at the end of the "Sub-agent judging rules — LOGO-ONLY MODE" block (just before §7 "Security and code-review pass"), append a new subsection:

```markdown
### 6a. Identity handoff to the reflex watcher

For every channel you ran a visual sub-agent on, emit an entry in the
top-level `identity_updates` array of your JSON output:

```json
{"channel_id": "<id>", "identity_status": "verified" | "mismatch"}
```

Rules:

- `verified` — logo matched (or no logo visible for a kids channel with
  correct genre-implied content per existing rules). Always include
  this — the watcher uses it to clear `reverify_requested`.
- `mismatch` — logo clearly belongs to a different channel. This flips
  the watcher into SLATE + backup-walk within ≤15 s of the wake finishing.
- `slate`, `blackframe`, `unknown` — DO NOT include in
  `identity_updates`. These verdicts are informational only; the watcher
  only acts on a confident verified/mismatch signal.

Priority selection for visual sub-agents this wake (replaces the
existing rotation — still capped at 4):

1. Channels whose last-known state file has `identity_status == "mismatch"`.
2. Channels whose last-known state file has `reverify_requested == true`.
3. Channels whose `prior_state.channel_history[id].last_visual_verdict`
   is not `match`.
4. Channels whose `last_visual_ts` is > 6 h old.
5. Routine rotation.

**Skip channels whose state file has `state != "LIVE"`.** Checking a
SLATE or BACKUP channel would flag slate/backup content as mismatch —
false positives that would cascade the reflex loop. Record the skip in
`wake_summary`.

Read the per-channel state files at `/var/run/albunyaan/state/<id>.json`
before selecting. Use the `cat` tool (allowed by BASH_ALLOWLIST).
```

- [ ] **Step 2: Update the JSON output schema hint**

In the same file, locate the output-object JSON schema (should be near the bottom). Add the `identity_updates` field next to `telegram_messages`:

```json
  "identity_updates": [
    {"channel_id": "basmah", "identity_status": "verified"},
    {"channel_id": "anees",  "identity_status": "mismatch"}
  ],
```

- [ ] **Step 3: Commit**

```bash
git add channels/brain_loop/PROMPT.md
git commit -m "feat(brain-prompt): populate identity_updates + priority-sort LIVE channels

Adds §6a: brain emits identity_updates list for channels it visually
checks, consumed by wake.sh to write /var/run/albunyaan/state/<ch>.json.
Visual sub-agents prioritize mismatch + reverify_requested channels
first and skip non-LIVE channels to avoid spurious flags."
```

---

## Phase 7 — E2E tests

### Task 7.1: Test fixture — controlled nginx upstream

**Files:**
- Create: `channels/tests/reflex/e2e/fixtures/nginx_upstream.conf`
- Create: `channels/tests/reflex/e2e/fixtures/test_channel.sh`
- Create: `channels/tests/reflex/e2e/setup_fixture.sh`
- Create: `channels/tests/reflex/e2e/teardown_fixture.sh`

- [ ] **Step 1: Write the fixture config**

`channels/tests/reflex/e2e/fixtures/nginx_upstream.conf`:

```nginx
# Nginx upstream for reflex E2E tests.
# Serves /srv/reflex-test/primary/ on :18080 and /srv/reflex-test/backup1/ on :18081.
daemon off;
worker_processes 1;
events { worker_connections 32; }

http {
    access_log off;
    server {
        listen 127.0.0.1:18080;
        location / {
            root /srv/reflex-test/primary;
            types { application/vnd.apple.mpegurl m3u8; video/mp2t ts; }
            add_header Cache-Control no-cache always;
        }
    }
    server {
        listen 127.0.0.1:18081;
        location / {
            root /srv/reflex-test/backup1;
            types { application/vnd.apple.mpegurl m3u8; video/mp2t ts; }
            add_header Cache-Control no-cache always;
        }
    }
}
```

`channels/tests/reflex/e2e/fixtures/test_channel.sh`:

```bash
#!/bin/bash
# Channel config for the reflex E2E test_channel. Mirrors channel_*.sh shape.

stream_name="test_channel"
stream_url="http://127.0.0.1:18080/master.m3u8"
stream_url_backup1="http://127.0.0.1:18081/master.m3u8"
stream_url_backup2=""
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/test_channel/master.m3u8"
stream_id="/var/www/html/stream/hls/test_channel/master.m3u8"
scale=0

backup_urls="$stream_url_backup1"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
```

- [ ] **Step 2: Write setup script**

`channels/tests/reflex/e2e/setup_fixture.sh`:

```bash
#!/bin/bash
# Creates /srv/reflex-test/{primary,backup1} with a tiny pre-rendered HLS
# loop each. Starts nginx on 127.0.0.1:18080 + 127.0.0.1:18081.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX_DIR="$SCRIPT_DIR/fixtures"
ROOT=/srv/reflex-test

SUDO="SUDO_ASKPASS=$HOME/.sudo_pass.sh sudo -A"
command -v ffmpeg >/dev/null || { echo "ffmpeg required"; exit 1; }
command -v nginx >/dev/null || { echo "nginx required"; exit 1; }

$SUDO mkdir -p "$ROOT"/primary "$ROOT"/backup1
$SUDO chown -R "$(id -u):$(id -g)" "$ROOT"

# Generate 30s looping HLS for each (different color bars so humans can tell them apart)
for v in primary:red backup1:blue; do
    dir=${v%%:*}; color=${v##*:}
    pushd "$ROOT/$dir" >/dev/null
    ffmpeg -y -f lavfi -i "color=c=${color}:s=640x360:d=30:r=25" \
           -f lavfi -i "sine=frequency=1000:d=30" \
           -c:v libx264 -preset ultrafast -g 25 \
           -c:a aac -b:a 64k \
           -f hls -hls_time 2 -hls_list_size 0 -hls_flags delete_segments \
           master.m3u8 >/dev/null 2>&1
    popd >/dev/null
done

# Start nginx with our config
$SUDO nginx -c "$FIX_DIR/nginx_upstream.conf" -p "$ROOT" &
echo "Fixture ready: primary=http://127.0.0.1:18080 backup1=http://127.0.0.1:18081"
```

`channels/tests/reflex/e2e/teardown_fixture.sh`:

```bash
#!/bin/bash
SUDO="SUDO_ASKPASS=$HOME/.sudo_pass.sh sudo -A"
$SUDO pkill -f "nginx.*reflex-test" || true
$SUDO rm -rf /srv/reflex-test
```

- [ ] **Step 3: Smoke-test the fixture**

```bash
chmod +x channels/tests/reflex/e2e/setup_fixture.sh channels/tests/reflex/e2e/teardown_fixture.sh
bash channels/tests/reflex/e2e/setup_fixture.sh
curl -sI http://127.0.0.1:18080/master.m3u8 | head -1
curl -sI http://127.0.0.1:18081/master.m3u8 | head -1
bash channels/tests/reflex/e2e/teardown_fixture.sh
```
Expected: both `HTTP/1.1 200 OK`.

- [ ] **Step 4: Commit**

```bash
git add channels/tests/reflex/e2e/
git commit -m "test(reflex): E2E fixture — nginx serving test primary + backup1"
```

---

### Task 7.2: E2E happy-path scenario

**Files:**
- Create: `channels/tests/reflex/e2e/reflex_e2e.sh`

- [ ] **Step 1: Write the scenario runner**

```bash
#!/bin/bash
# Reflex E2E scenario runner.
# Usage: reflex_e2e.sh <scenario>
#   happy_path | all_dead | backup_dies | identity_handoff | flapping
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
CHANNELS="$ROOT/channels"

scenario="${1:-happy_path}"

setup() {
    bash "$SCRIPT_DIR/setup_fixture.sh"
    # Start test_channel supervisor
    mkdir -p /var/www/html/stream/hls/test_channel
    cp "$SCRIPT_DIR/fixtures/test_channel.sh" "$CHANNELS/channel_test_channel.sh"
    pushd "$CHANNELS" >/dev/null
    bash channel_test_channel.sh &
    TS_PID=$!
    popd >/dev/null
    # Wait for segments to appear
    for _ in {1..30}; do
        ls /var/www/html/stream/hls/test_channel/*.ts >/dev/null 2>&1 && break
        sleep 1
    done
}

teardown() {
    [[ -n "${TS_PID:-}" ]] && kill "$TS_PID" 2>/dev/null || true
    wait "$TS_PID" 2>/dev/null || true
    rm -f "$CHANNELS/channel_test_channel.sh"
    rm -rf /var/www/html/stream/hls/test_channel
    bash "$SCRIPT_DIR/teardown_fixture.sh"
    rm -f /var/run/albunyaan/state/test_channel.json /var/run/albunyaan/pid/test_channel.pid
}

trap teardown EXIT

current_state() {
    jq -r '.state' /var/run/albunyaan/state/test_channel.json 2>/dev/null || echo "NONE"
}

case "$scenario" in
    happy_path)
        setup
        echo "scenario: happy_path"
        # Run a watcher cycle manually for determinism
        STATE_DIR=/var/run/albunyaan/state HLS_ROOT=/var/www/html/stream/hls \
          LOG_FILE=/tmp/reflex_e2e.log INTERVAL=1 REFLEX_DRY_RUN=0 \
          timeout 20 bash "$CHANNELS/reflex_watcher.sh" &
        WPID=$!
        sleep 3
        [[ "$(current_state)" == "LIVE" ]] || { echo "FAIL: initial state not LIVE"; exit 1; }
        # Kill the primary upstream
        SUDO_ASKPASS=$HOME/.sudo_pass.sh sudo -A pkill -f "nginx.*18080" || true
        sleep 15
        [[ "$(current_state)" =~ ^(SLATE|BACKUP)$ ]] || { echo "FAIL: did not leave LIVE after upstream kill, got $(current_state)"; kill $WPID; exit 1; }
        sleep 8
        [[ "$(current_state)" == "BACKUP" ]] || { echo "FAIL: did not reach BACKUP; state=$(current_state)"; kill $WPID; exit 1; }
        kill $WPID; wait $WPID 2>/dev/null || true
        echo "PASS: happy_path"
        ;;
    *)
        echo "unknown scenario: $scenario"; exit 2 ;;
esac
```

- [ ] **Step 2: Run it**

```bash
chmod +x channels/tests/reflex/e2e/reflex_e2e.sh
bash channels/tests/reflex/e2e/reflex_e2e.sh happy_path
```
Expected: `PASS: happy_path`.

- [ ] **Step 3: Commit**

```bash
git add channels/tests/reflex/e2e/reflex_e2e.sh
git commit -m "test(reflex): E2E happy_path — LIVE→SLATE→BACKUP on upstream kill"
```

---

### Task 7.3: E2E scenarios: all_dead, backup_dies, identity_handoff, flapping

For each, add a `case` branch to `reflex_e2e.sh` following the happy_path pattern:

- [ ] **Step 1: Add `all_dead` branch** — kill BOTH upstreams after `LIVE`; assert state stays SLATE for ≥30 s, no thrashing in `transition_history`.

- [ ] **Step 2: Add `backup_dies` branch** — kill primary (expect BACKUP); kill backup1 (expect SLATE and backup1 in `excluded_backups`).

- [ ] **Step 3: Add `identity_handoff` branch** — write `{"identity_status":"mismatch"}` into the state file via `jq`; assert state transitions to SLATE within ≤15 s and `reverify_requested==true`.

- [ ] **Step 4: Add `flapping` branch** — cycle the primary up/down 6 times rapidly; assert final state is DEGRADED and no more signals are dispatched.

Each branch commits individually with a descriptive message.

---

## Phase 8 — Operational integration

### Task 8.1: Systemd preflight + state/pid dir creation

**Files:**
- Modify: `channels/albunyaan-watcher.service`
- Create: `channels/reflex/preflight.sh`

- [ ] **Step 1: Preflight script**

```bash
#!/bin/bash
# channels/reflex/preflight.sh
# Runs before the watcher starts. Refuses to run blind: slate video must
# exist and state directory must be writable.
set -u

SLATE_VIDEO="${SLATE_VIDEO:-/var/www/html/stream/hls/slate/slate_loop.mp4}"
STATE_DIR="${STATE_DIR:-/var/run/albunyaan/state}"
PID_DIR="${REFLEX_PID_DIR:-/var/run/albunyaan/pid}"

fail() { echo "PREFLIGHT FAIL: $*" >&2; exit 1; }

[[ -f "$SLATE_VIDEO" && -r "$SLATE_VIDEO" ]] || fail "slate video missing or unreadable: $SLATE_VIDEO"
mkdir -p "$STATE_DIR" "$PID_DIR" || fail "cannot create state/pid dirs under /var/run/albunyaan"
[[ -w "$STATE_DIR" && -w "$PID_DIR" ]] || fail "state/pid dirs not writable"
echo "preflight OK"
```

- [ ] **Step 2: Wire into unit file**

In `channels/albunyaan-watcher.service`, under `[Service]`, add:

```
ExecStartPre=/home/msa/Development/scripts/albunyaan/channels/reflex/preflight.sh
RuntimeDirectory=albunyaan
RuntimeDirectoryMode=0755
```

`RuntimeDirectory=albunyaan` makes systemd create `/run/albunyaan` (symlinked as `/var/run/albunyaan` on most distros) with the unit's user/group.

- [ ] **Step 3: Reload + restart**

```bash
chmod +x channels/reflex/preflight.sh
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl daemon-reload
SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart albunyaan-watcher
systemctl status albunyaan-watcher --no-pager | head -20
```
Expected: active (running); last log lines include `preflight OK`.

- [ ] **Step 4: Commit**

```bash
git add channels/reflex/preflight.sh channels/albunyaan-watcher.service
git commit -m "feat(reflex): preflight + RuntimeDirectory for state/pid dirs"
```

---

### Task 8.2: Wire reflex tests into the main test harness

**Files:**
- Modify: `channels/tests/run_tests.sh`

- [ ] **Step 1: Add a reflex-test runner block**

At the end of `channels/tests/run_tests.sh` (before any final `echo` summary), add:

```bash
# Reflex loop tests
if [[ -d "$ROOT_DIR/tests/reflex" ]]; then
    for t in "$ROOT_DIR"/tests/reflex/unit/*.sh "$ROOT_DIR"/tests/reflex/integration/*.sh; do
        [[ -f "$t" ]] || continue
        echo "Running: $t"
        bash "$t" || fail "$t failed"
    done
fi
```

- [ ] **Step 2: Run the full suite**

```bash
bash channels/tests/run_tests.sh
```
Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add channels/tests/run_tests.sh
git commit -m "test: integrate reflex unit+integration tests into run_tests.sh"
```

---

## Post-implementation handoff

- [ ] **Final step: Append SESSION_HANDOFF entry**

```bash
cat >> SESSION_HANDOFF.md <<'EOF'

## 2026-04-15 — Reflex loop landed end-to-end

All phases 1–8 merged. Channel state files at
`/var/run/albunyaan/state/<id>.json` now carry:
  - state ∈ {LIVE, SLATE, BACKUP, DEGRADED}
  - identity_status ∈ {unknown, verified, mismatch}
  - reverify_requested (boolean)
  - transition_history (capped at 50, FIFO)

The Telegram session may want to:
  - Surface state != LIVE in the daily 08:00 report.
  - Surface identity_status == mismatch until brain clears it.
  - Watch for DEGRADED — that's a "call a human" signal.

Rate-limit resilience (task #10 in the reflex-loop session's task list)
is the immediate next plan. [NEW]
EOF
git add SESSION_HANDOFF.md
git commit -m "chore: mark reflex loop complete in SESSION_HANDOFF"
```

---

## Self-review checklist

- **Spec coverage:** every section of the spec maps to at least one task:
  - §5 Architecture → Tasks 3.1, 5.1
  - §6 Detection algorithm → Tasks 1.2 + regression canary
  - §7 Action path → Tasks 1.3, 1.4, 2.1, 4.1, 5.1
  - §8 Identity handoff → Tasks 6.1, 6.2
  - §9 Error handling → baked into state.sh + transitions.sh tests; flapping in Task 2.1 and 7.3; preflight in Task 8.1
  - §10 Testing → every task is TDD; Tasks 7.1–7.3 add E2E
- **Placeholder scan:** no "TBD/TODO/later" in the steps; all code blocks are concrete.
- **Type consistency:** state field names match across spec § 7 schema, `state.sh` default JSON, `transitions.sh` jq expressions, `wake.sh` Python handler, and `PROMPT.md` hint.
- **Scope:** single subsystem (the reflex watcher). Rate-limit resilience, 08:00 report, playability probe are explicitly out of scope — listed as spec §11 follow-ups.
