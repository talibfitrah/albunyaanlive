#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFLEX_DIR="$SCRIPT_DIR/../../../reflex"
source "$SCRIPT_DIR/../lib/test_helpers.sh"
source "$REFLEX_DIR/probe.sh"

# The fixture binds to 127.0.0.1, which probe.sh blocklists in production.
# Opt in for the HTTP-path tests; resolver-scheme and blocklist tests
# explicitly override.
export REFLEX_ALLOW_LOCAL_PROBE=1

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

test_probe_resolver_scheme_returns_unknown() {
    for u in "elahmad:makkahtv" "aloula:6" "seenshow:2120825/LIVE/3.m3u8" "youtube:@SaudiQuranTv"; do
        probe_url "$u" 2
        local rc=$?
        th_assert_eq "$rc" "2" "resolver scheme '$u' → rc=2 (unknown)" || return 1
    done
}

test_probe_blocklist_refuses_local() {
    # Without REFLEX_ALLOW_LOCAL_PROBE=1, loopback is refused at the
    # blocklist gate before any network call.
    (
        unset REFLEX_ALLOW_LOCAL_PROBE
        probe_url "http://127.0.0.1:8080/x" 1
        exit $?
    )
    local rc=$?
    th_assert_eq "$rc" "2" "loopback → rc=2 (blocklisted)" || return 1
}

test_probe_blocklist_refuses_rfc1918() {
    (
        unset REFLEX_ALLOW_LOCAL_PROBE
        probe_url "http://192.168.1.1/x" 1
        exit $?
    )
    local rc=$?
    th_assert_eq "$rc" "2" "192.168/16 → rc=2 (blocklisted)" || return 1
}

th_run "probe 200 passes"              test_probe_200_passes   || exit 1
th_run "probe 404 fails"               test_probe_404_fails    || exit 1
th_run "probe timeout fails"           test_probe_timeout_fails || exit 1
th_run "resolver scheme → unknown"     test_probe_resolver_scheme_returns_unknown || exit 1
th_run "loopback blocklisted"          test_probe_blocklist_refuses_local || exit 1
th_run "rfc1918 blocklisted"           test_probe_blocklist_refuses_rfc1918 || exit 1
echo "probe tests: all PASS"
