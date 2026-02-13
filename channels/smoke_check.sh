#!/bin/bash
# Deploy smoke check — verifies all services are healthy and key invariants hold.
# Run after deploying code changes or restarting services.
# Exit code: 0 = all checks pass, 1 = one or more checks failed.
set -euo pipefail

PASS=0
FAIL=0
WARN=0

_check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        ((PASS++)) || true
    else
        echo "  FAIL: $desc"
        ((FAIL++)) || true
    fi
}

_check_output() {
    local desc="$1" expected="$2"
    shift 2
    local actual
    actual=$("$@" 2>/dev/null) || true
    if [[ "$actual" == *"$expected"* ]]; then
        echo "  PASS: $desc"
        ((PASS++)) || true
    else
        echo "  FAIL: $desc (expected '$expected', got '${actual:0:120}')"
        ((FAIL++)) || true
    fi
}

_check_json_key() {
    local desc="$1" url="$2" jq_expr="$3" expected="$4"
    local actual
    actual=$(curl -sS --max-time 5 "$url" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    import functools, operator
    keys = '''$jq_expr'''.strip('.').split('.')
    val = functools.reduce(operator.getitem, keys, d)
    print(val)
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null) || true
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS: $desc ($jq_expr=$actual)"
        ((PASS++)) || true
    else
        echo "  FAIL: $desc ($jq_expr expected '$expected', got '${actual:0:80}')"
        ((FAIL++)) || true
    fi
}

echo "=== Deploy Smoke Check ==="
echo ""

# --- 1. Port listeners ---
echo "--- Port listeners ---"
_check "provider-sync listening on :8089" bash -c "ss -ltn | grep -q ':8089 '"
_check "seenshow-resolver listening on :8090" bash -c "ss -ltn | grep -q ':8090 '"
_check "youtube-resolver listening on :8088" bash -c "ss -ltn | grep -q ':8088 '"
_check "bgutil-pot listening on :4416" bash -c "ss -ltn | grep -q ':4416 '"
echo ""

# --- 2. Health endpoints ---
echo "--- Service health ---"
_check_output "provider-sync /health" '"status": "ok"' curl -sS --max-time 5 http://127.0.0.1:8089/health
_check_output "seenshow-resolver /health" '"status": "ok"' curl -sS --max-time 5 http://127.0.0.1:8090/health
_check_output "seenshow-resolver authenticated" '"authenticated": true' curl -sS --max-time 5 http://127.0.0.1:8090/health
_check_output "youtube-resolver /health" '"ok": true' curl -sS --max-time 5 http://127.0.0.1:8088/health
echo ""

# --- 3. Seenshow resolver details ---
echo "--- Seenshow resolver ---"
_check_json_key "max_concurrent" "http://127.0.0.1:8090/health" ".slots.max" "3"
_check_json_key "tokens total" "http://127.0.0.1:8090/health" ".tokens.total" "10"
_check_json_key "tokens valid" "http://127.0.0.1:8090/health" ".tokens.valid" "10"
echo ""

# --- 4. Provider sync credential count ---
echo "--- Provider sync ---"
CRED_COUNT=$(curl -sS --max-time 5 http://127.0.0.1:8089/credentials 2>/dev/null \
    | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null) || CRED_COUNT=0
if [[ "$CRED_COUNT" -ge 18 ]]; then
    echo "  PASS: credentials loaded ($CRED_COUNT)"
    ((PASS++)) || true
else
    echo "  FAIL: credentials loaded (expected >=18, got $CRED_COUNT)"
    ((FAIL++)) || true
fi
echo ""

# --- 5. Credential uniqueness in channel configs ---
echo "--- Credential invariants ---"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIQUE_CREDS=$(grep -rh 'vlc.news' "$ROOT_DIR"/channel_*.sh 2>/dev/null \
    | grep -oP '\d{12}/\d{12}' | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')
if [[ "${UNIQUE_CREDS:-0}" -le 1 ]]; then
    echo "  PASS: no duplicate VLC credentials in channel configs"
    ((PASS++)) || true
else
    echo "  FAIL: duplicate VLC credential found (max count=$UNIQUE_CREDS)"
    ((FAIL++)) || true
fi
echo ""

# --- 6. HLS output freshness ---
echo "--- Channel output freshness (last 60s) ---"
STALE=0
FRESH=0
NOW=$(date +%s)
for m3u8 in /var/www/html/stream/hls/*/master.m3u8; do
    if [[ ! -f "$m3u8" ]]; then continue; fi
    channel=$(basename "$(dirname "$m3u8")")
    mtime=$(stat -c %Y "$m3u8" 2>/dev/null) || continue
    age=$((NOW - mtime))
    if [[ $age -gt 60 ]]; then
        echo "  WARN: $channel stale (${age}s ago)"
        ((STALE++)) || true
        ((WARN++)) || true
    else
        ((FRESH++)) || true
    fi
done
echo "  $FRESH channels fresh, $STALE stale"
echo ""

# --- Summary ---
echo "=== Summary: $PASS passed, $FAIL failed, $WARN warnings ==="
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
