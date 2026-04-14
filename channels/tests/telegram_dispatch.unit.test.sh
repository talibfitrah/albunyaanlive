#!/bin/bash
# Unit tests for the bilingual Telegram dispatch path.
#
# Covers the bugs found by the Target-A code review:
#   A-1 wake.sh normalizer must not iterate over a bare string telegram_messages
#   A-1 wake.sh normalizer must not iterate over a bare dict telegram_messages
#   A-1 wake.sh normalizer must fall back to a single severe alert on exception
#   A-2 bot.sh offset write must be atomic (tmp + rename pattern)
#   A-2 bot.sh dispatch must happen BEFORE write_offset (at-least-once delivery)
#   A-3 tg_alert.sh must capture HTTP status and log failures
#   A-4 run_audit.sh severity gate must use contract enum {MAJOR|BLOCKING|CRITICAL}
#   A-5 run_audit.sh dispatcher must sleep ≥1s between sends (Telegram rate limit)
#   A-6 tg_alert.sh must log when no bot creds are available (not silently no-op)
#   A-7 reflex_watcher must escalate recovery to severe when prior was severe

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAKE_SH="$ROOT_DIR/brain_loop/wake.sh"
BOT_SH="$ROOT_DIR/operator_bot/bot.sh"
TG_ALERT_SH="$ROOT_DIR/tg_alert.sh"
RUN_AUDIT_SH="$ROOT_DIR/security_cadence/run_audit.sh"
WATCHER_SH="$ROOT_DIR/reflex_watcher.sh"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

# Extract the embedded normalizer from wake.sh into a standalone script so
# we can feed it test fixtures. The block sits between the line containing
# `python3 -c '` (opening the heredoc-style arg) and the line `' <<<"$JSON_DOC"`.
TMP_PY="$(mktemp --suffix=.py)"
trap 'rm -f "$TMP_PY"' EXIT
python3 - "$WAKE_SH" >"$TMP_PY" <<'EXTRACT'
import sys
lines = open(sys.argv[1]).readlines()
# Find the normalizer: a `python3 -c '` opener followed within a few lines
# by `import json, sys, os, subprocess, time` (unique to that block), and
# closing at the next line matching `' <<<"$JSON_DOC"`.
start = None
for i, line in enumerate(lines):
    if line.rstrip().endswith("python3 -c '"):
        # Peek ahead up to 5 lines for the normalizer signature.
        for j in range(i + 1, min(i + 6, len(lines))):
            if "subprocess" in lines[j] and "time" in lines[j]:
                start = i + 1
                break
        if start is not None:
            break
if start is None:
    sys.exit("normalizer opener not found")
end = None
for k in range(start, len(lines)):
    if lines[k].rstrip() == "' <<<\"$JSON_DOC\"":
        end = k
        break
if end is None:
    sys.exit("normalizer closer not found")
sys.stdout.write("".join(lines[start:end]))
EXTRACT

if [[ ! -s "$TMP_PY" ]]; then
    fail "could not extract wake.sh normalizer block (regex drift?)"
fi

# Sanity: the extracted block must contain the isinstance(raw, list) guard
# (A-1 regression check — proves we're testing the patched version)
grep -q "isinstance(raw, list)" "$TMP_PY" \
    || fail "wake.sh normalizer missing isinstance(raw, list) guard (A-1 regression)"
pass "wake.sh normalizer has isinstance(raw, list) guard"

# Stub curl so no real Telegram API calls happen during tests.
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR" "$TMP_PY"' EXIT
cat >"$STUB_DIR/curl" <<'STUB'
#!/bin/bash
# Record each call to a file for assertions.
printf 'CURL: %s\n' "$*" >>"${CURL_STUB_LOG:-/dev/null}"
exit 0
STUB
chmod +x "$STUB_DIR/curl"

run_normalizer() {
    # run_normalizer <input_json> <log_path>
    local json="$1" log="$2"
    CURL_STUB_LOG="$log" \
    OPERATOR_BOT_TOKEN="op-test" OPERATOR_OWNER_ID="111" \
    TELEGRAM_BOT_TOKEN="co-test" COLLEAGUE_OWNER_ID="222" \
    TELEGRAM_MAX_MSGS_PER_WAKE="10" RAW_LOG_PATH="/tmp/t.log" \
    PATH="$STUB_DIR:$PATH" \
    python3 "$TMP_PY" <<<"$json" >/dev/null 2>&1
}

# A-1: string input — must NOT iterate characters; must fall back to severe alert
LOG1="$(mktemp)"
run_normalizer '{"telegram_messages":"Alert: watcher hung"}' "$LOG1"
lines=$(wc -l <"$LOG1")
# Old buggy behavior: 17 curl calls (one per character of "Alert: watcher hung").
# New behavior: 2 curls (one EN fallback to operator + one AR fallback to colleague).
if [[ "$lines" -gt 4 ]]; then
    fail "A-1: string telegram_messages caused $lines curl calls — character iteration bug"
fi
if ! grep -q "malformed" "$LOG1" 2>/dev/null && ! grep -q "op-test" "$LOG1"; then
    fail "A-1: string input did not trigger fallback alert"
fi
rm -f "$LOG1"
pass "A-1: string telegram_messages triggers fallback (no char iteration)"

# A-1: dict input — must not iterate keys
LOG2="$(mktemp)"
run_normalizer '{"telegram_messages":{"severity":"severe","en":"x"}}' "$LOG2"
lines=$(wc -l <"$LOG2")
if [[ "$lines" -gt 4 ]]; then
    fail "A-1: dict telegram_messages caused $lines curl calls — key iteration bug"
fi
rm -f "$LOG2"
pass "A-1: dict telegram_messages triggers fallback (no key iteration)"

# A-1: valid mixed list — plain string normalizes to info, dict with severity=severe routes AR to colleague
LOG3="$(mktemp)"
run_normalizer '{"telegram_messages":[
    "legacy plain string",
    {"severity":"severe","en":"new EN","ar":"new AR"}
]}' "$LOG3"
# Expect: 2 EN sends to operator + 1 AR send to colleague = 3 curl calls.
if ! grep -q "co-test" "$LOG3"; then
    fail "A-1: severe dict did not route AR to colleague (co-test not seen in curl log)"
fi
en_count=$(grep -c "op-test" "$LOG3" || echo 0)
if [[ "$en_count" -lt 2 ]]; then
    fail "A-1: expected 2 EN sends (plain + severe dict), saw $en_count"
fi
rm -f "$LOG3"
pass "A-1: mixed list routes strings→info and dicts→severity correctly"

# A-1: malformed json top-level — normalizer must catch and send single fallback alert
LOG4="$(mktemp)"
run_normalizer 'NOT VALID JSON AT ALL' "$LOG4" || true
if ! grep -q "op-test" "$LOG4"; then
    fail "A-1: malformed JSON did not produce operator fallback"
fi
rm -f "$LOG4"
pass "A-1: malformed JSON top-level triggers fallback alert"

# A-2: atomic offset write — bot.sh must use mktemp/tmp + mv, not plain >
if ! grep -q 'mv -f "\$tmp" "\$OFFSET_FILE"' "$BOT_SH"; then
    fail "A-2: bot.sh offset write is not atomic (no mv -f pattern)"
fi
pass "A-2: bot.sh write_offset uses atomic tmp+rename"

# A-2: dispatch MUST come before write_offset in the main update loop.
# Extract the inner while-read body and check ordering there (the cold-start
# seed code also calls write_offset; we care about the dispatch path).
loop_slice=$(awk '
    /read -r update_id from_id chat_id text/ {inside=1}
    inside {print NR":"$0}
    inside && /^    done < </ {exit}
' "$BOT_SH")
if [[ -z "$loop_slice" ]]; then
    fail "A-2: could not locate main update loop"
fi
dispatch_line=$(echo "$loop_slice" | awk -F: '/dispatch "\$chat_id" "\$text"/{print $1; exit}')
write_line=$(echo "$loop_slice" | awk -F: '/write_offset "\$OFFSET"/{print $1; exit}')
if [[ -z "$dispatch_line" || -z "$write_line" ]]; then
    fail "A-2: dispatch or write_offset not found in main loop (slice lines missing)"
fi
if [[ "$dispatch_line" -ge "$write_line" ]]; then
    fail "A-2: dispatch (line $dispatch_line) must come BEFORE write_offset (line $write_line) in main loop"
fi
pass "A-2: bot.sh dispatches BEFORE advancing offset (at-least-once)"

# A-3: tg_alert.sh captures HTTP status and logs failures
if ! grep -q 'http_code' "$TG_ALERT_SH"; then
    fail "A-3: tg_alert.sh does not capture HTTP status code"
fi
if ! grep -q '_tg_log' "$TG_ALERT_SH"; then
    fail "A-3: tg_alert.sh has no failure-logging helper"
fi
pass "A-3: tg_alert.sh captures http_code and has _tg_log helper"

# A-4: run_audit.sh severity gate uses contract enum, not CRITICAL|HIGH
if grep -qE '\("CRITICAL",\s*"HIGH"\)' "$RUN_AUDIT_SH"; then
    fail "A-4: run_audit.sh still uses deprecated (CRITICAL, HIGH) gate"
fi
if ! grep -q "MAJOR" "$RUN_AUDIT_SH"; then
    fail "A-4: run_audit.sh AR gate missing MAJOR tier"
fi
if ! grep -q "BLOCKING" "$RUN_AUDIT_SH"; then
    fail "A-4: run_audit.sh AR gate missing BLOCKING tier"
fi
pass "A-4: run_audit.sh AR gate aligns with contract (MAJOR|BLOCKING|CRITICAL)"

# A-5: run_audit.sh has rate-limit sleep between sends
if ! grep -qE 'time\.sleep\(1\.[0-9]+\)' "$RUN_AUDIT_SH"; then
    fail "A-5: run_audit.sh missing time.sleep(≥1.0) rate-limit guard"
fi
pass "A-5: run_audit.sh has Telegram rate-limit sleep"

# A-6: tg_alert.sh logs when no bot creds available (not silent no-op)
if ! grep -q "no bot credentials available" "$TG_ALERT_SH"; then
    fail "A-6: tg_alert.sh missing no-creds log line"
fi
pass "A-6: tg_alert.sh logs missing-creds case"

# A-7: reflex_watcher escalates recovery to severe when prior was severe
if ! grep -q "Recovery escalation" "$WATCHER_SH"; then
    fail "A-7: reflex_watcher.sh missing recovery escalation block"
fi
if ! grep -q 'prior_sev.*severe' "$WATCHER_SH"; then
    fail "A-7: reflex_watcher.sh recovery logic does not check prior severity"
fi
pass "A-7: reflex_watcher.sh escalates recovery when prior was severe"

echo "PASS: All 11 telegram dispatch tests passed."
