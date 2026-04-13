#!/bin/bash
# Albunyaan brain loop wake. Fired by systemd timer every 30 min.
#
# Each wake:
#   1. Gathers prior brain state, live watcher state, and new git commits
#      since the last wake.
#   2. Renders the brain prompt (PROMPT.md) with those three blocks
#      inlined.
#   3. Invokes claude headless with broad read-only tools + Task (for
#      parallel sub-agents on visual identity).
#   4. Parses the trailing JSON object from the response.
#   5. Atomically writes new_state to the state file.
#   6. Posts each telegram_messages entry via the bot API (non-MCP, since
#      this runs from systemd).
#   7. Logs a one-line wake summary.
#
# The brain itself never writes the filesystem — the wrapper does.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_DIR="$REPO_ROOT/channels/brain"
STATE_FILE="$STATE_DIR/state.json"
WAKE_LOG="$STATE_DIR/wake.log"
RAW_DIR="$STATE_DIR/raw"
LOCK_FILE="$STATE_DIR/wake.lock"
WATCHER_STATE_FILE="${WATCHER_STATE_FILE:-/tmp/albunyaan-watcher-state.json}"
TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
CLAUDE_BIN="${CLAUDE_BIN:-/home/msa/.local/bin/claude}"
PROMPT_FILE="$SCRIPT_DIR/PROMPT.md"
TELEGRAM_MAX_MSGS_PER_WAKE="${TELEGRAM_MAX_MSGS_PER_WAKE:-10}"

mkdir -p "$STATE_DIR" "$RAW_DIR"

# Concurrency guard. If a previous wake is still running (claude can take
# minutes), bail out cleanly — we'd rather skip than corrupt state.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "[$(date -Iseconds)] another wake is in progress (lock held); skipping this tick" \
        | tee -a "$WAKE_LOG"
    exit 0
fi

TS="$(date -Iseconds)"
TS_SHORT="$(date +%Y%m%dT%H%M%S)"
RAW_LOG="$RAW_DIR/wake_${TS_SHORT}.log"

if [[ -r "$TELEGRAM_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$TELEGRAM_ENV"
    set +a
fi

tg_send() {
    local msg="$1"
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_OWNER_ID:-}" ]] && return 0
    curl -s --max-time 15 \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_OWNER_ID}" \
        --data-urlencode "text=${msg}" >/dev/null || true
}

log_line() {
    echo "[$TS] $*" | tee -a "$WAKE_LOG"
}

# --- gather context blocks -------------------------------------------------

if [[ -r "$STATE_FILE" ]]; then
    PRIOR_STATE="$(cat "$STATE_FILE")"
else
    PRIOR_STATE='{"schema":1,"ts":null,"wake_count":0,"last_wake_ts":null,"last_commit_reviewed":null,"last_resource_snapshot":{},"incidents":[],"channel_history":{}}'
fi

if [[ -r "$WATCHER_STATE_FILE" ]]; then
    WATCHER_STATE="$(cat "$WATCHER_STATE_FILE")"
else
    WATCHER_STATE='{"schema":0,"error":"watcher state file missing","unix":0}'
fi

LAST_REVIEWED_SHA="$(echo "$PRIOR_STATE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("last_commit_reviewed") or "")' 2>/dev/null || echo "")"
cd "$REPO_ROOT" || exit 3
if [[ -n "$LAST_REVIEWED_SHA" ]] && git rev-parse --verify "$LAST_REVIEWED_SHA" >/dev/null 2>&1; then
    NEW_COMMITS="$(git log --pretty=format:'%h %ad %s' --date=iso "${LAST_REVIEWED_SHA}..HEAD" 2>/dev/null || echo '(none)')"
else
    # First wake or unknown SHA — show last 5 commits as bootstrap context.
    NEW_COMMITS="$(git log --pretty=format:'%h %ad %s' --date=iso -5 2>/dev/null || echo '(none)')"
fi
[[ -z "$NEW_COMMITS" ]] && NEW_COMMITS="(no new commits since last wake)"

# --- render prompt ---------------------------------------------------------

PROMPT="$(cat "$PROMPT_FILE")
---

<<<PRIOR_STATE>>>
$PRIOR_STATE
<<<END PRIOR_STATE>>>

<<<WATCHER_STATE>>>
$WATCHER_STATE
<<<END WATCHER_STATE>>>

<<<NEW_COMMITS>>>
$NEW_COMMITS
<<<END NEW_COMMITS>>>

Now perform the wake checklist and emit the JSON output object as your
final line."

log_line "wake start (prior wake_count=$(echo "$PRIOR_STATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("wake_count",0))' 2>/dev/null || echo '?'))"

# --- invoke claude ---------------------------------------------------------

"$CLAUDE_BIN" -p \
    --output-format text \
    --allowed-tools "Read,Glob,Grep,Bash,Task" \
    --fallback-model claude-haiku-4-5-20251001 \
    "$PROMPT" >"$RAW_LOG" 2>&1
RC=$?

if [[ $RC -ne 0 ]]; then
    log_line "FAILED claude exit=$RC, raw: $RAW_LOG"
    tg_send "تنبيه: فشل في فحص النظام (رمز ${RC}). لم يتم تحديث الحالة. سيُعاد المحاولة في الجولة التالية."
    exit "$RC"
fi

# --- parse trailing JSON ---------------------------------------------------

# Tolerant: walk the file backwards looking for the last balanced JSON block.
# The brain might emit prose then JSON; we extract just the JSON.
JSON_DOC="$(python3 - "$RAW_LOG" <<'PYEOF'
import sys, json, re
path = sys.argv[1]
with open(path) as f:
    text = f.read()
# Find the LAST occurrence of "ok" key as an anchor for the response object,
# then scan backwards for the opening brace and forwards for balanced close.
candidates = []
for m in re.finditer(r'\{', text):
    start = m.start()
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if esc:
            esc = False
            continue
        if c == '\\':
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                blob = text[start:i+1]
                try:
                    parsed = json.loads(blob)
                    if isinstance(parsed, dict) and ('ok' in parsed or 'new_state' in parsed):
                        candidates.append(blob)
                except Exception:
                    pass
                break
if candidates:
    print(candidates[-1])
PYEOF
)"

if [[ -z "$JSON_DOC" ]]; then
    log_line "FAILED could not extract JSON output, raw: $RAW_LOG"
    tg_send "تنبيه: فحص النظام لم يُنتج تقريراً منظماً. التفاصيل في سجل الخادم."
    exit 4
fi

if ! echo "$JSON_DOC" | python3 -m json.tool >/dev/null 2>&1; then
    log_line "FAILED extracted JSON did not parse, raw: $RAW_LOG"
    tg_send "تنبيه: تقرير الفحص غير صالح. التفاصيل في سجل الخادم."
    exit 5
fi

# --- act on the response ---------------------------------------------------

# Extract and validate the new_state block before writing.
# Required: dict with "schema" and "wake_count" (int). Without these, the
# next wake's PRIOR_STATE parser breaks and the brain loses continuity —
# better to keep the prior good state.
NEW_STATE_VALID="$(echo "$JSON_DOC" | python3 -c '
import json, sys
d = json.load(sys.stdin)
ns = d.get("new_state")
if not isinstance(ns, dict):
    sys.exit(1)
if "schema" not in ns or "wake_count" not in ns:
    sys.exit(2)
if not isinstance(ns["wake_count"], int):
    sys.exit(3)
print(json.dumps(ns, indent=2, ensure_ascii=False))
' 2>/dev/null)"
if [[ -n "$NEW_STATE_VALID" ]]; then
    TMP_STATE="$(mktemp -p "$STATE_DIR" .state.tmp.XXXXXX)"
    echo "$NEW_STATE_VALID" >"$TMP_STATE"
    if ! mv -f "$TMP_STATE" "$STATE_FILE"; then
        log_line "WARN failed to install new state file; prior state retained"
        rm -f "$TMP_STATE"
    fi
else
    log_line "WARN brain returned invalid or missing new_state; prior state retained"
fi

# Post telegram messages, capped to TELEGRAM_MAX_MSGS_PER_WAKE (default 10).
# A wide-incident wake (e.g. all 22 channels stalled) shouldn't spam 22+
# pings. Anything beyond the cap is summarised in a footer pointing at the
# server log.
TELEGRAM_MAX_MSGS_PER_WAKE="$TELEGRAM_MAX_MSGS_PER_WAKE" RAW_LOG_PATH="$RAW_LOG" \
    python3 -c '
import json, sys, os, subprocess
d = json.loads(sys.stdin.read())
msgs = [m for m in (d.get("telegram_messages") or []) if isinstance(m, str) and m.strip()]
cap = int(os.environ.get("TELEGRAM_MAX_MSGS_PER_WAKE", "10"))
token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
chat = os.environ.get("TELEGRAM_OWNER_ID", "")
if not token or not chat:
    raise SystemExit(0)
to_send = msgs[:cap]
if len(msgs) > cap:
    overflow = len(msgs) - cap
    raw = os.environ.get("RAW_LOG_PATH", "(see server log)")
    to_send.append(f"... و{overflow} رسالة إضافية. التفاصيل الكاملة في سجل الخادم: {raw}")
for m in to_send:
    subprocess.run([
        "curl", "-s", "--max-time", "15",
        f"https://api.telegram.org/bot{token}/sendMessage",
        "--data-urlencode", f"chat_id={chat}",
        "--data-urlencode", f"text={m}",
    ], stdout=subprocess.DEVNULL, check=False)
' <<<"$JSON_DOC"

# Honor the action: restart_watcher (safe — uses sudo via askpass if available)
RESTART_WATCHER="$(echo "$JSON_DOC" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if (d.get("actions") or {}).get("restart_watcher") else "no")')"
if [[ "$RESTART_WATCHER" == "yes" ]]; then
    log_line "action: restart_watcher requested"
    if [[ -x "$HOME/.sudo_pass.sh" ]]; then
        SUDO_ASKPASS="$HOME/.sudo_pass.sh" sudo -A systemctl restart albunyaan-watcher.service \
            && log_line "watcher restarted" \
            || log_line "watcher restart FAILED"
    else
        log_line "no askpass helper; cannot restart watcher"
    fi
fi

# graceful_restart and extra_disk_cleanup actions are surfaced in logs but
# NOT auto-executed yet — they touch live streams. Brain proposes; user
# decides until we have more confidence.
PROPOSED_GRACEFUL="$(echo "$JSON_DOC" | python3 -c 'import json,sys; d=json.load(sys.stdin); a=(d.get("actions") or {}).get("graceful_restart") or []; print(",".join(a) if isinstance(a, list) else "")')"
if [[ -n "$PROPOSED_GRACEFUL" ]]; then
    log_line "action proposed (NOT executed): graceful_restart channels=$PROPOSED_GRACEFUL"
fi

WAKE_SUMMARY="$(echo "$JSON_DOC" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("wake_summary", "(no summary)"))')"
log_line "wake done: $WAKE_SUMMARY"

# Rotate raw logs: keep the last 200 (~4 days at 30min cadence)
find "$RAW_DIR" -maxdepth 1 -name 'wake_*.log' -type f | sort | head -n -200 | xargs -r rm -f
