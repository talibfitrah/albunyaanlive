#!/bin/bash
# Run a gstack security skill headlessly, capture findings as JSON, and route:
#   - all findings → channels/security/findings_<date>_<skill>.md (history)
#   - medium+ → TODOS.md ## Security (action list)
#   - medium+ → Telegram (real-time, plain Arabic/English with full detail)
#
# Usage: run_audit.sh <skill_name>
#   e.g. run_audit.sh cso

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SECURITY_DIR="$REPO_ROOT/channels/security"
TODOS_FILE="$REPO_ROOT/TODOS.md"
TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
CLAUDE_BIN="${CLAUDE_BIN:-/home/msa/.local/bin/claude}"

SKILL="${1:-}"
if [[ -z "$SKILL" ]]; then
    echo "usage: $0 <skill> (e.g. cso, health, review)" >&2
    exit 2
fi

DATE="$(date +%Y-%m-%d)"
TS="$(date -Iseconds)"
RUN_LOG="$SECURITY_DIR/findings_${DATE}_${SKILL}.md"
RAW_LOG="$SECURITY_DIR/raw_${DATE}_${SKILL}.log"
mkdir -p "$SECURITY_DIR"

# Source telegram env (TELEGRAM_BOT_TOKEN, TELEGRAM_OWNER_ID); failure non-fatal
if [[ -r "$TELEGRAM_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$TELEGRAM_ENV"
    set +a
fi

# Shared bilingual alert helper: user (EN) always, colleague (AR) on severe.
# shellcheck source=../tg_alert.sh
source "$(dirname "${BASH_SOURCE[0]}")/../tg_alert.sh"

# Structured-output contract pinned to the prompt. Trailing JSON line is what
# the wrapper parses; everything before is human prose / tool transcripts.
PROMPT="Run the /${SKILL} skill against this repository (the working directory).
Operate read-only — do NOT edit files; the wrapper handles all output writes.

After the skill completes, output a SINGLE JSON object on the LAST line of
your response with EXACTLY this shape:

{\"findings\": [
  {
    \"severity\": \"info|minor|medium|major|blocking|critical\",
    \"title\": \"short title (max 80 chars)\",
    \"location\": \"file:line or component name\",
    \"why_it_matters\": \"one sentence in plain Arabic or English, non-technical\",
    \"suggested_fix\": \"one sentence in plain Arabic or English, non-technical\"
  }
]}

If no findings, output: {\"findings\": []}
The why_it_matters and suggested_fix fields will be shown to a non-technical
home user via Telegram — no jargon, no file paths in the prose, no commands."

cd "$REPO_ROOT" || exit 3

echo "[$TS] starting /${SKILL} audit"

"$CLAUDE_BIN" -p \
    --output-format text \
    --allowed-tools "Read,Glob,Grep,Bash" \
    --fallback-model claude-haiku-4-5-20251001 \
    "$PROMPT" >"$RAW_LOG" 2>&1
RC=$?

if [[ $RC -ne 0 ]]; then
    tg_alert severe \
        "Security audit /${SKILL} failed (exit ${RC}). Check server log." \
        "فحص /${SKILL} فشل (رمز خروج ${RC}). راجع السجل على الخادم."
    echo "[$TS] FAILED rc=$RC, raw log: $RAW_LOG" >&2
    exit "$RC"
fi

# Last line containing the findings JSON. Tolerant: scans from the end.
JSON_LINE="$(tac "$RAW_LOG" | grep -m1 -oE '\{[[:space:]]*"findings"[[:space:]]*:.*\}$' || true)"

if [[ -z "$JSON_LINE" ]]; then
    echo "[$TS] no JSON findings block in output; copying raw to findings file" >&2
    {
        echo "# /${SKILL} audit — ${TS} (UNPARSED)"
        echo ""
        echo "Wrapper could not extract JSON findings from the run output."
        echo "Raw run log preserved below."
        echo ""
        echo '```'
        cat "$RAW_LOG"
        echo '```'
    } >"$RUN_LOG"
    tg_alert warn \
        "Security audit /${SKILL} completed but produced no structured report. Full file on server." \
        ""
    exit 4
fi

if ! echo "$JSON_LINE" | python3 -m json.tool >/dev/null 2>&1; then
    echo "[$TS] JSON line failed to parse" >&2
    cp "$RAW_LOG" "$RUN_LOG"
    tg_alert warn \
        "Security audit /${SKILL} produced invalid JSON. File saved for review." \
        ""
    exit 5
fi

# Render the per-day findings file
{
    echo "# /${SKILL} findings — ${TS}"
    echo ""
    echo '## Raw JSON'
    echo '```json'
    echo "$JSON_LINE" | python3 -m json.tool
    echo '```'
    echo ""
    echo '## Plain reading'
    echo ""
    echo "$JSON_LINE" | python3 -c '
import json, sys
data = json.load(sys.stdin)
findings = data.get("findings", [])
if not findings:
    print("_No findings._")
for i, f in enumerate(findings, 1):
    sev = f.get("severity", "?")
    title = f.get("title", "(untitled)")
    where = f.get("location", "?")
    why = f.get("why_it_matters", "?")
    fix = f.get("suggested_fix", "?")
    print(f"### {i}. [{sev}] {title}")
    print(f"- **Where:** {where}")
    print(f"- **Why it matters:** {why}")
    print(f"- **Suggested fix:** {fix}")
    print()
'
} >"$RUN_LOG"

# Filter to medium-and-above for routing
ROUTABLE_JSON="$(echo "$JSON_LINE" | python3 -c '
import json, sys
data = json.load(sys.stdin)
keep = {"medium", "major", "blocking", "critical"}
out = [f for f in data.get("findings", []) if f.get("severity", "").lower() in keep]
print(json.dumps(out))
')"
ROUTABLE_COUNT="$(echo "$ROUTABLE_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

if [[ "$ROUTABLE_COUNT" -eq 0 ]]; then
    echo "[$TS] /${SKILL} audit: no medium-or-above findings; nothing to route"
    echo "[$TS] complete. file: $RUN_LOG"
    exit 0
fi

# Append to TODOS.md
if ! grep -q '^## Security' "$TODOS_FILE" 2>/dev/null; then
    printf '\n## Security\n' >>"$TODOS_FILE"
fi
{
    echo ""
    echo "### /${SKILL} ${DATE} — ${ROUTABLE_COUNT} item(s)"
    echo "$ROUTABLE_JSON" | python3 -c '
import json, sys
for f in json.load(sys.stdin):
    sev = f.get("severity", "?")
    title = f.get("title", "(untitled)")
    where = f.get("location", "?")
    why = f.get("why_it_matters", "?")
    fix = f.get("suggested_fix", "?")
    print(f"- [ ] **[{sev}] {title}** — `{where}`")
    print(f"  - Why: {why}")
    print(f"  - Fix: {fix}")
'
} >>"$TODOS_FILE"

# Telegram: one message per finding, full detail in plain language.
# Pass the JSON as argv so we don't fight stdin with the python script source.
#
# Severity routing (aligned with contract enum info|minor|medium|major|blocking|critical):
#   - EN → user on every routable finding (medium and above)
#   - AR → colleague on severe tier (major, blocking, critical) only
# Previous gate used "CRITICAL"/"HIGH" which (a) never matched the contract
# and (b) silently dropped major/blocking findings from the colleague channel (A-4).
#
# Rate limit: 1.1s sleep between EACH send to stay under Telegram's 1 msg/s
# per-chat cap. Big audits (30+ findings × 2 channels) previously 429'd
# silently (A-5). Failures are logged by tg_alert's _tg_send via the shared
# library now — but this dispatcher still uses inline curl for historical
# reasons, so we capture HTTP status here and log failures.
SKILL_NAME="$SKILL" ROUTABLE_JSON_ARG="$ROUTABLE_JSON" \
TG_ALERT_LOG="$REPO_ROOT/channels/logs/tg_alert.log" \
python3 -c '
import json, os, subprocess, time, pathlib, datetime

skill = os.environ["SKILL_NAME"]
findings = json.loads(os.environ["ROUTABLE_JSON_ARG"])
op_token = os.environ.get("OPERATOR_BOT_TOKEN", "")
op_chat  = os.environ.get("OPERATOR_OWNER_ID", "")
co_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
co_chat  = os.environ.get("COLLEAGUE_OWNER_ID", "")

log_path = os.environ.get("TG_ALERT_LOG", "/tmp/tg_alert.log")
try:
    pathlib.Path(log_path).parent.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

def _log(line):
    try:
        with open(log_path, "a") as fh:
            fh.write(f"[{datetime.datetime.now().isoformat(timespec=\"seconds\")}] {line}\n")
    except Exception:
        pass

def send(label, token, chat, text):
    if not token or not chat:
        return
    try:
        r = subprocess.run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "15",
            f"https://api.telegram.org/bot{token}/sendMessage",
            "--data-urlencode", f"chat_id={chat}",
            "--data-urlencode", f"text={text}",
        ], capture_output=True, text=True, check=False, timeout=20)
        status = (r.stdout or "").strip()
        if status != "200":
            _log(f"FAIL run_audit {label} http={status or \"none\"} chat={chat} len={len(text)}")
    except Exception as exc:
        _log(f"FAIL run_audit {label} exc={type(exc).__name__}:{exc}")

# Severe tier = top three. Aligned with contract enum.
COLLEAGUE_TIER = {"MAJOR", "BLOCKING", "CRITICAL"}

first = True
for f in findings:
    sev = (f.get("severity") or "?").upper()
    title = f.get("title", "(untitled)")
    where = f.get("location", "?")
    why = f.get("why_it_matters", "?")
    fix = f.get("suggested_fix", "?")

    if not first:
        time.sleep(1.1)  # Telegram per-chat rate limit
    first = False

    en = (
        f"Security /{skill}\n"
        f"[{sev}] {title}\n"
        f"Location: {where}\n\n"
        f"Why it matters: {why}\n\n"
        f"Suggested fix: {fix}"
    )
    send("operator", op_token, op_chat, en)

    if sev in COLLEAGUE_TIER:
        time.sleep(1.1)  # separate chat also capped at 1 msg/s; also <30/s global
        ar = (
            f"\U0001F6E1 فحص /{skill}\n"
            f"[{sev}] {title}\n"
            f"الموقع: {where}\n\n"
            f"لماذا يهم: {why}\n\n"
            f"الحل المقترح: {fix}"
        )
        send("colleague", co_token, co_chat, ar)
'

echo "[$TS] complete. file: $RUN_LOG, routed: $ROUTABLE_COUNT"
