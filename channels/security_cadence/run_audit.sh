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

tg_send() {
    local msg="$1"
    [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_OWNER_ID:-}" ]] && return 0
    curl -s --max-time 15 \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_OWNER_ID}" \
        --data-urlencode "text=${msg}" >/dev/null || true
}

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
    tg_send "فحص /${SKILL} فشل (رمز خروج ${RC}). راجع السجل على الخادم."
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
    tg_send "فحص /${SKILL} اكتمل لكن لم يُنتج تقريراً منظماً. الملف الكامل محفوظ على الخادم."
    exit 4
fi

if ! echo "$JSON_LINE" | python3 -m json.tool >/dev/null 2>&1; then
    echo "[$TS] JSON line failed to parse" >&2
    cp "$RAW_LOG" "$RUN_LOG"
    tg_send "فحص /${SKILL} أنتج JSON غير صالح. الملف محفوظ للمراجعة."
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
SKILL_NAME="$SKILL" ROUTABLE_JSON_ARG="$ROUTABLE_JSON" python3 -c '
import json, os, subprocess
skill = os.environ["SKILL_NAME"]
findings = json.loads(os.environ["ROUTABLE_JSON_ARG"])
token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
chat = os.environ.get("TELEGRAM_OWNER_ID", "")
if not token or not chat:
    raise SystemExit(0)
for f in findings:
    sev = f.get("severity", "?").upper()
    title = f.get("title", "(untitled)")
    where = f.get("location", "?")
    why = f.get("why_it_matters", "?")
    fix = f.get("suggested_fix", "?")
    msg = (
        f"\U0001F6E1 فحص /{skill}\n"
        f"[{sev}] {title}\n"
        f"الموقع: {where}\n\n"
        f"لماذا يهم: {why}\n\n"
        f"الحل المقترح: {fix}"
    )
    subprocess.run([
        "curl", "-s", "--max-time", "15",
        f"https://api.telegram.org/bot{token}/sendMessage",
        "--data-urlencode", f"chat_id={chat}",
        "--data-urlencode", f"text={msg}",
    ], stdout=subprocess.DEVNULL, check=False)
'

echo "[$TS] complete. file: $RUN_LOG, routed: $ROUTABLE_COUNT"
