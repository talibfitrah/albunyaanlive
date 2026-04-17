#!/bin/bash
# Telegram confirmation poller.
#
# Every ~2 min (via systemd timer) this script:
#   1. Reads the last Telegram update_id from a persistent offset file.
#   2. Calls getUpdates against the colleague bot (TELEGRAM_BOT_TOKEN)
#      with offset+1 to fetch only new messages.
#   3. For each message from the colleague's chat_id, classifies the
#      text as confirm / reject / noise using a fusha-first keyword
#      list. If classifiable, finds the most recent pending_confirmation
#      (status=pending, chat_id match, sent_at > now - expiry) and calls
#      `lessons.sh pending-resolve` to write outcomes atomically.
#   4. Persists the new offset.
#   5. Calls `lessons.sh pending-expire` so stale pendings don't linger.
#
# The heavy lifting (keyword classification, DB lookup, atomic resolve)
# is in the embedded Python block — bash is a thin wrapper for env
# plumbing and the persistent offset file.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
STATE_DIR="${CONFIRMATION_STATE_DIR:-$REPO_ROOT/channels/brain}"
OFFSET_FILE="$STATE_DIR/tg_confirm_offset.txt"
LOG_FILE="$STATE_DIR/confirmation_poller.log"
LESSONS_CLI="$SCRIPT_DIR/lessons.sh"

mkdir -p "$STATE_DIR"

log() { echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"; }

# Source env for bot tokens. Bail early if the colleague bot isn't
# configured — there's nothing to poll.
if [[ ! -r "$TELEGRAM_ENV" ]]; then
    log "FATAL telegram env file unreadable: $TELEGRAM_ENV"
    exit 2
fi
set -a
# shellcheck disable=SC1090
source "$TELEGRAM_ENV"
set +a

if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${COLLEAGUE_OWNER_ID:-}" ]]; then
    log "FATAL TELEGRAM_BOT_TOKEN or COLLEAGUE_OWNER_ID missing from env"
    exit 2
fi

# Read last offset. First run safety: if no offset file, fetch current
# updates, save their max update_id as the offset, and exit WITHOUT
# processing — we'd rather miss an hour of confirmations than
# retroactively process months of chat history.
if [[ ! -r "$OFFSET_FILE" ]]; then
    log "first run: initialising offset from current Telegram max update_id"
    BOOTSTRAP="$(curl -s --max-time 10 \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" \
        --data-urlencode "offset=-1" \
        --data-urlencode "timeout=1" \
        --data-urlencode "allowed_updates=[\"message\"]" 2>/dev/null || echo '{}')"
    MAX_ID="$(echo "$BOOTSTRAP" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ids = [u.get("update_id", 0) for u in (d.get("result") or [])]
    print(max(ids) if ids else 0)
except Exception:
    print(0)
')"
    [[ "$MAX_ID" =~ ^[0-9]+$ ]] || MAX_ID=0
    echo "$MAX_ID" > "$OFFSET_FILE"
    log "first run: offset initialised to $MAX_ID; no messages processed this run"
    "$LESSONS_CLI" pending-expire >>"$LOG_FILE" 2>&1 || true
    exit 0
fi
OFFSET="$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)"
[[ "$OFFSET" =~ ^[0-9]+$ ]] || OFFSET=0

# Poll for updates. `timeout=1` keeps this a short-poll — good enough
# for a 2-minute cadence; long-poll would tie up the bot.
RESPONSE="$(curl -s --max-time 15 \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" \
    --data-urlencode "offset=$((OFFSET + 1))" \
    --data-urlencode "timeout=1" \
    --data-urlencode "allowed_updates=[\"message\"]" 2>/dev/null)"
CURL_RC=$?
if [[ "$CURL_RC" -ne 0 ]]; then
    log "WARN curl getUpdates failed rc=$CURL_RC"
    # Expire stale pendings even if polling failed — don't let a
    # Telegram outage pin unresolved rows forever.
    "$LESSONS_CLI" pending-expire >>"$LOG_FILE" 2>&1
    exit 0
fi

# Classify each message and resolve the matching pending via the CLI.
# Python block runs as a subprocess so crashes don't take down the shell.
python3 -c "$(cat <<'PYEOF'
import json, sys, subprocess, re

cli = sys.argv[1]
colleague_chat = sys.argv[2]
raw_response = sys.argv[3]

# Keyword banks. Fusha-first (per tone memory), dialect accepted as
# confirming signals because the colleague mixes registers. Keep the
# lists SHORT and STRICT — we'd rather leave a firing outcome=NULL than
# stamp it wrong and poison the effectiveness score.
CONFIRM = {
    # fusha
    "صحيح", "نعم", "موافق", "تم", "مؤكد", "مطابق",
    # common dialect
    "تمام", "مضبوط", "ممتاز", "ok", "okay", "yes",
    # emoji
    "👍", "✅", "❤", "🎉",
}
REJECT = {
    # fusha
    "لا", "خطأ", "غير صحيح", "ليس صحيحاً", "ليس مطابقاً",
    # common dialect
    "غلط", "مو صحيح", "no",
    # emoji
    "👎", "❌",
}

# Strip common punctuation so "تمام." and "تمام!" still match. Normalize
# to lowercase for the Latin keywords.
_PUNCT = re.compile(r"[.,;!?،؛؟:\s]+")

def classify(text):
    if not text:
        return None
    # Normalize: lowercase Latin, trim punctuation on edges.
    stripped = text.strip()
    stripped_lower = stripped.lower()
    # Exact whole-message match first (short reply like "تمام").
    for bank, label in ((CONFIRM, "confirmed_flag"), (REJECT, "wrong")):
        if stripped in bank or stripped_lower in bank:
            return label
    # Single-word reply: check the first non-punct token.
    tokens = [t for t in _PUNCT.split(stripped) if t]
    if len(tokens) == 1:
        t = tokens[0]
        for bank, label in ((CONFIRM, "confirmed_flag"), (REJECT, "wrong")):
            if t in bank or t.lower() in bank:
                return label
    # Longer messages: only match if the message is entirely a
    # confirming emoji or prefixed with one. Avoids false matches where
    # the reply contains the word "تمام" as part of a longer sentence
    # that might actually be a question or different assertion.
    if stripped[:2] in CONFIRM or stripped[:1] in CONFIRM:
        return "confirmed_flag"
    if stripped[:2] in REJECT or stripped[:1] in REJECT:
        return "wrong"
    return None

try:
    doc = json.loads(raw_response or '{}')
except Exception as e:
    print(f"poller: bad response JSON: {e}", file=sys.stderr)
    sys.exit(0)

if not doc.get("ok"):
    print(f"poller: Telegram replied ok=false: {doc.get('description')}", file=sys.stderr)
    sys.exit(0)

updates = doc.get("result") or []
last_update_id = 0
resolved_count = 0
ignored_count = 0

for upd in updates:
    uid = upd.get("update_id") or 0
    if uid > last_update_id:
        last_update_id = uid
    msg = upd.get("message") or {}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "")
    if not chat_id or chat_id != colleague_chat:
        # Not from the expected colleague chat — ignore.
        continue
    text = (msg.get("text") or "").strip()
    if not text:
        # Photos/voice/stickers — no auto-resolution.
        ignored_count += 1
        continue
    verdict = classify(text)
    if verdict is None:
        # Ambiguous. Don't guess — leave the firing outcome NULL for the
        # operator to resolve manually. Log for visibility.
        print(f"poller: chat={chat_id} text={text[:60]!r} → ambiguous (no match)",
              file=sys.stderr)
        ignored_count += 1
        continue
    # Find the MOST RECENT pending_confirmation for this chat that is
    # still 'pending' and not expired.
    lookup = subprocess.run(
        [cli, "pending-list", "--chat-id", chat_id, "--status", "pending", "--limit", "1"],
        capture_output=True, text=True, timeout=10)
    if lookup.returncode != 0 or not lookup.stdout.strip():
        print(f"poller: chat={chat_id} text={text[:60]!r} → no pending confirmation",
              file=sys.stderr)
        ignored_count += 1
        continue
    # pending-list output is a small table; extract the leading integer
    # id from the first data row (line 2 after header + separator).
    lines = [l for l in lookup.stdout.splitlines() if l.strip() and not l.startswith("-")]
    if len(lines) < 2:
        ignored_count += 1
        continue
    first_data_line = lines[1]
    m = re.match(r"^(\d+)\b", first_data_line.strip())
    if not m:
        ignored_count += 1
        continue
    pending_id = m.group(1)
    res = subprocess.run(
        [cli, "pending-resolve",
         "--id", pending_id,
         "--outcome", verdict,
         "--reply-text", text,
         "--by", "poller"],
        capture_output=True, text=True, timeout=10)
    if res.returncode == 0:
        resolved_count += 1
        print(f"poller: resolved pending id={pending_id} outcome={verdict} "
              f"reply={text[:60]!r}", file=sys.stderr)
    else:
        print(f"poller: pending-resolve failed for id={pending_id}: "
              f"{res.stderr.strip()}", file=sys.stderr)
        ignored_count += 1

# Summary (stdout -> captured by wrapper -> logged).
print(json.dumps({
    "last_update_id": last_update_id,
    "resolved": resolved_count,
    "ignored": ignored_count,
    "updates_seen": len(updates),
}))
PYEOF
)" "$LESSONS_CLI" "$COLLEAGUE_OWNER_ID" "$RESPONSE" 2>>"$LOG_FILE" | while IFS= read -r line; do
    log "RESULT $line"
    # Extract last_update_id and persist offset.
    NEW_OFFSET=$(echo "$line" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("last_update_id",0))' 2>/dev/null || echo 0)
    if [[ "$NEW_OFFSET" =~ ^[0-9]+$ ]] && [[ "$NEW_OFFSET" -gt "$OFFSET" ]]; then
        echo "$NEW_OFFSET" > "$OFFSET_FILE"
        log "offset updated: $OFFSET -> $NEW_OFFSET"
    fi
done

# Expire stale pendings regardless of polling outcome.
"$LESSONS_CLI" pending-expire >>"$LOG_FILE" 2>&1 || true

# Rotate log at 5 MB.
if [[ -f "$LOG_FILE" ]] && [[ "$(stat -c %s "$LOG_FILE")" -gt 5242880 ]]; then
    mv "$LOG_FILE" "$LOG_FILE.1"
fi
