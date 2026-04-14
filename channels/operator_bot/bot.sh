#!/usr/bin/env bash
# Albunyaan operator bot (bot #2 / @AbdulfattaahBot).
#
# Long-polls Telegram getUpdates with a 25s timeout, dispatches a small
# allowlist of commands from exactly one chat (OPERATOR_OWNER_ID), and
# replies in-chat. Designed to run forever under systemd.
#
# This bot is separate from the plugin-hosted bot #1. Different token,
# no polling conflict.
#
# Commands (v1):
#   /status — snapshot of brain + watcher + git
#   /wake   — force an immediate brain wake
#   /help   — list commands

set -euo pipefail

REPO_ROOT="/home/msa/Development/scripts/albunyaan"
STATE_DIR="${REPO_ROOT}/channels/operator_bot"
OFFSET_FILE="${STATE_DIR}/update_offset"
LOG_FILE="${REPO_ROOT}/channels/logs/operator_bot.log"
TELEGRAM_ENV="${HOME}/.claude/channels/telegram/.env"

mkdir -p "$(dirname "$LOG_FILE")"

log() { printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" >>"$LOG_FILE"; }

if [[ -r "$TELEGRAM_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$TELEGRAM_ENV"
    set +a
fi

if [[ -z "${OPERATOR_BOT_TOKEN:-}" || -z "${OPERATOR_OWNER_ID:-}" ]]; then
    log "FATAL OPERATOR_BOT_TOKEN or OPERATOR_OWNER_ID missing; env=$TELEGRAM_ENV"
    exit 1
fi

API="https://api.telegram.org/bot${OPERATOR_BOT_TOKEN}"

reply() {
    local chat_id="$1"
    local text="$2"
    local resp http_ok
    resp=$(curl -s --max-time 15 "${API}/sendMessage" \
        --data-urlencode "chat_id=${chat_id}" \
        --data-urlencode "text=${text}" 2>&1) || true
    http_ok=$(printf '%s' "$resp" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print("yes" if d.get("ok") else "no")' 2>/dev/null || echo "parse-fail")
    if [[ "$http_ok" != "yes" ]]; then
        log "reply FAILED chat=$chat_id len=${#text} resp=$(printf '%s' "$resp" | head -c 200)"
    fi
}

cmd_help() {
    cat <<'EOF'
Available commands:
/status — brain + watcher + last commit snapshot
/wake — force an immediate brain wake
/help — this list
EOF
}

cmd_status() {
    local brain_state="${REPO_ROOT}/channels/brain/state.json"
    local watcher_state="/tmp/albunyaan-watcher-state.json"

    local wake_count="?"
    local incidents="?"
    if [[ -r "$brain_state" ]]; then
        wake_count=$(python3 -c "import json; d=json.load(open('$brain_state')); print(d.get('wake_count','?'))" 2>/dev/null || echo "?")
        incidents=$(python3 -c "import json; d=json.load(open('$brain_state')); i=d.get('incidents',[]); print(len(i))" 2>/dev/null || echo "?")
    fi

    local state_age="?" unhealthy="?"
    if [[ -r "$watcher_state" ]]; then
        state_age=$(python3 -c "import json,time; d=json.load(open('$watcher_state')); print(int(time.time())-d['unix'])" 2>/dev/null || echo "?")
        unhealthy=$(python3 -c "import json; d=json.load(open('$watcher_state')); u=[c['id'] for c in d['channels'] if c['status']!='healthy']; print(','.join(u) if u else 'none')" 2>/dev/null || echo "?")
    fi

    local last_commit
    last_commit=$(cd "$REPO_ROOT" && git log --oneline -1 2>/dev/null || echo "?")

    cat <<EOF
System status

Brain: wake_count=${wake_count}, open incidents=${incidents}
Watcher: state age ${state_age}s, unhealthy: ${unhealthy}
Last commit: ${last_commit}
EOF
}

cmd_wake() {
    # systemctl start is a no-op if already active; exit code reflects that.
    if SUDO_ASKPASS="${HOME}/.sudo_pass.sh" sudo -A systemctl start albunyaan-brain.service 2>/dev/null; then
        echo "Brain wake triggered. Summary will follow when the wake completes."
    else
        echo "Brain wake failed (check systemd). A wake may already be running."
    fi
}

dispatch() {
    local chat_id="$1"
    local text="$2"
    # First token after trim. Only respond to messages that start with
    # "/" — casual chatter ("nice job", "thanks") stays silent instead of
    # triggering an "Unknown command" nag.
    local cmd
    cmd=$(printf '%s' "$text" | awk '{print $1}')
    case "$cmd" in
        /status)  reply "$chat_id" "$(cmd_status)" ;;
        /wake)    reply "$chat_id" "$(cmd_wake)" ;;
        /help|/start) reply "$chat_id" "$(cmd_help)" ;;
        /*)       reply "$chat_id" "Unknown command. Try /help." ;;
        *)        log "chatter from=$chat_id (ignored): $(printf '%s' "$text" | head -c 80)" ;;
    esac
}

# Atomic write: tmp + rename, so a crash mid-write cannot truncate the file
# and cause a 0-offset replay of 24h of queued chatter on restart (A-2).
write_offset() {
    local tmp="${OFFSET_FILE}.tmp.$$"
    printf '%s\n' "$1" >"$tmp" && mv -f "$tmp" "$OFFSET_FILE"
}

# Initialize offset.
# - Missing or unreadable file: start from Telegram's tail (offset=-1, limit=1)
#   so we fetch only the latest update_id and seed from there — don't replay
#   24h of queued messages on a cold start (A-2).
# - Zero/empty value: same recovery path. Non-zero values are trusted.
OFFSET=0
if [[ -r "$OFFSET_FILE" ]]; then
    OFFSET=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)
    OFFSET=${OFFSET:-0}
fi
if [[ "$OFFSET" -eq 0 ]]; then
    seed_resp=$(curl -s --max-time 15 "${API}/getUpdates?offset=-1&limit=1" 2>/dev/null || echo '{"ok":false}')
    SEED=$(printf '%s' "$seed_resp" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    r = d.get("result") or []
    if r:
        print(r[-1].get("update_id", 0) + 1)
    else:
        print(0)
except Exception:
    print(0)
' 2>/dev/null || echo 0)
    OFFSET=${SEED:-0}
    write_offset "$OFFSET"
    log "startup seeded offset=$OFFSET (no prior state)"
fi

log "startup offset=$OFFSET owner=$OPERATOR_OWNER_ID"

while true; do
    # Long-poll 25s. 30s is Telegram's max for getUpdates; 25s leaves slack.
    resp=$(curl -s --max-time 30 \
        "${API}/getUpdates?offset=${OFFSET}&timeout=25" 2>/dev/null || echo '{"ok":false}')

    if ! echo "$resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ok") else 1)' 2>/dev/null; then
        log "getUpdates failed; backing off 10s"
        sleep 10
        continue
    fi

    # Process each update FIRST, then advance offset. If we crash mid-dispatch,
    # Telegram re-delivers on restart (within its 24h queue) — at-least-once
    # beats at-most-once for operator commands (A-2).
    while IFS=$'\t' read -r update_id from_id chat_id text; do
        [[ -z "$update_id" ]] && continue

        if [[ "$from_id" != "$OPERATOR_OWNER_ID" ]]; then
            log "dropped update_id=$update_id from=$from_id (not owner)"
        else
            log "cmd update_id=$update_id text=$(printf '%s' "$text" | head -c 80)"
            # Wrap dispatch so a failing command cannot escape -euo pipefail
            # and let a poison-pill update infinite-loop via systemd restarts
            # (A-2 safety rail on at-least-once semantics).
            dispatch "$chat_id" "$text" || log "dispatch FAILED update_id=$update_id rc=$?"
        fi

        NEW_OFFSET=$((update_id + 1))
        OFFSET=$NEW_OFFSET
        write_offset "$OFFSET"
    done < <(echo "$resp" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for u in d.get("result", []):
    uid = u.get("update_id")
    msg = u.get("message") or {}
    frm = (msg.get("from") or {}).get("id")
    chat = (msg.get("chat") or {}).get("id")
    txt = msg.get("text") or ""
    if uid is None or frm is None or chat is None:
        # still advance offset so we do not loop on a malformed update
        if uid is not None:
            print(f"{uid}\t\t\t")
        continue
    # Keep text single-line; Telegram never sends tabs/newlines in /commands,
    # but colleague chatter could. We only act on /commands anyway.
    txt = txt.replace("\t", " ").replace("\n", " ")
    print(f"{uid}\t{frm}\t{chat}\t{txt}")
')
done
