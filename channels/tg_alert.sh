#!/usr/bin/env bash
# Shared Telegram alert helper with severity-based bilingual routing.
#
# Usage (after sourcing):
#   tg_alert <severity> <english_text> [arabic_text]
#
#   severity ∈ { info | warn | severe }
#   english_text → always sent to user (bot #2)
#   arabic_text  → sent to colleague (bot #1) only when severity=severe
#                  (omit for user-only alerts)
#
# Env loaded from $HOME/.claude/channels/telegram/.env by caller:
#   OPERATOR_BOT_TOKEN   — bot #2, user channel
#   OPERATOR_OWNER_ID    — user chat_id
#   TELEGRAM_BOT_TOKEN   — bot #1, colleague channel
#   COLLEAGUE_OWNER_ID   — colleague chat_id
#
# Delivery failures are logged to $TG_ALERT_LOG (default
# channels/logs/tg_alert.log) so severe alerts can't silently disappear on
# 401/429/network errors (A-3). Set TG_ALERT_LOG=/dev/null to opt out.

: "${TG_ALERT_LOG:=/home/msa/Development/scripts/albunyaan/channels/logs/tg_alert.log}"

_tg_log() {
    # Best-effort log; never fail the caller.
    mkdir -p "$(dirname "$TG_ALERT_LOG")" 2>/dev/null || return 0
    printf '[%s] %s\n' "$(date -Iseconds)" "$*" >>"$TG_ALERT_LOG" 2>/dev/null || true
}

_tg_send() {
    # _tg_send <label> <token> <chat_id> <text>
    # Captures response + HTTP status, logs failures with body head.
    # Token is NEVER logged or echoed (A-3).
    local label="$1" token="$2" chat="$3" text="$4"
    local body_file status
    body_file=$(mktemp -t tg_alert.XXXXXX 2>/dev/null || echo "/tmp/.tg_alert.$$.body")
    status=$(curl -s --max-time 10 -o "$body_file" -w '%{http_code}' \
           "https://api.telegram.org/bot${token}/sendMessage" \
           --data-urlencode "chat_id=${chat}" \
           --data-urlencode "text=${text}" 2>/dev/null) || status=""
    if [[ "$status" != "200" ]]; then
        local body
        body=$(head -c 200 "$body_file" 2>/dev/null | tr -d '\n' || true)
        _tg_log "FAIL $label http=${status:-none} chat=$chat len=${#text} body=$body"
    fi
    rm -f "$body_file" 2>/dev/null
}

tg_alert() {
    local severity="$1"
    local en_msg="$2"
    local ar_msg="${3:-}"

    local op_ok=0 co_ok=0
    [[ -n "${OPERATOR_BOT_TOKEN:-}" && -n "${OPERATOR_OWNER_ID:-}" ]] && op_ok=1
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${COLLEAGUE_OWNER_ID:-}" ]] && co_ok=1

    # A-6: if no channel has valid creds, log loudly — partial or total env
    # loss silently degrades alert coverage otherwise.
    if [[ $op_ok -eq 0 && $co_ok -eq 0 ]]; then
        _tg_log "CONFIG no bot credentials available; dropping severity=$severity en_len=${#en_msg}"
        return 0
    fi

    if [[ $op_ok -eq 1 ]]; then
        _tg_send "operator" "$OPERATOR_BOT_TOKEN" "$OPERATOR_OWNER_ID" "$en_msg"
    else
        _tg_log "WARN operator bot creds missing; severity=$severity en_len=${#en_msg} not delivered"
    fi

    if [[ "$severity" == "severe" && -n "$ar_msg" ]]; then
        if [[ $co_ok -eq 1 ]]; then
            _tg_send "colleague" "$TELEGRAM_BOT_TOKEN" "$COLLEAGUE_OWNER_ID" "$ar_msg"
        else
            _tg_log "WARN colleague bot creds missing; severe alert ar_len=${#ar_msg} not delivered"
        fi
    fi
}
