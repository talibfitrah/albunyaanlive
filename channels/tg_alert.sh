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

tg_alert() {
    local severity="$1"
    local en_msg="$2"
    local ar_msg="${3:-}"

    if [[ -n "${OPERATOR_BOT_TOKEN:-}" && -n "${OPERATOR_OWNER_ID:-}" ]]; then
        curl -s --max-time 10 \
            "https://api.telegram.org/bot${OPERATOR_BOT_TOKEN}/sendMessage" \
            --data-urlencode "chat_id=${OPERATOR_OWNER_ID}" \
            --data-urlencode "text=${en_msg}" >/dev/null 2>&1 || true
    fi

    if [[ "$severity" == "severe" \
          && -n "$ar_msg" \
          && -n "${TELEGRAM_BOT_TOKEN:-}" \
          && -n "${COLLEAGUE_OWNER_ID:-}" ]]; then
        curl -s --max-time 10 \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            --data-urlencode "chat_id=${COLLEAGUE_OWNER_ID}" \
            --data-urlencode "text=${ar_msg}" >/dev/null 2>&1 || true
    fi
}
