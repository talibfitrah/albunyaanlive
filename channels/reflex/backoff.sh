#!/bin/bash
# channels/reflex/backoff.sh
# Primary-probe backoff schedule (seconds).
# 0-2 failures → 5 min; 3 → 15 min; 4 → 30 min; 5+ → 60 min (cap).

backoff_delay() {
    local n="$1"
    case "$n" in
        0|1|2) echo 300 ;;
        3)     echo 900 ;;
        4)     echo 1800 ;;
        *)     echo 3600 ;;
    esac
}
