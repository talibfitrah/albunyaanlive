#!/bin/bash
# Kill streamlink processes that have been reparented to PID 1 (systemd)
# AND are older than 10 minutes. A PPID=1 streamlink whose parent died is
# writing to a closed pipe — it's doing work that nothing consumes.
#
# The >10min age filter avoids racing with brand-new orphans that may be
# mid-reparenting during a legitimate feeder restart.

set -u

log() { logger -t reap-orphan-streamlinks "$*"; }

# etimes (elapsed seconds) > 600 = older than 10 min
mapfile -t ORPHANS < <(ps -eo pid,ppid,etimes,cmd --no-headers \
    | awk '$2==1 && $3>600 && /streamlink --stdout/ {print $1}')

if (( ${#ORPHANS[@]} == 0 )); then
    exit 0
fi

log "Reaping ${#ORPHANS[@]} orphan streamlink(s): ${ORPHANS[*]}"

# SIGTERM first (polite); SIGKILL any that survive
kill -TERM "${ORPHANS[@]}" 2>/dev/null
sleep 2
mapfile -t SURVIVORS < <(ps -eo pid,ppid,etimes,cmd --no-headers \
    | awk '$2==1 && $3>600 && /streamlink --stdout/ {print $1}')

if (( ${#SURVIVORS[@]} > 0 )); then
    log "SIGKILL survivors: ${SURVIVORS[*]}"
    kill -KILL "${SURVIVORS[@]}" 2>/dev/null
fi
