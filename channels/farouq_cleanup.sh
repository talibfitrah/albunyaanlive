#!/bin/bash
# farouq_cleanup.sh — removes /var/www/html/stream/hls/farouq-*/ directories
# whose most-recent file is older than 48h, plus matching watcher state files.
#
# Rationale: farouq-* are ephemeral halal-video processing artifacts, not
# production channels. Operator policy (2026-04-20): keep 48h after last
# activity so the colleague can review/download, then drop to free disk
# and stop polluting the reflex watcher's state dir.
#
# Runs hourly via albunyaan-farouq-cleanup.timer. Service runs as root
# because the .mp4 files inside are owned by root + msa; some need root
# to remove.
#
# Dry-run: set FAROUQ_CLEANUP_DRY_RUN=1 to only log what would be removed.

set -euo pipefail

HLS_ROOT=/var/www/html/stream/hls
STATE_DIR=/run/albunyaan/state
MAX_AGE_SEC=$((48 * 3600))
DRY_RUN="${FAROUQ_CLEANUP_DRY_RUN:-0}"

log() { echo "[farouq_cleanup $(date -Iseconds)] $*" >&2; }

now=$(date +%s)
removed=0
kept=0

shopt -s nullglob
for dir in "$HLS_ROOT"/farouq-*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")

    # awk finds the max mtime in a single pass — no SIGPIPE race vs head -1.
    latest=$(find "$dir" -type f -printf '%T@\n' 2>/dev/null | awk 'BEGIN{m=0} $1>m{m=$1} END{print m}')
    if [[ -z "$latest" ]]; then
        latest=$(stat -c %Y "$dir" 2>/dev/null || echo 0)
    fi
    latest_int=${latest%.*}
    age=$(( now - latest_int ))

    if (( age > MAX_AGE_SEC )); then
        log "expire ${name}: age=${age}s ($(date -d "@${latest_int}" +%F' '%T))"
        if [[ "$DRY_RUN" == "1" ]]; then
            log "  DRY_RUN=1: skipping rm"
        else
            rm -rf -- "$dir"
            rm -f -- "$STATE_DIR/${name}.json" "$STATE_DIR/${name}.lock"
        fi
        removed=$(( removed + 1 ))
    else
        remaining=$(( MAX_AGE_SEC - age ))
        log "keep ${name}: age=${age}s, ~${remaining}s (~$((remaining/3600))h) left"
        kept=$(( kept + 1 ))
    fi
done

# Orphan state files: reflex state for farouq-* whose HLS dir is gone.
for sfile in "$STATE_DIR"/farouq-*.json; do
    [ -f "$sfile" ] || continue
    name=$(basename "$sfile" .json)
    if [[ ! -d "$HLS_ROOT/$name" ]]; then
        log "orphan state ${name}: removing"
        if [[ "$DRY_RUN" != "1" ]]; then
            rm -f -- "$sfile" "$STATE_DIR/${name}.lock"
        fi
    fi
done

log "done: removed=$removed kept=$kept dry_run=$DRY_RUN"
