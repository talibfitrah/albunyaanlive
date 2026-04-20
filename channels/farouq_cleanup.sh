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
# Safety: the glob `farouq-*` plus a `rm -rf` running as root is a potent
# combination. Three guardrails:
#   1. HLS_ROOT is hardcoded and asserted at startup.
#   2. Every candidate is stat'd for L-flag; symlinks are skipped (a
#      symlinked farouq-evil -> /var/www/html/stream/hls/makkah would
#      otherwise turn this into an arbitrary-delete primitive).
#   3. realpath(candidate) must still be a direct child of HLS_ROOT
#      after resolution (defense-in-depth against mount tricks).
#   4. .lock files are never unlinked — flock is inode-based, so removing
#      a held .lock breaks mutual exclusion for the next holder (split-
#      brain lock). The few-bytes files are tolerable stragglers.
#
# Dry-run: set FAROUQ_CLEANUP_DRY_RUN=1 to only log what would be removed.

set -euo pipefail

HLS_ROOT=/var/www/html/stream/hls
STATE_DIR=/run/albunyaan/state
MAX_AGE_SEC=$((48 * 3600))
DRY_RUN="${FAROUQ_CLEANUP_DRY_RUN:-0}"

log() { echo "[farouq_cleanup $(date -Iseconds)] $*" >&2; }

# Guardrail 1: HLS_ROOT sanity — if someone refactors this constant to
# empty or to `/`, we refuse to run rather than nuke the filesystem.
[[ "$HLS_ROOT" == "/var/www/html/stream/hls" ]] || {
    log "FATAL: HLS_ROOT is not the expected path ($HLS_ROOT); refusing to run"
    exit 2
}
[[ -d "$HLS_ROOT" ]] || { log "HLS_ROOT missing; nothing to clean"; exit 0; }

now=$(date +%s)
removed=0
kept=0
skipped=0

shopt -s nullglob
for dir in "$HLS_ROOT"/farouq-*/; do
    [ -d "$dir" ] || continue
    # Strip the trailing slash so `[[ -L ]]` tests the link, not the target.
    entry="${dir%/}"
    name=$(basename "$entry")

    # Guardrail 2: symlink check. `rm -rf dir/` with a trailing slash on
    # a symlinked directory follows the link (verified 2026-04-20 against
    # GNU coreutils). Skip, don't delete.
    if [[ -L "$entry" ]]; then
        log "skip ${name}: entry is a symlink (refuse to follow)"
        skipped=$((skipped + 1))
        continue
    fi

    # Guardrail 3: realpath must resolve back under HLS_ROOT. Catches
    # bind-mounts and other indirection the -L test misses.
    real=$(realpath -e "$entry" 2>/dev/null || true)
    if [[ -z "$real" ]] || [[ "$real" != "$HLS_ROOT/$name" ]]; then
        log "skip ${name}: realpath=${real:-unresolved} not a direct child of HLS_ROOT"
        skipped=$((skipped + 1))
        continue
    fi

    # Relax pipefail around find|awk: if a concurrent writer removes the
    # directory mid-scan, find exits non-zero and the whole pipeline
    # aborts under `set -euo pipefail`. We treat the scan as best-effort
    # and fall back to the dir mtime below.
    latest=$({ find "$entry" -type f -printf '%T@\n' 2>/dev/null || true; } \
             | awk 'BEGIN{m=0} $1>m{m=$1} END{print m}')
    if [[ -z "$latest" ]] || [[ "$latest" == "0" ]]; then
        latest=$(stat -c %Y "$entry" 2>/dev/null || echo 0)
    fi
    latest_int=${latest%.*}
    age=$(( now - latest_int ))

    if (( age > MAX_AGE_SEC )); then
        log "expire ${name}: age=${age}s ($(date -d "@${latest_int}" +%F' '%T))"
        if [[ "$DRY_RUN" == "1" ]]; then
            log "  DRY_RUN=1: skipping rm"
        else
            rm -rf -- "$entry"
            # Guardrail 4: only unlink the state JSON. Leave .lock alone —
            # removing a held flock file creates split-brain locks.
            rm -f -- "$STATE_DIR/${name}.json"
        fi
        removed=$(( removed + 1 ))
    else
        remaining=$(( MAX_AGE_SEC - age ))
        log "keep ${name}: age=${age}s, ~${remaining}s (~$((remaining/3600))h) left"
        kept=$(( kept + 1 ))
    fi
done

# Orphan state files: reflex state JSON for farouq-* whose HLS dir is gone.
# farouq-* channels are never registered in channel_registry.json, so
# reflex_watcher does NOT track them and holds no fds on their state —
# but we still leave .lock alone on principle (see guardrail 4).
for sfile in "$STATE_DIR"/farouq-*.json; do
    [ -f "$sfile" ] || continue
    name=$(basename "$sfile" .json)
    if [[ ! -d "$HLS_ROOT/$name" ]]; then
        log "orphan state ${name}: removing"
        if [[ "$DRY_RUN" != "1" ]]; then
            rm -f -- "$sfile"
        fi
    fi
done

log "done: removed=$removed kept=$kept skipped=$skipped dry_run=$DRY_RUN"
