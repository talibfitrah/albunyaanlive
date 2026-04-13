#!/bin/bash
# Extract one frame per channel from the newest HLS segment.
# Output: $THUMBS_DIR/thumb_<channel>.png
# Phase 2: content-identity verification sampler.

set -u
shopt -s nullglob

HLS_ROOT="${HLS_ROOT:-/var/www/html/stream/hls}"
THUMBS_DIR="${THUMBS_DIR:-/tmp/albunyaan-thumbs}"
LOG_FILE="${LOG_FILE:-/home/msa/Development/scripts/albunyaan/channels/logs/thumbnail_sampler.log}"

mkdir -p "$THUMBS_DIR" "$(dirname "$LOG_FILE")"

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG_FILE"; }

sample_channel() {
    local dir="$1" ch="$2"
    local newest
    newest=$(ls -t "$dir"/*.ts 2>/dev/null | head -1)
    if [[ -z "$newest" ]]; then
        log "skip $ch: no segments"
        return 1
    fi
    local out="$THUMBS_DIR/thumb_${ch}.png"
    local out_tmp="${out}.tmp"
    if ffmpeg -nostdin -v error -i "$newest" -frames:v 1 -vf "scale=640:-1" -c:v png -f image2 -y "$out_tmp" 2>>"$LOG_FILE"; then
        mv -f "$out_tmp" "$out"
        log "ok $ch <- $(basename "$newest")"
    else
        rm -f "$out_tmp"
        log "fail $ch <- $(basename "$newest")"
        return 1
    fi
}

main() {
    local count_ok=0 count_fail=0
    for dir in "$HLS_ROOT"/*/; do
        local ch="$(basename "$dir")"
        [[ "$ch" == "slate" ]] && continue
        if sample_channel "$dir" "$ch"; then
            count_ok=$((count_ok+1))
        else
            count_fail=$((count_fail+1))
        fi
    done
    log "sweep done: ok=$count_ok fail=$count_fail"
    echo "ok=$count_ok fail=$count_fail thumbs=$THUMBS_DIR"
}

main "$@"
