#!/bin/bash
# channels/reflex/freshness.sh
# Output-freshness check: is any .ts segment in the channel's HLS dir
# fresher than the threshold? Returns 0=fresh, 1=stale, 2=no-dir.

# is_output_fresh <hls_dir> [threshold_seconds]
is_output_fresh() {
    local hls_dir="$1"
    local threshold_sec="${2:-10}"
    [[ -d "$hls_dir" ]] || return 2
    local fresh_count
    fresh_count=$(find "$hls_dir" -maxdepth 1 -name '*.ts' \
                       -newermt "-${threshold_sec} seconds" 2>/dev/null | wc -l)
    (( fresh_count > 0 ))
}
