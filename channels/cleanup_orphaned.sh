#!/bin/bash

# =============================================================================
# Orphaned Segment Cleanup Script
# =============================================================================
# Removes stale HLS segments from channels that are no longer running
# Run via cron: 0 */4 * * * /path/to/cleanup_orphaned.sh
#
# Fixed Issues:
#   - [BLOCKER] Uses consistent channel_id (HLS directory name) for process detection
#   - Never deletes segments from actively running channels
# =============================================================================

HLS_BASE_DIR="/var/www/html/stream/hls"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STALE_THRESHOLD_HOURS=1
DRY_RUN=false

# Choose a writable log directory (fallback to /tmp if repo logs are not writable)
resolve_log_dir() {
    local preferred="$1"
    local fallback="/tmp/albunyaan-logs"

    if mkdir -p "$preferred" 2>/dev/null && [[ -w "$preferred" ]]; then
        echo "$preferred"
        return
    fi

    mkdir -p "$fallback" 2>/dev/null || true
    if [[ -w "$fallback" ]]; then
        echo "$fallback"
        return
    fi

    echo "$preferred"
}

LOG_DIR=$(resolve_log_dir "$SCRIPT_DIR/logs")
LOG_FILE="$LOG_DIR/cleanup.log"

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Parse arguments
while getopts 'dn' OPTION; do
    case "$OPTION" in
        d) DRY_RUN=true ;;
        n) DRY_RUN=true ;;
        *) echo "Usage: $0 [-d] (dry run)"; exit 1 ;;
    esac
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# =============================================================================
# BLOCKER FIX: Helper function to get channel_id
# =============================================================================

get_channel_id() {
    local channel_dir="$1"
    basename "$channel_dir"
}

# Escape regex special characters for safe pgrep patterns
escape_regex() {
    printf '%s' "$1" | sed 's/[][\\.^$*+?{}|()]/\\&/g'
}

# Check if channel has a script (is configured)
has_channel_script() {
    local channel_id="$1"
    local underscore_name="${channel_id//-/_}"  # Convert hyphens to underscores

    local patterns=(
        "channel_${channel_id}_revised.sh"
        "channel_${channel_id}.sh"
        "channel_${underscore_name}_revised.sh"
        "channel_${underscore_name}.sh"
    )

    for pattern in "${patterns[@]}"; do
        if [[ -f "$SCRIPT_DIR/$pattern" ]]; then
            return 0
        fi
    done

    # Try fuzzy match
    if find "$SCRIPT_DIR" -maxdepth 1 \( -name "channel_*${channel_id}*.sh" -o -name "channel_*${underscore_name}*.sh" \) -type f 2>/dev/null | grep -q .; then
        return 0
    fi

    return 1
}

# =============================================================================
# BLOCKER FIX: Check if channel is running using consistent channel_id
# =============================================================================

is_channel_running() {
    local channel_id="$1"
    local escaped_channel_id
    escaped_channel_id=$(escape_regex "$channel_id")
    local pidfile="/tmp/stream_${channel_id}.pid"
    local lockdir="/tmp/stream_${channel_id}.lock"

    # Method 1: Check pidfile (most reliable)
    if [[ -f "$pidfile" ]]; then
        local pid=$(cat "$pidfile" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0  # Running
        fi
    fi

    # Method 2: Check lock directory
    if [[ -d "$lockdir" ]]; then
        # Lock exists - check if FFmpeg is writing to this channel
        if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
            return 0  # Running
        fi
    fi

    # Method 3: Direct FFmpeg check (in case lock/pid are missing)
    if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
        return 0  # Running
    fi

    return 1  # Not running
}

# Get age of newest segment in directory
get_newest_segment_age() {
    local dir="$1"
    local current_time=$(date +%s)

    local newest=$(find "$dir" -name "*.ts" -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
    if [[ -n "$newest" ]]; then
        local mtime=$(echo "$newest" | cut -d'.' -f1)
        echo $((current_time - mtime))
    else
        echo 999999
    fi
}

# Clean a channel directory
clean_channel() {
    local channel_dir="$1"
    local channel_id=$(get_channel_id "$channel_dir")

    local segment_count=$(find "$channel_dir" -name "*.ts" -type f 2>/dev/null | wc -l)
    local total_size=$(du -sh "$channel_dir" 2>/dev/null | cut -f1)

    if [[ $DRY_RUN == true ]]; then
        log "[DRY RUN] Would delete $segment_count segments ($total_size) from $channel_id"
    else
        log "Cleaning $channel_id: $segment_count segments ($total_size)"
        rm -f "$channel_dir"/*.ts
        rm -f "$channel_dir"/*.m3u8
        log "Cleaned $channel_id"
    fi
}

# Main cleanup logic
main() {
    log "=== Starting orphaned segment cleanup ==="
    if [[ $DRY_RUN == true ]]; then
        log "DRY RUN MODE - No files will be deleted"
    fi

    if [[ ! -d "$HLS_BASE_DIR" ]]; then
        log "ERROR: HLS directory not found: $HLS_BASE_DIR"
        exit 1
    fi

    local cleaned=0
    local skipped=0
    local protected=0
    local current_time=$(date +%s)
    local threshold_seconds=$((STALE_THRESHOLD_HOURS * 3600))

    for channel_dir in "$HLS_BASE_DIR"/*/; do
        if [[ ! -d "$channel_dir" ]]; then
            continue
        fi

        local channel_id=$(get_channel_id "$channel_dir")
        local playlist="$channel_dir/master.m3u8"

        # Skip if no segments exist
        if [[ ! -f "$playlist" ]]; then
            continue
        fi

        # Check playlist age
        local playlist_mtime=$(stat -c %Y "$playlist" 2>/dev/null || echo 0)
        local playlist_age=$((current_time - playlist_mtime))

        # Skip if playlist is fresh (within threshold)
        if [[ $playlist_age -lt $threshold_seconds ]]; then
            skipped=$((skipped + 1))
            continue
        fi

        # CRITICAL SAFETY CHECK: Never clean if channel is actively running
        if is_channel_running "$channel_id"; then
            log "PROTECTED: Channel $channel_id is running (stale playlist but active process)"
            protected=$((protected + 1))
            continue
        fi

        # Check if channel has a script (is a configured channel)
        if has_channel_script "$channel_id"; then
            # Channel has a script but is not running - might be intentionally stopped
            # Still safe to clean since it's not running
            log "Channel $channel_id has script but is not running"
        fi

        # Channel is stale and not running - safe to clean
        clean_channel "$channel_dir"
        cleaned=$((cleaned + 1))
    done

    log "=== Cleanup complete: $cleaned cleaned, $skipped skipped (fresh), $protected protected (running) ==="
}

main "$@"
