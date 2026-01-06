#!/bin/bash

# =============================================================================
# HLS Channel Health Monitor with Auto-Restart
# =============================================================================

SUDO_PASS_FILE="${SUDO_PASS_FILE:-$HOME/.sudo_pass.sh}"
sudo_run() {
    if [[ $(id -u) -eq 0 ]]; then
        "$@"
        return $?
    fi
    if [[ -r "$SUDO_PASS_FILE" ]]; then
        sudo -S "$@" < "$SUDO_PASS_FILE"
        return $?
    fi
    sudo -n "$@"
}

DEVNULL="/dev/null"
devnull_fallback=0
if [[ ! -c /dev/null || ! -w /dev/null ]]; then
    DEVNULL="/tmp/albunyaan-dev-null"
    : > "$DEVNULL" || true
    devnull_fallback=1
fi

# STABILITY: Ensure /dev/null is a character device (not a regular file)
if [[ ! -c /dev/null ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: /dev/null is not a character device, attempting fix..."
    # Use atomic replacement to avoid races with concurrent redirects to /dev/null.
    sudo_run rm -f /dev/null.new 2>$DEVNULL || true
    sudo_run mknod -m 666 /dev/null.new c 1 3 2>$DEVNULL || true
    sudo_run chown root:root /dev/null.new 2>$DEVNULL || true
    sudo_run chmod 666 /dev/null.new 2>$DEVNULL || true
    sudo_run mv -f /dev/null.new /dev/null 2>$DEVNULL || true
    if [[ ! -c /dev/null ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FATAL: Cannot fix /dev/null, exiting"
        exit 1
    fi
fi

if [[ $devnull_fallback -eq 1 && -c /dev/null && -w /dev/null ]]; then
    DEVNULL="/dev/null"
fi

# =============================================================================
# Monitors HLS output directories for stale segments and auto-restarts channels
# Run via cron: */2 * * * * /path/to/health_monitor.sh >> /tmp/albunyaan-logs/health_cron.log 2>&1
#
# Fixed Issues:
#   - [BLOCKER] Uses channel_id (HLS directory name) for process detection
#   - [MINOR] Updated thresholds: 15s segment stale, 30s playlist stale
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HLS_BASE_DIR="/var/www/html/stream/hls"
RESTART_TRACKING_DIR="/tmp/stream_health"
MAX_RESTARTS_PER_HOUR=5

# MINOR FIX: Updated thresholds per spec (was 30/60, now 15/30)
SEGMENT_STALE_THRESHOLD=15   # seconds - segment freshness check
PLAYLIST_STALE_THRESHOLD=30  # seconds - playlist freshness check

# Choose a writable log directory (fallback to /tmp if repo logs are not writable)
resolve_log_dir() {
    local preferred="$1"
    local fallback="/tmp/albunyaan-logs"

    if mkdir -p "$preferred" 2>$DEVNULL && [[ -w "$preferred" ]]; then
        echo "$preferred"
        return
    fi

    mkdir -p "$fallback" 2>$DEVNULL || true
    if [[ -w "$fallback" ]]; then
        echo "$fallback"
        return
    fi

    echo "$preferred"
}

LOG_DIR=$(resolve_log_dir "$SCRIPT_DIR/logs")
LOG_FILE="$LOG_DIR/health_monitor.log"

mkdir -p "$(dirname "$LOG_FILE")" 2>$DEVNULL || true
mkdir -p "$RESTART_TRACKING_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_console() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    log "$1"
}

# =============================================================================
# BLOCKER FIX: Helper function to get channel_id
# =============================================================================
# The channel_id is simply the HLS directory name (e.g., "basmah", "almajd-news")
# This matches the channel_id used by try_start_stream.sh and generic_channel.sh
# =============================================================================

get_channel_id() {
    local channel_dir="$1"
    basename "$channel_dir"
}

# Escape regex special characters for safe pgrep/pkill patterns
escape_regex() {
    printf '%s' "$1" | sed 's/[][\\.^$*+?{}|()]/\\&/g'
}

# Get restart count for a channel in the last hour
get_restart_count() {
    local channel_id="$1"
    local count_file="$RESTART_TRACKING_DIR/${channel_id}_restarts"
    local current_time=$(date +%s)
    local one_hour_ago=$((current_time - 3600))

    if [[ ! -f "$count_file" ]]; then
        echo 0
        return
    fi

    # Count restarts in the last hour
    local count=0
    while IFS= read -r timestamp; do
        if [[ $timestamp -gt $one_hour_ago ]]; then
            count=$((count + 1))
        fi
    done < "$count_file"

    echo $count
}

# Record a restart
record_restart() {
    local channel_id="$1"
    local count_file="$RESTART_TRACKING_DIR/${channel_id}_restarts"
    local current_time=$(date +%s)
    local one_hour_ago=$((current_time - 3600))

    # Clean old entries and add new one
    if [[ -f "$count_file" ]]; then
        local temp_file="${count_file}.tmp"
        while IFS= read -r timestamp; do
            if [[ $timestamp -gt $one_hour_ago ]]; then
                echo "$timestamp"
            fi
        done < "$count_file" > "$temp_file"
        mv "$temp_file" "$count_file"
    fi

    echo "$current_time" >> "$count_file"
}

# Get channel script path from channel_id
get_channel_script() {
    local channel_id="$1"

    # Try different naming patterns
    local patterns=(
        "channel_${channel_id}_revised.sh"
        "channel_${channel_id}.sh"
    )

    for pattern in "${patterns[@]}"; do
        if [[ -f "$SCRIPT_DIR/$pattern" ]]; then
            echo "$SCRIPT_DIR/$pattern"
            return
        fi
    done

    # Try fuzzy match (handle hyphenated channel names like "almajd-news")
    # Convert hyphens to underscores for script name matching
    local underscore_name="${channel_id//-/_}"
    local patterns_alt=(
        "channel_${underscore_name}_revised.sh"
        "channel_${underscore_name}.sh"
    )

    for pattern in "${patterns_alt[@]}"; do
        if [[ -f "$SCRIPT_DIR/$pattern" ]]; then
            echo "$SCRIPT_DIR/$pattern"
            return
        fi
    done

    # Last resort: fuzzy match
    local match=$(find "$SCRIPT_DIR" -maxdepth 1 -name "channel_*${channel_id}*.sh" -type f 2>$DEVNULL | head -1)
    if [[ -n "$match" ]]; then
        echo "$match"
        return
    fi

    # Try with underscores
    match=$(find "$SCRIPT_DIR" -maxdepth 1 -name "channel_*${underscore_name}*.sh" -type f 2>$DEVNULL | head -1)
    if [[ -n "$match" ]]; then
        echo "$match"
        return
    fi

    echo ""
}

# =============================================================================
# BLOCKER FIX: Check if channel is running using consistent channel_id
# =============================================================================
# Uses pidfile and lock directory created by try_start_stream.sh
# Falls back to FFmpeg process detection via HLS path
# =============================================================================

is_channel_running() {
    local channel_id="$1"
    local escaped_channel_id
    escaped_channel_id=$(escape_regex "$channel_id")
    local pidfile="/tmp/stream_${channel_id}.pid"
    local lockdir="/tmp/stream_${channel_id}.lock"

    # Method 1: Check pidfile (most reliable)
    if [[ -f "$pidfile" ]]; then
        local pid=$(cat "$pidfile" 2>$DEVNULL)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>$DEVNULL; then
            return 0  # Running
        fi
    fi

    # Method 2: Check lock directory
    if [[ -d "$lockdir" ]]; then
        # Lock exists - check if FFmpeg is writing to this channel
        if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >$DEVNULL 2>&1; then
            return 0  # Running
        fi
    fi

    # Method 3: Direct FFmpeg check (in case lock/pid are missing)
    if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >$DEVNULL 2>&1; then
        return 0  # Running
    fi

    return 1  # Not running
}

# Restart a channel
restart_channel() {
    local channel_id="$1"
    local script_path="$2"
    local escaped_channel_id
    escaped_channel_id=$(escape_regex "$channel_id")

    if [[ -z "$script_path" || ! -f "$script_path" ]]; then
        log "ERROR: Cannot find script for channel $channel_id"
        return 1
    fi

    log_console "RESTARTING channel: $channel_id"

    # Kill existing FFmpeg processes for this channel
    # NOTE: FFmpeg may run as root, so try both regular and sudo kill
    pkill -9 -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>$DEVNULL || true

    # If running as non-root and processes are owned by root, use sudo
    if [[ $(id -u) -ne 0 ]]; then
        local ffmpeg_pids=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>$DEVNULL)
        if [[ -n "$ffmpeg_pids" ]]; then
            log "Processes still running after pkill, trying sudo kill..."
            for pid in $ffmpeg_pids; do
                sudo_run kill -9 "$pid" 2>$DEVNULL || true
            done
        fi
    fi

    # Remove lock and pid files (generic_channel.sh or try_start_stream.sh will recreate)
    rmdir "/tmp/stream_${channel_id}.lock" 2>$DEVNULL || sudo_run rmdir "/tmp/stream_${channel_id}.lock" 2>$DEVNULL || true
    rm -f "/tmp/stream_${channel_id}.pid" 2>$DEVNULL || sudo_run rm -f "/tmp/stream_${channel_id}.pid" 2>$DEVNULL || true

    sleep 2

    # Start the channel script
    cd "$SCRIPT_DIR"
    bash "$script_path" &

    record_restart "$channel_id"
    log "Channel $channel_id restart initiated"
}

# Check a single channel's health
check_channel_health() {
    local channel_dir="$1"
    local channel_id=$(get_channel_id "$channel_dir")
    local playlist="$channel_dir/master.m3u8"
    local current_time=$(date +%s)

    # Skip if no playlist exists (channel never started or cleaned up)
    if [[ ! -f "$playlist" ]]; then
        return 0
    fi

    # Check playlist age
    local playlist_mtime=$(stat -c %Y "$playlist" 2>$DEVNULL || echo 0)
    local playlist_age=$((current_time - playlist_mtime))

    # Find the newest .ts segment
    local newest_segment=$(find "$channel_dir" -name "*.ts" -type f -printf '%T@ %p\n' 2>$DEVNULL | sort -n | tail -1)
    local segment_mtime=0
    local segment_age=999999

    if [[ -n "$newest_segment" ]]; then
        segment_mtime=$(echo "$newest_segment" | cut -d' ' -f1 | cut -d'.' -f1)
        segment_age=$((current_time - segment_mtime))
    fi

    # Check if channel has a script (is configured)
    local script_path=$(get_channel_script "$channel_id")
    if [[ -z "$script_path" ]]; then
        # No script found - might be a manually created channel or removed channel
        return 0
    fi

    # Check if process is running using consistent channel_id detection
    local process_running=0
    if is_channel_running "$channel_id"; then
        process_running=1
    fi

    # Determine health status
    local status="OK"
    local needs_restart=0

    if [[ $process_running -eq 0 ]]; then
        status="STOPPED"
        needs_restart=1
    elif [[ $segment_age -gt $SEGMENT_STALE_THRESHOLD ]]; then
        status="STALE_SEGMENTS"
        needs_restart=1
    elif [[ $playlist_age -gt $PLAYLIST_STALE_THRESHOLD ]]; then
        status="STALE_PLAYLIST"
        needs_restart=1
    fi

    # Log status
    if [[ "$status" != "OK" ]]; then
        log "Channel $channel_id: $status (playlist_age=${playlist_age}s, segment_age=${segment_age}s, process_running=$process_running)"
    fi

    # Auto-restart if needed
    if [[ $needs_restart -eq 1 ]]; then
        local restart_count=$(get_restart_count "$channel_id")

        if [[ $restart_count -ge $MAX_RESTARTS_PER_HOUR ]]; then
            log "WARNING: Channel $channel_id exceeded max restarts ($restart_count). Skipping."
            return 1
        fi

        restart_channel "$channel_id" "$script_path"
    fi

    return 0
}

# Main monitoring loop
main() {
    log "=== Health monitor started (segment_threshold=${SEGMENT_STALE_THRESHOLD}s, playlist_threshold=${PLAYLIST_STALE_THRESHOLD}s) ==="

    # Find all channel directories
    if [[ ! -d "$HLS_BASE_DIR" ]]; then
        log "ERROR: HLS base directory not found: $HLS_BASE_DIR"
        exit 1
    fi

    local total_checked=0
    local issues_found=0

    for channel_dir in "$HLS_BASE_DIR"/*/; do
        if [[ -d "$channel_dir" ]]; then
            check_channel_health "$channel_dir"
            if [[ $? -ne 0 ]]; then
                issues_found=$((issues_found + 1))
            fi
            total_checked=$((total_checked + 1))
        fi
    done

    log "Health check complete: $total_checked channels checked, $issues_found issues"
}

# Run main
main "$@"
