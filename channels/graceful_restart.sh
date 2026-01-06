#!/bin/bash

# =============================================================================
# Graceful Channel Restart Script with Seamless Handoff
# =============================================================================
# Restarts a channel with minimal viewer interruption using temp playlist swap
# Usage: ./graceful_restart.sh <channel_id>
#
# Fixed Issues:
#   - [BLOCKER] Config extraction uses awk parsing instead of source (no execution)
#   - [MAJOR] Temp channel_id is unique per channel to avoid lock collisions
#   - [MAJOR] Temp directory cleared before reuse to avoid stale segments
#   - [BLOCKER] Uses consistent channel_id (HLS directory name)
#
# How it works:
#   1. Parse config from channel script WITHOUT executing it
#   2. Start new stream writing to a unique temp directory
#   3. Wait for N segments to be generated
#   4. Stop the old writer (single-writer guarantee)
#   5. Stop the temp writer (freeze temp output)
#   6. Copy segments then atomically swap playlists into the live directory
#   7. Start the channel script to resume normal streaming
#   8. Clean up temp files
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HLS_BASE_DIR="/var/www/html/stream/hls"
REQUIRED_SEGMENTS=3
MAX_WAIT_SECONDS=60

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
LOG_FILE="$LOG_DIR/graceful_restart.log"

mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Escape regex special characters for safe pgrep/pkill patterns
escape_regex() {
    printf '%s' "$1" | sed 's/[][\\.^$*+?{}|()]/\\&/g'
}

# =============================================================================
# Argument parsing and validation
# =============================================================================

if [[ -z "$1" ]]; then
    echo "Usage: $0 <channel_id>"
    echo "Example: $0 basmah"
    echo ""
    echo "The channel_id is the HLS output directory name (e.g., 'basmah', 'almajd-news')"
    exit 1
fi

CHANNEL_ID="$1"
CHANNEL_DIR="$HLS_BASE_DIR/$CHANNEL_ID"
PLAYLIST="$CHANNEL_DIR/master.m3u8"

# =============================================================================
# MAJOR FIX: Unique temp directory per channel to avoid lock/pid collisions
# =============================================================================
# The temp_channel_id must be unique per channel so that concurrent restarts
# of different channels don't collide on locks/pids in /tmp
# =============================================================================

TEMP_CHANNEL_ID=".graceful_${CHANNEL_ID}"
TEMP_DIR="$CHANNEL_DIR/${TEMP_CHANNEL_ID}"
TEMP_PLAYLIST="$TEMP_DIR/master.m3u8"

ESC_CHANNEL_ID=$(escape_regex "$CHANNEL_ID")
ESC_TEMP_CHANNEL_ID=$(escape_regex "$TEMP_CHANNEL_ID")

# Validate channel directory exists
if [[ ! -d "$CHANNEL_DIR" ]]; then
    log "ERROR: Channel directory not found: $CHANNEL_DIR"
    exit 1
fi

# =============================================================================
# Find channel script
# =============================================================================

find_channel_script() {
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
            echo "$SCRIPT_DIR/$pattern"
            return
        fi
    done

    # Try fuzzy match
    find "$SCRIPT_DIR" -maxdepth 1 \( -name "channel_*${channel_id}*.sh" -o -name "channel_*${underscore_name}*.sh" \) -type f 2>/dev/null | head -1
}

CHANNEL_SCRIPT=$(find_channel_script "$CHANNEL_ID")

if [[ -z "$CHANNEL_SCRIPT" || ! -f "$CHANNEL_SCRIPT" ]]; then
    log "ERROR: Cannot find script for channel: $CHANNEL_ID"
    exit 1
fi

# =============================================================================
# Helper: Check if channel is running
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
            echo "$pid"
            return 0
        fi
    fi

    # Method 2: Check lock directory
    if [[ -d "$lockdir" ]]; then
        # Lock exists - check if FFmpeg is writing to this channel
        if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
            local ffmpeg_pid=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>/dev/null | head -1)
            echo "$ffmpeg_pid"
            return 0
        fi
    fi

    # Method 3: Fallback - check FFmpeg directly
    local ffmpeg_pid=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>/dev/null | head -1)
    if [[ -n "$ffmpeg_pid" ]]; then
        echo "$ffmpeg_pid"
        return 0
    fi

    echo ""
    return 1
}

# =============================================================================
# BLOCKER FIX: Parse stream config from channel script WITHOUT executing it
# =============================================================================
# Previously used `source "$script"` which executed the channel script,
# causing it to run ./generic_channel.sh and start duplicate streams.
# Now we use awk to safely extract variable values without execution.
# =============================================================================

parse_config_value() {
    local script="$1"
    local varname="$2"
    # Extract value from lines like:
    #   varname="value" | varname='value' | varname=value | export varname=value
    awk -v var="$varname" '
        $0 ~ "^[ \t]*(export[ \t]+)?"+var"[ \t]*=" {
            line = $0
            sub(/^[ \t]*(export[ \t]+)?[ \t]*[^=]+=[ \t]*/, "", line)
            # Strip inline comments (only when preceded by whitespace)
            sub(/[ \t]+#.*/, "", line)
            # Remove leading/trailing quotes and whitespace
            gsub(/^[ \t]*["'"'"']?/, "", line)
            gsub(/["'"'"']?[ \t]*$/, "", line)
            print line
            exit
        }
    ' "$script"
}

get_stream_config() {
    local script="$1"

    STREAM_URL=$(parse_config_value "$script" "stream_url")
    BACKUP1=$(parse_config_value "$script" "stream_url_backup1")
    BACKUP2=$(parse_config_value "$script" "stream_url_backup2")
    SCALE=$(parse_config_value "$script" "scale")
    RTMP_URL=$(parse_config_value "$script" "rtmp_url")

    # Validate we got at least the primary URL
    if [[ -z "$STREAM_URL" ]]; then
        log "ERROR: Could not parse stream_url from $script"
        return 1
    fi

    return 0
}

# =============================================================================
# Helper: Count segments in a directory
# =============================================================================

count_segments() {
    local dir="$1"
    find "$dir" -name "*.ts" -type f 2>/dev/null | wc -l
}

# =============================================================================
# Cleanup function for temp files
# =============================================================================

cleanup_temp() {
    local temp_channel_id="$TEMP_CHANNEL_ID"

    # Clean up temp directory
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log "Cleaned up temp directory: $TEMP_DIR"
    fi

    # Clean up temp stream lock/pid files (matched to temp_channel_id)
    rmdir "/tmp/stream_${temp_channel_id}.lock" 2>/dev/null
    rm -f "/tmp/stream_${temp_channel_id}.pid" 2>/dev/null
}
trap cleanup_temp EXIT

# =============================================================================
# Main graceful restart logic
# =============================================================================

log "=== Starting graceful restart for channel: $CHANNEL_ID ==="
log "Using script: $CHANNEL_SCRIPT"
log "Channel directory: $CHANNEL_DIR"
log "Temp channel_id: $TEMP_CHANNEL_ID"

# Step 1: Record current state
OLD_PID=$(is_channel_running "$CHANNEL_ID")
CURRENT_SEQ=0
if [[ -f "$PLAYLIST" ]]; then
    CURRENT_SEQ=$(grep "EXT-X-MEDIA-SEQUENCE" "$PLAYLIST" 2>/dev/null | cut -d: -f2 || echo 0)
    log "Current sequence number: $CURRENT_SEQ"
fi

SEGMENT_COUNT_BEFORE=$(count_segments "$CHANNEL_DIR")
log "Segments before restart: $SEGMENT_COUNT_BEFORE"

if [[ -n "$OLD_PID" ]]; then
    log "Current process PID: $OLD_PID"
else
    log "WARNING: No running process found for $CHANNEL_ID"
fi

# =============================================================================
# MINOR FIX: Clear temp directory before reuse to prevent stale segment issues
# =============================================================================

if [[ -d "$TEMP_DIR" ]]; then
    log "Clearing existing temp directory..."
    rm -rf "$TEMP_DIR"
fi
mkdir -p "$TEMP_DIR"
log "Created temp directory: $TEMP_DIR"

# Step 3: Extract stream configuration using safe parsing
log "Parsing stream configuration..."
if ! get_stream_config "$CHANNEL_SCRIPT"; then
    log "ERROR: Failed to parse configuration from $CHANNEL_SCRIPT"
    exit 1
fi

# Build backup URL string
BACKUP_URLS=""
[[ -n "$BACKUP1" ]] && BACKUP_URLS="$BACKUP1"
[[ -n "$BACKUP2" ]] && BACKUP_URLS="${BACKUP_URLS:+$BACKUP_URLS|}$BACKUP2"

log "Stream URL: $STREAM_URL"
log "Scale: ${SCALE:-default}"

# Step 4: Start new stream writing to temp location
# Build argv with temp destination - use TEMP_CHANNEL_ID for display name so that
# try_start_stream.sh derives a unique channel_id for locks/pids.
TEMP_DEST="$TEMP_DIR/master.m3u8"
NEW_CMD=( "$SCRIPT_DIR/try_start_stream.sh" -u "$STREAM_URL" -d "$TEMP_DEST" -n "$TEMP_CHANNEL_ID" )
[[ -n "$SCALE" ]] && NEW_CMD+=( -s "$SCALE" )
[[ -n "$BACKUP_URLS" ]] && NEW_CMD+=( -b "$BACKUP_URLS" )

log "Starting new stream to temp location..."
printf -v cmd_pretty "%q " "${NEW_CMD[@]}"
log "Command: $cmd_pretty"

# Start in background
"${NEW_CMD[@]}" &
NEW_STREAM_PID=$!
log "New stream process started with PID: $NEW_STREAM_PID"

# Step 5: Wait for segments to be generated
log "Waiting for $REQUIRED_SEGMENTS segments in temp directory..."
WAITED=0
SEGMENT_COUNT=0

while [[ $WAITED -lt $MAX_WAIT_SECONDS ]]; do
    sleep 2
    WAITED=$((WAITED + 2))

    if [[ ! -d "$TEMP_DIR" ]]; then
        log "ERROR: Temp directory disappeared"
        break
    fi

    SEGMENT_COUNT=$(count_segments "$TEMP_DIR")

    if [[ $SEGMENT_COUNT -ge $REQUIRED_SEGMENTS ]]; then
        log "SUCCESS: $SEGMENT_COUNT segments generated after ${WAITED}s"
        break
    fi

    # Check if new process is still running
    if ! kill -0 "$NEW_STREAM_PID" 2>/dev/null; then
        log "ERROR: New stream process died"
        break
    fi

    log "Waiting... ($SEGMENT_COUNT/$REQUIRED_SEGMENTS segments, ${WAITED}s elapsed)"
done

if [[ $SEGMENT_COUNT -lt $REQUIRED_SEGMENTS ]]; then
    log "ERROR: Failed to generate enough segments. Aborting graceful restart."

    # Kill the new process if it's still running
    kill -TERM "$NEW_STREAM_PID" 2>/dev/null
    sleep 2
    kill -9 "$NEW_STREAM_PID" 2>/dev/null

    # Cleanup is handled by trap
    exit 1
fi

# Step 6: Stop the old stream before copying (single-writer guarantee)
if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    log "Stopping old process before swap: $OLD_PID"
    kill -TERM "$OLD_PID" 2>/dev/null

    # Wait for graceful shutdown (up to 10 seconds)
    for i in {1..10}; do
        if ! kill -0 "$OLD_PID" 2>/dev/null; then
            log "Old process terminated gracefully"
            break
        fi
        sleep 1
    done

    # Force kill if still running
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log "Force killing old process"
        kill -9 "$OLD_PID" 2>/dev/null
    fi
else
    log "Old process not running or already stopped"
fi

# Ensure no FFmpeg processes are writing to the live channel output
pkill -f "ffmpeg.*/${ESC_CHANNEL_ID}/master\\.m3u8" 2>/dev/null

# Step 7: Stop the temp stream to freeze its playlist/segments
if kill -0 "$NEW_STREAM_PID" 2>/dev/null; then
    log "Stopping temp stream before swap: $NEW_STREAM_PID"
    kill -TERM "$NEW_STREAM_PID" 2>/dev/null

    # Wait for temp process to exit (up to 10 seconds)
    for i in {1..10}; do
        if ! kill -0 "$NEW_STREAM_PID" 2>/dev/null; then
            log "Temp stream terminated gracefully"
            break
        fi
        sleep 1
    done

    # Force kill if still running
    if kill -0 "$NEW_STREAM_PID" 2>/dev/null; then
        log "Force killing temp stream"
        kill -9 "$NEW_STREAM_PID" 2>/dev/null
    fi
fi

# Ensure no FFmpeg processes are writing to the temp output
pkill -f "ffmpeg.*/${ESC_TEMP_CHANNEL_ID}/master\\.m3u8" 2>/dev/null

# Step 8: Perform atomic playlist swap (after both writers stopped)
log "Performing atomic playlist swap..."

# Copy all segments from temp to main directory (atomic per-file swap)
log "Copying segments from temp to main directory..."
for segment in "$TEMP_DIR"/*.ts; do
    if [[ -f "$segment" ]]; then
        seg_name=$(basename "$segment")
        cp -f "$segment" "${CHANNEL_DIR}/${seg_name}.new"
        mv -f "${CHANNEL_DIR}/${seg_name}.new" "${CHANNEL_DIR}/${seg_name}"
    fi
done

# Copy all playlists (not just master.m3u8) in case of variant playlists
for playlist_file in "$TEMP_DIR"/*.m3u8; do
    if [[ -f "$playlist_file" ]]; then
        local_name=$(basename "$playlist_file")
        cp -f "$playlist_file" "${CHANNEL_DIR}/${local_name}.new"
        mv "${CHANNEL_DIR}/${local_name}.new" "${CHANNEL_DIR}/${local_name}"
    fi
done

log "Playlist swapped atomically"

# Step 9: Clean up main channel locks/pids (will be recreated by new stream)
rm -f "/tmp/stream_${CHANNEL_ID}.pid" 2>/dev/null
rmdir "/tmp/stream_${CHANNEL_ID}.lock" 2>/dev/null

# Brief pause before starting new permanent stream
sleep 2

# Step 10: Start the permanent new stream
log "Starting permanent new stream..."
cd "$SCRIPT_DIR"
bash "$CHANNEL_SCRIPT" &

# Step 11: Verify new process started
sleep 3
FINAL_PID=$(is_channel_running "$CHANNEL_ID")

if [[ -n "$FINAL_PID" ]]; then
    log "SUCCESS: Channel $CHANNEL_ID restarted successfully with PID $FINAL_PID"
else
    log "WARNING: Could not verify new process is running"
fi

# Final segment count
SEGMENT_COUNT_AFTER=$(count_segments "$CHANNEL_DIR")
log "Segments after restart: $SEGMENT_COUNT_AFTER"

log "=== Graceful restart complete for $CHANNEL_ID ==="
