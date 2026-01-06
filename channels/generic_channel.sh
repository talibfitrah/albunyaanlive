#!/bin/bash

# =============================================================================
# Generic Channel Launcher with Backup URL Support
# =============================================================================
# Usage: ./generic_channel.sh <name> <id> <primary_url> <output_path> [scale] [backup_urls]
#   backup_urls: pipe-separated backup URLs (e.g., "url1|url2")
#
# Fixed Issues:
#   - [BLOCKER] Uses channel_id (from output path) for process detection
#   - This ensures consistent identity with try_start_stream.sh and monitors
#
# Features:
#   - Config hot-reload: automatically detects calling channel script for live URL updates
#   - Primary fallback: auto-switches back to primary URL when it recovers
# =============================================================================

streamName="$1"
streamID="$2"
streamURL="$3"
rtmpURL="$4"
scale="$5"
backupURLs="$6"  # Pipe-separated backup URLs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# =============================================================================
# Detect channel config file for hot-reload
# =============================================================================
# Find the channel_*.sh config that corresponds to this stream output so
# try_start_stream.sh can hot-reload URLs when the config changes.
# =============================================================================

config_file=""

# =============================================================================
# BLOCKER FIX: Derive channel_id from output path (consistent with try_start_stream.sh)
# =============================================================================
# The channel_id is the HLS output directory name (e.g., "basmah", "almajd-news")
# This MUST match how try_start_stream.sh derives channel_id for consistency
# =============================================================================

# Ensure rtmpURL ends with .m3u8 for consistent path extraction
output_path="$rtmpURL"
if [[ "$output_path" != *.m3u8 ]]; then
    output_path="${output_path%/}/master.m3u8"
fi

# Best-effort: match channel scripts by exact output path (or its directory)
detect_channel_config_file() {
    local output_path="$1"
    local stream_id="$2"
    local dest_dir
    dest_dir=$(dirname "$output_path")

    local match=""

    if [[ -n "$stream_id" ]]; then
        match=$(grep -lF -- "$stream_id" "$SCRIPT_DIR"/channel_*.sh 2>/dev/null | head -1 || true)
    fi
    if [[ -z "$match" ]]; then
        match=$(grep -lF -- "$output_path" "$SCRIPT_DIR"/channel_*.sh 2>/dev/null | head -1 || true)
    fi
    if [[ -z "$match" ]]; then
        match=$(grep -lF -- "$dest_dir" "$SCRIPT_DIR"/channel_*.sh 2>/dev/null | head -1 || true)
    fi

    echo "$match"
}

config_file=$(detect_channel_config_file "$output_path" "$streamID")

# Extract channel_id from output path (same logic as try_start_stream.sh)
channel_id=$(basename "$(dirname "$output_path")")

if [[ -z "$channel_id" || "$channel_id" == "." || "$channel_id" == ".." ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Cannot derive channel_id from output path: $rtmpURL"
    exit 1
fi

# Escape regex special chars for safe pgrep/pkill patterns
escape_regex() {
    printf '%s' "$1" | sed 's/[][\\.^$*+?{}|()]/\\&/g'
}
escaped_channel_id=$(escape_regex "$channel_id")

# Log the channel identity for debugging
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Channel identity: channel_id=$channel_id, stream_name=$streamName"

# =============================================================================
# Process detection using channel_id (NOT stream_name)
# =============================================================================
# This ensures we detect processes correctly regardless of stream_name format
# =============================================================================

# Check if try_start_stream.sh is already running for this channel_id
# Look for the pidfile that try_start_stream.sh creates
pidfile="/tmp/stream_${channel_id}.pid"
lockdir="/tmp/stream_${channel_id}.lock"

is_running=0

# Method 1: Check pidfile
if [[ -f "$pidfile" ]]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        is_running=1
    fi
fi

# Method 2: Check lock directory (created atomically by try_start_stream.sh)
if [[ -d "$lockdir" && $is_running -eq 0 ]]; then
    # Lock exists but PID check failed - might be stale
    # Double-check with pgrep using the destination path
    if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
        is_running=1
    fi
fi

if [[ $is_running -eq 1 ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Channel [$channel_id] already running. Skipping."
    exit 0
fi

# =============================================================================
# Clean up orphaned processes before starting
# =============================================================================

# Remove stale lock/pid if no process is actually running
if [[ -d "$lockdir" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Removing stale lock for $channel_id"
    rmdir "$lockdir" 2>/dev/null
fi
if [[ -f "$pidfile" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Removing stale pidfile for $channel_id"
    rm -f "$pidfile"
fi

# Kill any orphaned FFmpeg processes writing to this channel's HLS directory
if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Killing orphaned FFmpeg process for $channel_id..."
    pkill -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>/dev/null
    sleep 1
fi

# =============================================================================
# Build and execute the stream command (avoid eval; keep safe quoting)
# =============================================================================

cmd=( "./try_start_stream.sh" "-u" "${streamURL}" "-d" "${rtmpURL}" "-n" "${streamName}" )

# Add scale if provided
if [[ -n "${scale}" ]] && [[ "${scale}" =~ ^[0-9]+$ ]]; then
    cmd+=( "-s" "${scale}" )
fi

# Add backup URLs if provided
if [[ -n "${backupURLs}" ]]; then
    cmd+=( "-b" "${backupURLs}" )
fi

# Add config file for hot-reload (if detected)
if [[ -n "${config_file}" ]]; then
    cmd+=( "-c" "${config_file}" )
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting channel: $channel_id (stream_name: $streamName)"
if [[ -n "${config_file}" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Config hot-reload enabled: $config_file"
fi
printf "Command: "
printf "%q " "${cmd[@]}"
printf "\n"

# Execute the command in background
"${cmd[@]}" &

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Channel $channel_id launched with PID $!"
