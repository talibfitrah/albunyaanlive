#!/bin/bash

# =============================================================================
# HLS Channel Health Monitor with Auto-Restart
# =============================================================================

# Sudo helper script that outputs the password (used with sudo -A or -S)
# For better security, consider using sudoers NOPASSWD for specific commands instead
SUDO_PASS_SCRIPT="${SUDO_PASS_SCRIPT:-${SUDO_PASS_FILE:-$HOME/.sudo_pass.sh}}"

# Verify helper script permissions if it exists
if [[ -f "$SUDO_PASS_SCRIPT" ]]; then
    file_perms=$(stat -c %a "$SUDO_PASS_SCRIPT" 2>/dev/null || stat -f %OLp "$SUDO_PASS_SCRIPT" 2>/dev/null)
    if [[ "$file_perms" =~ ^[0-7]{3}$ ]]; then
        group_perm="${file_perms:1:1}"
        other_perm="${file_perms:2:1}"
        if [[ "$group_perm" != "0" || "$other_perm" != "0" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $SUDO_PASS_SCRIPT has insecure permissions ($file_perms). Should not be group/other accessible." >&2
        fi
    fi
    if [[ ! -x "$SUDO_PASS_SCRIPT" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $SUDO_PASS_SCRIPT is not executable; sudo -A may fail." >&2
    fi
fi

sudo_run() {
    if [[ $(id -u) -eq 0 ]]; then
        "$@"
        return $?
    fi
    if [[ -r "$SUDO_PASS_SCRIPT" ]]; then
        SUDO_ASKPASS="$SUDO_PASS_SCRIPT" sudo -A "$@" && return $?
        if [[ -x "$SUDO_PASS_SCRIPT" ]]; then
            "$SUDO_PASS_SCRIPT" | sudo -S "$@"
        else
            bash "$SUDO_PASS_SCRIPT" | sudo -S "$@"
        fi
        return $?
    fi
    sudo -n "$@"
}

DEVNULL="/dev/null"
devnull_fallback=0
if [[ ! -c /dev/null || ! -w /dev/null ]]; then
    # Use unique per-process fallback to avoid contention
    DEVNULL="/tmp/albunyaan-dev-null-$$"
    : > "$DEVNULL" || true
    devnull_fallback=1
    # Schedule periodic truncation to prevent unbounded growth
    (while sleep 60; do : > "$DEVNULL" 2>/dev/null || true; done) &
    _devnull_cleaner_pid=$!
    # Cleanup fallback file and cleaner on exit (handle multiple signals to avoid orphaned processes)
    trap 'kill $_devnull_cleaner_pid 2>/dev/null; rm -f "$DEVNULL" 2>/dev/null' EXIT INT TERM HUP
fi

# Cross-platform stat helpers (GNU/BSD compatibility)
get_file_size() {
    local file="$1"
    stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0
}

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
#   - [MINOR] Updated thresholds: 300s segment stale, 300s playlist stale (feeder recovery window)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HLS_BASE_DIR="/var/www/html/stream/hls"
RESTART_TRACKING_DIR="/tmp/stream_health_${UID}"
MAX_RESTARTS_PER_HOUR=15

# Raised thresholds: let try_start_stream.sh manage its own feeder recovery.
# Health monitor only intervenes for truly dead channels (5 min stale).
SEGMENT_STALE_THRESHOLD=300  # seconds - segment freshness check (5 min)
PLAYLIST_STALE_THRESHOLD=300 # seconds - playlist freshness check (5 min)

# Choose a writable log directory (fallback to /tmp if repo logs are not writable)
resolve_log_dir() {
    local preferred="$1"
    local fallback="/tmp/albunyaan-logs-$UID"

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
if ! : >> "$LOG_FILE" 2>$DEVNULL; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: Cannot write to $LOG_FILE, falling back to /tmp" >&2
    LOG_DIR="/tmp/albunyaan-logs-$UID"
    LOG_FILE="$LOG_DIR/health_monitor.log"
    mkdir -p "$(dirname "$LOG_FILE")" 2>$DEVNULL || true
    : >> "$LOG_FILE" 2>$DEVNULL || true
fi
mkdir -p "$RESTART_TRACKING_DIR" 2>$DEVNULL || true
if [[ ! -w "$RESTART_TRACKING_DIR" ]]; then
    RESTART_TRACKING_DIR="/tmp/stream_health_${UID}_$$"
    mkdir -p "$RESTART_TRACKING_DIR" 2>$DEVNULL || true
fi

# Log size limits to prevent disk exhaustion
LOG_FILE_MAX_MB="${LOG_FILE_MAX_MB:-5}"
LOG_FILE_MAX_BYTES=$((LOG_FILE_MAX_MB * 1024 * 1024))
LOG_FILE_TRIM_MB="${LOG_FILE_TRIM_MB:-1}"
LOG_FILE_TRIM_BYTES=$((LOG_FILE_TRIM_MB * 1024 * 1024))
LOG_GC_INTERVAL="${LOG_GC_INTERVAL:-300}"
last_log_gc=0

log_maintenance() {
    local now
    now=$(date +%s)
    if [[ $((now - last_log_gc)) -lt $LOG_GC_INTERVAL ]]; then
        return
    fi
    last_log_gc=$now

    if [[ -f "$LOG_FILE" && "$LOG_FILE_MAX_BYTES" -gt 0 ]]; then
        local size
        size=$(get_file_size "$LOG_FILE")
        if [[ "$size" -gt "$LOG_FILE_MAX_BYTES" && "$LOG_FILE_TRIM_BYTES" -gt 0 ]]; then
            tail -c "$LOG_FILE_TRIM_BYTES" "$LOG_FILE" > "${LOG_FILE}.tmp" 2>$DEVNULL && mv "${LOG_FILE}.tmp" "$LOG_FILE"
        fi
    fi
}

log() {
    log_maintenance
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

# Validate that a pidfile points to the expected try_start_stream.sh instance
is_expected_parent_pid() {
    local pid="$1"
    local channel_id="$2"
    local -a cmd_args=()

    if [[ -r "/proc/$pid/cmdline" ]]; then
        mapfile -d '' -t cmd_args < "/proc/$pid/cmdline" 2>$DEVNULL
    else
        local cmdline
        cmdline=$(ps -o args= -p "$pid" 2>$DEVNULL || true)
        read -r -a cmd_args <<< "$cmdline"
    fi

    if [[ ${#cmd_args[@]} -eq 0 ]]; then
        return 1
    fi

    local has_script=0
    local dest=""
    local i
    for i in "${!cmd_args[@]}"; do
        if [[ "${cmd_args[$i]}" == *"try_start_stream.sh"* ]]; then
            has_script=1
        fi
        if [[ "${cmd_args[$i]}" == "-d" && -n "${cmd_args[$((i+1))]}" ]]; then
            dest="${cmd_args[$((i+1))]}"
        fi
    done

    if [[ $has_script -eq 0 ]]; then
        return 1
    fi

    if [[ -n "$dest" ]]; then
        local dest_channel_id
        dest_channel_id=$(basename "$(dirname "$dest")")
        [[ "$dest_channel_id" == "$channel_id" ]]
        return $?
    fi

    for i in "${cmd_args[@]}"; do
        if [[ "$i" == *"/${channel_id}/"* ]]; then
            return 0
        fi
    done

    return 1
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

    # Method 1: Check pidfile + validate PID ownership via /proc/cmdline
    # (handles PID recycling after reboot on ext4 /tmp)
    if [[ -f "$pidfile" ]]; then
        local pid=$(cat "$pidfile" 2>$DEVNULL)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>$DEVNULL; then
            if is_expected_parent_pid "$pid" "$channel_id"; then
                return 0  # Running — PID confirmed as try_start_stream for this channel
            fi
            # PID alive but not ours — recycled, fall through to other checks
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
    local pidfile="/tmp/stream_${channel_id}.pid"

    if [[ -z "$script_path" || ! -f "$script_path" ]]; then
        log "ERROR: Cannot find script for channel $channel_id"
        return 1
    fi

    log_console "RESTARTING channel: $channel_id"

    # ==========================================================================
    # CRITICAL FIX: Kill the parent script FIRST (try_start_stream.sh)
    # ==========================================================================
    # This prevents the race condition where we kill FFmpeg, the old script
    # restarts it, AND we start a new script - causing duplicate processes
    # ==========================================================================
    if [[ -f "$pidfile" ]]; then
        local parent_pid=$(cat "$pidfile" 2>$DEVNULL)
        if [[ -n "$parent_pid" ]] && kill -0 "$parent_pid" 2>$DEVNULL; then
            if is_expected_parent_pid "$parent_pid" "$channel_id"; then
                log "Killing parent script (PID $parent_pid) for $channel_id"
                kill -TERM "$parent_pid" 2>$DEVNULL || sudo_run kill -TERM "$parent_pid" 2>$DEVNULL || true
                sleep 1
                # Force kill if still running
                if kill -0 "$parent_pid" 2>$DEVNULL; then
                    kill -KILL "$parent_pid" 2>$DEVNULL || sudo_run kill -KILL "$parent_pid" 2>$DEVNULL || true
                fi
            else
                log "Skipping parent kill: pidfile PID $parent_pid does not match expected channel $channel_id"
            fi
        fi
    fi

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

    # Remove only the pidfile. Leave the lock directory in place — the new
    # try_start_stream.sh instance will detect the stale lock (no valid pidfile,
    # no matching process) and reclaim it atomically.  Deleting the lock here
    # opens a race window where a *third* instance could grab the lock between
    # our delete and the new script's mkdir.
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
        # If the parent try_start_stream.sh process is alive (pidfile exists + PID valid),
        # skip restart — let the FIFO feeder architecture manage source recovery internally.
        # Only intervene if the parent is truly dead.
        local pidfile="/tmp/stream_${channel_id}.pid"
        if [[ "$status" != "STOPPED" && -f "$pidfile" ]]; then
            local parent_pid
            parent_pid=$(cat "$pidfile" 2>/dev/null)
            if [[ -n "$parent_pid" ]] && kill -0 "$parent_pid" 2>/dev/null; then
                # Verify the PID actually belongs to try_start_stream for this channel
                # (guards against PID recycling after reboot)
                local pid_cmdline=""
                pid_cmdline=$(tr '\0' ' ' < "/proc/$parent_pid/cmdline" 2>/dev/null || true)
                if [[ "$pid_cmdline" == *try_start_stream* && "$pid_cmdline" == *"$channel_id"* ]]; then
                    log "Channel $channel_id: $status but parent PID $parent_pid alive — skipping restart (feeder recovery in progress)"
                    return 0
                fi
            fi
        fi

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
