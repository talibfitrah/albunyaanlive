#!/bin/bash

# =============================================================================
# HLS Stream Manager with Backup URL Failover and Seamless Transitions
# =============================================================================
# Fixed Issues:
#   - [BLOCKER] channel_id derived from destination path (filesystem-safe)
#   - [MAJOR] Error-type aware failover with 60s buffer window
#   - [MINOR] Seamless flags (epoch) added to all scales including 7/8
#
# NEW Features:
#   - [PRIMARY_FALLBACK] Auto-switch back to primary URL when it recovers
#     * Checks primary every 5 minutes when running on backup
#     * Smooth transition without stream interruption
#   - [HOT_RELOAD] Live config updates without restart
#     * Monitors channel config file for changes (every 60s)
#     * Reloads backup URLs on-the-fly
#     * Logs when primary URL changes (recommends graceful restart)
# =============================================================================

# Get script directory for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

url=""
backup_urls=""
key=""
destination=""
channel_name=""
scale=""
config_file=""

# =============================================================================
# NEW: Primary URL fallback and config hot-reload settings
# =============================================================================
PRIMARY_CHECK_INTERVAL="${PRIMARY_CHECK_INTERVAL:-300}"  # Default: check primary every 5 minutes (300 seconds)
CONFIG_CHECK_INTERVAL="${CONFIG_CHECK_INTERVAL:-60}"     # Default: check config file every 60 seconds
last_primary_check=0
last_config_check=0
config_file_mtime=0

# User-Agent string (used by both ffmpeg and curl preflight for consistency)
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Parse command line arguments BEFORE setting up logfile
while getopts 'hu:d:k:n:s:b:c:' OPTION; do
    case "$OPTION" in
        h)
            echo "HLS Stream Manager"
            echo ""
            echo "Options:"
            echo "  -u URL       Primary source URL (HLS link)"
            echo "  -b URLS      Backup URLs separated by pipe (|)"
            echo "  -d PATH      Destination (HLS output path)"
            echo "  -k KEY       Stream key (if needed)"
            echo "  -n NAME      Channel name (for display only)"
            echo "  -s SCALE     Scale/variant (0-8)"
            echo "  -c FILE      Config file for hot-reload (optional)"
            echo ""
            echo "Scales:"
            echo "  0 - Stream copy (default)"
            echo "  2 - Stream copy with threads"
            echo "  3 - NVIDIA GPU encode (no scaling)"
            echo "  4 - NVIDIA GPU encode + scale to 1080p"
            echo "  5 - CPU encode (libx264)"
            echo "  6 - CPU encode + scale to 1080p"
            echo "  7 - Stream copy with extended buffer"
            echo "  8 - CUDA passthrough"
            echo ""
            echo "Features:"
            echo "  - Auto-fallback to primary URL when it recovers (every 5 min check)"
            echo "  - Hot-reload: updates backup URLs from config file without restart"
            exit 0
            ;;
        u) url=$OPTARG ;;
        d) destination=$OPTARG ;;
        k) key=$OPTARG ;;
        n) channel_name=$OPTARG ;;
        s) scale=$OPTARG ;;
        b) backup_urls=$OPTARG ;;
        c) config_file=$OPTARG ;;
        \?)
            echo "Unsupported flag. Use -h for help."
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z $url || -z $destination ]]; then
    echo "Missing required -u (url) or -d (destination). Use -h for help."
    exit 1
fi

# Enforce full HLS file path
if [[ "$destination" != *.m3u8 ]]; then
    destination="${destination%/}/master.m3u8"
fi

# =============================================================================
# BLOCKER FIX: Derive channel_id from destination path (filesystem-safe)
# =============================================================================
# This ensures channel_id is always safe for use in lock/pid/log paths
# regardless of what channel_name contains (slashes, spaces, etc.)
# The channel_id is the directory name from the HLS output path (e.g., "basmah", "almajd-news")
# =============================================================================

channel_id=$(basename "$(dirname "$destination")")

# Validate channel_id is not empty or problematic
if [[ -z "$channel_id" || "$channel_id" == "." || "$channel_id" == ".." ]]; then
    echo "ERROR: Cannot derive valid channel_id from destination: $destination"
    exit 1
fi

# Use channel_name for display only, channel_id for filesystem operations
if [[ -z "$channel_name" ]]; then
    channel_name="$channel_id"
fi

# =============================================================================
# Setup logging with filesystem-safe channel_id
# =============================================================================

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

    # Last resort: keep preferred (logging may fail, but stream can still run)
    echo "$preferred"
}

logfile_dir=$(resolve_log_dir "$SCRIPT_DIR/logs")
if [[ "$logfile_dir" != "$SCRIPT_DIR/logs" ]]; then
    echo "WARN: Log directory not writable: $SCRIPT_DIR/logs. Using $logfile_dir" >&2
fi

mkdir -p "$logfile_dir" 2>/dev/null || true
logfile="$logfile_dir/${channel_id}.log"
errorfile="$logfile_dir/${channel_id}.error.log"
pidfile="/tmp/stream_${channel_id}.pid"
lockdir="/tmp/stream_${channel_id}.lock"
ffmpeg_pid=""

# Log rotation (50MB threshold, keep last 5)
rotate_logs() {
    local file="$1"
    if [[ -f "$file" && $(stat -c%s "$file" 2>/dev/null || echo 0) -gt 52428800 ]]; then
        # Rotate: .log -> .log.1 -> .log.2 -> ... -> .log.5 (delete .log.5)
        for i in 4 3 2 1; do
            [[ -f "${file}.$i" ]] && mv "${file}.$i" "${file}.$((i+1))"
        done
        mv "$file" "${file}.1"
        # Compress old logs in background
        gzip -f "${file}".{2,3,4,5} 2>/dev/null &
    fi
}

rotate_logs "$logfile"
rotate_logs "$errorfile"

# Timestamp function for logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$logfile"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$errorfile"
    log "$1"
}

log_console() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    log "$1"
}

# =============================================================================
# Prerequisite checks (avoid silent runtime failures)
# =============================================================================

require_ffmpeg() {
    if ! command -v ffmpeg >/dev/null 2>&1; then
        log_error "ERROR: ffmpeg not found in PATH. Install ffmpeg and retry."
        echo "ERROR: ffmpeg not found in PATH. Install ffmpeg and retry." >&2
        exit 1
    fi
}

encoder_available() {
    local encoder="$1"
    ffmpeg -hide_banner -encoders 2>/dev/null | grep -qE "[[:space:]]${encoder}[[:space:]]"
}

require_encoder() {
    local encoder="$1"
    if ! encoder_available "$encoder"; then
        log_error "ERROR: Required encoder '${encoder}' is not available. Scale ${scale} cannot run."
        echo "ERROR: Required encoder '${encoder}' is not available. Scale ${scale} cannot run." >&2
        exit 1
    fi
}

require_ffmpeg
if [[ "$scale" == "5" || "$scale" == "6" ]]; then
    require_encoder "libx264"
fi

# Cache supported FFmpeg input protocols once (used to fast-fail unsupported URL schemes like https
# when ffmpeg is built without TLS support).
FFMPEG_INPUT_PROTOCOLS=$(ffmpeg -hide_banner -protocols 2>/dev/null | awk '
    /^Input:$/ { in_input=1; next }
    /^Output:$/ { in_input=0 }
    in_input && $1 ~ /^[a-z0-9]/ { print $1 }
' || true)

# Cleanup function
cleanup() {
    # If we're interrupted while FFmpeg is running, stop it to avoid orphaned encoders.
    if [[ -n "$ffmpeg_pid" ]] && kill -0 "$ffmpeg_pid" 2>/dev/null; then
        log "[$channel_id] Cleanup: stopping FFmpeg PID $ffmpeg_pid"
        kill -TERM "$ffmpeg_pid" 2>/dev/null || true
        for i in {1..10}; do
            if ! kill -0 "$ffmpeg_pid" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        if kill -0 "$ffmpeg_pid" 2>/dev/null; then
            log "[$channel_id] Cleanup: force killing FFmpeg PID $ffmpeg_pid"
            kill -KILL "$ffmpeg_pid" 2>/dev/null || true
        fi
        wait "$ffmpeg_pid" 2>/dev/null || true
    fi

    rm -f "$pidfile"
    rmdir "$lockdir" 2>/dev/null
    log "[$channel_id] Cleanup completed"
}
trap cleanup EXIT

# Acquire lock (atomic using mkdir)
if ! mkdir "$lockdir" 2>/dev/null; then
    log_console "[$channel_id] Another instance is already running (lock exists). Exiting."
    exit 0
fi

# Write PID file
echo $$ > "$pidfile"

# Create destination directory if needed
mkdir -p "$(dirname "$destination")"

# Log identity for debugging
log "=== Stream Manager Started ==="
log "channel_id (filesystem): $channel_id"
log "channel_name (display): $channel_name"
log "destination: $destination"
log "pidfile: $pidfile"
log "lockdir: $lockdir"

# =============================================================================
# Build URL array (primary + backups)
# =============================================================================

declare -a url_array
primary_url="$url"  # Store original primary for fallback checks
url_array+=("$url")
if [[ -n "$backup_urls" ]]; then
    IFS='|' read -ra backup_array <<< "$backup_urls"
    for backup in "${backup_array[@]}"; do
        # Skip empty entries
        backup=$(echo "$backup" | xargs)  # trim whitespace
        if [[ -n "$backup" ]]; then
            url_array+=("$backup")
        fi
    done
fi
url_count=${#url_array[@]}

# =============================================================================
# HOT_RELOAD: Auto-detect channel config file (no channel script changes needed)
# =============================================================================
# If -c is not provided, try to find the channel_*.sh script that corresponds to
# this channel_id by matching the HLS destination directory inside the script.
# This enables config hot-reload automatically for existing channel scripts.
# =============================================================================

detect_channel_config_file() {
    local channel_id="$1"
    local destination="$2"
    local dest_dir
    dest_dir=$(dirname "$destination")

    # 1) Most reliable: match the exact HLS output directory path in the script
    local match
    match=$(grep -lF "$dest_dir" "$SCRIPT_DIR"/channel_*.sh 2>/dev/null | head -1)
    if [[ -n "$match" ]]; then
        echo "$match"
        return 0
    fi

    # 2) Fallback: common naming patterns
    local underscore_name="${channel_id//-/_}"
    local patterns=(
        "channel_${channel_id}_revised.sh"
        "channel_${channel_id}.sh"
        "channel_${underscore_name}_revised.sh"
        "channel_${underscore_name}.sh"
    )

    for pattern in "${patterns[@]}"; do
        if [[ -f "$SCRIPT_DIR/$pattern" ]]; then
            echo "$SCRIPT_DIR/$pattern"
            return 0
        fi
    done

    # 3) Last resort: fuzzy match
    match=$(find "$SCRIPT_DIR" -maxdepth 1 \( -name "channel_*${channel_id}*.sh" -o -name "channel_*${underscore_name}*.sh" \) -type f 2>/dev/null | head -1)
    if [[ -n "$match" ]]; then
        echo "$match"
        return 0
    fi

    echo ""
    return 1
}

if [[ -z "$config_file" ]]; then
    config_file=$(detect_channel_config_file "$channel_id" "$destination")
    if [[ -n "$config_file" ]]; then
        log "HOT_RELOAD: Auto-detected channel config file: $config_file"
    else
        log "HOT_RELOAD: No channel config file auto-detected; hot-reload disabled"
    fi
fi

# Store initial config file mtime for hot-reload detection
if [[ -n "$config_file" && -f "$config_file" ]]; then
    config_file_mtime=$(stat -c %Y "$config_file" 2>/dev/null || echo 0)
    log "Config hot-reload enabled: $config_file (mtime: $config_file_mtime)"
fi

# =============================================================================
# NEW: Primary URL health check with auto-fallback
# =============================================================================
# When running on a backup URL, periodically check if primary is back online.
# If primary responds with 2xx, smoothly switch back to it.
# =============================================================================

get_url_scheme() {
    local url="$1"
    if [[ "$url" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*): ]]; then
        local scheme="${BASH_REMATCH[1]}"
        scheme="${scheme,,}"
        echo "$scheme"
        return 0
    fi
    echo "file"
}

ffmpeg_supports_url() {
    local url="$1"
    local scheme
    scheme=$(get_url_scheme "$url")
    if [[ -z "$FFMPEG_INPUT_PROTOCOLS" ]]; then
        # If we couldn't detect protocols, don't block (best effort).
        return 0
    fi
    grep -Fqx "$scheme" <<< "$FFMPEG_INPUT_PROTOCOLS"
}

check_and_fallback_to_primary() {
    # Only check if we're currently on a backup URL (not primary)
    if [[ $current_url_index -eq 0 ]]; then
        return 1  # Already on primary
    fi

    local now=$(date +%s)
    local elapsed=$((now - last_primary_check))

    # Only check every PRIMARY_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $PRIMARY_CHECK_INTERVAL ]]; then
        return 1
    fi

    last_primary_check=$now
    log "PRIMARY_CHECK: Testing if primary URL is back online..."

    local scheme
    scheme=$(get_url_scheme "$primary_url")

    # If FFmpeg can't read this URL scheme (e.g., https not compiled in), don't attempt fallback.
    if ! ffmpeg_supports_url "$primary_url"; then
        log "PRIMARY_CHECK: Primary URL uses unsupported protocol for this ffmpeg build ($scheme). Staying on backup."
        return 1
    fi

    # Only HTTP/S sources can be preflight-checked; others must be handled by ffmpeg directly.
    if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
        log "PRIMARY_CHECK: Skipping health check for non-HTTP primary ($scheme). Staying on backup."
        return 1
    fi

    # Test primary URL health
    local primary_status=$(validate_url "$primary_url")
    log "PRIMARY_CHECK: Primary URL returned HTTP $primary_status"

    if [[ "$primary_status" =~ ^2[0-9]{2}$ ]]; then
        # Primary is healthy! Switch back to it
        log "PRIMARY_RESTORED: Primary URL is healthy (HTTP $primary_status). Switching back..."
        current_url_index=0
        reset_url_retries
        total_cycles=0
        return 0  # Signal that we should switch
    else
        log "PRIMARY_CHECK: Primary still unavailable (HTTP $primary_status). Staying on backup."
        return 1
    fi
}

# =============================================================================
# NEW: Config hot-reload for backup URLs
# =============================================================================
# Periodically check if config file changed, and reload URLs without restart.
# This allows adding/removing backup URLs while stream is running.
# =============================================================================

parse_config_value() {
    local script="$1"
    local varname="$2"
    awk -v var="$varname" '
        $0 ~ "^[ \t]*(export[ \t]+)?"var"[ \t]*=" {
            line = $0
            sub(/^[ \t]*(export[ \t]+)?[ \t]*[^=]+=[ \t]*/, "", line)
            sub(/[ \t]+#.*/, "", line)
            gsub(/^[ \t]*["'"'"']?/, "", line)
            gsub(/["'"'"']?[ \t]*$/, "", line)
            print line
            exit
        }
    ' "$script"
}

config_has_var() {
    local script="$1"
    local varname="$2"
    awk -v var="$varname" '
        $0 ~ "^[ \t]*(export[ \t]+)?"var"[ \t]*=" { found=1; exit }
        END { exit(found ? 0 : 1) }
    ' "$script"
}

reload_config_if_changed() {
    # Skip if no config file specified
    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        return 1
    fi

    local now=$(date +%s)
    local elapsed=$((now - last_config_check))

    # Only check every CONFIG_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $CONFIG_CHECK_INTERVAL ]]; then
        return 1
    fi

    last_config_check=$now
    local current_mtime=$(stat -c %Y "$config_file" 2>/dev/null || echo 0)

    # Check if file was modified
    if [[ "$current_mtime" -le "$config_file_mtime" ]]; then
        return 1  # No change
    fi

    log "CONFIG_RELOAD: Config file changed. Reloading..."
    log "CONFIG_RELOAD: mtime $config_file_mtime -> $current_mtime"
    config_file_mtime=$current_mtime

    # Parse new URLs from config file (supports channel_*.sh format + env-style vars)
    local new_primary=""
    if config_has_var "$config_file" "stream_url"; then
        new_primary=$(parse_config_value "$config_file" "stream_url")
    elif config_has_var "$config_file" "SOURCE_URL"; then
        new_primary=$(parse_config_value "$config_file" "SOURCE_URL")
    fi

    local backups_defined=false
    local new_backups=""
    if config_has_var "$config_file" "BACKUP_URLS"; then
        backups_defined=true
        new_backups=$(parse_config_value "$config_file" "BACKUP_URLS")
    elif config_has_var "$config_file" "stream_url_backup1" || config_has_var "$config_file" "stream_url_backup2"; then
        backups_defined=true
        local b1
        local b2
        b1=$(parse_config_value "$config_file" "stream_url_backup1")
        b2=$(parse_config_value "$config_file" "stream_url_backup2")
        [[ -n "$b1" ]] && new_backups="$b1"
        [[ -n "$b2" ]] && new_backups="${new_backups:+$new_backups|}$b2"
    fi

    # If primary URL changed, that's a major change - log it but keep current
    if [[ -n "$new_primary" && "$new_primary" != "$primary_url" ]]; then
        log "CONFIG_RELOAD: Primary URL changed! Old: $primary_url -> New: $new_primary"
        log "CONFIG_RELOAD: To use new primary, graceful restart is recommended"
        primary_url="$new_primary"
        url_array[0]="$new_primary"
    fi

    # Rebuild backup URLs (allow clearing backups by setting empty values)
    if [[ "$backups_defined" == true ]]; then
        # Clear existing backups (keep primary at index 0)
        url_array=("${url_array[0]}")

        # Add new backups (if any)
        if [[ -n "$new_backups" ]]; then
            IFS='|' read -ra new_backup_array <<< "$new_backups"
            for backup in "${new_backup_array[@]}"; do
                backup=$(echo "$backup" | xargs)
                if [[ -n "$backup" ]]; then
                    url_array+=("$backup")
                fi
            done
        fi

        local old_count=$url_count
        url_count=${#url_array[@]}
        log "CONFIG_RELOAD: Backup URLs updated. URL count: $old_count -> $url_count"

        # Reset retry arrays for new URL count
        url_retry_counts=()
        url_last_error_type=()
        for ((i=0; i<url_count; i++)); do
            url_retry_counts[$i]=0
            url_last_error_type[$i]=""
        done

        # If current_url_index is now out of bounds, reset to primary
        if [[ $current_url_index -ge $url_count ]]; then
            log "CONFIG_RELOAD: Current URL index $current_url_index out of bounds. Resetting to primary."
            current_url_index=0
        fi

        # Log new URL list
        log "CONFIG_RELOAD: URL list now:"
        for i in $(seq 0 $((url_count - 1))); do
            if [[ $i -eq 0 ]]; then
                log "  [$i] Primary: ${url_array[$i]}"
            else
                log "  [$i] Backup: ${url_array[$i]}"
            fi
        done

        return 0
    fi

    return 1
}

# =============================================================================
# STARTUP FIX: Load backup URLs from config if none were passed via -b
# =============================================================================
# This ensures fallback is enabled even if:
#   1. Channel was started without -b flag
#   2. Backup URLs are added to config file at any time
# The hot-reload will then detect future changes to backup URLs.
# =============================================================================

load_backup_urls_from_config() {
    local script="$1"

    if [[ -z "$script" || ! -f "$script" ]]; then
        return 1
    fi

    local new_backups=""
    local backups_found=false

    # Check for BACKUP_URLS variable first
    if grep -qE "^[[:space:]]*(export[[:space:]]+)?BACKUP_URLS[[:space:]]*=" "$script" 2>/dev/null; then
        backups_found=true
        new_backups=$(parse_config_value "$script" "BACKUP_URLS")
    # Then check for stream_url_backup1/backup2 variables
    elif grep -qE "^[[:space:]]*(export[[:space:]]+)?stream_url_backup[12][[:space:]]*=" "$script" 2>/dev/null; then
        backups_found=true
        local b1 b2
        b1=$(parse_config_value "$script" "stream_url_backup1")
        b2=$(parse_config_value "$script" "stream_url_backup2")
        [[ -n "$b1" ]] && new_backups="$b1"
        [[ -n "$b2" ]] && new_backups="${new_backups:+$new_backups|}$b2"
    fi

    if [[ "$backups_found" == true && -n "$new_backups" ]]; then
        # Add backup URLs to url_array
        IFS='|' read -ra backup_array <<< "$new_backups"
        for backup in "${backup_array[@]}"; do
            backup=$(echo "$backup" | xargs)  # trim whitespace
            if [[ -n "$backup" ]]; then
                url_array+=("$backup")
            fi
        done
        url_count=${#url_array[@]}
        return 0
    fi

    return 1
}

# If no backup URLs were passed via -b, try loading them from config file
if [[ $url_count -eq 1 && -n "$config_file" && -f "$config_file" ]]; then
    log "STARTUP: No backup URLs passed via -b flag. Checking config file..."
    if load_backup_urls_from_config "$config_file"; then
        log "STARTUP: Loaded backup URLs from config file. URL count: $url_count"
        for i in $(seq 1 $((url_count - 1))); do
            log "STARTUP: Backup URL $i: ${url_array[$i]}"
        done
    else
        log "STARTUP: No backup URLs found in config file."
    fi
fi

# =============================================================================
# URL validation function with HTTP status detection
# =============================================================================

validate_url() {
    local test_url="$1"
    local timeout=10
    local response

    # MAJOR FIX: Use same User-Agent as ffmpeg to avoid false 4xx from UA mismatch
    # Also follow redirects (-L) to handle 301/302 properly
    response=$(curl -A "$USER_AGENT" -L -s -o /dev/null -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>/dev/null)

    echo "$response"
}

# Check if HTTP status indicates a 4xx error (immediate failover)
is_4xx_error() {
    local status="$1"
    [[ "$status" =~ ^4[0-9]{2}$ ]]
}

# =============================================================================
# Anti-bot stealth headers and network settings
# =============================================================================

# -rw_timeout: 30 seconds in microseconds (was 4+ hours - BUG FIX)
# Use the shared USER_AGENT variable for consistency with preflight curl checks
base_flags=( -user_agent "$USER_AGENT" -rw_timeout 30000000 -reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5 )

# =============================================================================
# HLS output settings for seamless transitions
# =============================================================================
# -hls_start_number_source epoch: Continues sequence numbers across restarts
# -hls_list_size 15: 90 seconds buffer at 6s segments
# -hls_flags delete_segments+temp_file: Atomic writes, auto-cleanup
# =============================================================================

hls_seamless=( -hls_start_number_source epoch -hls_list_size 15 )

# =============================================================================
# Build FFmpeg command based on scale
# =============================================================================

build_ffmpeg_cmd() {
    local stream_url="$1"
    local output_path="$2"

    ffmpeg_cmd=( ffmpeg -loglevel error )
    local scheme
    scheme=$(get_url_scheme "$stream_url")
    if [[ "$scheme" == "http" || "$scheme" == "https" ]]; then
        ffmpeg_cmd+=( "${base_flags[@]}" )
    fi

    case "$scale" in
        2)
            # Stream copy with threads
            ffmpeg_cmd+=( -re -i "$stream_url" -c copy -f hls -hls_time 10 -threads 2 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        3)
            # NVIDIA GPU encode (no scaling) - FIXED: added GOP, tune, bufsize
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$stream_url" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k )
            ffmpeg_cmd+=( -c:a aac -b:a 192k )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        4)
            # NVIDIA GPU encode + scale to 1080p - FIXED: added GOP, tune, bufsize
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$stream_url" )
            ffmpeg_cmd+=( -vf "scale_npp=1920:1080" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k )
            ffmpeg_cmd+=( -c:a aac -b:a 192k )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        5)
            # CPU encode (libx264)
            ffmpeg_cmd+=( -i "$stream_url" )
            ffmpeg_cmd+=( -c:v libx264 -preset ultrafast -tune zerolatency -g 180 -keyint_min 180 )
            ffmpeg_cmd+=( -c:a aac -b:a 128k -bufsize 16M -b:v 2500k -threads 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        6)
            # CPU encode + scale to 1080p
            ffmpeg_cmd+=( -i "$stream_url" )
            ffmpeg_cmd+=( -vf "scale=1920:1080" -c:v libx264 -preset ultrafast -tune zerolatency -g 180 -keyint_min 180 )
            ffmpeg_cmd+=( -c:a aac -b:a 128k -bufsize 16M -b:v 2500k -threads 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        7)
            # Stream copy with extended buffer - FIXED: added hls_seamless (epoch)
            ffmpeg_cmd+=( -re -i "$stream_url" -c copy -f hls -hls_time 10 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+program_date_time+temp_file -bufsize 5000k "$output_path" )
            ;;
        8)
            # CUDA passthrough - FIXED: added hls_seamless (epoch) and bufsize
            ffmpeg_cmd+=( -hwaccel cuda -i "$stream_url" -c copy -f hls -hls_time 10 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+program_date_time+temp_file -bufsize 7000k "$output_path" )
            ;;
        *)
            # Default: stream copy
            ffmpeg_cmd+=( -re -i "$stream_url" -c copy -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
    esac
}

# =============================================================================
# MAJOR FIX: Error-type aware failover with 60-second buffer window
# =============================================================================
# Spec requirements:
#   - Per-URL retries: 3 attempts with 2s, 4s, 8s backoff (~14s per URL)
#   - With 3 URLs: ~42 seconds to try all URLs once
#   - 4xx errors: immediate switch to next URL
#   - After all URLs exhausted: wait 10s, restart cycle
#   - Total buffer time: ~60 seconds before viewer sees error
#   - Maximum cycles: 5 (then wait 2 minutes before retry)
# =============================================================================

current_url_index=0
total_cycles=0
max_cycles=5
cycle_start_time=0

# Per-URL retry state
declare -a url_retry_counts
declare -a url_last_error_type
for ((i=0; i<url_count; i++)); do
    url_retry_counts[$i]=0
    url_last_error_type[$i]=""
done

log_console "Starting [$channel_id] with ${url_count} URL(s)"
log "Primary URL: ${url_array[0]}"
if [[ $url_count -gt 1 ]]; then
    for i in $(seq 1 $((url_count - 1))); do
        log "Backup URL $i: ${url_array[$i]}"
    done
fi

# Reset URL retry state for a new cycle
reset_url_retries() {
    for ((i=0; i<url_count; i++)); do
        url_retry_counts[$i]=0
        url_last_error_type[$i]=""
    done
}

# Get backoff delay for current retry count (2s, 4s, 8s)
get_backoff_delay() {
    local retries=$1
    case $retries in
        0) echo 2 ;;
        1) echo 4 ;;
        *) echo 8 ;;
    esac
}

# Switch to next URL
switch_to_next_url() {
    local reason="$1"
    current_url_index=$(( (current_url_index + 1) % url_count ))
    log "URL_SWITCH: Switching to URL index $current_url_index (reason: $reason)"

    if [[ $current_url_index -eq 0 ]]; then
        # Completed a full cycle through all URLs
        total_cycles=$((total_cycles + 1))
        log "CYCLE_COMPLETE: Completed URL cycle $total_cycles of $max_cycles"

        # Calculate time spent in this cycle
        local cycle_end_time=$(date +%s)
        local cycle_duration=$((cycle_end_time - cycle_start_time))
        log "Cycle duration: ${cycle_duration}s"

        if [[ $total_cycles -ge $max_cycles ]]; then
            log "MAX_CYCLES: Reached maximum cycles ($max_cycles). Waiting 2 minutes before retry..."
            sleep 120
            total_cycles=0
            reset_url_retries
        else
            # Brief pause between cycles (contributes to 60s buffer)
            log "All URLs failed. Waiting 10 seconds before next cycle..."
            sleep 10
        fi

        # Reset retry counts for new cycle
        reset_url_retries
        cycle_start_time=$(date +%s)
    fi
}

# =============================================================================
# Main streaming loop with intelligent failover
# =============================================================================

cycle_start_time=$(date +%s)
last_primary_check=$(date +%s)  # Initialize to now so first check is after interval
last_config_check=$(date +%s)

is_process_running() {
    local pid="$1"
    if [[ -z "$pid" ]]; then
        return 1
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        return 1
    fi
    # Avoid getting stuck on zombies (kill -0 succeeds for Z state)
    if [[ -r "/proc/$pid/stat" ]]; then
        local state
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || echo "")
        if [[ "$state" == "Z" ]]; then
            return 1
        fi
    fi
    return 0
}

while true; do
    # NEW: Check if config file changed and reload URLs
    reload_config_if_changed

    # NEW: Check if primary URL is back online (only when on backup)
    if check_and_fallback_to_primary; then
        log "Switched back to primary URL. Continuing with primary..."
    fi

    current_url="${url_array[$current_url_index]}"
    current_retries=${url_retry_counts[$current_url_index]}

    log "ATTEMPT: URL index $current_url_index, retry $current_retries"

    # Fast-fail unsupported URL schemes (e.g., https when ffmpeg lacks TLS)
    if ! ffmpeg_supports_url "$current_url"; then
        scheme=$(get_url_scheme "$current_url")
        log_error "UNSUPPORTED_PROTOCOL: ffmpeg does not support input protocol '$scheme' (URL index $current_url_index). Switching."
        url_last_error_type[$current_url_index]="unsupported_protocol"
        switch_to_next_url "unsupported_protocol"
        continue
    fi

    # Pre-flight URL validation (detect 4xx early) for HTTP/S only
    scheme=$(get_url_scheme "$current_url")
    if [[ "$scheme" == "http" || "$scheme" == "https" ]]; then
        http_status=$(validate_url "$current_url")
        log "URL validation status: $http_status"

        if is_4xx_error "$http_status"; then
            log_error "4XX_ERROR: HTTP $http_status on URL index $current_url_index - immediate switch"
            url_last_error_type[$current_url_index]="4xx"
            switch_to_next_url "HTTP_${http_status}"
            continue
        fi
    else
        log "URL validation skipped for non-HTTP scheme: $scheme"
    fi

    # Build and execute FFmpeg command
    ffmpeg_cmd=()
    build_ffmpeg_cmd "$current_url" "$destination"
    printf -v ffmpeg_cmd_pretty "%q " "${ffmpeg_cmd[@]}"
    log "FFmpeg command starting: $ffmpeg_cmd_pretty"

    # Run FFmpeg and capture stderr for error analysis
    ffmpeg_error_file="/tmp/ffmpeg_error_${channel_id}_$$.log"
    start_time=$(date +%s)
    stop_reason=""

    # Run FFmpeg in background so we can hot-reload config and check primary health
    "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
    ffmpeg_pid=$!
    log "FFmpeg PID: $ffmpeg_pid"

    while is_process_running "$ffmpeg_pid"; do
        sleep 1

        # HOT_RELOAD: pick up config edits while streaming (every 60s)
        reload_config_if_changed

        # PRIMARY_FALLBACK: check primary while on backup (every 5 min)
        if [[ -z "$stop_reason" ]] && check_and_fallback_to_primary; then
            stop_reason="primary_restore"
            log "PRIMARY_RESTORED: Restarting stream to use primary URL..."

            # Graceful stop, then force kill as a last resort
            kill -TERM "$ffmpeg_pid" 2>/dev/null || true
            for i in {1..10}; do
                if ! is_process_running "$ffmpeg_pid"; then
                    break
                fi
                sleep 1
            done
            if is_process_running "$ffmpeg_pid"; then
                log "PRIMARY_RESTORED: Force killing FFmpeg PID $ffmpeg_pid"
                kill -KILL "$ffmpeg_pid" 2>/dev/null || true
            fi
            break
        fi
    done

    wait "$ffmpeg_pid"
    exit_code=$?
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    # If we intentionally stopped FFmpeg to switch back to primary, restart immediately.
    if [[ "$stop_reason" == "primary_restore" ]]; then
        rm -f "$ffmpeg_error_file" 2>/dev/null || true
        # Avoid tight loop if something is wrong with primary
        sleep 1
        continue
    fi

    # Capture and log FFmpeg errors
    if [[ -f "$ffmpeg_error_file" && -s "$ffmpeg_error_file" ]]; then
        ffmpeg_errors=$(cat "$ffmpeg_error_file")
        log_error "FFmpeg stderr: $ffmpeg_errors"

        # Check for HTTP errors in FFmpeg output
        if echo "$ffmpeg_errors" | grep -qE "HTTP error 4[0-9]{2}|Server returned 4[0-9]{2}"; then
            log "4XX_DETECTED: HTTP 4xx error detected in FFmpeg output"
            url_last_error_type[$current_url_index]="4xx"
            rm -f "$ffmpeg_error_file"
            switch_to_next_url "FFmpeg_4xx"
            continue
        fi
    fi
    rm -f "$ffmpeg_error_file"

    log "FFmpeg exited with code $exit_code after ${duration}s"

    # Determine success/failure based on runtime
    if [[ $duration -gt 60 ]]; then
        # Stream was running successfully - reset all counters
        log "SUCCESS_RUN: Stream ran for ${duration}s. Resetting failure counters."
        total_cycles=0
        reset_url_retries
        cycle_start_time=$(date +%s)
        # Small pause before retry (stream ended normally)
        sleep 2
    else
        # Short run = failure
        url_retry_counts[$current_url_index]=$((current_retries + 1))
        current_retries=${url_retry_counts[$current_url_index]}
        log "SHORT_RUN: Duration ${duration}s. URL $current_url_index retry count: $current_retries"

        if [[ $current_retries -ge 3 ]]; then
            # Exhausted retries for this URL, switch to next
            switch_to_next_url "max_retries"
        else
            # Exponential backoff: 2s, 4s, 8s
            backoff=$(get_backoff_delay $((current_retries - 1)))
            log "BACKOFF: Waiting ${backoff}s before retry $current_retries on URL index $current_url_index"
            sleep $backoff
        fi
    fi
done
