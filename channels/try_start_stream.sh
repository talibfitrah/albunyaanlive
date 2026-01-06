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

DEVNULL="/dev/null"
devnull_fallback=0
if [[ ! -c /dev/null || ! -w /dev/null ]]; then
    DEVNULL="/tmp/albunyaan-dev-null"
    : > "$DEVNULL" || true
    devnull_fallback=1
fi

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
PRIMARY_HLS_CHECK_DELAY="${PRIMARY_HLS_CHECK_DELAY:-8}"  # Seconds between HLS playlist samples
PRIMARY_HLS_MAX_WAIT="${PRIMARY_HLS_MAX_WAIT:-15}"       # Cap HLS sample wait to avoid long stalls
CONFIG_CHECK_INTERVAL="${CONFIG_CHECK_INTERVAL:-60}"     # Default: check config file every 60 seconds
last_primary_check=0
last_config_check=0
config_file_mtime=0

# =============================================================================
# NEW: Segment staleness detection for automatic backup URL failover
# =============================================================================
# When FFmpeg is running but not producing segments (source hung), detect this
# and proactively switch to backup URL instead of waiting for FFmpeg to die.
# =============================================================================
SEGMENT_STALE_THRESHOLD="${SEGMENT_STALE_THRESHOLD:-60}"      # Switch to backup if no segments for 60s
SEGMENT_CHECK_INTERVAL="${SEGMENT_CHECK_INTERVAL:-10}"        # Check segment freshness every 10s
last_segment_check=0
stream_start_time=0

# =============================================================================
# YouTube URL resolution settings
# =============================================================================
YOUTUBE_REFRESH_MARGIN="${YOUTUBE_REFRESH_MARGIN:-1800}"  # Refresh 30 min before expiry (1800s)
YOUTUBE_CHECK_INTERVAL="${YOUTUBE_CHECK_INTERVAL:-60}"    # Check expiry every 60s
YTDLP_TIMEOUT="${YTDLP_TIMEOUT:-30}"                      # yt-dlp timeout in seconds
YTDLP_FORMAT="${YTDLP_FORMAT:-best}"                      # yt-dlp format selection
YOUTUBE_STREAM_END_RETRY="${YOUTUBE_STREAM_END_RETRY:-5}" # Retries when stream ends (for general URLs)
last_youtube_check=0

# YouTube state arrays (initialized after URL parsing)
# url_is_youtube[i]     - 1 if YouTube URL, 0 otherwise
# url_youtube_type[i]   - "general" (channel/live) or "specific" (video ID) or ""
# url_original[i]       - Original YouTube URL (for re-resolution)
# url_general_url[i]    - Associated general URL (for specific URLs that have a general fallback)
# url_expire_time[i]    - Unix timestamp when resolved URL expires
# url_stream_ended[i]   - 1 if stream ended (for specific URLs), triggers general URL re-fetch

# User-Agent string (used by both ffmpeg and curl preflight for consistency)
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Parse command line arguments BEFORE setting up logfile
while getopts 'hu:d:k:n:s:b:c:' OPTION; do
    case "$OPTION" in
        h)
            echo "HLS Stream Manager"
            echo ""
            echo "Options:"
            echo "  -u URL       Primary source URL (HLS link or YouTube URL)"
            echo "  -b URLS      Backup URLs separated by pipe (|)"
            echo "  -d PATH      Destination (HLS output path)"
            echo "  -k KEY       Stream key (if needed)"
            echo "  -n NAME      Channel name (for display only)"
            echo "  -s SCALE     Scale/variant (0-9)"
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
            echo "  9 - Software decode + CPU scale + NVENC (for corrupted streams)"
            echo ""
            echo "YouTube URL Support:"
            echo "  Two types of YouTube live URLs are supported:"
            echo ""
            echo "  GENERAL URLs (recommended for 24/7 channels):"
            echo "    https://www.youtube.com/@ChannelName/live"
            echo "    - Points to channel's current live stream"
            echo "    - Auto-redirects when stream ends and new one starts"
            echo "    - Ideal for continuous restreaming"
            echo ""
            echo "  SPECIFIC URLs:"
            echo "    https://www.youtube.com/watch?v=VIDEO_ID"
            echo "    - Points to a specific live video"
            echo "    - Becomes invalid when stream ends"
            echo "    - If channel URL is in the URL, general URL is auto-derived"
            echo ""
            echo "Features:"
            echo "  - Auto-fallback to primary URL when it recovers (every 5 min check)"
            echo "  - Hot-reload: updates backup URLs from config file without restart"
            echo "  - YouTube stream-end detection with automatic re-fetch"
            echo "  - General YouTube URLs auto-refresh when broadcast changes"
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

    if mkdir -p "$preferred" 2>$DEVNULL && [[ -w "$preferred" ]]; then
        echo "$preferred"
        return
    fi

    mkdir -p "$fallback" 2>$DEVNULL || true
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

mkdir -p "$logfile_dir" 2>$DEVNULL || true
logfile="$logfile_dir/${channel_id}.log"
errorfile="$logfile_dir/${channel_id}.error.log"
pidfile="/tmp/stream_${channel_id}.pid"
lockdir="/tmp/stream_${channel_id}.lock"
ffmpeg_pid=""
proxy_pid=""

# Log rotation (50MB threshold, keep last 5)
rotate_logs() {
    local file="$1"
    if [[ -f "$file" && $(stat -c%s "$file" 2>$DEVNULL || echo 0) -gt 52428800 ]]; then
        # Rotate: .log -> .log.1 -> .log.2 -> ... -> .log.5 (delete .log.5)
        for i in 4 3 2 1; do
            [[ -f "${file}.$i" ]] && mv "${file}.$i" "${file}.$((i+1))"
        done
        mv "$file" "${file}.1"
        # Compress old logs in background
        gzip -f "${file}".{2,3,4,5} 2>$DEVNULL &
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

if [[ $devnull_fallback -eq 1 ]]; then
    log "WARN: /dev/null unusable; using $DEVNULL for null redirections"
fi

# =============================================================================
# Prerequisite checks (avoid silent runtime failures)
# =============================================================================

require_ffmpeg() {
    if ! command -v ffmpeg >$DEVNULL 2>&1; then
        log_error "ERROR: ffmpeg not found in PATH. Install ffmpeg and retry."
        echo "ERROR: ffmpeg not found in PATH. Install ffmpeg and retry." >&2
        exit 1
    fi
}

encoder_available() {
    local encoder="$1"
    ffmpeg -hide_banner -encoders 2>$DEVNULL | grep -qE "[[:space:]]${encoder}[[:space:]]"
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
FFMPEG_INPUT_PROTOCOLS=$(ffmpeg -hide_banner -protocols 2>$DEVNULL | awk '
    /^Input:$/ { in_input=1; next }
    /^Output:$/ { in_input=0 }
    in_input && $1 ~ /^[a-z0-9]/ { print $1 }
' || true)

# Check if ffmpeg has native HTTPS support
FFMPEG_HAS_HTTPS=0
if grep -qx "https" <<< "$FFMPEG_INPUT_PROTOCOLS"; then
    FFMPEG_HAS_HTTPS=1
fi

# =============================================================================
# HTTPS Proxy via yt-dlp
# =============================================================================
# If ffmpeg lacks HTTPS support, we can use yt-dlp to fetch HTTPS streams
# and pipe them to ffmpeg. This preserves GPU encoding while handling HTTPS.
# =============================================================================

needs_https_proxy() {
    local url="$1"
    local scheme
    scheme=$(get_url_scheme "$url")

    # Need proxy if: URL is HTTPS and ffmpeg doesn't support HTTPS
    [[ "$scheme" == "https" && "$FFMPEG_HAS_HTTPS" -eq 0 ]]
}

# =============================================================================
# ERROR LOG SIZE LIMITING
# =============================================================================
# Prevents ffmpeg error logs from growing unbounded when source is down.
# AGGRESSIVE LIMITS to prevent disk space exhaustion:
#   - Max size: 100KB (was 1MB)
#   - After 3 rapid failures, redirect errors to $DEVNULL
#   - Cleanup orphaned error files on startup
# =============================================================================
MAX_ERROR_LOG_SIZE=$((100 * 1024))    # 100KB (aggressive limit)
ERROR_LOG_KEEP_SIZE=$((50 * 1024))    # Keep last 50KB when truncating
RAPID_FAILURE_THRESHOLD=3             # After this many rapid failures, stop logging
rapid_failure_count=0

truncate_error_log_if_needed() {
    local error_file="$1"
    [[ -z "$error_file" || ! -f "$error_file" ]] && return 0

    local file_size
    file_size=$(stat -c%s "$error_file" 2>$DEVNULL) || return 0

    if [[ "$file_size" -gt "$MAX_ERROR_LOG_SIZE" ]]; then
        log "ERROR_LOG_TRUNCATE: $error_file is ${file_size} bytes, truncating to last ${ERROR_LOG_KEEP_SIZE} bytes"
        # Keep the last ERROR_LOG_KEEP_SIZE bytes
        tail -c "$ERROR_LOG_KEEP_SIZE" "$error_file" > "${error_file}.tmp" 2>$DEVNULL
        mv "${error_file}.tmp" "$error_file" 2>$DEVNULL || rm -f "${error_file}.tmp"
    fi
}

cleanup_ffmpeg_error_file() {
    local error_file="$1"
    [[ -z "$error_file" || "$error_file" == "$DEVNULL" ]] && return 0
    rm -f "$error_file" 2>$DEVNULL || true
}

# Cleanup orphaned ffmpeg error files from /tmp on startup
# These can accumulate when processes are killed externally
cleanup_orphaned_error_files() {
    local count=0
    local cleaned=0
    for f in /tmp/ffmpeg_error_*.log; do
        [[ -e "$f" ]] || continue
        count=$((count + 1))
        # Extract PID from filename (ffmpeg_error_CHANNEL_PID.log)
        local pid_from_file
        pid_from_file=$(echo "$f" | sed -n 's/.*_\([0-9]\+\)\.log$/\1/p')
        if [[ -n "$pid_from_file" ]]; then
            # If process doesn't exist, remove the file
            if ! kill -0 "$pid_from_file" 2>$DEVNULL; then
                rm -f "$f" 2>$DEVNULL && cleaned=$((cleaned + 1))
            fi
        fi
    done
    if [[ $cleaned -gt 0 ]]; then
        log "STARTUP_CLEANUP: Removed $cleaned orphaned error files from /tmp (of $count found)"
    fi
}

# Run startup cleanup
cleanup_orphaned_error_files

cleanup_done=0

# Cleanup function
cleanup() {
    if [[ $cleanup_done -eq 1 ]]; then
        return
    fi
    cleanup_done=1

    # Stop proxy process (streamlink/yt-dlp) first to avoid pipeline waits
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>$DEVNULL; then
        log "[$channel_id] Cleanup: stopping proxy PID $proxy_pid"
        kill -TERM "$proxy_pid" 2>$DEVNULL || true
        sleep 1
        if kill -0 "$proxy_pid" 2>$DEVNULL; then
            kill -KILL "$proxy_pid" 2>$DEVNULL || true
        fi
    fi

    # If we're interrupted while FFmpeg is running, stop it to avoid orphaned encoders.
    if [[ -n "$ffmpeg_pid" ]] && kill -0 "$ffmpeg_pid" 2>$DEVNULL; then
        log "[$channel_id] Cleanup: stopping FFmpeg PID $ffmpeg_pid"
        kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
        for i in {1..10}; do
            if ! kill -0 "$ffmpeg_pid" 2>$DEVNULL; then
                break
            fi
            sleep 1
        done
        if kill -0 "$ffmpeg_pid" 2>$DEVNULL; then
            log "[$channel_id] Cleanup: force killing FFmpeg PID $ffmpeg_pid"
            kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
        fi
        # Avoid hanging on wait if the PID is stuck or not a child (e.g., pipeline edge cases).
        if ! kill -0 "$ffmpeg_pid" 2>$DEVNULL; then
            wait "$ffmpeg_pid" 2>$DEVNULL || true
        elif [[ -r "/proc/$ffmpeg_pid/stat" ]]; then
            local state
            state=$(awk '{print $3}' "/proc/$ffmpeg_pid/stat" 2>$DEVNULL || echo "")
            if [[ "$state" == "Z" ]]; then
                wait "$ffmpeg_pid" 2>$DEVNULL || true
            fi
        fi
    fi

    rm -f "$pidfile"
    rmdir "$lockdir" 2>$DEVNULL
    # Cleanup any error file for this process
    rm -f "/tmp/ffmpeg_error_${channel_id}_$$.log" 2>$DEVNULL
    log "[$channel_id] Cleanup completed"
}

on_term() {
    cleanup
    exit 0
}

trap on_term TERM INT
trap cleanup EXIT

# Acquire lock (atomic using mkdir)
if ! mkdir "$lockdir" 2>$DEVNULL; then
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
# Build URL array (primary + backups) with YouTube URL support
# =============================================================================

declare -a url_array
declare -a url_is_youtube
declare -a url_youtube_type
declare -a url_original
declare -a url_general_url
declare -a url_expire_time
declare -a url_stream_ended

# First, build the raw URL array
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

# NOTE: YouTube metadata initialization moved to after function definitions (see below)

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
    match=$(grep -lF "$dest_dir" "$SCRIPT_DIR"/channel_*.sh 2>$DEVNULL | head -1)
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
    match=$(find "$SCRIPT_DIR" -maxdepth 1 \( -name "channel_*${channel_id}*.sh" -o -name "channel_*${underscore_name}*.sh" \) -type f 2>$DEVNULL | head -1)
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
    config_file_mtime=$(stat -c %Y "$config_file" 2>$DEVNULL || echo 0)
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
    local index="${2:-}"
    local scheme
    scheme=$(get_url_scheme "$url")

    # If HTTPS and ffmpeg lacks TLS, require an appropriate proxy tool
    if [[ "$scheme" == "https" && "$FFMPEG_HAS_HTTPS" -eq 0 ]]; then
        # YouTube URLs require yt-dlp
        if [[ -n "$index" && "${url_is_youtube[$index]}" == "1" ]]; then
            command -v yt-dlp >$DEVNULL 2>&1 && return 0
            return 1
        fi

        # HLS URLs require streamlink
        if [[ "$url" == *.m3u8* ]]; then
            command -v streamlink >$DEVNULL 2>&1 && return 0
            return 1
        fi

        # Other HTTPS sources default to streamlink
        command -v streamlink >$DEVNULL 2>&1 && return 0
        return 1
    fi

    if [[ -z "$FFMPEG_INPUT_PROTOCOLS" ]]; then
        # If we couldn't detect protocols, don't block (best effort).
        return 0
    fi
    grep -Fqx "$scheme" <<< "$FFMPEG_INPUT_PROTOCOLS"
}

# =============================================================================
# YouTube URL detection and resolution functions
# =============================================================================

is_youtube_url() {
    local url="$1"
    # Match youtube.com, youtu.be, youtube-nocookie.com
    [[ "$url" =~ ^https?://(www\.)?(youtube\.com|youtu\.be|youtube-nocookie\.com)/ ]]
}

# =============================================================================
# YouTube URL Type Detection
# =============================================================================
# Two types of YouTube live URLs:
#   1. SPECIFIC: Has video ID - e.g., https://www.youtube.com/watch?v=3oudVvsPMXs
#      - Points to a specific live stream
#      - When stream ends, URL becomes invalid
#
#   2. GENERAL: Channel live page - e.g., https://www.youtube.com/@ZadTVchannel/live
#      - Points to channel's current live stream
#      - Automatically redirects to latest live stream
#      - Ideal for 24/7 channels that restart broadcasts
#
# General URLs are preferred for 24/7 streaming because they auto-update
# when a broadcast ends and a new one starts.
# =============================================================================

get_youtube_url_type() {
    local url="$1"

    if ! is_youtube_url "$url"; then
        echo ""
        return 1
    fi

    # General URL patterns:
    # - /@username/live or /c/channelname/live or /channel/ID/live
    # - /user/username/live
    if [[ "$url" =~ /(@[^/]+|c/[^/]+|channel/[^/]+|user/[^/]+)/live/?([?#].*)?$ ]]; then
        echo "general"
        return 0
    fi

    # Specific URL patterns:
    # - /watch?v=VIDEO_ID
    # - /live/VIDEO_ID
    # - youtu.be/VIDEO_ID
    if [[ "$url" =~ watch\?.*v= ]] || \
       [[ "$url" =~ /live/[a-zA-Z0-9_-]{11} ]] || \
       [[ "$url" =~ youtu\.be/[a-zA-Z0-9_-]{11} ]]; then
        echo "specific"
        return 0
    fi

    # Default to specific if it's a YouTube URL but type unknown
    echo "specific"
    return 0
}

is_youtube_general_url() {
    local url="$1"
    [[ "$(get_youtube_url_type "$url")" == "general" ]]
}

is_youtube_specific_url() {
    local url="$1"
    [[ "$(get_youtube_url_type "$url")" == "specific" ]]
}

# Extract channel identifier from a YouTube URL (for matching specific to general)
get_youtube_channel_from_url() {
    local url="$1"

    # Extract @username
    if [[ "$url" =~ /@([^/]+) ]]; then
        echo "@${BASH_REMATCH[1]}"
        return 0
    fi

    # Extract /c/channelname
    if [[ "$url" =~ /c/([^/]+) ]]; then
        echo "c/${BASH_REMATCH[1]}"
        return 0
    fi

    # Extract /channel/ID
    if [[ "$url" =~ /channel/([^/]+) ]]; then
        echo "channel/${BASH_REMATCH[1]}"
        return 0
    fi

    # Extract /user/username
    if [[ "$url" =~ /user/([^/]+) ]]; then
        echo "user/${BASH_REMATCH[1]}"
        return 0
    fi

    echo ""
    return 1
}

# Build general URL from channel identifier
build_youtube_general_url() {
    local channel_id="$1"

    if [[ "$channel_id" =~ ^@ ]]; then
        echo "https://www.youtube.com/${channel_id}/live"
    elif [[ "$channel_id" =~ ^(c|channel|user)/ ]]; then
        echo "https://www.youtube.com/${channel_id}/live"
    else
        echo ""
        return 1
    fi
}

resolve_youtube_url() {
    local youtube_url="$1"
    local resolved_url=""

    log "YOUTUBE: Resolving URL: $youtube_url"

    # Check if yt-dlp is available
    if ! command -v yt-dlp >$DEVNULL 2>&1; then
        log_error "YOUTUBE: yt-dlp not found. Install with: pip install yt-dlp"
        return 1
    fi

    # Use yt-dlp with timeout to extract stream URL
    # -g: Get URL only, --no-warnings: suppress warnings
    # -f: Format selection
    local ytdlp_cmd=(yt-dlp -g --no-warnings --no-playlist -f "$YTDLP_FORMAT" "$youtube_url")
    if command -v timeout >$DEVNULL 2>&1; then
        resolved_url=$(timeout "$YTDLP_TIMEOUT" "${ytdlp_cmd[@]}" 2>$DEVNULL | head -1)
    else
        log "YOUTUBE: 'timeout' not found; running yt-dlp without timeout"
        resolved_url=$("${ytdlp_cmd[@]}" 2>$DEVNULL | head -1)
    fi

    if [[ -z "$resolved_url" ]]; then
        log_error "YOUTUBE: Failed to resolve URL: $youtube_url"
        return 1
    fi

    log "YOUTUBE: Resolved to: ${resolved_url:0:80}..."
    echo "$resolved_url"
    return 0
}

extract_youtube_expiry() {
    local url="$1"
    local expire_ts=""

    # Extract expire timestamp from query param like ?expire=1767702805
    if [[ "$url" =~ ([\?\&]expire=)([0-9]+) ]]; then
        expire_ts="${BASH_REMATCH[2]}"
        echo "$expire_ts"
        return 0
    fi

    # Extract expire timestamp from URL path like /expire/1767702805/
    if [[ "$url" =~ /expire/([0-9]+)/ ]]; then
        expire_ts="${BASH_REMATCH[1]}"
        echo "$expire_ts"
        return 0
    fi

    # Fallback: assume 5 hours from now if no expire found
    local fallback=$(($(date +%s) + 18000))
    log "YOUTUBE: No expiry found in URL, assuming 5 hours from now"
    echo "$fallback"
    return 1
}

# Initialize YouTube metadata for a URL slot
init_url_youtube_metadata() {
    local index="$1"
    local url="$2"
    local associated_general="${3:-}"  # Optional: associated general URL for specific URLs

    # Initialize all metadata fields
    url_stream_ended[$index]=0

    if is_youtube_url "$url"; then
        local yt_type
        yt_type=$(get_youtube_url_type "$url")
        log "YOUTUBE: Detected $yt_type YouTube URL at index $index: $url"

        url_is_youtube[$index]=1
        url_youtube_type[$index]="$yt_type"
        url_original[$index]="$url"

        # Store associated general URL if provided, or extract from URL
        if [[ -n "$associated_general" ]]; then
            url_general_url[$index]="$associated_general"
            log "YOUTUBE: Associated general URL for index $index: $associated_general"
        elif [[ "$yt_type" == "general" ]]; then
            # General URLs are their own fallback
            url_general_url[$index]="$url"
        else
            # Try to extract channel and build general URL
            local channel_id
            channel_id=$(get_youtube_channel_from_url "$url")
            if [[ -n "$channel_id" ]]; then
                local general_url
                general_url=$(build_youtube_general_url "$channel_id")
                if [[ -n "$general_url" ]]; then
                    url_general_url[$index]="$general_url"
                    log "YOUTUBE: Auto-derived general URL for index $index: $general_url"
                fi
            fi
        fi

        # Resolve immediately
        local resolved
        resolved=$(resolve_youtube_url "$url")
        if [[ -n "$resolved" ]]; then
            local expire_time
            expire_time=$(extract_youtube_expiry "$resolved")
            url_expire_time[$index]="$expire_time"

            # Update url_array with resolved URL
            url_array[$index]="$resolved"

            local expire_date
            expire_date=$(date -d "@$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
            log "YOUTUBE: URL index $index resolved ($yt_type), expires at $expire_date"
            return 0
        else
            log_error "YOUTUBE: Failed initial resolution for index $index, keeping original URL"
            url_expire_time[$index]=0
            # Keep original YouTube URL - ffmpeg will fail but failover will work
            return 1
        fi
    else
        url_is_youtube[$index]=0
        url_youtube_type[$index]=""
        url_original[$index]="$url"
        url_general_url[$index]=""
        url_expire_time[$index]=0
    fi
    return 0
}

# =============================================================================
# YouTube Stream End Detection and Re-fetch
# =============================================================================
# When a specific YouTube stream ends, we need to:
#   1. Detect the stream has ended (FFmpeg error, yt-dlp says no live)
#   2. If we have a general URL, use it to fetch the new live stream
#   3. Update the resolved URL and continue streaming seamlessly
# =============================================================================

youtube_check_stream_ended() {
    local youtube_url="$1"
    local yt_type="$2"

    # Only check specific URLs - general URLs auto-redirect
    if [[ "$yt_type" != "specific" ]]; then
        return 1
    fi

    # Use yt-dlp to check if the stream is still live
    local is_live
    if command -v timeout >$DEVNULL 2>&1; then
        is_live=$(timeout 10 yt-dlp --no-download --print "%(is_live)s" "$youtube_url" 2>$DEVNULL || echo "error")
    else
        log "YOUTUBE: 'timeout' not found; running yt-dlp without timeout for live check"
        is_live=$(yt-dlp --no-download --print "%(is_live)s" "$youtube_url" 2>$DEVNULL || echo "error")
    fi

    if [[ "$is_live" == "False" || "$is_live" == "error" ]]; then
        log "YOUTUBE: Stream ended or unavailable for $youtube_url (is_live=$is_live)"
        return 0  # Stream ended
    fi

    return 1  # Stream still live
}

youtube_refetch_via_general() {
    local index="$1"
    local general_url="${url_general_url[$index]}"

    if [[ -z "$general_url" ]]; then
        log_error "YOUTUBE_REFETCH: No general URL available for index $index"
        return 1
    fi

    log "YOUTUBE_REFETCH: Fetching new live stream via general URL: $general_url"

    local retry_count=0
    local max_retries=$YOUTUBE_STREAM_END_RETRY
    local resolved=""

    while [[ $retry_count -lt $max_retries ]]; do
        resolved=$(resolve_youtube_url "$general_url")

        if [[ -n "$resolved" ]]; then
            local expire_time
            expire_time=$(extract_youtube_expiry "$resolved")
            url_expire_time[$index]="$expire_time"
            url_array[$index]="$resolved"
            url_stream_ended[$index]=0
            url_original[$index]="$general_url"
            url_youtube_type[$index]="general"
            url_general_url[$index]="$general_url"

            local expire_date
            expire_date=$(date -d "@$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
            log "YOUTUBE_REFETCH: Success! New stream resolved, expires at $expire_date"
            return 0
        fi

        retry_count=$((retry_count + 1))
        if [[ $retry_count -lt $max_retries ]]; then
            local wait_time=$((retry_count * 10))
            log "YOUTUBE_REFETCH: Attempt $retry_count failed. Waiting ${wait_time}s before retry..."
            sleep $wait_time
        fi
    done

    log_error "YOUTUBE_REFETCH: Failed after $max_retries attempts"
    return 1
}

# Check if current YouTube URL's stream ended and needs re-fetch
check_youtube_stream_ended_and_refetch() {
    local index="$1"

    # Skip non-YouTube URLs
    if [[ "${url_is_youtube[$index]}" != "1" ]]; then
        return 1
    fi

    local yt_type="${url_youtube_type[$index]}"
    local original_url="${url_original[$index]}"
    local general_url="${url_general_url[$index]}"

    # For general URLs, just re-resolve (they always point to current live)
    if [[ "$yt_type" == "general" ]]; then
        log "YOUTUBE_STREAM_END: General URL detected, re-resolving to get latest stream..."
        if refresh_youtube_url "$index"; then
            return 0
        fi
        return 1
    fi

    # For specific URLs, confirm stream status and use general URL if available
    if [[ "$yt_type" == "specific" ]]; then
        if youtube_check_stream_ended "$original_url" "$yt_type"; then
            if [[ -n "$general_url" ]]; then
                log "YOUTUBE_STREAM_END: Specific URL ended, using general URL for re-fetch..."
                if youtube_refetch_via_general "$index"; then
                    return 0
                fi
            else
                log "YOUTUBE_STREAM_END: Specific URL ended and no general URL available"
            fi
        else
            log "YOUTUBE_STREAM_END: Specific URL still live, refreshing resolved URL..."
            if refresh_youtube_url "$index"; then
                return 0
            fi
        fi
    fi

    return 1
}

youtube_url_needs_refresh() {
    local index="$1"
    local now=$(date +%s)

    # Skip if not a YouTube URL
    if [[ "${url_is_youtube[$index]}" != "1" ]]; then
        return 1
    fi

    local expire_time="${url_expire_time[$index]:-0}"

    # Skip if no valid expiry time
    if [[ "$expire_time" -eq 0 ]]; then
        return 1
    fi

    local time_until_expiry=$((expire_time - now))

    # Check if within refresh margin (default 30 min before expiry)
    if [[ $time_until_expiry -le $YOUTUBE_REFRESH_MARGIN ]]; then
        log "YOUTUBE: URL index $index expires in ${time_until_expiry}s (threshold: ${YOUTUBE_REFRESH_MARGIN}s)"
        return 0
    fi

    return 1
}

refresh_youtube_url() {
    local index="$1"
    local original_url="${url_original[$index]}"

    if [[ -z "$original_url" ]]; then
        log_error "YOUTUBE: No original URL for index $index"
        return 1
    fi

    log "YOUTUBE_REFRESH: Refreshing URL index $index..."

    local new_resolved
    new_resolved=$(resolve_youtube_url "$original_url")

    if [[ -z "$new_resolved" ]]; then
        log_error "YOUTUBE_REFRESH: Failed to resolve $original_url"
        return 1
    fi

    local new_expire
    new_expire=$(extract_youtube_expiry "$new_resolved")

    # Update arrays
    url_expire_time[$index]="$new_expire"
    url_array[$index]="$new_resolved"

    local expire_date
    expire_date=$(date -d "@$new_expire" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$new_expire" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
    log "YOUTUBE_REFRESH: URL index $index refreshed, new expiry: $expire_date"
    return 0
}

check_youtube_urls_need_refresh() {
    local now=$(date +%s)
    local elapsed=$((now - last_youtube_check))

    # Only check every YOUTUBE_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $YOUTUBE_CHECK_INTERVAL ]]; then
        return 1  # No refresh triggered
    fi

    last_youtube_check=$now
    local current_refresh_needed=0

    # Check current URL first (most important)
    if youtube_url_needs_refresh "$current_url_index"; then
        log "YOUTUBE_REFRESH: Current URL (index $current_url_index) needs refresh"
        if refresh_youtube_url "$current_url_index"; then
            current_refresh_needed=1
        fi
    fi

    # Also proactively refresh other URLs that are expiring soon
    for i in $(seq 0 $((url_count - 1))); do
        if [[ $i -ne $current_url_index ]] && youtube_url_needs_refresh "$i"; then
            log "YOUTUBE_REFRESH: Backup URL (index $i) needs refresh"
            refresh_youtube_url "$i" || true  # Don't fail on backup refresh
        fi
    done

    if [[ $current_refresh_needed -eq 1 ]]; then
        return 0  # Signal that current URL was refreshed - need FFmpeg restart
    fi

    return 1
}

check_segment_staleness() {
    local now=$(date +%s)
    local elapsed=$((now - last_segment_check))

    # Only check every SEGMENT_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $SEGMENT_CHECK_INTERVAL ]]; then
        return 1
    fi

    last_segment_check=$now

    # Only trigger failover if backups exist
    if [[ $url_count -lt 2 ]]; then
        return 1
    fi

    local output_dir
    output_dir=$(dirname "$destination")
    if [[ ! -d "$output_dir" ]]; then
        return 1
    fi

    local newest_segment
    newest_segment=$(find "$output_dir" -maxdepth 1 -name "*.ts" -type f -printf '%T@ %p\n' 2>$DEVNULL | sort -n | tail -1)

    if [[ -z "$newest_segment" ]]; then
        if [[ $stream_start_time -gt 0 ]]; then
            local age=$((now - stream_start_time))
            if [[ $age -gt $SEGMENT_STALE_THRESHOLD ]]; then
                log "SEGMENT_STALE: No segments created for ${age}s (threshold: ${SEGMENT_STALE_THRESHOLD}s)"
                return 0
            fi
        fi
        return 1
    fi

    local segment_mtime
    segment_mtime=$(echo "$newest_segment" | awk '{print $1}' | cut -d'.' -f1)
    if [[ -z "$segment_mtime" ]]; then
        return 1
    fi

    if [[ $stream_start_time -gt 0 && $segment_mtime -lt $stream_start_time ]]; then
        local age_since_start=$((now - stream_start_time))
        if [[ $age_since_start -gt $SEGMENT_STALE_THRESHOLD ]]; then
            log "SEGMENT_STALE: No new segments since start (${age_since_start}s, threshold: ${SEGMENT_STALE_THRESHOLD}s)"
            return 0
        fi
        return 1
    fi

    local segment_age=$((now - segment_mtime))
    if [[ $segment_age -gt $SEGMENT_STALE_THRESHOLD ]]; then
        log "SEGMENT_STALE: Latest segment age ${segment_age}s (threshold: ${SEGMENT_STALE_THRESHOLD}s)"
        return 0
    fi

    return 1
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

    # YouTube primary requires yt-dlp resolution (HTTP status on channel page is not enough)
    if [[ "${url_is_youtube[0]}" == "1" ]]; then
        local check_url="${url_original[0]}"
        if [[ -n "${url_general_url[0]}" ]]; then
            check_url="${url_general_url[0]}"
        fi

        if ! command -v yt-dlp >$DEVNULL 2>&1; then
            log "PRIMARY_CHECK: yt-dlp not available; cannot validate YouTube primary. Staying on backup."
            return 1
        fi

        local resolved
        resolved=$(resolve_youtube_url "$check_url")
        if [[ -n "$resolved" ]]; then
            local expire_time
            expire_time=$(extract_youtube_expiry "$resolved")
            url_array[0]="$resolved"
            url_expire_time[0]="$expire_time"
            url_original[0]="$check_url"
            url_youtube_type[0]=$(get_youtube_url_type "$check_url")
            if [[ "${url_youtube_type[0]}" == "general" ]]; then
                url_general_url[0]="$check_url"
            fi

            log "PRIMARY_RESTORED: Primary YouTube stream resolved. Switching back..."
            current_url_index=0
            reset_url_retries
            total_cycles=0
            return 0
        fi

        log "PRIMARY_CHECK: Primary YouTube URL not available. Staying on backup."
        return 1
    fi

    local scheme
    scheme=$(get_url_scheme "$primary_url")

    # If FFmpeg can't read this URL scheme (e.g., https not compiled in), don't attempt fallback.
    if ! ffmpeg_supports_url "$primary_url" 0; then
        log "PRIMARY_CHECK: Primary URL uses unsupported protocol for this ffmpeg build ($scheme). Staying on backup."
        return 1
    fi

    # Only HTTP/S sources can be preflight-checked; others must be handled by ffmpeg directly.
    if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
        log "PRIMARY_CHECK: Skipping health check for non-HTTP primary ($scheme). Staying on backup."
        return 1
    fi

    # Test primary URL health (prefer HLS playlist advancement when applicable)
    local hls_check_result=1
    hls_check_result=$(check_hls_playlist_fresh "$primary_url")

    if [[ "$hls_check_result" -eq 0 ]]; then
        log "PRIMARY_RESTORED: Primary HLS playlist is advancing. Switching back..."
        current_url_index=0
        reset_url_retries
        total_cycles=0
        return 0
    fi

    if [[ "$hls_check_result" -eq 2 ]]; then
        local primary_status
        primary_status=$(validate_url "$primary_url")
        log "PRIMARY_CHECK: Primary URL returned HTTP $primary_status"

        if [[ "$primary_status" =~ ^2[0-9]{2}$ ]]; then
            # Primary is healthy! Switch back to it
            log "PRIMARY_RESTORED: Primary URL is healthy (HTTP $primary_status). Switching back..."
            current_url_index=0
            reset_url_retries
            total_cycles=0
            return 0  # Signal that we should switch
        fi

        log "PRIMARY_CHECK: Primary still unavailable (HTTP $primary_status). Staying on backup."
        return 1
    fi

    log "PRIMARY_CHECK: Primary HLS playlist is stale. Staying on backup."
    return 1
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
    local current_mtime=$(stat -c %Y "$config_file" 2>$DEVNULL || echo 0)

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

    # If primary URL changed, re-initialize metadata (works for both YouTube and regular URLs)
    if [[ -n "$new_primary" && "$new_primary" != "$primary_url" ]]; then
        log "CONFIG_RELOAD: Primary URL changed! Old: ${primary_url} -> New: $new_primary"
        primary_url="$new_primary"

        # Re-initialize metadata (handles YouTube detection automatically)
        init_url_youtube_metadata 0 "$new_primary"
        log "CONFIG_RELOAD: Primary URL re-initialized. Will use on next FFmpeg restart."
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

        # Initialize YouTube metadata for all backup URLs (index 1+)
        for ((i=1; i<url_count; i++)); do
            init_url_youtube_metadata "$i" "${url_array[$i]}"
        done

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
    if grep -qE "^[[:space:]]*(export[[:space:]]+)?BACKUP_URLS[[:space:]]*=" "$script" 2>$DEVNULL; then
        backups_found=true
        new_backups=$(parse_config_value "$script" "BACKUP_URLS")
    # Then check for stream_url_backup1/backup2 variables
    elif grep -qE "^[[:space:]]*(export[[:space:]]+)?stream_url_backup[12][[:space:]]*=" "$script" 2>$DEVNULL; then
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
        # Initialize YouTube metadata for newly loaded backup URLs
        for i in $(seq 1 $((url_count - 1))); do
            log "STARTUP: Initializing backup URL $i: ${url_array[$i]}"
            init_url_youtube_metadata "$i" "${url_array[$i]}"
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
    response=$(curl -A "$USER_AGENT" -L -s -o $DEVNULL -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL)

    echo "$response"
}

fetch_url_body() {
    local test_url="$1"
    local timeout="${2:-10}"
    curl -A "$USER_AGENT" -L -s --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL
}

fetch_url_prefix() {
    local test_url="$1"
    local timeout="${2:-10}"
    curl -A "$USER_AGENT" -L -s -r 0-4096 --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL
}

check_hls_playlist_fresh() {
    local test_url="$1"
    local timeout=10

    local prefix
    prefix=$(fetch_url_prefix "$test_url" "$timeout")
    if [[ -z "$prefix" ]]; then
        log "PRIMARY_CHECK: HLS playlist probe failed"
        return 1
    fi
    if ! echo "$prefix" | grep -q "^#EXTM3U"; then
        return 2  # Not an HLS playlist
    fi

    local first
    first=$(fetch_url_body "$test_url" "$timeout")
    if [[ -z "$first" ]]; then
        log "PRIMARY_CHECK: HLS playlist fetch failed"
        return 1
    fi

    if echo "$first" | grep -q "^#EXT-X-ENDLIST"; then
        log "PRIMARY_CHECK: HLS playlist is ended (EXT-X-ENDLIST)"
        return 1
    fi

    local seq1
    local target
    local seg1
    seq1=$(echo "$first" | awk -F: '/^#EXT-X-MEDIA-SEQUENCE:/ {print $2; exit}')
    target=$(echo "$first" | awk -F: '/^#EXT-X-TARGETDURATION:/ {print $2; exit}')
    seg1=$(echo "$first" | awk '!/^#/ && NF {last=$0} END {print last}')

    local delay="$PRIMARY_HLS_CHECK_DELAY"
    if [[ "$target" =~ ^[0-9]+$ && "$target" -gt "$delay" ]]; then
        delay="$target"
    fi
    if [[ "$delay" -gt "$PRIMARY_HLS_MAX_WAIT" ]]; then
        delay="$PRIMARY_HLS_MAX_WAIT"
    fi

    sleep "$delay"

    local second
    second=$(fetch_url_body "$test_url" "$timeout")
    if [[ -z "$second" ]]; then
        log "PRIMARY_CHECK: HLS playlist re-fetch failed"
        return 1
    fi
    if ! echo "$second" | grep -q "^#EXTM3U"; then
        log "PRIMARY_CHECK: HLS playlist is invalid on re-fetch"
        return 1
    fi
    if echo "$second" | grep -q "^#EXT-X-ENDLIST"; then
        log "PRIMARY_CHECK: HLS playlist ended on re-fetch (EXT-X-ENDLIST)"
        return 1
    fi

    local seq2
    local seg2
    seq2=$(echo "$second" | awk -F: '/^#EXT-X-MEDIA-SEQUENCE:/ {print $2; exit}')
    seg2=$(echo "$second" | awk '!/^#/ && NF {last=$0} END {print last}')

    if [[ -n "$seq1" && -n "$seq2" && "$seq2" -gt "$seq1" ]]; then
        return 0
    fi
    if [[ -n "$seg1" && -n "$seg2" && "$seg1" != "$seg2" ]]; then
        return 0
    fi

    log "PRIMARY_CHECK: HLS playlist not advancing (seq ${seq1:-?} -> ${seq2:-?}, seg ${seg1:-?} -> ${seg2:-?})"
    return 1
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

    # Check if we need HTTPS proxy (yt-dlp pipe)
    use_https_proxy=0
    actual_input_url="$stream_url"

    if needs_https_proxy "$stream_url"; then
        use_https_proxy=1
        actual_input_url="pipe:0"
        log "HTTPS_PROXY: Will use proxy for HTTPS stream (ffmpeg lacks TLS support)"
    fi

    ffmpeg_cmd=( ffmpeg -loglevel error )
    local scheme
    scheme=$(get_url_scheme "$stream_url")

    # Only add HTTP flags for direct HTTP connections (not for pipe input)
    if [[ "$use_https_proxy" -eq 0 && ("$scheme" == "http" || "$scheme" == "https") ]]; then
        ffmpeg_cmd+=( "${base_flags[@]}" )
    fi

    case "$scale" in
        2)
            # Stream copy with threads
            ffmpeg_cmd+=( -re -i "$actual_input_url" -c copy -f hls -hls_time 10 -threads 2 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        3)
            # NVIDIA GPU encode (no scaling) - FIXED: added GOP, tune, bufsize
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$actual_input_url" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k )
            ffmpeg_cmd+=( -c:a aac -b:a 192k )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        4)
            # NVIDIA GPU encode + scale to 1080p - FIXED: added GOP, tune, bufsize
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$actual_input_url" )
            ffmpeg_cmd+=( -vf "scale_npp=1920:1080" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k )
            ffmpeg_cmd+=( -c:a aac -b:a 192k )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        5)
            # CPU encode (libx264)
            ffmpeg_cmd+=( -i "$actual_input_url" )
            ffmpeg_cmd+=( -c:v libx264 -preset ultrafast -tune zerolatency -g 180 -keyint_min 180 )
            ffmpeg_cmd+=( -c:a aac -b:a 128k -bufsize 16M -b:v 2500k -threads 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        6)
            # CPU encode + scale to 1080p
            ffmpeg_cmd+=( -i "$actual_input_url" )
            ffmpeg_cmd+=( -vf "scale=1920:1080" -c:v libx264 -preset ultrafast -tune zerolatency -g 180 -keyint_min 180 )
            ffmpeg_cmd+=( -c:a aac -b:a 128k -bufsize 16M -b:v 2500k -threads 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        7)
            # Stream copy with extended buffer - FIXED: added hls_seamless (epoch)
            ffmpeg_cmd+=( -re -i "$actual_input_url" -c copy -f hls -hls_time 10 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+program_date_time+temp_file -bufsize 5000k "$output_path" )
            ;;
        8)
            # CUDA passthrough - FIXED: added hls_seamless (epoch) and bufsize
            ffmpeg_cmd+=( -hwaccel cuda -i "$actual_input_url" -c copy -f hls -hls_time 10 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+program_date_time+temp_file -bufsize 7000k "$output_path" )
            ;;
        9)
            # Software decode + CPU scale + NVENC encode (for problematic streams)
            # Uses software decoder which tolerates corrupted H.264 packets better than h264_cuvid
            # Added error recovery flags to handle severely corrupted streams
            ffmpeg_cmd+=( -err_detect ignore_err -fflags +discardcorrupt+genpts )
            ffmpeg_cmd+=( -i "$actual_input_url" )
            ffmpeg_cmd+=( -vf "scale=1920:1080" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k )
            ffmpeg_cmd+=( -c:a aac -b:a 192k )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
        *)
            # Default: stream copy
            ffmpeg_cmd+=( -re -i "$actual_input_url" -c copy -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file "$output_path" )
            ;;
    esac
}

# =============================================================================
# Initialize YouTube metadata for all URLs
# =============================================================================
# This must happen after all functions are defined but before the main loop.
# Resolves YouTube URLs via yt-dlp and sets up metadata for refresh/failover.
# =============================================================================

log "Initializing ${url_count} URL(s) with YouTube detection..."
for i in $(seq 0 $((url_count - 1))); do
    init_url_youtube_metadata "$i" "${url_array[$i]}"
done

# Keep primary_url as the canonical (unresolved) source for health checks
if [[ "${url_is_youtube[0]}" == "1" && -n "${url_original[0]}" ]]; then
    primary_url="${url_original[0]}"
    log "Primary URL kept as original YouTube URL for health checks"
fi

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

# Log URL details with YouTube type info
for i in $(seq 0 $((url_count - 1))); do
    url_label="Primary"
    [[ $i -gt 0 ]] && url_label="Backup $i"

    if [[ "${url_is_youtube[$i]}" == "1" ]]; then
        yt_type="${url_youtube_type[$i]}"
        general="${url_general_url[$i]}"
        log "$url_label URL: ${url_original[$i]}"
        log "  -> Type: YouTube ($yt_type)"
        log "  -> Resolved: ${url_array[$i]:0:80}..."
        [[ -n "$general" && "$general" != "${url_original[$i]}" ]] && log "  -> General URL: $general"
    else
        log "$url_label URL: ${url_array[$i]}"
    fi
done

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
    local previous_index="$current_url_index"
    current_url_index=$(( (current_url_index + 1) % url_count ))
    log "URL_SWITCH: Switching to URL index $current_url_index (reason: $reason)"

    if [[ $previous_index -eq 0 && $current_url_index -ne 0 ]]; then
        # Delay primary health checks after failing over to backup.
        last_primary_check=$(date +%s)
        log "PRIMARY_CHECK: Delaying primary checks for ${PRIMARY_CHECK_INTERVAL}s after failover"
    fi

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
            rapid_failure_count=0  # Reset to re-enable error logging after long pause
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
    if ! kill -0 "$pid" 2>$DEVNULL; then
        return 1
    fi
    # Avoid getting stuck on zombies (kill -0 succeeds for Z state)
    if [[ -r "/proc/$pid/stat" ]]; then
        local state
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>$DEVNULL || echo "")
        if [[ "$state" == "Z" ]]; then
            return 1
        fi
    fi
    return 0
}

while true; do
    # NEW: Check if config file changed and reload URLs
    reload_config_if_changed

    # YOUTUBE: Check if any YouTube URLs need refresh before starting FFmpeg
    if check_youtube_urls_need_refresh; then
        log "YOUTUBE: URLs refreshed before FFmpeg start"
    fi

    # NEW: Check if primary URL is back online (only when on backup)
    if check_and_fallback_to_primary; then
        log "Switched back to primary URL. Continuing with primary..."
    fi

    current_url="${url_array[$current_url_index]}"
    current_retries=${url_retry_counts[$current_url_index]}

    log "ATTEMPT: URL index $current_url_index, retry $current_retries"

    # Fast-fail unsupported URL schemes (e.g., https when ffmpeg lacks TLS)
    if ! ffmpeg_supports_url "$current_url" "$current_url_index"; then
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
    # After too many rapid failures, discard errors to prevent disk fill
    if [[ $rapid_failure_count -ge $RAPID_FAILURE_THRESHOLD ]]; then
        ffmpeg_error_file="$DEVNULL"
        log "RAPID_FAILURE: Discarding FFmpeg errors (failure count: $rapid_failure_count)"
    else
        ffmpeg_error_file="/tmp/ffmpeg_error_${channel_id}_$$.log"
    fi
    start_time=$(date +%s)
    stream_start_time=$start_time
    stop_reason=""
    # Reset segment check timer for new FFmpeg run
    last_segment_check=0

    # Run FFmpeg in background so we can hot-reload config and check primary health
    proxy_pid=""
    if [[ "$use_https_proxy" -eq 1 ]]; then
        if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
            if ! command -v yt-dlp >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: yt-dlp not found for YouTube URL; switching to next URL"
                switch_to_next_url "proxy_missing"
                continue
            fi
            proxy_source_url="${url_original[$current_url_index]:-$current_url}"
            log "HTTPS_PROXY: Starting yt-dlp pipe for YouTube: $proxy_source_url"
            yt-dlp -q -o - "$proxy_source_url" 2>>"$logfile" | "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            proxy_pid=$(pgrep -P $$ -n -f "yt-dlp.*$proxy_source_url" 2>$DEVNULL || true)
            log "FFmpeg PID: $ffmpeg_pid, yt-dlp PID: ${proxy_pid:-unknown}"
        elif [[ "$current_url" == *.m3u8* ]]; then
            if ! command -v streamlink >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: streamlink not found for HLS URL; switching to next URL"
                switch_to_next_url "proxy_missing"
                continue
            fi
            log "HTTPS_PROXY: Starting streamlink pipe for HLS: $current_url"
            streamlink --stdout "$current_url" best 2>>"$logfile" | "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            proxy_pid=$(pgrep -P $$ -n -f "streamlink.*$current_url" 2>$DEVNULL || true)
            log "FFmpeg PID: $ffmpeg_pid, streamlink PID: ${proxy_pid:-unknown}"
        else
            if ! command -v streamlink >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: streamlink not found for HTTPS URL; switching to next URL"
                switch_to_next_url "proxy_missing"
                continue
            fi
            log "HTTPS_PROXY: Starting streamlink pipe for: $current_url"
            streamlink --stdout "$current_url" best 2>>"$logfile" | "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            proxy_pid=$(pgrep -P $$ -n -f "streamlink.*$current_url" 2>$DEVNULL || true)
            log "FFmpeg PID: $ffmpeg_pid, streamlink PID: ${proxy_pid:-unknown}"
        fi
    else
        "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
        ffmpeg_pid=$!
        log "FFmpeg PID: $ffmpeg_pid"
    fi

    while is_process_running "$ffmpeg_pid"; do
        sleep 1

        # ERROR_LOG_SIZE_LIMIT: Prevent unbounded error log growth
        truncate_error_log_if_needed "$ffmpeg_error_file"

        # HOT_RELOAD: pick up config edits while streaming (every 60s)
        reload_config_if_changed

        # PRIMARY_FALLBACK: check primary while on backup (every 5 min)
        if [[ -z "$stop_reason" ]] && check_and_fallback_to_primary; then
            stop_reason="primary_restore"
            log "PRIMARY_RESTORED: Restarting stream to use primary URL..."

            # Graceful stop, then force kill as a last resort
            kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
            for i in {1..10}; do
                if ! is_process_running "$ffmpeg_pid"; then
                    break
                fi
                sleep 1
            done
            if is_process_running "$ffmpeg_pid"; then
                log "PRIMARY_RESTORED: Force killing FFmpeg PID $ffmpeg_pid"
                kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
            fi
            break
        fi

        # YOUTUBE_REFRESH: check if current YouTube URL needs refresh while streaming
        if [[ -z "$stop_reason" ]] && check_youtube_urls_need_refresh; then
            stop_reason="youtube_refresh"
            log "YOUTUBE_REFRESH: Restarting stream with refreshed URL..."

            # Graceful stop, same as primary_restore
            kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
            for i in {1..10}; do
                if ! is_process_running "$ffmpeg_pid"; then
                    break
                fi
                sleep 1
            done
            if is_process_running "$ffmpeg_pid"; then
                log "YOUTUBE_REFRESH: Force killing FFmpeg PID $ffmpeg_pid"
                kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
            fi
            break
        fi

        # SEGMENT_STALE: check if output is stale and switch to backup URL
        if [[ -z "$stop_reason" ]] && check_segment_staleness; then
            stop_reason="segment_stale"
            log "SEGMENT_STALE: Output stale, switching to backup URL..."

            # Graceful stop
            kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
            for i in {1..10}; do
                if ! is_process_running "$ffmpeg_pid"; then
                    break
                fi
                sleep 1
            done
            if is_process_running "$ffmpeg_pid"; then
                log "SEGMENT_STALE: Force killing FFmpeg PID $ffmpeg_pid"
                kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
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
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        # Avoid tight loop if something is wrong with primary
        sleep 1
        continue
    fi

    # If we stopped FFmpeg to use a refreshed YouTube URL, restart immediately.
    if [[ "$stop_reason" == "youtube_refresh" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        # Brief pause before restart with new URL
        sleep 1
        continue
    fi

    # If we stopped FFmpeg due to stale output, switch to backup URL
    if [[ "$stop_reason" == "segment_stale" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        log "SEGMENT_STALE: Switching to next URL due to stale output"
        switch_to_next_url "segment_stale"
        # Reset segment check timer for new URL
        last_segment_check=$(date +%s)
        sleep 2
        continue
    fi

    # Capture and log FFmpeg errors
    # Truncate before reading to prevent massive log entries
    truncate_error_log_if_needed "$ffmpeg_error_file"
    youtube_stream_ended_detected=0
    if [[ -f "$ffmpeg_error_file" && -s "$ffmpeg_error_file" ]]; then
        ffmpeg_errors=$(cat "$ffmpeg_error_file")
        log_error "FFmpeg stderr: $ffmpeg_errors"

        # Check for HTTP errors in FFmpeg output
        if echo "$ffmpeg_errors" | grep -qE "HTTP error 4[0-9]{2}|Server returned 4[0-9]{2}"; then
            log "4XX_DETECTED: HTTP 4xx error detected in FFmpeg output"
            url_last_error_type[$current_url_index]="4xx"

            # YOUTUBE_STREAM_END: Check if this is a YouTube stream that ended
            # YouTube returns 403/404 when a live stream ends
            if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
                log "YOUTUBE_STREAM_END: YouTube URL failed with 4xx - likely stream ended"
                youtube_stream_ended_detected=1
            else
                cleanup_ffmpeg_error_file "$ffmpeg_error_file"
                switch_to_next_url "FFmpeg_4xx"
                continue
            fi
        fi

        # Check for YouTube-specific stream end indicators
        if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
            if echo "$ffmpeg_errors" | grep -qiE "live.+ended|stream.+unavailable|video.+unavailable|playback.+failed|this live event has ended"; then
                log "YOUTUBE_STREAM_END: Detected stream end message in FFmpeg output"
                youtube_stream_ended_detected=1
            fi
        fi
    fi
    cleanup_ffmpeg_error_file "$ffmpeg_error_file"

    log "FFmpeg exited with code $exit_code after ${duration}s"

    # ==========================================================================
    # YOUTUBE_STREAM_END: Handle YouTube stream ending gracefully
    # ==========================================================================
    # For 24/7 channels using general URLs, when a stream ends:
    # 1. First try to re-fetch the new stream via general URL
    # 2. Only failover to backup if re-fetch fails
    # This provides seamless viewing experience when streams restart
    # ==========================================================================

    if [[ $youtube_stream_ended_detected -eq 1 || ($exit_code -ne 0 && "${url_is_youtube[$current_url_index]}" == "1") ]]; then
        yt_type="${url_youtube_type[$current_url_index]}"
        general_url="${url_general_url[$current_url_index]}"

        log "YOUTUBE_STREAM_END: Handling stream end for URL index $current_url_index (type: $yt_type)"

        # If we have a general URL (either this IS a general URL, or it has an associated one)
        if [[ -n "$general_url" ]]; then
            log "YOUTUBE_STREAM_END: Attempting re-fetch via general URL: $general_url"

            if check_youtube_stream_ended_and_refetch "$current_url_index"; then
                log "YOUTUBE_STREAM_END: Successfully re-fetched new stream. Restarting FFmpeg..."
                # Reset retry counters since we got a new stream
                url_retry_counts[$current_url_index]=0
                # Brief pause to let the new stream stabilize
                sleep 3
                continue
            else
                log_error "YOUTUBE_STREAM_END: Re-fetch failed. Will try backup URLs..."
            fi
        fi

        # No general URL or re-fetch failed - proceed with normal failover
        url_last_error_type[$current_url_index]="youtube_stream_ended"
        switch_to_next_url "youtube_stream_ended"
        continue
    fi

    # Determine success/failure based on runtime
    if [[ $duration -gt 60 ]]; then
        # Stream was running successfully - reset all counters
        log "SUCCESS_RUN: Stream ran for ${duration}s. Resetting failure counters."
        total_cycles=0
        rapid_failure_count=0  # Reset rapid failure count on success
        reset_url_retries
        cycle_start_time=$(date +%s)

        # YOUTUBE: If this was a YouTube URL that ended after a successful run,
        # try to re-fetch before doing anything else
        if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
            general_url="${url_general_url[$current_url_index]}"
            if [[ -n "$general_url" ]]; then
                log "YOUTUBE: Stream ended normally after ${duration}s. Trying to fetch next live stream..."
                if check_youtube_stream_ended_and_refetch "$current_url_index"; then
                    log "YOUTUBE: Next stream fetched successfully. Continuing..."
                    sleep 2
                    continue
                fi
            fi
        fi

        # Small pause before retry (stream ended normally)
        sleep 2
    else
        # Short run = failure
        url_retry_counts[$current_url_index]=$((current_retries + 1))
        current_retries=${url_retry_counts[$current_url_index]}
        rapid_failure_count=$((rapid_failure_count + 1))  # Track rapid failures for error log suppression
        log "SHORT_RUN: Duration ${duration}s. URL $current_url_index retry count: $current_retries (rapid failures: $rapid_failure_count)"

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
