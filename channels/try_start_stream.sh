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
#     * Checks primary every 60 minutes when running on backup (default)
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
    # Use unique per-process fallback to avoid contention between instances
    DEVNULL="/tmp/albunyaan-dev-null-$$"
    : > "$DEVNULL" || true
    devnull_fallback=1
fi

# =============================================================================
# Cross-platform stat helpers (GNU/BSD compatibility)
# =============================================================================
# GNU stat uses -c, BSD stat uses -f
# =============================================================================

get_file_size() {
    local file="$1"
    stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0
}

get_file_mtime() {
    local file="$1"
    stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || echo 0
}

get_dir_size_bytes() {
    local dir="$1"
    if du -sb "$dir" >$DEVNULL 2>&1; then
        du -sb "$dir" 2>$DEVNULL | awk 'NR==1 {print $1}'
        return
    fi
    du -s -B1 "$dir" 2>$DEVNULL | awk 'NR==1 {print $1}'
}

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
PRIMARY_CHECK_INTERVAL="${PRIMARY_CHECK_INTERVAL:-3600}"  # Default: check primary every 60 minutes (3600 seconds)
PRIMARY_HLS_CHECK_DELAY="${PRIMARY_HLS_CHECK_DELAY:-8}"  # Seconds between HLS playlist samples
PRIMARY_HLS_MAX_WAIT="${PRIMARY_HLS_MAX_WAIT:-15}"       # Cap HLS sample wait to avoid long stalls
PRIMARY_RESTORE_CONFIRMATIONS="${PRIMARY_RESTORE_CONFIRMATIONS:-2}"  # Require N successful checks before switching back
PRIMARY_RESTORE_MEDIA_PROBE="${PRIMARY_RESTORE_MEDIA_PROBE:-1}"      # 1=probe media decode with ffprobe before restore
PRIMARY_RESTORE_MEDIA_PROBE_TIMEOUT="${PRIMARY_RESTORE_MEDIA_PROBE_TIMEOUT:-12}"  # Seconds
PRIMARY_HOTSWAP_ENABLE="${PRIMARY_HOTSWAP_ENABLE:-1}"    # 1=use graceful handoff on failback (no-cut)
PRIMARY_HOTSWAP_TIMEOUT="${PRIMARY_HOTSWAP_TIMEOUT:-180}"  # Timeout for graceful handoff script
PRIMARY_HOTSWAP_COOLDOWN="${PRIMARY_HOTSWAP_COOLDOWN:-600}"  # Min seconds between handoff attempts
PRIMARY_HOTSWAP_SCRIPT="${PRIMARY_HOTSWAP_SCRIPT:-$SCRIPT_DIR/graceful_restart.sh}"
URL_HOTSWAP_ENABLE="${URL_HOTSWAP_ENABLE:-1}"  # 1=use graceful handoff for failover URL switches
URL_HOTSWAP_TIMEOUT="${URL_HOTSWAP_TIMEOUT:-180}"  # Timeout for failover handoff
URL_HOTSWAP_COOLDOWN="${URL_HOTSWAP_COOLDOWN:-90}"  # Min seconds between failover handoff attempts
URL_HOTSWAP_SCRIPT="${URL_HOTSWAP_SCRIPT:-$PRIMARY_HOTSWAP_SCRIPT}"
SHORT_RUN_FAST_SWITCH_THRESHOLD="${SHORT_RUN_FAST_SWITCH_THRESHOLD:-30}"  # SHORT_RUNs >30s are "costly"
TRY_START_INITIAL_URL_INDEX="${TRY_START_INITIAL_URL_INDEX:-${INITIAL_URL_INDEX:-}}"  # Optional startup URL index override
TRY_START_ADOPT_LOCK="${TRY_START_ADOPT_LOCK:-0}"  # 1=adopt pre-existing lock (graceful handoff only)
CONFIG_CHECK_INTERVAL="${CONFIG_CHECK_INTERVAL:-60}"     # Default: check config file every 60 seconds
last_primary_check=0
primary_restore_confirm_count=0
last_primary_hotswap_attempt=0
last_url_hotswap_attempt=0
last_config_check=0
config_file_mtime=0

# =============================================================================
# NEW: Segment staleness detection for automatic backup URL failover
# =============================================================================
# When FFmpeg is running but not producing segments (source hung), detect this
# and proactively switch to backup URL instead of waiting for FFmpeg to die.
# =============================================================================
SEGMENT_STALE_THRESHOLD="${SEGMENT_STALE_THRESHOLD:-90}"      # Non-FIFO stale threshold (FIFO mode uses FEEDER_STALE_THRESHOLD instead)

# =============================================================================
# Always-FIFO architecture: route all sources through a persistent FIFO so
# feeder processes can be killed/replaced without touching the HLS encoder.
# =============================================================================
ALWAYS_FIFO="${ALWAYS_FIFO:-1}"                                # Route all sources through FIFO (0 to disable)
FEEDER_STALE_THRESHOLD="${FEEDER_STALE_THRESHOLD:-90}"         # Kill feeder after 90s stale output
FEEDER_MAX_RESTARTS="${FEEDER_MAX_RESTARTS:-10}"               # Per-URL feeder restarts before switching URL
FEEDER_MAX_RESTART_BACKOFF="${FEEDER_MAX_RESTART_BACKOFF:-10}" # Max backoff seconds between feeder restarts
SEGMENT_CHECK_INTERVAL="${SEGMENT_CHECK_INTERVAL:-5}"         # Check segment freshness every 5s
last_segment_check=0
stream_start_time=0
# Segment cleanup safeguards to prevent disk growth (running channels too)
SEGMENT_CLEANUP_INTERVAL="${SEGMENT_CLEANUP_INTERVAL:-300}"   # Seconds between cleanup passes
SEGMENT_MAX_AGE="${SEGMENT_MAX_AGE:-1800}"                    # Max segment age in seconds (default 30 min)
SEGMENT_MAX_COUNT="${SEGMENT_MAX_COUNT:-300}"                 # Hard cap on segment files per channel
last_segment_cleanup=0

# =============================================================================
# YouTube URL resolution settings
# =============================================================================
YOUTUBE_REFRESH_MARGIN="${YOUTUBE_REFRESH_MARGIN:-1800}"  # Refresh 30 min before expiry (1800s)
YOUTUBE_CHECK_INTERVAL="${YOUTUBE_CHECK_INTERVAL:-300}"   # Check expiry every 5 min (reduced from 60s to prevent rate limiting)
YTDLP_TIMEOUT="${YTDLP_TIMEOUT:-30}"                      # yt-dlp timeout in seconds
YTDLP_FORMAT="${YTDLP_FORMAT:-best}"                      # yt-dlp format selection
YTDLP_EXTRACTOR_ARGS="${YTDLP_EXTRACTOR_ARGS:-youtubepot-bgutilhttp:base_url=http://127.0.0.1:4416}"  # POT provider for bot bypass
YTDLP_COOKIES="${YTDLP_COOKIES:-}"                        # Optional: path to cookies.txt for YouTube auth
YTDLP_COOKIES_BROWSER="${YTDLP_COOKIES_BROWSER:-}"        # Optional: browser[:profile_path] for cookies
YTDLP_PROXY="${YTDLP_PROXY:-}"                            # Optional: proxy for yt-dlp/streamlink
YTDLP_ALLOW_DIRECT_FALLBACK="${YTDLP_ALLOW_DIRECT_FALLBACK:-1}"  # Retry without proxy if proxy resolve fails
TOR_ROTATE_FAILURES="${TOR_ROTATE_FAILURES:-3}"           # Rotate Tor after N consecutive YouTube failures
TOR_ROTATE_COOLDOWN="${TOR_ROTATE_COOLDOWN:-300}"         # Min seconds between Tor rotations (5 min)
TOR_FAILURE_FILE="${TOR_FAILURE_FILE:-/tmp/tor_youtube_failures_${UID}}"  # Track YouTube failures
TOR_ROTATE_TIMESTAMP="${TOR_ROTATE_TIMESTAMP:-/tmp/tor_last_rotate_${UID}}"  # Last rotation timestamp
YTDLP_THROTTLE_SECONDS="${YTDLP_THROTTLE_SECONDS:-20}"   # Min seconds between yt-dlp calls (global) - increased to prevent rate limiting
YTDLP_LOCK_FILE="${YTDLP_LOCK_FILE:-/tmp/ytdlp_global_${UID}.lock}"  # Global lock file for throttling
YTDLP_TIMESTAMP_FILE="${YTDLP_TIMESTAMP_FILE:-/tmp/ytdlp_last_call_${UID}}"  # Last call timestamp
YOUTUBE_STREAM_END_RETRY="${YOUTUBE_STREAM_END_RETRY:-2}" # Retries when stream ends (reduced from 5 to prevent rate limiting)
last_youtube_check=0
YOUTUBE_BROWSER_RESOLVER="${YOUTUBE_BROWSER_RESOLVER:-}"   # Optional: http://127.0.0.1:8088 YouTube browser proxy
YOUTUBE_BROWSER_RESOLVER_TIMEOUT="${YOUTUBE_BROWSER_RESOLVER_TIMEOUT:-6}"
YOUTUBE_BROWSER_RESOLVER_COOLDOWN="${YOUTUBE_BROWSER_RESOLVER_COOLDOWN:-300}"
last_browser_resolver_failure=0

# Seenshow token resolver integration
SEENSHOW_RESOLVER_URL="${SEENSHOW_RESOLVER_URL:-http://127.0.0.1:8090}"
SEENSHOW_RESOLVER_TIMEOUT="${SEENSHOW_RESOLVER_TIMEOUT:-8}"
SEENSHOW_TOKEN_MARGIN="${SEENSHOW_TOKEN_MARGIN:-21600}"   # Refresh when token has <=6h left
SEENSHOW_RESOLVE_RETRIES="${SEENSHOW_RESOLVE_RETRIES:-2}"
SEENSHOW_SLOT_TOUCH_INTERVAL="${SEENSHOW_SLOT_TOUCH_INTERVAL:-60}"  # Keep semaphore slot alive while streaming
SEENSHOW_ENABLE_RESOLVER="${SEENSHOW_ENABLE_RESOLVER:-1}"
seenshow_slot_held=0
seenshow_last_touch=0

# Aloula/KwikMotion resolver (aloula.sba.sa public API)
ALOULA_API_BASE="${ALOULA_API_BASE:-https://aloula.faulio.com/api/v1.1}"
ALOULA_TOKEN_MARGIN="${ALOULA_TOKEN_MARGIN:-3600}"  # Refresh when token has <=1h left (tokens last ~24h)
ALOULA_RESOLVE_TIMEOUT="${ALOULA_RESOLVE_TIMEOUT:-10}"

# Elahmad.com resolver (encrypted stream API)
ELAHMAD_BASE="${ELAHMAD_BASE:-https://www.elahmad.com}"
ELAHMAD_RESOLVE_TIMEOUT="${ELAHMAD_RESOLVE_TIMEOUT:-15}"
ELAHMAD_REFRESH_INTERVAL="${ELAHMAD_REFRESH_INTERVAL:-14400}"  # Re-resolve every 4 hours

# =============================================================================
# NEW: Per-channel rate limit protection
# =============================================================================
# Prevents a single channel from making too many yt-dlp calls in succession
# =============================================================================
YTDLP_CHANNEL_COOLDOWN="${YTDLP_CHANNEL_COOLDOWN:-300}"   # Min 5 minutes between yt-dlp calls per channel
YTDLP_CHANNEL_TIMESTAMP_DIR="${YTDLP_CHANNEL_TIMESTAMP_DIR:-/tmp/ytdlp_channel_${UID}}"  # Per-channel timestamp directory
YTDLP_FAILURE_BACKOFF_BASE="${YTDLP_FAILURE_BACKOFF_BASE:-30}"  # Base backoff on failure (30s)
YTDLP_FAILURE_BACKOFF_MAX="${YTDLP_FAILURE_BACKOFF_MAX:-300}"   # Max backoff on failure (5 min)
YTDLP_STARTUP_STAGGER_MAX="${YTDLP_STARTUP_STAGGER_MAX:-30}"    # Max random delay at startup (seconds)
ytdlp_startup_stagger_done=0
ytdlp_cookies_browser_checked=0
ytdlp_cookies_browser_args=()
torsocks_warned=0
tor_socks_unreachable_warned=0

# YouTube state arrays (initialized after URL parsing)
# url_is_youtube[i]     - 1 if YouTube URL, 0 otherwise
# url_youtube_type[i]   - "general" (channel/live) or "specific" (video ID) or ""
# url_original[i]       - Original YouTube URL (for re-resolution)
# url_general_url[i]    - Associated general URL (for specific URLs that have a general fallback)
# url_expire_time[i]    - Unix timestamp when resolved URL expires

# User-Agent string (used by both ffmpeg and curl preflight for consistency)
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
# kwikmotion CDN blocks browser/tool UAs over plain HTTP; use curl's default UA
KWIKMOTION_USER_AGENT="curl/7.81.0"

# Returns the appropriate User-Agent for a URL — kwikmotion HTTP needs a
# curl-like UA because their CDN blocks browser and tool UAs over plain HTTP.
effective_user_agent() {
    local url="$1"
    if [[ "$url" =~ ^http://[^/]*kwikmotion\.com/ ]]; then
        echo "$KWIKMOTION_USER_AGENT"
    else
        echo "$USER_AGENT"
    fi
}

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
            echo "  0 - Stream copy (default) — no processing, remux only"
            echo "  4 - GPU: CUDA decode + scale to 1080p + NVENC encode (3.5Mbps)"
            echo "  9 - GPU tolerant: Software decode + GPU scale + NVENC (for corrupted/RTMP)"
            echo "      Falls back to libx264 CPU pipeline when GPU is unavailable"
            echo " 12 - GPU stretch: CUDA decode + stretch-fill 1080p + NVENC (6-8Mbps VBR)"
            echo ""
            echo "Legacy aliases (mapped to above):"
            echo "  2,7,8 → 0 (copy)   3 → 4 (gpu)   5,6,10,11 → 9 (tolerant)   13 → 12 (stretch)"
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
            echo "  - Auto-fallback to primary URL when it recovers (default: every 60 min)"
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

# Backwards-compatibility: -k is accepted but currently unused by this runner.
: "${key:=}"

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

# Keep semaphore accounting tied to canonical live channel identity, even for
# temporary handoff runners (e.g., .graceful_<channel_id>).
SEENSHOW_SLOT_CHANNEL_ID="${SEENSHOW_SLOT_CHANNEL_ID:-$channel_id}"
if [[ ! "$SEENSHOW_SLOT_CHANNEL_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "WARN: Invalid SEENSHOW_SLOT_CHANNEL_ID '$SEENSHOW_SLOT_CHANNEL_ID'; using '$channel_id'" >&2
    SEENSHOW_SLOT_CHANNEL_ID="$channel_id"
fi

# =============================================================================
# Setup logging with filesystem-safe channel_id
# =============================================================================

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
last_ffmpeg_pid=""
proxy_pid=""
stream_fifo=""

# Always-FIFO feeder state
feeder_pid=""
feeder_is_slate=0
feeder_restart_count=0
feeder_last_restart_time=0
fifo_write_fd=""

# Log size limits to prevent disk exhaustion
LOG_FILE_MAX_MB="${LOG_FILE_MAX_MB:-50}"
LOG_FILE_MAX_BYTES=$((LOG_FILE_MAX_MB * 1024 * 1024))
LOG_FILE_TRIM_MB="${LOG_FILE_TRIM_MB:-5}"
LOG_FILE_TRIM_BYTES=$((LOG_FILE_TRIM_MB * 1024 * 1024))
LOG_DIR_MAX_MB="${LOG_DIR_MAX_MB:-256}"
LOG_DIR_MAX_BYTES=$((LOG_DIR_MAX_MB * 1024 * 1024))
LOG_GC_INTERVAL="${LOG_GC_INTERVAL:-300}"
last_log_gc=0

# Log rotation (LOG_FILE_MAX_MB threshold, keep last 5)
rotate_logs() {
    local file="$1"
    if [[ "$LOG_FILE_MAX_BYTES" -gt 0 && -f "$file" && $(get_file_size "$file") -gt "$LOG_FILE_MAX_BYTES" ]]; then
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

log_dir_prune() {
    local dir_size="$1"
    local target="$LOG_DIR_MAX_BYTES"
    local old_file

    while [[ "$dir_size" -gt "$target" ]]; do
        old_file=$(find "$logfile_dir" -type f ! -path "$logfile" ! -path "$errorfile" -printf '%T@ %p\n' 2>$DEVNULL \
            | sort -n | head -1 | cut -d' ' -f2-)
        if [[ -z "$old_file" ]]; then
            break
        fi
        local old_size
        old_size=$(get_file_size "$old_file")
        rm -f "$old_file" 2>$DEVNULL || true
        if [[ "$old_size" =~ ^[0-9]+$ ]]; then
            dir_size=$((dir_size - old_size))
        else
            dir_size=$(get_dir_size_bytes "$logfile_dir")
        fi
    done

    if [[ "$dir_size" -gt "$target" && "$LOG_FILE_TRIM_BYTES" -gt 0 ]]; then
        if [[ -f "$logfile" ]]; then
            tail -c "$LOG_FILE_TRIM_BYTES" "$logfile" > "${logfile}.tmp" 2>$DEVNULL && mv "${logfile}.tmp" "$logfile"
        fi
        if [[ -f "$errorfile" ]]; then
            tail -c "$LOG_FILE_TRIM_BYTES" "$errorfile" > "${errorfile}.tmp" 2>$DEVNULL && mv "${errorfile}.tmp" "$errorfile"
        fi
    fi
}

log_maintenance() {
    local now
    now=$(date +%s)
    if [[ $((now - last_log_gc)) -lt $LOG_GC_INTERVAL ]]; then
        return
    fi
    last_log_gc=$now

    rotate_logs "$logfile"
    rotate_logs "$errorfile"

    if [[ "$LOG_DIR_MAX_BYTES" -le 0 ]]; then
        return
    fi

    local dir_size
    dir_size=$(get_dir_size_bytes "$logfile_dir")
    if [[ -z "$dir_size" || "$dir_size" -le "$LOG_DIR_MAX_BYTES" ]]; then
        return
    fi
    log_dir_prune "$dir_size"
}

# Timestamp function for logging
log() {
    log_maintenance
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$logfile"
}

log_error() {
    log_maintenance
    local msg
    msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$errorfile"
    echo "$msg" >> "$logfile"
}

log_console() {
    local msg
    msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    log_maintenance
    echo "$msg" >> "$logfile"
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
# Scale 9 (and aliases 5,6,10,11) falls back to libx264 when GPU is unavailable.
# Check availability at startup so we fail fast instead of mid-stream.
case "$scale" in
    9|5|6|10|11)
        if ! nvidia-smi >$DEVNULL 2>&1; then
            require_encoder "libx264"
        fi
        ;;
esac

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

    # Need proxy if URL is HTTPS and:
    # 1) ffmpeg lacks native HTTPS support, OR
    # 2) source is known to require browser-like/proxied fetch semantics.
    [[ "$scheme" == "https" ]] || return 1
    if is_seenshow_url "$url"; then
        return 0
    fi
    [[ "$FFMPEG_HAS_HTTPS" -eq 0 ]]
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
    file_size=$(get_file_size "$error_file")
    [[ "$file_size" -eq 0 ]] && return 0

    if [[ "$file_size" -gt "$MAX_ERROR_LOG_SIZE" ]]; then
        log "ERROR_LOG_TRUNCATE: $error_file is ${file_size} bytes, truncating to last ${ERROR_LOG_KEEP_SIZE} bytes"
        # Use flock if available to prevent race conditions with FFmpeg writes
        if command -v flock >$DEVNULL 2>&1; then
            (
                flock -x 200 || exit 1
                tail -c "$ERROR_LOG_KEEP_SIZE" "$error_file" > "${error_file}.tmp" 2>$DEVNULL
                mv "${error_file}.tmp" "$error_file" 2>$DEVNULL || rm -f "${error_file}.tmp"
            ) 200>"${error_file}.lock"
            local lock_exit=$?
            rm -f "${error_file}.lock" 2>$DEVNULL
            [[ $lock_exit -ne 0 ]] && return 1
        else
            # Fallback: atomic copy-replace (best effort without locking)
            tail -c "$ERROR_LOG_KEEP_SIZE" "$error_file" > "${error_file}.tmp" 2>$DEVNULL
            mv "${error_file}.tmp" "$error_file" 2>$DEVNULL || rm -f "${error_file}.tmp"
        fi
    fi
}

cleanup_ffmpeg_error_file() {
    local error_file="$1"
    [[ -z "$error_file" || "$error_file" == "$DEVNULL" ]] && return 0
    rm -f "$error_file" 2>$DEVNULL || true
}

# =============================================================================
# SEGMENT CLEANUP (RUNNING CHANNELS)
# =============================================================================
# Defensive cleanup in case FFmpeg's delete_segments isn't applied or old files
# linger across restarts. Keeps recent segments only.
# =============================================================================

prune_old_segments() {
    local force="$1"
    local now
    now=$(date +%s)
    if [[ "$force" != "force" ]]; then
        local elapsed=$((now - last_segment_cleanup))
        if [[ "$elapsed" -lt "$SEGMENT_CLEANUP_INTERVAL" ]]; then
            return
        fi
    fi
    last_segment_cleanup=$now

    local output_dir
    output_dir=$(dirname "$destination")
    [[ -d "$output_dir" ]] || return

    local deleted=0
    local age_minutes=$((SEGMENT_MAX_AGE / 60))

    if [[ "$SEGMENT_MAX_AGE" -gt 0 && "$age_minutes" -gt 0 ]]; then
        while IFS= read -r old_file; do
            rm -f "$old_file" 2>$DEVNULL && deleted=$((deleted + 1))
        done < <(find "$output_dir" -maxdepth 1 -name "*.ts" -type f -mmin "+$age_minutes" 2>$DEVNULL)
    fi

    if [[ "$SEGMENT_MAX_COUNT" -gt 0 ]]; then
        local total
        total=$(find "$output_dir" -maxdepth 1 -name "*.ts" -type f 2>$DEVNULL | wc -l)
        if [[ "$total" -gt "$SEGMENT_MAX_COUNT" ]]; then
            local to_delete=$((total - SEGMENT_MAX_COUNT))
            while IFS= read -r old_file; do
                rm -f "$old_file" 2>$DEVNULL && deleted=$((deleted + 1))
            done < <(
                find "$output_dir" -maxdepth 1 -name "*.ts" -type f -printf '%T@ %p\n' 2>$DEVNULL \
                    | sort -n | head -n "$to_delete" | cut -d' ' -f2-
            )
        fi
    fi

    if [[ "$deleted" -gt 0 ]]; then
        log "SEGMENT_CLEANUP: Removed $deleted old segments from $output_dir"
    fi
}

# Disk space guard — prevents silent FFmpeg failures when partition fills up.
# Returns 0 if OK, 1 if critical (should pause streaming).
DISK_CHECK_INTERVAL="${DISK_CHECK_INTERVAL:-60}"  # Check every 60s
last_disk_check=0
check_disk_space() {
    local now
    now=$(date +%s)
    local elapsed=$((now - last_disk_check))
    if [[ "$elapsed" -lt "$DISK_CHECK_INTERVAL" ]]; then
        return 0
    fi
    last_disk_check=$now

    local output_dir
    output_dir=$(dirname "$destination")
    local usage_pct
    usage_pct=$(df --output=pcent "$output_dir" 2>$DEVNULL | tail -1 | tr -d ' %')
    [[ -z "$usage_pct" ]] && return 0

    if [[ "$usage_pct" -ge 95 ]]; then
        log "DISK_GUARD: CRITICAL — ${usage_pct}% disk usage. Force-pruning all channels."
        # Emergency: prune ALL HLS directories, not just ours
        # Constrain to the expected HLS base to prevent accidental deletion elsewhere
        local hls_base="/var/www/html/stream/hls"
        [[ -d "$hls_base" ]] || hls_base=$(dirname "$output_dir")
        find "$hls_base" -name "*.ts" -type f -mmin +10 -delete 2>$DEVNULL
        return 1
    elif [[ "$usage_pct" -ge 90 ]]; then
        log "DISK_GUARD: WARNING — ${usage_pct}% disk usage. Aggressive segment pruning."
        prune_old_segments force
    fi
    return 0
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
preserve_runtime_markers=0

# Early no-op stubs for functions referenced in cleanup()/trap paths.
# Full implementations are defined later, after all dependencies are available.
# This prevents "command not found" when cleanup fires before the full defs load
# (e.g., duplicate-lock early exit).
slate_ffmpeg_pid=""
stop_slate_stream() { :; }

mark_successful_handoff_exit() {
    local reason="${1:-handoff}"
    preserve_runtime_markers=1
    log "HANDOFF_SUCCESS: Preserving pid/lock markers for replacement runner ($reason)"
}

# Cleanup function
cleanup() {
    if [[ $cleanup_done -eq 1 ]]; then
        return
    fi
    cleanup_done=1

    # Stop slate placeholder if running
    stop_slate_stream

    # Kill feeder process first (stop writes to FIFO)
    kill_feeder 2>/dev/null || true

    # Then close held FIFO write FD (allows encoder to get EOF)
    if [[ -n "$fifo_write_fd" ]]; then
        exec {fifo_write_fd}>&- 2>/dev/null || true
        fifo_write_fd=""
    fi

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
        # Stop any child proxy process attached to this FFmpeg process.
        pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true

        if ! wait_for_pid_exit "$ffmpeg_pid" 10; then
            log "[$channel_id] Cleanup: force killing FFmpeg PID $ffmpeg_pid"
            kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
            pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
            wait_for_pid_exit "$ffmpeg_pid" 3 || true
        fi

        # Best-effort reap, guarded to avoid indefinite waits.
        if ! is_process_running "$ffmpeg_pid"; then
            wait "$ffmpeg_pid" 2>$DEVNULL || true
        fi
    fi

    # Best-effort release of any active Seenshow semaphore slot.
    if [[ $seenshow_slot_held -eq 1 && "$SEENSHOW_ENABLE_RESOLVER" == "1" && -n "$SEENSHOW_RESOLVER_URL" ]]; then
        if command -v curl >$DEVNULL 2>&1; then
            curl -A "$USER_AGENT" -sS --max-time "$SEENSHOW_RESOLVER_TIMEOUT" -X POST \
                -H "Accept: application/json" "${SEENSHOW_RESOLVER_URL%/}/release/${SEENSHOW_SLOT_CHANNEL_ID}" >$DEVNULL 2>$DEVNULL || true
        fi
        seenshow_slot_held=0
    fi

    if [[ $preserve_runtime_markers -eq 1 ]]; then
        log "[$channel_id] Cleanup: preserving pid/lock markers after successful handoff"
    else
        rm -f "$pidfile"
        rmdir "$lockdir" 2>$DEVNULL
    fi
    # Cleanup any error file for this process
    rm -f "/tmp/ffmpeg_error_${channel_id}_$$.log" 2>$DEVNULL
    # Cleanup stream FIFO if it exists
    if [[ -n "$stream_fifo" ]]; then
        rm -f "$stream_fifo" 2>$DEVNULL
    fi
    # Cleanup DEVNULL fallback file if used
    if [[ $devnull_fallback -eq 1 ]]; then
        rm -f "$DEVNULL" 2>/dev/null
    fi
    log "[$channel_id] Cleanup completed"
}

on_term() {
    cleanup
    exit 0
}

trap on_term TERM INT
trap cleanup EXIT

# Acquire lock (atomic using mkdir), unless handoff explicitly requests lock adoption.
lock_adopted=0
if [[ "$TRY_START_ADOPT_LOCK" == "1" && -d "$lockdir" ]]; then
    lock_adopted=1
    log "LOCK: Adopting existing lock directory for graceful handoff"
fi

# is_stale_owner checks if a PID actually belongs to a try_start_stream process
# for THIS channel.  After a reboot the PID may have been recycled to an unrelated
# process, so a plain kill -0 check is not enough.
is_stale_owner() {
    local pid="$1"
    # PID not running at all → stale
    kill -0 "$pid" 2>$DEVNULL || return 0
    # PID is running — verify it is actually try_start_stream for this channel.
    # /proc/<pid>/cmdline is NUL-delimited; tr converts to spaces for grep -F (fixed-string).
    local cmd
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>$DEVNULL) || return 0
    if echo "$cmd" | grep -qF "try_start_stream" && echo "$cmd" | grep -qF "$channel_id"; then
        return 1  # legitimate owner
    fi
    return 0  # PID recycled to something else → stale
}

if [[ $lock_adopted -eq 0 ]]; then
    if ! mkdir "$lockdir" 2>$DEVNULL; then
        # Lock exists — check if the owner is still alive and legitimate.
        # Handles: SIGKILL leaving stale locks, reboot with ext4 /tmp (PID recycling),
        # and crash between mkdir and pidfile write.
        stale_lock=0
        if [[ -f "$pidfile" ]]; then
            stale_pid=$(cat "$pidfile" 2>$DEVNULL)
            if [[ -n "$stale_pid" ]] && is_stale_owner "$stale_pid"; then
                log_console "[$channel_id] Stale lock detected (PID $stale_pid is dead or recycled). Reclaiming."
                stale_lock=1
            else
                log_console "[$channel_id] Another instance is already running (PID ${stale_pid:-unknown}). Exiting."
                exit 0
            fi
        else
            # No pidfile but lock exists — process crashed between mkdir and pidfile write.
            # Check if any try_start_stream for this channel is actually running.
            # Escape channel_id for use in regex (pgrep -f uses extended regex).
            local escaped_cid
            escaped_cid=$(printf '%s' "$channel_id" | sed 's/[][\\.^$*+?{}|()]/\\&/g')
            if ! pgrep -f "try_start_stream.*${escaped_cid}" 2>$DEVNULL | grep -v "^$$\$" | grep -q .; then
                log_console "[$channel_id] Stale lock detected (no pidfile, no matching process). Reclaiming."
                stale_lock=1
            else
                log_console "[$channel_id] Another instance is already running (lock exists, process found). Exiting."
                exit 0
            fi
        fi
        if [[ $stale_lock -eq 1 ]]; then
            rmdir "$lockdir" 2>$DEVNULL
            rm -f "$pidfile" 2>$DEVNULL
            if ! mkdir "$lockdir" 2>$DEVNULL; then
                log_console "[$channel_id] Lock reclaim race lost. Another instance started. Exiting."
                exit 0
            fi
        fi
    fi
fi

# Write PID file
echo $$ > "$pidfile"

# Create destination directory if needed
mkdir -p "$(dirname "$destination")"
prune_old_segments force

# Log identity for debugging
log "=== Stream Manager Started ==="
log "channel_id (filesystem): $channel_id"
log "channel_name (display): $channel_name"
if [[ "$SEENSHOW_SLOT_CHANNEL_ID" != "$channel_id" ]]; then
    log "SEENSHOW slot identity override: $SEENSHOW_SLOT_CHANNEL_ID"
fi
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
declare -a url_is_seenshow
declare -a url_seenshow_hls_path
declare -a url_seenshow_expiry
declare -a url_elahmad_resolve_time

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

requested_start_url_index=0
if [[ -n "$TRY_START_INITIAL_URL_INDEX" ]]; then
    if [[ "$TRY_START_INITIAL_URL_INDEX" =~ ^[0-9]+$ && "$TRY_START_INITIAL_URL_INDEX" -lt "$url_count" ]]; then
        requested_start_url_index="$TRY_START_INITIAL_URL_INDEX"
    else
        log_error "START_INDEX: Ignoring invalid TRY_START_INITIAL_URL_INDEX='$TRY_START_INITIAL_URL_INDEX' (url_count=$url_count)"
    fi
fi

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
    config_file_mtime=$(get_file_mtime "$config_file")
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

# =============================================================================
# Global yt-dlp throttle to prevent YouTube rate limiting
# =============================================================================
# Uses flock for cross-process synchronization and a timestamp file to enforce
# minimum delay between yt-dlp calls across all channel scripts.
# =============================================================================

ytdlp_throttle_acquire() {
    local now last_call wait_time

    # Create lock file if it doesn't exist
    touch "$YTDLP_LOCK_FILE" 2>$DEVNULL

    # Acquire exclusive lock (wait up to 60 seconds)
    exec 200>"$YTDLP_LOCK_FILE"
    if ! flock -w 60 200; then
        exec 200>&- 2>$DEVNULL || true
        log_error "YTDLP_THROTTLE: Failed to acquire lock after 60s"
        return 1
    fi

    # Check last call timestamp and wait if needed
    now=$(date +%s)
    if [[ -f "$YTDLP_TIMESTAMP_FILE" ]]; then
        last_call=$(cat "$YTDLP_TIMESTAMP_FILE" 2>$DEVNULL || echo "0")
        if [[ "$last_call" =~ ^[0-9]+$ ]]; then
            wait_time=$((YTDLP_THROTTLE_SECONDS - (now - last_call)))
            if [[ $wait_time -gt 0 ]]; then
                log "YTDLP_THROTTLE: Waiting ${wait_time}s before yt-dlp call (rate limit protection)"
                sleep "$wait_time"
            fi
        fi
    fi

    # Update timestamp
    date +%s > "$YTDLP_TIMESTAMP_FILE" 2>$DEVNULL

    # Lock remains held - caller must call ytdlp_throttle_release
    return 0
}

ytdlp_throttle_release() {
    # Release the lock by closing fd 200
    exec 200>&- 2>$DEVNULL || true
}

# =============================================================================
# Per-channel yt-dlp rate limiting
# =============================================================================
# Prevents individual channels from making too many yt-dlp calls
# Each channel has its own cooldown timer stored in a file
# =============================================================================

# Ensure per-channel timestamp directory exists and is writable
mkdir -p "$YTDLP_CHANNEL_TIMESTAMP_DIR" 2>$DEVNULL
if [[ ! -w "$YTDLP_CHANNEL_TIMESTAMP_DIR" ]]; then
    YTDLP_CHANNEL_TIMESTAMP_DIR="/tmp/ytdlp_channel_${UID}_$$"
    mkdir -p "$YTDLP_CHANNEL_TIMESTAMP_DIR" 2>$DEVNULL || true
fi

# Track per-channel failure count for exponential backoff
declare -A channel_failure_count

ytdlp_channel_can_call() {
    # Check if this channel is allowed to make a yt-dlp call (cooldown check)
    local now
    now=$(date +%s)
    local ts_file="${YTDLP_CHANNEL_TIMESTAMP_DIR}/${channel_id}"

    if [[ -f "$ts_file" ]]; then
        local last_call
        last_call=$(cat "$ts_file" 2>$DEVNULL || echo 0)
        if [[ "$last_call" =~ ^[0-9]+$ ]]; then
            local elapsed=$((now - last_call))
            if [[ $elapsed -lt $YTDLP_CHANNEL_COOLDOWN ]]; then
                local remaining=$((YTDLP_CHANNEL_COOLDOWN - elapsed))
                log "YTDLP_CHANNEL: Channel $channel_id on cooldown (${remaining}s remaining). Skipping yt-dlp call."
                return 1
            fi
        fi
    fi
    return 0
}

ytdlp_channel_record_call() {
    # Record that this channel made a yt-dlp call
    local ts_file="${YTDLP_CHANNEL_TIMESTAMP_DIR}/${channel_id}"
    date +%s > "$ts_file" 2>$DEVNULL
}

ytdlp_get_failure_backoff() {
    # Calculate exponential backoff based on consecutive failures
    local failures=${channel_failure_count[$channel_id]:-0}
    if [[ $failures -eq 0 ]]; then
        echo 0
        return
    fi

    # Exponential backoff: base * 2^(failures-1), capped at max
    local backoff=$YTDLP_FAILURE_BACKOFF_BASE
    local i
    for ((i=1; i<failures && i<5; i++)); do
        backoff=$((backoff * 2))
    done

    if [[ $backoff -gt $YTDLP_FAILURE_BACKOFF_MAX ]]; then
        backoff=$YTDLP_FAILURE_BACKOFF_MAX
    fi

    echo "$backoff"
}

ytdlp_record_failure() {
    # Record a failure and apply backoff
    local current=${channel_failure_count[$channel_id]:-0}
    channel_failure_count[$channel_id]=$((current + 1))

    local backoff
    backoff=$(ytdlp_get_failure_backoff)
    if [[ $backoff -gt 0 ]]; then
        log "YTDLP_BACKOFF: Channel $channel_id failure #${channel_failure_count[$channel_id]}, backing off ${backoff}s"
        sleep "$backoff"
    fi
}

ytdlp_reset_failures() {
    # Reset failure count on success
    channel_failure_count[$channel_id]=0
}

ytdlp_startup_stagger() {
    # Add random delay at startup to prevent all channels hitting YouTube at once
    if [[ $ytdlp_startup_stagger_done -eq 1 ]]; then
        return
    fi
    ytdlp_startup_stagger_done=1
    if [[ $YTDLP_STARTUP_STAGGER_MAX -gt 0 ]]; then
        local delay=$((RANDOM % YTDLP_STARTUP_STAGGER_MAX))
        if [[ $delay -gt 0 ]]; then
            log "YTDLP_STAGGER: Startup delay ${delay}s to prevent rate limiting"
            sleep "$delay"
        fi
    fi
}

# Resolve cookies-from-browser args once to avoid repeated failures.
init_ytdlp_cookies_browser_args() {
    if [[ $ytdlp_cookies_browser_checked -eq 1 ]]; then
        return
    fi
    ytdlp_cookies_browser_checked=1

    if [[ -z "$YTDLP_COOKIES_BROWSER" ]]; then
        return
    fi

    if [[ "$YTDLP_COOKIES_BROWSER" == *:* ]]; then
        local profile_path="${YTDLP_COOKIES_BROWSER#*:}"
        if [[ -n "$profile_path" && ! -e "$profile_path" ]]; then
            log_error "YOUTUBE: cookies-from-browser profile not found: $profile_path; skipping"
            return
        fi
    fi

    ytdlp_cookies_browser_args=(--cookies-from-browser "$YTDLP_COOKIES_BROWSER")
}

# =============================================================================
# Proxy helpers for yt-dlp/streamlink
# =============================================================================
proxy_is_local_tor() {
    local proxy="$1"
    if [[ "$proxy" =~ ^socks5h?://([^@/]+@)?(127\.0\.0\.1|localhost):([0-9]+)(/|$) ]]; then
        local port="${BASH_REMATCH[3]}"
        [[ "$port" == "9050" || "$port" == "9150" ]]
        return $?
    fi
    return 1
}

tor_socks_reachable() {
    local proxy="$1"
    local host port
    if [[ "$proxy" =~ ^socks5h?://([^@/]+@)?(127\.0\.0\.1|localhost):([0-9]+)(/|$) ]]; then
        host="${BASH_REMATCH[2]}"
        port="${BASH_REMATCH[3]}"
    else
        return 1
    fi

    if ! command -v timeout >$DEVNULL 2>&1; then
        return 0
    fi

    timeout 2 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>$DEVNULL
}

should_use_torsocks() {
    local proxy="$1"
    proxy_is_local_tor "$proxy" || return 1
    command -v torsocks >$DEVNULL 2>&1 || return 1
    return 0
}

is_seenshow_url() {
    local url="$1"
    [[ "$url" =~ ^https?://live\.seenshow\.com(/|$) ]]
}

url_decode() {
    local encoded="$1"
    encoded="${encoded//+/ }"
    printf '%b' "${encoded//%/\\x}" 2>$DEVNULL || printf '%s' "$1"
}

extract_seenshow_hls_path() {
    local url="$1"
    # Accept both:
    #   /hls/live/<id>/<name>/master.m3u8?hdntl=...
    #   /hls/live/<id>/<name>/hdntl=.../3.m3u8
    if [[ "$url" =~ ^https?://live\.seenshow\.com/hls/live/([^/?#]+/[^/?#]+)/(hdnt[ls]=[^/]+/)?[^/?#]+\.m3u8([?#].*)?$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

extract_seenshow_expiry() {
    local url="$1"

    if [[ "$url" =~ [\?\&]exp=([0-9]{9,}) ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    if [[ "$url" =~ [\?\&]hdntl=([^&]+) ]]; then
        local hdntl_raw="${BASH_REMATCH[1]}"
        local hdntl_decoded
        hdntl_decoded=$(url_decode "$hdntl_raw")
        if [[ "$hdntl_decoded" =~ (^|~)exp=([0-9]{9,}) ]]; then
            echo "${BASH_REMATCH[2]}"
            return 0
        fi
    fi

    if [[ "$url" =~ /hdntl=([^/]+) ]]; then
        local hdntl_path_raw="${BASH_REMATCH[1]}"
        local hdntl_path_decoded
        hdntl_path_decoded=$(url_decode "$hdntl_path_raw")
        if [[ "$hdntl_path_decoded" =~ (^|~)exp=([0-9]{9,}) ]]; then
            echo "${BASH_REMATCH[2]}"
            return 0
        fi
    fi

    if [[ "$url" =~ [\?\&]hdnts=([^&]+) ]]; then
        local hdnts_raw="${BASH_REMATCH[1]}"
        local hdnts_decoded
        hdnts_decoded=$(url_decode "$hdnts_raw")
        if [[ "$hdnts_decoded" =~ (^|~)exp=([0-9]{9,}) ]]; then
            echo "${BASH_REMATCH[2]}"
            return 0
        fi
    fi

    local decoded_url
    decoded_url=$(url_decode "$url")
    if [[ "$decoded_url" =~ (^|[\?\&~])exp=([0-9]{9,}) ]]; then
        echo "${BASH_REMATCH[2]}"
        return 0
    fi

    if [[ "$decoded_url" =~ exp=([0-9]{9,}) ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    echo "0"
    return 1
}

init_url_seenshow_metadata() {
    local index="$1"
    local url="$2"

    if is_seenshow_url "$url"; then
        url_is_seenshow[$index]=1
        url_seenshow_hls_path[$index]=$(extract_seenshow_hls_path "$url" || true)
        local expiry=0
        expiry=$(extract_seenshow_expiry "$url" || echo 0)
        [[ "$expiry" =~ ^[0-9]+$ ]] || expiry=0
        url_seenshow_expiry[$index]="$expiry"
    else
        url_is_seenshow[$index]=0
        url_seenshow_hls_path[$index]=""
        url_seenshow_expiry[$index]=0
    fi
}

seenshow_resolver_enabled() {
    [[ "$SEENSHOW_ENABLE_RESOLVER" == "1" ]] || return 1
    [[ -n "$SEENSHOW_RESOLVER_URL" ]] || return 1
    command -v curl >$DEVNULL 2>&1 || return 1
    return 0
}

seenshow_call_resolver() {
    local method="$1"
    local route="$2"
    local endpoint="${SEENSHOW_RESOLVER_URL%/}${route}"
    curl -A "$USER_AGENT" -sS --max-time "$SEENSHOW_RESOLVER_TIMEOUT" -X "$method" \
        -H "Accept: application/json" "$endpoint" 2>$DEVNULL
}

seenshow_release_slot() {
    if [[ $seenshow_slot_held -eq 0 ]]; then
        return 0
    fi

    if seenshow_resolver_enabled; then
        seenshow_call_resolver "POST" "/release/${SEENSHOW_SLOT_CHANNEL_ID}" >$DEVNULL || true
    fi
    seenshow_slot_held=0
    seenshow_last_touch=0
    log "SEENSHOW: Released resolver slot for ${SEENSHOW_SLOT_CHANNEL_ID} (runner: $channel_id)"
    return 0
}

seenshow_acquire_slot_if_needed() {
    local index="$1"
    # Enforce resolver slot accounting for every active Seenshow stream, including
    # Seenshow-as-primary channels. This keeps account-level concurrency bounded.
    if [[ $seenshow_slot_held -eq 1 ]]; then
        return 0
    fi
    if ! seenshow_resolver_enabled; then
        log_error "SEENSHOW: Resolver unavailable; cannot acquire slot for URL index $index"
        return 1
    fi

    local response
    response=$(seenshow_call_resolver "POST" "/acquire/${SEENSHOW_SLOT_CHANNEL_ID}") || {
        log_error "SEENSHOW: Acquire request failed for ${SEENSHOW_SLOT_CHANNEL_ID}"
        return 1
    }

    if echo "$response" | grep -qiE '"granted"[[:space:]]*:[[:space:]]*true'; then
        seenshow_slot_held=1
        seenshow_last_touch=$(date +%s)
        log "SEENSHOW: Acquired resolver slot for ${SEENSHOW_SLOT_CHANNEL_ID} (runner: $channel_id)"
        return 0
    fi

    local reason
    reason=$(echo "$response" | sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -1)
    [[ -z "$reason" ]] && reason="unknown"
    log_error "SEENSHOW: Slot denied for ${SEENSHOW_SLOT_CHANNEL_ID} (runner: $channel_id, reason: $reason)"
    return 1
}

seenshow_touch_slot_if_needed() {
    if [[ $seenshow_slot_held -ne 1 ]]; then
        return 0
    fi
    if ! seenshow_resolver_enabled; then
        return 1
    fi

    local now elapsed
    now=$(date +%s)
    elapsed=$((now - seenshow_last_touch))
    if [[ $elapsed -lt "$SEENSHOW_SLOT_TOUCH_INTERVAL" ]]; then
        return 0
    fi

    local response
    response=$(seenshow_call_resolver "POST" "/acquire/${SEENSHOW_SLOT_CHANNEL_ID}") || {
        log_error "SEENSHOW: Slot heartbeat failed for ${SEENSHOW_SLOT_CHANNEL_ID} (request error)"
        return 1
    }

    if echo "$response" | grep -qiE '"granted"[[:space:]]*:[[:space:]]*true'; then
        seenshow_last_touch=$now
        return 0
    fi

    local reason
    reason=$(echo "$response" | sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -1)
    [[ -z "$reason" ]] && reason="unknown"
    log_error "SEENSHOW: Slot heartbeat denied for ${SEENSHOW_SLOT_CHANNEL_ID} (reason: $reason)"
    return 1
}

seenshow_token_needs_refresh() {
    local index="$1"
    local now
    now=$(date +%s)
    local expiry="${url_seenshow_expiry[$index]:-0}"
    [[ "$expiry" =~ ^[0-9]+$ ]] || expiry=0

    if [[ "${url_array[$index]}" != *"hdntl="* ]]; then
        return 0
    fi
    if [[ "$expiry" -le 0 ]]; then
        return 0
    fi
    if [[ $((expiry - now)) -le "$SEENSHOW_TOKEN_MARGIN" ]]; then
        return 0
    fi
    return 1
}

resolve_seenshow_url_for_index() {
    local index="$1"
    local hls_path="${url_seenshow_hls_path[$index]}"
    if [[ -z "$hls_path" ]]; then
        hls_path=$(extract_seenshow_hls_path "${url_array[$index]}" || true)
        url_seenshow_hls_path[$index]="$hls_path"
    fi
    if [[ -z "$hls_path" ]]; then
        log_error "SEENSHOW: Could not parse hls_path for URL index $index"
        return 1
    fi
    if ! seenshow_resolver_enabled; then
        log_error "SEENSHOW: Resolver disabled/unavailable for URL index $index"
        return 1
    fi

    local response
    response=$(seenshow_call_resolver "GET" "/resolve/${hls_path}") || {
        log_error "SEENSHOW: Resolve request failed for path $hls_path"
        return 1
    }

    local resolved_url
    resolved_url=$(printf '%s' "$response" \
        | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' \
        | head -1 \
        | sed 's#\\/#/#g')

    if [[ ! "$resolved_url" =~ ^https?:// ]]; then
        local err
        err=$(printf '%s' "$response" | sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -1)
        [[ -z "$err" ]] && err="invalid_response"
        log_error "SEENSHOW: Resolver returned no URL for index $index ($err)"
        return 1
    fi

    url_array[$index]="$resolved_url"
    init_url_seenshow_metadata "$index" "$resolved_url"

    local expiry="${url_seenshow_expiry[$index]:-0}"
    if [[ "$expiry" =~ ^[0-9]+$ && "$expiry" -gt 0 ]]; then
        local expiry_date
        expiry_date=$(date -d "@$expiry" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expiry" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
        log "SEENSHOW: Refreshed tokenized URL for index $index (expires at $expiry_date)"
    else
        log "SEENSHOW: Refreshed URL for index $index (expiry unknown)"
    fi
    return 0
}

prepare_seenshow_url_for_index() {
    local index="$1"
    if [[ "${url_is_seenshow[$index]:-0}" != "1" ]]; then
        return 0
    fi

    if ! seenshow_acquire_slot_if_needed "$index"; then
        return 1
    fi

    if seenshow_token_needs_refresh "$index"; then
        local attempt
        for attempt in $(seq 1 "$SEENSHOW_RESOLVE_RETRIES"); do
            if resolve_seenshow_url_for_index "$index"; then
                return 0
            fi
            if [[ "$attempt" -lt "$SEENSHOW_RESOLVE_RETRIES" ]]; then
                sleep 1
            fi
        done
        return 1
    fi

    return 0
}

# =============================================================================
# Aloula/KwikMotion resolver
# =============================================================================
# Uses the public aloula.sba.sa CMS API to get tokenized KwikMotion stream URLs.
# Backup URLs use aloula:<channel_id> scheme (e.g., aloula:7 for Quran TV).
# The API returns a master playlist with short-lived token (~12s), but inside
# are variant stream URLs with ~24h tokens. We extract the highest quality
# variant URL and use it directly with FFmpeg.
#
# Channel IDs:  7 = qurantvsa (القرآن الكريم)
#               6 = sunnatvsa (السنة النبوية)
# =============================================================================

is_aloula_url() {
    local url="$1"
    [[ "$url" =~ ^aloula:[0-9]+$ ]]
}

extract_aloula_channel_id() {
    local url="$1"
    if [[ "$url" =~ ^aloula:([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

is_kwikmotion_url() {
    local url="$1"
    [[ "$url" =~ ^https?://live\.kwikmotion\.com/ ]]
}

extract_kwikmotion_expiry() {
    local url="$1"
    # Check hdntl= path token (used in variant URLs)
    # Uses sed instead of grep -P for portability (grep -P unavailable on BusyBox/Alpine)
    if [[ "$url" =~ /hdntl= ]]; then
        local hdntl_segment
        hdntl_segment=$(printf '%s' "$url" | sed -n 's|.*/hdntl=\([^/]*\).*|\1|p' | head -1)
        if [[ -n "$hdntl_segment" ]]; then
            local decoded
            decoded=$(url_decode "$hdntl_segment")
            if [[ "$decoded" =~ (^|~)exp=([0-9]{9,}) ]]; then
                echo "${BASH_REMATCH[2]}"
                return 0
            fi
        fi
    fi
    # Check hdnts= query token (used in master playlist URL)
    if [[ "$url" =~ [\?\&]hdnts= ]]; then
        local hdnts_val
        hdnts_val=$(printf '%s' "$url" | sed -n 's|.*[?&]hdnts=\([^&]*\).*|\1|p' | head -1)
        if [[ -n "$hdnts_val" ]]; then
            local decoded
            decoded=$(url_decode "$hdnts_val")
            if [[ "$decoded" =~ (^|~)exp=([0-9]{9,}) ]]; then
                echo "${BASH_REMATCH[2]}"
                return 0
            fi
        fi
    fi
    echo "0"
    return 1
}

# Resolve an HLS variant URI against a master playlist URL.
# Handles three URI forms per RFC 8216:
#   1. Absolute URI (https://...) — used as-is
#   2. Absolute path (/path/...) — joined with scheme+host from master
#   3. Relative path (file.m3u8)  — joined with base directory of master (query stripped)
_resolve_hls_variant_url() {
    local master_url="$1"
    local variant_path="$2"
    local resolved_url
    if [[ "$variant_path" =~ ^https?:// ]]; then
        resolved_url="$variant_path"
    elif [[ "$variant_path" =~ ^/ ]]; then
        local origin
        origin=$(printf '%s' "$master_url" | sed -E 's#^(https?://[^/]+).*#\1#')
        resolved_url="${origin}${variant_path}"
    else
        local base_url
        base_url="${master_url%%\?*}"
        base_url="${base_url%/*}/"
        resolved_url="${base_url}${variant_path}"
    fi
    printf '%s' "$resolved_url"
}

resolve_aloula_url() {
    local aloula_channel_id="$1"
    local api_url="${ALOULA_API_BASE}/channels/${aloula_channel_id}/player"

    local response
    response=$(curl -sS --max-time "$ALOULA_RESOLVE_TIMEOUT" \
        -H "Accept: application/json" "$api_url" 2>$DEVNULL) || {
        log_error "ALOULA: API request failed for channel $aloula_channel_id"
        return 1
    }

    # Extract HLS master playlist URL — prefer jq for robust JSON parsing,
    # fall back to sed if jq is not installed.
    local master_url
    if command -v jq &>$DEVNULL; then
        master_url=$(printf '%s' "$response" | jq -r '.hls // empty' 2>$DEVNULL)
    fi
    if [[ -z "$master_url" ]]; then
        master_url=$(printf '%s' "$response" \
            | sed -n 's/.*"hls"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -1 \
            | sed 's|\\\/|/|g')
    fi
    if [[ -z "$master_url" || ! "$master_url" =~ ^https?:// ]]; then
        log_error "ALOULA: No HLS URL in API response for channel $aloula_channel_id"
        return 1
    fi

    # Fetch master playlist to get variant stream URLs with long-lived tokens
    local master_content
    master_content=$(curl -sS --max-time 5 "$master_url" 2>$DEVNULL) || {
        log_error "ALOULA: Failed to fetch master playlist for channel $aloula_channel_id"
        return 1
    }

    # Select highest-bandwidth variant by parsing #EXT-X-STREAM-INF BANDWIDTH.
    # Falls back to the last URI line (HLS playlists list variants in ascending
    # bandwidth order by convention) if BANDWIDTH parsing fails.
    local variant_path best_bw=0
    local prev_bw=0
    while IFS= read -r line; do
        if [[ "$line" =~ BANDWIDTH=([0-9]+) ]]; then
            prev_bw="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[^#] && -n "$line" ]]; then
            if [[ $prev_bw -ge $best_bw ]]; then
                best_bw=$prev_bw
                variant_path="$line"
            fi
            prev_bw=0
        fi
    done <<< "$master_content"
    # Final fallback: first non-comment line
    if [[ -z "$variant_path" ]]; then
        variant_path=$(echo "$master_content" | grep -v '^#' | grep -v '^$' | head -1)
    fi
    if [[ -z "$variant_path" ]]; then
        log_error "ALOULA: No variant streams in master playlist for channel $aloula_channel_id"
        return 1
    fi

    local resolved_url
    resolved_url=$(_resolve_hls_variant_url "$master_url" "$variant_path")

    # Downgrade HTTPS to HTTP for kwikmotion CDN — their TLS fingerprinting
    # blocks streamlink/Python requests, but plain HTTP works fine and lets
    # FFmpeg connect directly without an HTTPS proxy.
    if [[ "$resolved_url" =~ ^https://live\.kwikmotion\.com/ ]]; then
        resolved_url="${resolved_url/https:\/\//http:\/\/}"
    fi

    echo "$resolved_url"
    return 0
}

resolve_aloula_url_for_index() {
    local index="$1"
    local original="${url_original[$index]}"
    local aloula_ch_id
    aloula_ch_id=$(extract_aloula_channel_id "$original") || {
        log_error "ALOULA: Cannot extract channel ID from ${original}"
        return 1
    }

    local resolved
    resolved=$(resolve_aloula_url "$aloula_ch_id") || return 1

    url_array[$index]="$resolved"

    local expiry
    expiry=$(extract_kwikmotion_expiry "$resolved" || echo 0)
    [[ "$expiry" =~ ^[0-9]+$ ]] || expiry=0
    url_expire_time[$index]="$expiry"

    if [[ "$expiry" -gt 0 ]]; then
        local expiry_date
        expiry_date=$(date -d "@$expiry" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expiry" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
        log "ALOULA: Resolved channel $aloula_ch_id for index $index → $(echo "$resolved" | head -c 80)... (expires $expiry_date)"
    else
        log "ALOULA: Resolved channel $aloula_ch_id for index $index (expiry unknown)"
    fi
    return 0
}

aloula_token_needs_refresh() {
    local index="$1"
    local now
    now=$(date +%s)
    local expiry="${url_expire_time[$index]:-0}"
    [[ "$expiry" =~ ^[0-9]+$ ]] || expiry=0

    if [[ "$expiry" -le 0 ]]; then
        return 0  # Unknown expiry → refresh
    fi
    if [[ $((expiry - now)) -le "$ALOULA_TOKEN_MARGIN" ]]; then
        return 0  # Within margin → refresh
    fi
    return 1  # Still fresh
}

prepare_aloula_url_for_index() {
    local index="$1"
    local original="${url_original[$index]}"
    if ! is_aloula_url "$original"; then
        return 0
    fi

    if aloula_token_needs_refresh "$index"; then
        log "ALOULA: Token refresh needed for index $index"
        if resolve_aloula_url_for_index "$index"; then
            return 0
        fi
        log_error "ALOULA: Failed to refresh token for index $index"
        return 1
    fi

    return 0
}

# =============================================================================
# Elahmad.com resolver
# =============================================================================
# Uses elahmad.com's encrypted API to resolve live stream URLs.
# Backup URLs use elahmad:<channel_id> scheme (e.g., elahmad:makkahtv).
# The API returns AES-256-CBC encrypted stream URLs that we decrypt with openssl.
# =============================================================================

is_elahmad_url() {
    local url="$1"
    [[ "$url" =~ ^elahmad:[a-zA-Z0-9_-]+$ ]]
}

extract_elahmad_channel_id() {
    local url="$1"
    if [[ "$url" =~ ^elahmad:([a-zA-Z0-9_-]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

resolve_elahmad_url() {
    local channel_id="$1"
    local page_url="${ELAHMAD_BASE}/tv/mobiletv/glarb.php?id=${channel_id}"

    # Step 1: Fetch the page to get CSRF token and session cookie
    local cookie_jar
    cookie_jar=$(mktemp /tmp/elahmad_cookies.XXXXXX)
    local page_content
    page_content=$(curl -sS --max-time "$ELAHMAD_RESOLVE_TIMEOUT" \
        -c "$cookie_jar" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml" \
        "$page_url" 2>$DEVNULL)
    local curl_rc=$?
    if [[ $curl_rc -ne 0 || -z "$page_content" ]]; then
        log_error "ELAHMAD: Failed to fetch page for channel $channel_id (curl rc=$curl_rc)"
        rm -f "$cookie_jar"
        return 1
    fi

    # Extract CSRF token from meta tag
    # The page is a single long line, so use grep -oP (Perl regex) with grep -oE fallback
    local csrf_token
    csrf_token=$(printf '%s' "$page_content" | grep -oP 'csrf-token"\s+content="\K[^"]+' 2>$DEVNULL | head -1)
    if [[ -z "$csrf_token" ]]; then
        csrf_token=$(printf '%s' "$page_content" | grep -oE 'csrf-token"[[:space:]]+content="[0-9a-f]+"' 2>$DEVNULL | head -1 | sed 's/.*content="//;s/"//')
    fi
    if [[ -z "$csrf_token" ]]; then
        log_error "ELAHMAD: No CSRF token found in page for channel $channel_id"
        rm -f "$cookie_jar"
        return 1
    fi

    # Step 2: POST to the API endpoint with CSRF token and session cookie
    local api_url="${ELAHMAD_BASE}/tv/result/embed_result_80.php"
    local api_response
    api_response=$(curl -sS --max-time "$ELAHMAD_RESOLVE_TIMEOUT" \
        -b "$cookie_jar" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "X-Requested-With: XMLHttpRequest" \
        -H "Referer: ${page_url}" \
        -d "id=${channel_id}&csrf_token=${csrf_token}" \
        "$api_url" 2>$DEVNULL)
    curl_rc=$?
    rm -f "$cookie_jar"

    if [[ $curl_rc -ne 0 || -z "$api_response" ]]; then
        log_error "ELAHMAD: API request failed for channel $channel_id (curl rc=$curl_rc)"
        return 1
    fi

    # Step 3: Parse JSON response — extract link_4, key, iv
    local encrypted_link aes_key aes_iv
    if command -v jq &>$DEVNULL; then
        encrypted_link=$(printf '%s' "$api_response" | jq -r '.link_4 // .link_3 // .link_2 // .link_1 // empty' 2>$DEVNULL)
        aes_key=$(printf '%s' "$api_response" | jq -r '.key // empty' 2>$DEVNULL)
        aes_iv=$(printf '%s' "$api_response" | jq -r '.iv // empty' 2>$DEVNULL)
    fi
    # Fallback to sed if jq unavailable or failed — unescape JSON \/ to /
    if [[ -z "$encrypted_link" ]]; then
        encrypted_link=$(printf '%s' "$api_response" | sed -n 's/.*"link_4"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | sed 's|\\\/|/|g')
        [[ -z "$encrypted_link" ]] && encrypted_link=$(printf '%s' "$api_response" | sed -n 's/.*"link_3"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | sed 's|\\\/|/|g')
        [[ -z "$encrypted_link" ]] && encrypted_link=$(printf '%s' "$api_response" | sed -n 's/.*"link_2"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | sed 's|\\\/|/|g')
        [[ -z "$encrypted_link" ]] && encrypted_link=$(printf '%s' "$api_response" | sed -n 's/.*"link_1"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | sed 's|\\\/|/|g')
    fi
    if [[ -z "$aes_key" ]]; then
        aes_key=$(printf '%s' "$api_response" | sed -n 's/.*"key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi
    if [[ -z "$aes_iv" ]]; then
        aes_iv=$(printf '%s' "$api_response" | sed -n 's/.*"iv"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi

    if [[ -z "$encrypted_link" ]]; then
        log_error "ELAHMAD: No encrypted link found in API response for channel $channel_id"
        return 1
    fi
    if [[ -z "$aes_key" || -z "$aes_iv" ]]; then
        log_error "ELAHMAD: Missing AES key/iv in API response for channel $channel_id"
        return 1
    fi

    # Step 4: Decrypt the stream URL using openssl
    local decrypted_url
    decrypted_url=$(printf '%s' "$encrypted_link" | openssl enc -aes-256-cbc -d -A -base64 -K "$aes_key" -iv "$aes_iv" 2>$DEVNULL)
    if [[ $? -ne 0 || -z "$decrypted_url" ]]; then
        log_error "ELAHMAD: AES decryption failed for channel $channel_id"
        return 1
    fi

    # Strip any trailing whitespace/control chars
    decrypted_url=$(printf '%s' "$decrypted_url" | tr -d '[:cntrl:]' | sed 's/[[:space:]]*$//')

    if [[ ! "$decrypted_url" =~ ^https?:// ]]; then
        log_error "ELAHMAD: Decrypted URL is not valid HTTP(S): $decrypted_url"
        return 1
    fi

    echo "$decrypted_url"
    return 0
}

resolve_elahmad_url_for_index() {
    local index="$1"
    local original="${url_original[$index]}"
    local elahmad_ch_id
    elahmad_ch_id=$(extract_elahmad_channel_id "$original") || {
        log_error "ELAHMAD: Cannot extract channel ID from ${original}"
        return 1
    }

    local resolved
    resolved=$(resolve_elahmad_url "$elahmad_ch_id") || return 1

    url_array[$index]="$resolved"
    url_elahmad_resolve_time[$index]=$(date +%s)

    log "ELAHMAD: Resolved channel $elahmad_ch_id for index $index → $(echo "$resolved" | head -c 80)..."
    return 0
}

elahmad_url_needs_refresh() {
    local index="$1"
    local now
    now=$(date +%s)
    local last_resolve="${url_elahmad_resolve_time[$index]:-0}"
    [[ "$last_resolve" =~ ^[0-9]+$ ]] || last_resolve=0

    if [[ "$last_resolve" -le 0 ]]; then
        return 0  # Never resolved → refresh
    fi
    if [[ $((now - last_resolve)) -ge "$ELAHMAD_REFRESH_INTERVAL" ]]; then
        return 0  # Interval elapsed → refresh
    fi
    return 1  # Still fresh
}

prepare_elahmad_url_for_index() {
    local index="$1"
    local original="${url_original[$index]}"
    if ! is_elahmad_url "$original"; then
        return 0
    fi

    if elahmad_url_needs_refresh "$index"; then
        log "ELAHMAD: Refresh needed for index $index"
        if resolve_elahmad_url_for_index "$index"; then
            return 0
        fi
        log_error "ELAHMAD: Failed to refresh URL for index $index"
        return 1
    fi

    return 0
}

set_streamlink_args() {
    local url="$1"

    if should_use_torsocks "$YTDLP_PROXY"; then
        if ! tor_socks_reachable "$YTDLP_PROXY"; then
            if [[ $tor_socks_unreachable_warned -eq 0 ]]; then
                log_error "TOR: SOCKS proxy not reachable; attempting Tor restart"
                tor_socks_unreachable_warned=1
            fi
            tor_rotate_circuit || true
        fi
        streamlink_args=(torsocks streamlink --stdout)
    else
        if proxy_is_local_tor "$YTDLP_PROXY" && ! command -v torsocks >$DEVNULL 2>&1; then
            if [[ $torsocks_warned -eq 0 ]]; then
                log_error "TOR: torsocks not found; using streamlink --http-proxy"
                torsocks_warned=1
            fi
        fi
        streamlink_args=(streamlink --stdout)
        [[ -n "$YTDLP_PROXY" ]] && streamlink_args+=(--http-proxy "$YTDLP_PROXY")
    fi

    # live.seenshow.com frequently enforces browser-like header checks.
    # Keep these headers centralized so all seenshow fallbacks behave uniformly.
    if is_seenshow_url "$url"; then
        streamlink_args+=(--http-header "User-Agent=$USER_AGENT")
        streamlink_args+=(--http-header "Referer=https://live.seenshow.com/")
        streamlink_args+=(--http-header "Origin=https://live.seenshow.com")
    fi

    streamlink_args+=("$url" best)
}

# =============================================================================
# Tor circuit rotation for YouTube bot detection bypass
# =============================================================================
# When YouTube blocks the current Tor exit node, we rotate to a new circuit.
# Uses a global failure counter and cooldown to prevent excessive rotations.
# =============================================================================

tor_record_youtube_failure() {
    local failures=0
    [[ -f "$TOR_FAILURE_FILE" ]] && failures=$(cat "$TOR_FAILURE_FILE" 2>$DEVNULL || echo 0)
    ((failures++))
    echo "$failures" > "$TOR_FAILURE_FILE"

    if [[ $failures -ge $TOR_ROTATE_FAILURES ]]; then
        tor_rotate_circuit
    fi
}

tor_reset_failure_count() {
    echo "0" > "$TOR_FAILURE_FILE" 2>$DEVNULL
}

tor_rotate_circuit() {
    local now last_rotate wait_time
    now=$(date +%s)

    # Check cooldown
    if [[ -f "$TOR_ROTATE_TIMESTAMP" ]]; then
        last_rotate=$(cat "$TOR_ROTATE_TIMESTAMP" 2>$DEVNULL || echo 0)
        wait_time=$((TOR_ROTATE_COOLDOWN - (now - last_rotate)))
        if [[ $wait_time -gt 0 ]]; then
            log "TOR_ROTATE: Cooldown active, ${wait_time}s remaining. Skipping rotation."
            return 1
        fi
    fi

    log "TOR_ROTATE: Rotating Tor circuit due to YouTube bot detection..."

    # Try to restart Tor service
    if command -v systemctl >$DEVNULL 2>&1; then
        if SUDO_ASKPASS=~/.sudo_pass.sh sudo -A sh -c 'systemctl restart tor >/dev/null 2>&1'; then
            log "TOR_ROTATE: Tor service restarted successfully"
            echo "$now" > "$TOR_ROTATE_TIMESTAMP"
            tor_reset_failure_count
            sleep 3  # Wait for new circuit
            return 0
        fi
    fi

    log_error "TOR_ROTATE: Failed to restart Tor service"
    return 1
}

resolve_youtube_via_browser_proxy() {
    local youtube_url="$1"
    local label="${2:-$channel_id}"

    # Only run when explicitly enabled
    if [[ -z "$YOUTUBE_BROWSER_RESOLVER" ]]; then
        return 1
    fi

    if ! command -v curl >$DEVNULL 2>&1; then
        log_error "YOUTUBE_BROWSER: curl not found; skipping browser resolver"
        return 1
    fi

    local now
    now=$(date +%s)
    if [[ $last_browser_resolver_failure -ne 0 && $((now - last_browser_resolver_failure)) -lt $YOUTUBE_BROWSER_RESOLVER_COOLDOWN ]]; then
        return 1
    fi

    local endpoint="${YOUTUBE_BROWSER_RESOLVER%/}/register"
    local response
    response=$(curl -f -G -A "$USER_AGENT" -sS --max-time "$YOUTUBE_BROWSER_RESOLVER_TIMEOUT" \
        --data-urlencode "url=$youtube_url" \
        --data-urlencode "id=${label:-youtube}" \
        "$endpoint" 2>$DEVNULL) || {
        last_browser_resolver_failure=$now
        log_error "YOUTUBE_BROWSER: Resolver request failed; will skip for ${YOUTUBE_BROWSER_RESOLVER_COOLDOWN}s"
        return 1
    }

    local playback
    playback=$(printf '%s' "$response" | head -n1 | tr -d '\r')
    if [[ "$playback" =~ ^https?:// ]]; then
        log "YOUTUBE_BROWSER: Resolved via browser service for $label"
        echo "$playback"
        return 0
    fi

    playback=$(printf '%s' "$response" | sed -n 's/.*\"playback\"[[:space:]]*:[[:space:]]*\"\\?\([^"]\+\)\".*/\1/p' | head -1)
    if [[ "$playback" =~ ^https?:// ]]; then
        log "YOUTUBE_BROWSER: Resolved via browser service (JSON) for $label"
        echo "$playback"
        return 0
    fi

    log "YOUTUBE_BROWSER: Resolver responded without playback URL"
    return 1
}

resolve_youtube_url() {
    local youtube_url="$1"
    local skip_cooldown="${2:-0}"  # Optional: skip cooldown check (for startup)
    local resolved_url=""
    local use_proxy="$YTDLP_PROXY"
    local attempted_direct=0

    log "YOUTUBE: Resolving URL: $youtube_url"

    # Try browser-backed resolver first (avoids signature churn / 403s)
    local browser_resolved=""
    browser_resolved=$(resolve_youtube_via_browser_proxy "$youtube_url" "${channel_id:-youtube}") || true
    if [[ -n "$browser_resolved" ]]; then
        echo "$browser_resolved"
        return 0
    fi

    # Check if yt-dlp is available
    if ! command -v yt-dlp >$DEVNULL 2>&1; then
        log_error "YOUTUBE: yt-dlp not found. Install with: pip install yt-dlp"
        return 1
    fi

    # Require timeout command to prevent indefinite hangs
    if ! command -v timeout >$DEVNULL 2>&1; then
        log_error "YOUTUBE: 'timeout' command required but not found. Install coreutils."
        return 1
    fi

    # Check per-channel cooldown (skip on initial startup resolution)
    if [[ "$skip_cooldown" != "1" ]] && ! ytdlp_channel_can_call; then
        log "YOUTUBE: Skipping resolution due to per-channel cooldown"
        return 1
    fi

    # Record this call for per-channel rate limiting (once per logical resolve)
    ytdlp_channel_record_call

    while true; do
        # Acquire global throttle lock
        if ! ytdlp_throttle_acquire; then
            log_error "YOUTUBE: Failed to acquire throttle lock"
            return 1
        fi

        # If using local Tor, ensure SOCKS is reachable before calling yt-dlp
        if proxy_is_local_tor "$use_proxy" && ! tor_socks_reachable "$use_proxy"; then
            log_error "YOUTUBE: Tor SOCKS proxy not reachable; attempting Tor restart before resolve"
            tor_rotate_circuit || true
            sleep 2
        fi

        # Use yt-dlp with timeout to extract stream URL
        # -g: Get URL only, --no-warnings: suppress warnings
        # -f: Format selection
        local ytdlp_cmd=(yt-dlp -g --no-warnings --no-playlist -f "$YTDLP_FORMAT")
        # Add proxy if configured
        if [[ -n "$use_proxy" ]]; then
            ytdlp_cmd+=(--proxy "$use_proxy")
        fi
        # Add cookies: prefer explicit file, fall back to browser extraction
        init_ytdlp_cookies_browser_args
        if [[ -n "$YTDLP_COOKIES" && -f "$YTDLP_COOKIES" ]]; then
            ytdlp_cmd+=(--cookies "$YTDLP_COOKIES")
        elif [[ ${#ytdlp_cookies_browser_args[@]} -gt 0 ]]; then
            ytdlp_cmd+=("${ytdlp_cookies_browser_args[@]}")
        fi
        # Add extractor-args if configured (for POT provider etc.)
        if [[ -n "$YTDLP_EXTRACTOR_ARGS" ]]; then
            ytdlp_cmd+=(--extractor-args "$YTDLP_EXTRACTOR_ARGS")
        fi
        ytdlp_cmd+=("$youtube_url")
        resolved_url=$(timeout "$YTDLP_TIMEOUT" "${ytdlp_cmd[@]}" 2>$DEVNULL | head -1)

        # Release throttle lock after yt-dlp completes
        ytdlp_throttle_release

        if [[ -n "$resolved_url" ]]; then
            break
        fi

        # Retry once without proxy if allowed (helps when Tor is blocked/unreachable)
        if [[ -n "$use_proxy" && $attempted_direct -eq 0 && "$YTDLP_ALLOW_DIRECT_FALLBACK" == "1" ]]; then
            log "YOUTUBE: Proxy resolution failed; retrying direct (no proxy) once"
            use_proxy=""
            attempted_direct=1
            continue
        fi

        break
    done

    if [[ -z "$resolved_url" ]]; then
        log_error "YOUTUBE: Failed to resolve URL: $youtube_url"
        tor_record_youtube_failure  # Track failure, may trigger Tor rotation
        ytdlp_record_failure        # Apply exponential backoff
        return 1
    fi

    tor_reset_failure_count  # Success - reset failure counter
    ytdlp_reset_failures     # Reset exponential backoff
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

    # Browser resolver URLs: the resolver handles renewal internally.
    # Return 0 (no expiry) so youtube_url_needs_refresh() never triggers.
    if is_browser_resolver_url "$url"; then
        echo "0"
        return 0
    fi

    # Fallback: assume 5 hours from now if no expire found
    local fallback=$(($(date +%s) + 18000))
    log "YOUTUBE: No expiry found in URL, assuming 5 hours from now"
    echo "$fallback"
    return 0  # Return success since we're providing a valid fallback timestamp
}

# Check if a URL is served by the browser resolver (stable proxy, no restart needed)
is_browser_resolver_url() {
    local url="$1"
    [[ -n "$YOUTUBE_BROWSER_RESOLVER" ]] || return 1
    local resolver_origin="${YOUTUBE_BROWSER_RESOLVER%/}"
    [[ "$url" == "${resolver_origin}"/* ]] && return 0
    return 1
}

# Initialize YouTube metadata for a URL slot
init_url_youtube_metadata() {
    local index="$1"
    local url="$2"
    local associated_general="${3:-}"  # Optional: associated general URL for specific URLs
    local is_startup="${4:-0}"         # Optional: 1 if called during startup (for stagger)

    # Handle aloula: scheme URLs (resolve via aloula.sba.sa API)
    if is_aloula_url "$url"; then
        url_is_youtube[$index]=0
        url_youtube_type[$index]=""
        url_original[$index]="$url"
        url_general_url[$index]=""
        url_is_seenshow[$index]=0
        url_seenshow_hls_path[$index]=""
        url_seenshow_expiry[$index]=0

        local aloula_ch_id
        aloula_ch_id=$(extract_aloula_channel_id "$url")
        log "ALOULA: Detected aloula:${aloula_ch_id} URL at index $index"

        if resolve_aloula_url_for_index "$index"; then
            return 0
        else
            log_error "ALOULA: Failed initial resolution for index $index, will retry before use"
            url_expire_time[$index]=0
            return 1
        fi
    fi

    # Handle elahmad: scheme URLs (resolve via elahmad.com encrypted API)
    if is_elahmad_url "$url"; then
        url_is_youtube[$index]=0
        url_youtube_type[$index]=""
        url_original[$index]="$url"
        url_general_url[$index]=""
        url_is_seenshow[$index]=0
        url_seenshow_hls_path[$index]=""
        url_seenshow_expiry[$index]=0
        url_expire_time[$index]=0

        local elahmad_ch_id
        elahmad_ch_id=$(extract_elahmad_channel_id "$url")
        log "ELAHMAD: Detected elahmad:${elahmad_ch_id} URL at index $index"

        if resolve_elahmad_url_for_index "$index"; then
            return 0
        else
            log_error "ELAHMAD: Failed initial resolution for index $index, will retry before use"
            return 1
        fi
    fi

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
            local yt_channel_id
            yt_channel_id=$(get_youtube_channel_from_url "$url")
            if [[ -n "$yt_channel_id" ]]; then
                local general_url
                general_url=$(build_youtube_general_url "$yt_channel_id")
                if [[ -n "$general_url" ]]; then
                    url_general_url[$index]="$general_url"
                    log "YOUTUBE: Auto-derived general URL for index $index: $general_url"
                fi
            fi
        fi

        # Add staggered delay at startup to prevent rate limiting
        if [[ "$is_startup" == "1" ]]; then
            ytdlp_startup_stagger
        fi

        # Resolve immediately (skip per-channel cooldown on startup)
        local resolved
        resolved=$(resolve_youtube_url "$url" "1")  # 1 = skip cooldown
        if [[ -n "$resolved" ]]; then
            local expire_time
            expire_time=$(extract_youtube_expiry "$resolved")
            url_expire_time[$index]="$expire_time"

            # Update url_array with resolved URL
            url_array[$index]="$resolved"
            init_url_seenshow_metadata "$index" "${url_array[$index]}"

            local expire_date
            if [[ "$expire_time" -eq 0 ]]; then
                log "YOUTUBE: URL index $index resolved ($yt_type), browser-proxied (no expiry tracking)"
            else
                expire_date=$(date -d "@$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
                log "YOUTUBE: URL index $index resolved ($yt_type), expires at $expire_date"
            fi
            return 0
        else
            log_error "YOUTUBE: Failed initial resolution for index $index, keeping original URL"
            url_expire_time[$index]=0
            init_url_seenshow_metadata "$index" "${url_array[$index]}"
            # Keep original YouTube URL - ffmpeg will fail but failover will work
            return 1
        fi
    else
        url_is_youtube[$index]=0
        url_youtube_type[$index]=""
        url_original[$index]="$url"
        url_general_url[$index]=""
        url_expire_time[$index]=0
        init_url_seenshow_metadata "$index" "$url"
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

    # Acquire global throttle lock
    if ! ytdlp_throttle_acquire; then
        log_error "YOUTUBE: Failed to acquire throttle lock for live check"
        return 1  # Assume still live if we can't check
    fi

    # Use yt-dlp to check if the stream is still live
    local is_live
    local ytdlp_live_cmd=(yt-dlp --no-download --print "%(is_live)s")
    # Add proxy if configured
    if [[ -n "$YTDLP_PROXY" ]]; then
        ytdlp_live_cmd+=(--proxy "$YTDLP_PROXY")
    fi
    # Add cookies: prefer explicit file, fall back to browser extraction
    init_ytdlp_cookies_browser_args
    if [[ -n "$YTDLP_COOKIES" && -f "$YTDLP_COOKIES" ]]; then
        ytdlp_live_cmd+=(--cookies "$YTDLP_COOKIES")
    elif [[ ${#ytdlp_cookies_browser_args[@]} -gt 0 ]]; then
        ytdlp_live_cmd+=("${ytdlp_cookies_browser_args[@]}")
    fi
    ytdlp_live_cmd+=("$youtube_url")
    if command -v timeout >$DEVNULL 2>&1; then
        is_live=$(timeout 10 "${ytdlp_live_cmd[@]}" 2>$DEVNULL || echo "error")
    else
        log "YOUTUBE: 'timeout' not found; running yt-dlp without timeout for live check"
        is_live=$("${ytdlp_live_cmd[@]}" 2>$DEVNULL || echo "error")
    fi

    # Release throttle lock
    ytdlp_throttle_release

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
            url_original[$index]="$general_url"
            url_youtube_type[$index]="general"
            url_general_url[$index]="$general_url"

            local expire_date
            if [[ "$expire_time" -eq 0 ]]; then
                log "YOUTUBE_REFETCH: Success! New stream resolved, browser-proxied (no expiry tracking)"
            else
                expire_date=$(date -d "@$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$expire_time" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
                log "YOUTUBE_REFETCH: Success! New stream resolved, expires at $expire_date"
            fi
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
# OPTIMIZED: Skip redundant youtube_check_stream_ended call to prevent extra yt-dlp calls
# Since FFmpeg already failed, we know the stream needs refresh - no need to verify again
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
    # No need to check stream status - general URLs auto-redirect to latest stream
    if [[ "$yt_type" == "general" ]]; then
        log "YOUTUBE_STREAM_END: General URL detected, re-resolving to get latest stream..."
        if refresh_youtube_url "$index"; then
            return 0
        fi
        return 1
    fi

    # For specific URLs, try to use general URL if available
    # OPTIMIZATION: Skip youtube_check_stream_ended call - FFmpeg failure already indicates issue
    # This saves 1 yt-dlp call per stream-end event
    if [[ "$yt_type" == "specific" ]]; then
        if [[ -n "$general_url" ]]; then
            log "YOUTUBE_STREAM_END: Specific URL failed, using general URL for re-fetch..."
            if youtube_refetch_via_general "$index"; then
                return 0
            fi
        else
            # No general URL - try direct refresh as fallback
            log "YOUTUBE_STREAM_END: Specific URL failed, attempting direct refresh..."
            if refresh_youtube_url "$index"; then
                return 0
            fi
        fi
    fi

    return 1
}

youtube_url_needs_refresh() {
    local index="$1"
    local now
    now=$(date +%s)

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
    if [[ "$new_expire" -eq 0 ]]; then
        log "YOUTUBE_REFRESH: URL index $index refreshed, browser-proxied (no expiry tracking)"
    else
        expire_date=$(date -d "@$new_expire" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || date -r "$new_expire" '+%Y-%m-%d %H:%M:%S' 2>$DEVNULL || echo "unknown")
        log "YOUTUBE_REFRESH: URL index $index refreshed, new expiry: $expire_date"
    fi
    return 0
}

check_youtube_urls_need_refresh() {
    local now
    now=$(date +%s)
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

    # OPTIMIZATION: Only refresh ONE backup URL per cycle to prevent rate limiting
    # Previous behavior refreshed ALL expiring backups at once, causing multiple yt-dlp calls
    for i in $(seq 0 $((url_count - 1))); do
        if [[ $i -ne $current_url_index ]] && youtube_url_needs_refresh "$i"; then
            log "YOUTUBE_REFRESH: Backup URL (index $i) needs refresh"
            refresh_youtube_url "$i" || true  # Don't fail on backup refresh
            break  # Only refresh one backup per cycle
        fi
    done

    # Log browser-resolver status once per session
    if [[ "${url_is_youtube[$current_url_index]}" == "1" ]] && is_browser_resolver_url "${url_array[$current_url_index]}"; then
        if [[ "${_browser_resolver_logged:-0}" -eq 0 ]]; then
            log "YOUTUBE_REFRESH: Current URL (index $current_url_index) is browser-proxied; resolver handles renewal internally"
            _browser_resolver_logged=1
        fi
    fi

    if [[ $current_refresh_needed -eq 1 ]]; then
        return 0  # Signal that current URL was refreshed - need FFmpeg restart
    fi

    return 1
}

check_segment_staleness() {
    local now
    now=$(date +%s)
    local elapsed=$((now - last_segment_check))

    # Only check every SEGMENT_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $SEGMENT_CHECK_INTERVAL ]]; then
        return 1
    fi

    last_segment_check=$now

    # Under ALWAYS_FIFO, use feeder-specific stale threshold (operator tunable)
    local stale_threshold="$SEGMENT_STALE_THRESHOLD"
    if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
        stale_threshold="$FEEDER_STALE_THRESHOLD"
    fi

    # Even with no backups, a stale output means FFmpeg is hung or the source is dead.
    # The caller will restart FFmpeg on the current URL when no alternates exist.

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
            if [[ $age -gt $stale_threshold ]]; then
                log "SEGMENT_STALE: No segments created for ${age}s (threshold: ${stale_threshold}s)"
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
        if [[ $age_since_start -gt $stale_threshold ]]; then
            log "SEGMENT_STALE: No new segments since start (${age_since_start}s, threshold: ${stale_threshold}s)"
            return 0
        fi
        return 1
    fi

    local segment_age=$((now - segment_mtime))
    if [[ $segment_age -gt $stale_threshold ]]; then
        log "SEGMENT_STALE: Latest segment age ${segment_age}s (threshold: ${stale_threshold}s)"
        return 0
    fi

    return 1
}

reset_primary_restore_confirmation() {
    local reason="${1:-}"
    if [[ $primary_restore_confirm_count -gt 0 ]]; then
        if [[ -n "$reason" ]]; then
            log "PRIMARY_CHECK: Resetting restore confirmation streak (${primary_restore_confirm_count}) - $reason"
        else
            log "PRIMARY_CHECK: Resetting restore confirmation streak (${primary_restore_confirm_count})"
        fi
    fi
    primary_restore_confirm_count=0
}

record_primary_restore_confirmation() {
    local reason="$1"

    if [[ "$PRIMARY_RESTORE_CONFIRMATIONS" -le 1 ]]; then
        return 0
    fi

    primary_restore_confirm_count=$((primary_restore_confirm_count + 1))
    if [[ $primary_restore_confirm_count -lt $PRIMARY_RESTORE_CONFIRMATIONS ]]; then
        log "PRIMARY_CHECK: Primary looks healthy ($reason), confirmation ${primary_restore_confirm_count}/${PRIMARY_RESTORE_CONFIRMATIONS}. Keeping backup active."
        return 1
    fi

    log "PRIMARY_CHECK: Confirmation ${primary_restore_confirm_count}/${PRIMARY_RESTORE_CONFIRMATIONS} reached ($reason)."
    return 0
}

probe_primary_media_decode() {
    local probe_url="$1"

    if [[ "$PRIMARY_RESTORE_MEDIA_PROBE" != "1" ]]; then
        return 0
    fi

    if ! command -v ffprobe >$DEVNULL 2>&1; then
        log "PRIMARY_CHECK: ffprobe not found; skipping media decode probe."
        return 0
    fi

    local probe_output=""
    if [[ -n "$YTDLP_PROXY" ]] && proxy_is_local_tor "$YTDLP_PROXY" && command -v torsocks >$DEVNULL 2>&1; then
        probe_output=$(timeout "$PRIMARY_RESTORE_MEDIA_PROBE_TIMEOUT" \
            torsocks ffprobe -v error -analyzeduration 3000000 -probesize 3000000 \
            -user_agent "$USER_AGENT" -rw_timeout 8000000 \
            -show_entries stream=codec_type -of csv=p=0 "$probe_url" 2>$DEVNULL || true)
    else
        probe_output=$(timeout "$PRIMARY_RESTORE_MEDIA_PROBE_TIMEOUT" \
            ffprobe -v error -analyzeduration 3000000 -probesize 3000000 \
            -user_agent "$USER_AGENT" -rw_timeout 8000000 \
            -show_entries stream=codec_type -of csv=p=0 "$probe_url" 2>$DEVNULL || true)
    fi

    if echo "$probe_output" | grep -qE '(^|[[:space:],])(video|audio)($|[[:space:],])'; then
        log "PRIMARY_CHECK: ffprobe decode probe passed."
        return 0
    fi

    log "PRIMARY_CHECK: ffprobe decode probe failed (no audio/video stream detected)."
    return 1
}

can_use_primary_hotswap() {
    [[ "$PRIMARY_HOTSWAP_ENABLE" == "1" ]] || return 1
    [[ "$channel_id" != .graceful_* ]] || return 1
    [[ -n "$PRIMARY_HOTSWAP_SCRIPT" ]] || return 1
    [[ -x "$PRIMARY_HOTSWAP_SCRIPT" ]] || return 1
    return 0
}

run_primary_hotswap_handoff() {
    if ! can_use_primary_hotswap; then
        return 1
    fi

    local now
    now=$(date +%s)
    if [[ $last_primary_hotswap_attempt -gt 0 ]]; then
        local elapsed=$((now - last_primary_hotswap_attempt))
        if [[ $elapsed -lt $PRIMARY_HOTSWAP_COOLDOWN ]]; then
            log "PRIMARY_HOTSWAP: Cooldown active (${elapsed}s/${PRIMARY_HOTSWAP_COOLDOWN}s). Keeping current stream."
            return 1
        fi
    fi
    last_primary_hotswap_attempt=$now

    log "PRIMARY_HOTSWAP: Starting seamless handoff via ${PRIMARY_HOTSWAP_SCRIPT} ${channel_id}"
    local rc=1
    # Pass caller PID so graceful_restart can avoid killing this runner before
    # handoff outcome is known.
    if GRACEFUL_SKIP_CALLER_KILL=1 GRACEFUL_CALLER_PID="$$" \
        timeout "$PRIMARY_HOTSWAP_TIMEOUT" "$PRIMARY_HOTSWAP_SCRIPT" "$channel_id" >> "$logfile" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    if [[ $rc -eq 0 ]]; then
        log "PRIMARY_HOTSWAP: Handoff completed successfully"
        return 0
    fi

    if [[ $rc -eq 124 ]]; then
        log_error "PRIMARY_HOTSWAP: Handoff timed out after ${PRIMARY_HOTSWAP_TIMEOUT}s"
    else
        log_error "PRIMARY_HOTSWAP: Handoff failed with exit code $rc"
    fi
    return 1
}

can_use_url_hotswap() {
    [[ "$URL_HOTSWAP_ENABLE" == "1" ]] || return 1
    [[ "$channel_id" != .graceful_* ]] || return 1
    [[ $url_count -gt 1 ]] || return 1
    [[ -n "$URL_HOTSWAP_SCRIPT" ]] || return 1
    [[ -x "$URL_HOTSWAP_SCRIPT" ]] || return 1
    return 0
}

build_url_hotswap_plan() {
    local target_index="$1"
    if [[ ! "$target_index" =~ ^[0-9]+$ || $target_index -lt 0 || $target_index -ge $url_count ]]; then
        return 1
    fi

    url_hotswap_start_index="$target_index"
    # Keep canonical URL order stable: primary remains index 0 and backups retain
    # their configured ordering. We only override the startup index.
    # Use original URLs for aloula: scheme so the new instance can self-refresh tokens.
    url_hotswap_primary_url="${url_original[0]:-${url_array[0]}}"
    if [[ -z "$url_hotswap_primary_url" ]]; then
        return 1
    fi

    url_hotswap_backup_urls=""
    local idx next_url
    for ((idx=1; idx<url_count; idx++)); do
        # Prefer original URL (preserves aloula: scheme and YouTube channel URLs)
        next_url="${url_original[$idx]:-${url_array[$idx]}}"
        [[ -n "$next_url" ]] || continue
        url_hotswap_backup_urls="${url_hotswap_backup_urls:+${url_hotswap_backup_urls}|}${next_url}"
    done

    return 0
}

run_url_hotswap_handoff() {
    local target_index="$1"
    local reason="${2:-unknown}"

    if ! can_use_url_hotswap; then
        return 1
    fi

    if [[ ! "$target_index" =~ ^[0-9]+$ || $target_index -lt 0 || $target_index -ge $url_count ]]; then
        log_error "URL_HOTSWAP: Invalid target index '$target_index' for reason '$reason'"
        return 1
    fi

    if [[ $target_index -eq $current_url_index ]]; then
        return 1
    fi

    local now
    now=$(date +%s)
    if [[ $last_url_hotswap_attempt -gt 0 ]]; then
        local elapsed=$((now - last_url_hotswap_attempt))
        if [[ $elapsed -lt $URL_HOTSWAP_COOLDOWN ]]; then
            log "URL_HOTSWAP: Cooldown active (${elapsed}s/${URL_HOTSWAP_COOLDOWN}s). Skipping failover handoff."
            return 1
        fi
    fi

    if ! build_url_hotswap_plan "$target_index"; then
        log_error "URL_HOTSWAP: Could not build URL handoff plan for target index $target_index"
        return 1
    fi

    last_url_hotswap_attempt=$now
    log "URL_HOTSWAP: Attempting seamless handoff from index $current_url_index to $target_index (reason: $reason)"
    log "URL_HOTSWAP: Preserving primary routing order with startup index $url_hotswap_start_index"
    log "URL_HOTSWAP: New primary: $url_hotswap_primary_url"
    if [[ -n "$url_hotswap_backup_urls" ]]; then
        log "URL_HOTSWAP: New backups: $url_hotswap_backup_urls"
    fi

    local rc=1
    if GRACEFUL_SKIP_CALLER_KILL=1 GRACEFUL_CALLER_PID="$$" \
        GRACEFUL_OVERRIDE_STREAM_URL="$url_hotswap_primary_url" \
        GRACEFUL_OVERRIDE_BACKUP_URLS="$url_hotswap_backup_urls" \
        GRACEFUL_OVERRIDE_START_INDEX="$url_hotswap_start_index" \
        GRACEFUL_OVERRIDE_SCALE="$scale" \
        GRACEFUL_OVERRIDE_CHANNEL_NAME="$channel_name" \
        timeout "$URL_HOTSWAP_TIMEOUT" "$URL_HOTSWAP_SCRIPT" "$channel_id" >> "$logfile" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    if [[ $rc -eq 0 ]]; then
        log "URL_HOTSWAP: Handoff completed successfully"
        return 0
    fi

    if [[ $rc -eq 124 ]]; then
        log_error "URL_HOTSWAP: Handoff timed out after ${URL_HOTSWAP_TIMEOUT}s"
    else
        log_error "URL_HOTSWAP: Handoff failed with exit code $rc"
    fi
    return 1
}

has_live_output_state() {
    local output_dir
    output_dir=$(dirname "$destination")

    if [[ -s "$destination" ]]; then
        return 0
    fi

    if find "$output_dir" -maxdepth 1 -type f -name "*.ts" -print -quit 2>$DEVNULL | grep -q .; then
        return 0
    fi

    return 1
}

attempt_url_hotswap_and_exit_if_success() {
    local target_index="$1"
    local reason="$2"

    if ! can_use_url_hotswap; then
        return 1
    fi

    if [[ "$reason" != "segment_stale" ]] && ! has_live_output_state; then
        log "URL_HOTSWAP: No live output state detected (reason: $reason). Attempting cold handoff to avoid hard switch."
    fi

    if run_url_hotswap_handoff "$target_index" "$reason"; then
        log "URL_HOTSWAP: Handoff completed. Exiting current instance."
        mark_successful_handoff_exit "url_hotswap:${reason}"
        cleanup
        exit 0
    fi

    return 1
}

check_and_fallback_to_primary() {
    # Only check if we're currently on a backup URL (not primary)
    if [[ $current_url_index -eq 0 ]]; then
        return 1  # Already on primary
    fi

    local now
    now=$(date +%s)
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

            if ! record_primary_restore_confirmation "youtube_resolve"; then
                return 1
            fi
            if ! probe_primary_media_decode "$resolved"; then
                reset_primary_restore_confirmation "decode probe failed"
                return 1
            fi

            log "PRIMARY_RESTORED: Primary YouTube stream confirmed (failback conditions met)."
            reset_primary_restore_confirmation "switching to primary"
            current_url_index=0
            reset_url_retries
            total_cycles=0
            return 0
        fi

        reset_primary_restore_confirmation "youtube primary unavailable"
        log "PRIMARY_CHECK: Primary YouTube URL not available. Staying on backup."
        return 1
    fi

    local scheme
    scheme=$(get_url_scheme "$primary_url")

    # If FFmpeg can't read this URL scheme (e.g., https not compiled in), don't attempt fallback.
    if ! ffmpeg_supports_url "$primary_url" 0; then
        reset_primary_restore_confirmation "unsupported primary protocol"
        log "PRIMARY_CHECK: Primary URL uses unsupported protocol for this ffmpeg build ($scheme). Staying on backup."
        return 1
    fi

    # Only HTTP/S sources can be preflight-checked; others must be handled by ffmpeg directly.
    if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
        reset_primary_restore_confirmation "non-http primary"
        log "PRIMARY_CHECK: Skipping health check for non-HTTP primary ($scheme). Staying on backup."
        return 1
    fi

    local health_ok=0
    local health_reason=""

    # Test primary URL health (prefer HLS playlist advancement when applicable)
    local hls_check_result=1
    hls_check_result=$(check_hls_playlist_fresh "$primary_url")

    if [[ "$hls_check_result" -eq 0 ]]; then
        health_ok=1
        health_reason="hls_advancing"
    fi

    if [[ "$hls_check_result" -eq 2 ]]; then
        local primary_status
        primary_status=$(validate_url "$primary_url")
        log "PRIMARY_CHECK: Primary URL returned HTTP $primary_status"

        # Some providers use 3xx redirects to short-lived tokenized URLs.
        # Consider 2xx/3xx as "reachable" here; we still require ffprobe decode
        # to pass before switching.
        if [[ "$primary_status" =~ ^[23][0-9]{2}$ ]]; then
            health_ok=1
            health_reason="http_${primary_status}"
        else
            reset_primary_restore_confirmation "primary HTTP $primary_status"
            log "PRIMARY_CHECK: Primary still unavailable (HTTP $primary_status). Staying on backup."
            return 1
        fi
    elif [[ "$hls_check_result" -ne 0 ]]; then
        reset_primary_restore_confirmation "hls playlist stale"
        log "PRIMARY_CHECK: Primary HLS playlist is stale. Staying on backup."
        return 1
    fi

    if [[ "$health_ok" -ne 1 ]]; then
        reset_primary_restore_confirmation "health check failed"
        return 1
    fi

    if ! record_primary_restore_confirmation "$health_reason"; then
        return 1
    fi
    if ! probe_primary_media_decode "$primary_url"; then
        reset_primary_restore_confirmation "decode probe failed"
        return 1
    fi

    log "PRIMARY_RESTORED: Primary URL confirmed healthy (failback conditions met)."
    reset_primary_restore_confirmation "switching to primary"
    current_url_index=0
    reset_url_retries
    total_cycles=0
    return 0
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

    local now
    now=$(date +%s)
    local elapsed=$((now - last_config_check))

    # Only check every CONFIG_CHECK_INTERVAL seconds
    if [[ $elapsed -lt $CONFIG_CHECK_INTERVAL ]]; then
        return 1
    fi

    last_config_check=$now
    local current_mtime
    current_mtime=$(get_file_mtime "$config_file")

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
        local b3
        b1=$(parse_config_value "$config_file" "stream_url_backup1")
        b2=$(parse_config_value "$config_file" "stream_url_backup2")
        b3=$(parse_config_value "$config_file" "stream_url_backup3")
        [[ -n "$b1" ]] && new_backups="$b1"
        [[ -n "$b2" ]] && new_backups="${new_backups:+$new_backups|}$b2"
        [[ -n "$b3" ]] && new_backups="${new_backups:+$new_backups|}$b3"
    fi

    # If primary URL changed, re-initialize metadata (works for both YouTube and regular URLs)
    if [[ -n "$new_primary" && "$new_primary" != "$primary_url" ]]; then
        log "CONFIG_RELOAD: Primary URL changed! Old: ${primary_url} -> New: $new_primary"
        primary_url="$new_primary"

        # IMPORTANT: url_array[0] is what FFmpeg actually uses when current_url_index=0.
        # Keep it in sync with primary_url; otherwise the runner keeps streaming a stale URL.
        url_array[0]="$new_primary"

        # Re-initialize metadata (handles YouTube detection automatically).
        # For non-YouTube URLs, this does not rewrite url_array[0], so we set it above.
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
        url_costly_short_runs=()
        for ((i=0; i<url_count; i++)); do
            url_retry_counts[$i]=0
            url_costly_short_runs[$i]=0
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

    # Use effective_user_agent() to pick the right UA per URL (kwikmotion
    # CDN blocks browser/tool UAs over plain HTTP).
    local ua
    ua=$(effective_user_agent "$test_url")

    # IMPORTANT: Avoid GET + -L for stream URLs; it can download large amounts of
    # data and create unnecessary provider connections. Prefer a lightweight
    # HEAD request and treat 3xx as "reachable".

    # If YTDLP_PROXY is set to Tor SOCKS proxy, use torsocks for validation
    # shellcheck disable=SC2094
    if [[ -n "$YTDLP_PROXY" ]] && proxy_is_local_tor "$YTDLP_PROXY" && command -v torsocks >$DEVNULL 2>&1; then
        if command -v timeout >$DEVNULL 2>&1; then
            response=$(timeout $((timeout + 2)) torsocks curl -A "$ua" -I -s -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
        else
            response=$(torsocks curl -A "$ua" -I -s -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
        fi
    else
        if command -v timeout >$DEVNULL 2>&1; then
            response=$(timeout $((timeout + 2)) curl -A "$ua" -I -s -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
        else
            response=$(curl -A "$ua" -I -s -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
        fi
    fi

    # Some servers block HEAD; fall back to a tiny ranged GET.
    if [[ "$response" == "405" || "$response" == "000" ]]; then
        if [[ -n "$YTDLP_PROXY" ]] && proxy_is_local_tor "$YTDLP_PROXY" && command -v torsocks >$DEVNULL 2>&1; then
            if command -v timeout >$DEVNULL 2>&1; then
                response=$(timeout $((timeout + 2)) torsocks curl -A "$ua" -s -r 0-0 -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
            else
                response=$(torsocks curl -A "$ua" -s -r 0-0 -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
            fi
        else
            if command -v timeout >$DEVNULL 2>&1; then
                response=$(timeout $((timeout + 2)) curl -A "$ua" -s -r 0-0 -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
            else
                response=$(curl -A "$ua" -s -r 0-0 -o "$DEVNULL" -w "%{http_code}" --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true)
            fi
        fi
    fi

    [[ "$response" =~ ^[0-9]{3}$ ]] || response="000"
    echo "$response"
}

fetch_url_body() {
    local test_url="$1"
    local timeout="${2:-10}"
    local ua
    ua=$(effective_user_agent "$test_url")

    # Use torsocks if proxy is configured for Tor
    if [[ -n "$YTDLP_PROXY" ]] && proxy_is_local_tor "$YTDLP_PROXY" && command -v torsocks >$DEVNULL 2>&1; then
        if command -v timeout >$DEVNULL 2>&1; then
            timeout $((timeout + 2)) torsocks curl -A "$ua" -L -s --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        else
            torsocks curl -A "$ua" -L -s --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        fi
    else
        if command -v timeout >$DEVNULL 2>&1; then
            timeout $((timeout + 2)) curl -A "$ua" -L -s --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        else
            curl -A "$ua" -L -s --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        fi
    fi
}

fetch_url_prefix() {
    local test_url="$1"
    local timeout="${2:-10}"
    local ua
    ua=$(effective_user_agent "$test_url")

    # Use torsocks if proxy is configured for Tor
    if [[ -n "$YTDLP_PROXY" ]] && proxy_is_local_tor "$YTDLP_PROXY" && command -v torsocks >$DEVNULL 2>&1; then
        if command -v timeout >$DEVNULL 2>&1; then
            timeout $((timeout + 2)) torsocks curl -A "$ua" -L -s -r 0-4096 --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        else
            torsocks curl -A "$ua" -L -s -r 0-4096 --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        fi
    else
        if command -v timeout >$DEVNULL 2>&1; then
            timeout $((timeout + 2)) curl -A "$ua" -L -s -r 0-4096 --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        else
            curl -A "$ua" -L -s -r 0-4096 --connect-timeout "$timeout" --max-time "$timeout" "$test_url" 2>$DEVNULL || true
        fi
    fi
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

    if echo "$first" | grep -q "#EXT-X-ENDLIST"; then
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
    if echo "$second" | grep -q "#EXT-X-ENDLIST"; then
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
# -hls_flags delete_segments+temp_file+omit_endlist: Atomic writes, auto-cleanup, never finalize playlist
# =============================================================================

hls_seamless=( -hls_start_number_source epoch -hls_list_size 20 )

# =============================================================================
# Slate failover: placeholder stream during URL transitions
# =============================================================================

SLATE_VIDEO="/var/www/html/stream/hls/slate/slate_loop.mp4"
slate_ffmpeg_pid=""

start_slate_stream() {
    local output="$1"
    [[ ! -f "$SLATE_VIDEO" ]] && { log "SLATE: No slate video found at $SLATE_VIDEO"; return 1; }
    [[ -n "$slate_ffmpeg_pid" ]] && kill -0 "$slate_ffmpeg_pid" 2>$DEVNULL && return 0

    log "SLATE: Starting placeholder stream..."
    ffmpeg -re -stream_loop -1 -i "$SLATE_VIDEO" \
      -c copy -map 0:v:0 -map 0:a:0 \
      -f hls -hls_time 6 -hls_list_size 15 \
      -hls_start_number_source epoch \
      -hls_flags delete_segments+temp_file+omit_endlist \
      "$output" </dev/null >$DEVNULL 2>&1 &
    slate_ffmpeg_pid=$!
    log "SLATE: Placeholder started (PID $slate_ffmpeg_pid)"
}

stop_slate_stream() {
    [[ -z "$slate_ffmpeg_pid" ]] && return
    kill -TERM "$slate_ffmpeg_pid" 2>$DEVNULL || true
    wait "$slate_ffmpeg_pid" 2>$DEVNULL || true
    slate_ffmpeg_pid=""
    log "SLATE: Placeholder stopped"
}

inject_discontinuity_tag() {
    local playlist="$1"
    [[ ! -f "$playlist" ]] && return
    # Add #EXT-X-DISCONTINUITY before the first segment entry to tell
    # players to reset their decoders after slate/stream transition.
    local tmp="${playlist}.disc_tmp"
    awk '
        /^#EXTINF:/ && !done { print "#EXT-X-DISCONTINUITY"; done=1 }
        { print }
    ' "$playlist" > "$tmp" && mv -f "$tmp" "$playlist"
}

# =============================================================================
# Always-FIFO feeder functions
# =============================================================================
# These functions manage lightweight feeder processes that write to a persistent
# FIFO. The HLS encoder reads from the FIFO and is never killed for source
# issues — only the feeder is killed and replaced.
# =============================================================================

# start_http_feeder — Lightweight FFmpeg copy-mode feeder for HTTP/RTMP sources
start_http_feeder() {
    local source_url="$1" fifo_path="$2"
    local feeder_cmd=( ffmpeg -loglevel error )
    local scheme
    scheme=$(get_url_scheme "$source_url")
    if [[ "$scheme" == "http" || "$scheme" == "https" ]]; then
        local ua
        ua=$(effective_user_agent "$source_url")
        feeder_cmd+=( -user_agent "$ua" -rw_timeout 30000000 )
        feeder_cmd+=( -reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 30 )
    fi
    feeder_cmd+=( -err_detect ignore_err -fflags +discardcorrupt+genpts )
    feeder_cmd+=( -i "$source_url" -c copy -f mpegts pipe:1 )
    local feeder_cmd_pretty
    printf -v feeder_cmd_pretty "%q " "${feeder_cmd[@]}"
    "${feeder_cmd[@]}" > "$fifo_path" 2>>"$logfile" &
    feeder_pid=$!
    feeder_is_slate=0
    log "FEEDER: Started HTTP feeder PID $feeder_pid: $feeder_cmd_pretty"
}

# start_slate_feeder — Loops slate video into the FIFO to keep HLS alive
start_slate_feeder() {
    local fifo_path="$1"
    [[ ! -f "$SLATE_VIDEO" ]] && { log "FEEDER_SLATE: No slate video at $SLATE_VIDEO"; return 1; }
    ffmpeg -loglevel error -re -stream_loop -1 -i "$SLATE_VIDEO" \
        -c copy -f mpegts pipe:1 \
        > "$fifo_path" 2>>"$logfile" &
    feeder_pid=$!
    feeder_is_slate=1
    slate_was_active=1
    log "FEEDER_SLATE: Started slate feeder PID $feeder_pid"
}

# swap_to_slate_feeder — Atomic kill-current + start-slate (zero-gap transition)
# Idempotent: returns 0 if already on slate. Pre-checks SLATE_VIDEO BEFORE
# killing the current feeder so we never lose a working feeder if slate is unavailable.
swap_to_slate_feeder() {
    # Already on slate and feeder alive → nothing to do
    if [[ "$feeder_is_slate" -eq 1 ]] && [[ -n "$feeder_pid" ]] && kill -0 "$feeder_pid" 2>$DEVNULL; then
        return 0
    fi
    # Pre-check: can we actually start slate?
    if [[ ! -f "$SLATE_VIDEO" ]]; then
        log "SWAP_SLATE: No slate video at $SLATE_VIDEO — cannot inject slate"
        return 1
    fi
    kill_feeder
    if start_slate_feeder "$stream_fifo"; then
        log "SWAP_SLATE: Swapped to slate feeder"
        return 0
    else
        log_error "SWAP_SLATE: Failed to start slate feeder"
        return 1
    fi
}

# probe_and_restore_source — Background probe loop while slate plays
# Runs when all sources are exhausted. Probes each URL every PROBE_INTERVAL
# seconds and verifies with segment production before presenting to viewers.
# Returns 0 if a source was verified and is now live, 1 if encoder died.
probe_and_restore_source() {
    local PROBE_INTERVAL="${PROBE_RESTORE_INTERVAL:-30}"
    local PROBE_VERIFY_TIMEOUT="${PROBE_RESTORE_VERIFY_TIMEOUT:-15}"
    # Guard against non-numeric env overrides that would cause sleep to fail
    # and the loop to spin at 100% CPU.
    [[ "$PROBE_INTERVAL" =~ ^[0-9]+$ ]] || PROBE_INTERVAL=30
    [[ "$PROBE_VERIFY_TIMEOUT" =~ ^[0-9]+$ ]] || PROBE_VERIFY_TIMEOUT=15
    log "PROBE_RESTORE: Entering probe mode. Checking sources every ${PROBE_INTERVAL}s."

    while true; do
        # If encoder died, break out — outer loop handles restart
        if ! is_process_running "$ffmpeg_pid"; then
            log "PROBE_RESTORE: Encoder died during probe mode. Exiting."
            return 1
        fi

        # If slate feeder died, restart it to keep viewers seeing slate
        if [[ -n "$feeder_pid" ]] && ! kill -0 "$feeder_pid" 2>$DEVNULL; then
            wait "$feeder_pid" 2>$DEVNULL || true
            log "PROBE_RESTORE: Slate feeder died. Restarting slate."
            start_slate_feeder "$stream_fifo" || true
        fi

        # Hot-reload config during probe mode
        reload_config_if_changed

        sleep "$PROBE_INTERVAL"

        # Probe each URL in order
        local probe_idx
        for ((probe_idx=0; probe_idx<url_count; probe_idx++)); do
            local probe_url="${url_array[$probe_idx]}"

            # Prepare provider-specific URLs before probing
            if [[ "${url_is_seenshow[$probe_idx]:-0}" == "1" ]]; then
                if ! prepare_seenshow_url_for_index "$probe_idx"; then
                    log "PROBE_RESTORE: Seenshow prepare failed for index $probe_idx. Skipping."
                    continue
                fi
                probe_url="${url_array[$probe_idx]}"
            elif is_aloula_url "${url_original[$probe_idx]:-}"; then
                if ! prepare_aloula_url_for_index "$probe_idx"; then
                    log "PROBE_RESTORE: Aloula prepare failed for index $probe_idx. Skipping."
                    continue
                fi
                probe_url="${url_array[$probe_idx]}"
            elif is_elahmad_url "${url_original[$probe_idx]:-}"; then
                if ! prepare_elahmad_url_for_index "$probe_idx"; then
                    log "PROBE_RESTORE: Elahmad prepare failed for index $probe_idx. Skipping."
                    continue
                fi
                probe_url="${url_array[$probe_idx]}"
            fi

            # Lightweight HTTP probe (skip for seenshow — creates connections)
            if [[ "${url_is_seenshow[$probe_idx]:-0}" != "1" ]]; then
                local http_status
                http_status=$(validate_url "$probe_url")
                if is_4xx_error "$http_status" || [[ "$http_status" == "000" ]]; then
                    # Proxy-needed HTTPS URLs can return false 4xx to curl but
                    # still stream via streamlink — mirror startup preflight logic.
                    local probe_uses_https_proxy=0
                    if needs_https_proxy "$probe_url"; then
                        probe_uses_https_proxy=1
                    fi
                    if [[ "$probe_uses_https_proxy" -eq 0 ]]; then
                        continue
                    fi
                    log "PROBE_RESTORE: HTTP $http_status on proxy URL index $probe_idx; attempting test-feed anyway"
                fi
            fi

            # Source looks reachable — test-feed to verify actual segment production
            log "PROBE_RESTORE: URL index $probe_idx probe passed. Test-feeding..."
            kill_feeder   # kills slate
            current_url_index=$probe_idx
            current_url="${url_array[$probe_idx]}"
            start_feeder_for_current_url
            feeder_restart_count=0

            # Wait up to PROBE_VERIFY_TIMEOUT seconds for segment advancement.
            # We track the newest segment by mtime, not file count, because
            # -hls_flags delete_segments keeps count constant while stream is live.
            local dest_dir
            dest_dir=$(dirname "$destination")
            local baseline_seg
            baseline_seg=$(find "$dest_dir" -maxdepth 1 -name "*.ts" -type f -printf '%T@ %f\n' 2>$DEVNULL | sort -n | tail -1 | awk '{print $2}')
            local advances=0
            local verified=0
            local attempt
            for ((attempt=1; attempt<=PROBE_VERIFY_TIMEOUT; attempt++)); do
                sleep 1
                # Check if encoder died
                if ! is_process_running "$ffmpeg_pid"; then
                    log "PROBE_RESTORE: Encoder died during verification."
                    return 1
                fi
                # Check if feeder died
                if [[ -n "$feeder_pid" ]] && ! kill -0 "$feeder_pid" 2>$DEVNULL; then
                    log "PROBE_RESTORE: Feeder died during verification for index $probe_idx."
                    break
                fi
                # Check for segment advancement by identity (not count)
                local newest_seg
                newest_seg=$(find "$dest_dir" -maxdepth 1 -name "*.ts" -type f -printf '%T@ %f\n' 2>$DEVNULL | sort -n | tail -1 | awk '{print $2}')
                if [[ -n "$newest_seg" && "$newest_seg" != "$baseline_seg" ]]; then
                    advances=$((advances + 1))
                    baseline_seg="$newest_seg"
                fi
                # Require 2 advancements to confirm sustained segment production
                if [[ $advances -ge 2 ]]; then
                    verified=1
                    break
                fi
            done

            if [[ $verified -eq 1 ]]; then
                log "PROBE_RESTORE: Source index $probe_idx verified ($advances segment advancements)! Presenting real stream."
                total_cycles=0
                feeder_restart_count=0
                return 0
            else
                log "PROBE_RESTORE: Verification failed for index $probe_idx (advances=$advances). Back to slate."
                swap_to_slate_feeder || true
            fi
        done

        log "PROBE_RESTORE: All URLs probed, none verified. Staying on slate."
    done

    return 1
}

# kill_feeder — Stop feeder process and its children without touching encoder
kill_feeder() {
    [[ -z "$feeder_pid" ]] && return
    kill -0 "$feeder_pid" 2>$DEVNULL || { wait "$feeder_pid" 2>$DEVNULL || true; feeder_pid=""; return; }
    kill -TERM "$feeder_pid" 2>$DEVNULL || true
    pkill -TERM -P "$feeder_pid" 2>$DEVNULL || true
    local i
    for i in {1..4}; do
        kill -0 "$feeder_pid" 2>$DEVNULL || break
        sleep 0.5
    done
    if kill -0 "$feeder_pid" 2>$DEVNULL; then
        kill -KILL "$feeder_pid" 2>$DEVNULL || true
        pkill -KILL -P "$feeder_pid" 2>$DEVNULL || true
    fi
    wait "$feeder_pid" 2>$DEVNULL || true
    feeder_pid=""
    feeder_is_slate=0
}

# start_feeder_for_current_url — Dispatch to correct feeder type for current URL
start_feeder_for_current_url() {
    local url="${url_array[$current_url_index]}"
    if [[ "${url_is_youtube[$current_url_index]}" == "1" ]] || needs_https_proxy "$url"; then
        # Use streamlink for HTTPS/YouTube sources (same as existing proxy path)
        if ! command -v streamlink >$DEVNULL 2>&1; then
            log_error "FEEDER: streamlink not found for ${url:0:80}; falling back to HTTP feeder"
            start_http_feeder "$url" "$stream_fifo"
            feeder_last_restart_time=$(date +%s)
            return
        fi
        set_streamlink_args "$url"
        "${streamlink_args[@]}" > "$stream_fifo" 2>>"$logfile" &
        feeder_pid=$!
        feeder_is_slate=0
        log "FEEDER: Started streamlink feeder PID $feeder_pid for ${url:0:80}"
    else
        start_http_feeder "$url" "$stream_fifo"
    fi
    feeder_last_restart_time=$(date +%s)
}

# switch_feeder_to_next_url — Source switch without killing encoder
# Optional arg $1 = recursion depth (default 0). Guards against infinite loops
# when all provider URLs fail their prepare step.
switch_feeder_to_next_url() {
    local depth="${1:-0}"
    if [[ $depth -ge $url_count ]]; then
        log_error "FEEDER_SWITCH: All $url_count URLs failed prepare. Injecting slate."
        swap_to_slate_feeder || start_slate_feeder "$stream_fifo" || true
        return
    fi

    # Slate-first: protect viewers immediately before any switching logic
    swap_to_slate_feeder || true
    local previous_index="$current_url_index"
    current_url_index=$(( (current_url_index + 1) % url_count ))
    log "FEEDER_SWITCH: Switching feeder to URL index $current_url_index"

    # If we are leaving Seenshow for a non-Seenshow URL, release slot immediately.
    if [[ "${url_is_seenshow[$previous_index]:-0}" == "1" && "${url_is_seenshow[$current_url_index]:-0}" != "1" ]]; then
        seenshow_release_slot
    fi

    # Full cycle detection — enter probe mode if all URLs exhausted
    if [[ $current_url_index -eq 0 ]]; then
        total_cycles=$((total_cycles + 1))
        log "FEEDER_CYCLE: Completed URL cycle $total_cycles of $max_cycles"
        if [[ $total_cycles -ge $max_cycles ]]; then
            log "FEEDER_CYCLE: All URLs exhausted after $max_cycles cycles. Entering probe mode."
            # Ensure slate is playing (idempotent)
            swap_to_slate_feeder || true
            if probe_and_restore_source; then
                # Source verified and live — return to caller
                return
            fi
            # Probe mode exited (encoder died) — let outer loop handle
            return
        fi
    fi

    current_url="${url_array[$current_url_index]}"

    # Prepare provider-specific URLs (slot acquire, token refresh) before starting feeder.
    # In the non-FIFO path, the outer while loop handles this; in FIFO mode we must do it here.
    if [[ "${url_is_seenshow[$current_url_index]:-0}" == "1" ]]; then
        if ! prepare_seenshow_url_for_index "$current_url_index"; then
            log_error "FEEDER_SWITCH: Seenshow prepare failed for URL index $current_url_index. Skipping."
            feeder_restart_count=0
            switch_feeder_to_next_url $((depth + 1))
            return
        fi
        current_url="${url_array[$current_url_index]}"
    elif is_aloula_url "${url_original[$current_url_index]:-}"; then
        if ! prepare_aloula_url_for_index "$current_url_index"; then
            log_error "FEEDER_SWITCH: Aloula prepare failed for URL index $current_url_index. Skipping."
            feeder_restart_count=0
            switch_feeder_to_next_url $((depth + 1))
            return
        fi
        current_url="${url_array[$current_url_index]}"
    elif is_elahmad_url "${url_original[$current_url_index]:-}"; then
        if ! prepare_elahmad_url_for_index "$current_url_index"; then
            log_error "FEEDER_SWITCH: Elahmad prepare failed for URL index $current_url_index. Skipping."
            feeder_restart_count=0
            switch_feeder_to_next_url $((depth + 1))
            return
        fi
        current_url="${url_array[$current_url_index]}"
    fi

    # Kill slate and start real feeder
    kill_feeder
    start_feeder_for_current_url
    feeder_restart_count=0
}

# calculate_feeder_backoff — Exponential backoff for feeder restarts
calculate_feeder_backoff() {
    local delay=1 i
    for ((i=0; i<feeder_restart_count && i<5; i++)); do
        delay=$((delay * 2))
    done
    [[ $delay -gt $FEEDER_MAX_RESTART_BACKOFF ]] && delay=$FEEDER_MAX_RESTART_BACKOFF
    echo "$delay"
}

# =============================================================================
# CPU guard: kill runaway FFmpeg processes
# =============================================================================

check_ffmpeg_cpu_usage() {
    [[ -z "$ffmpeg_pid" ]] && return 0
    local cpu
    cpu=$(ps -p "$ffmpeg_pid" -o %cpu= 2>$DEVNULL | tr -d ' ')
    [[ -z "$cpu" ]] && return 0
    local cpu_int=${cpu%.*}
    if [[ $cpu_int -gt 200 ]]; then
        log "CPU_GUARD: FFmpeg PID $ffmpeg_pid using ${cpu}% CPU — killing to prevent system overload"
        kill -TERM "$ffmpeg_pid" 2>$DEVNULL
        return 1
    fi
    return 0
}

# =============================================================================
# Build FFmpeg command based on scale
# =============================================================================

build_ffmpeg_cmd() {
    local stream_url="$1"
    local output_path="$2"

    # Check if we need HTTPS proxy (yt-dlp pipe) or ALWAYS_FIFO pipe
    use_https_proxy=0
    actual_input_url="$stream_url"

    if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
        # ALWAYS_FIFO: force pipe:0 input for all source types
        use_https_proxy=1
        actual_input_url="pipe:0"
        if [[ "$scale" -eq 4 || "$scale" -eq 3 || "$scale" -eq 12 || "$scale" -eq 13 ]]; then
            log "ALWAYS_FIFO: Downgrading scale $scale -> 9 (software decode) for pipe input"
            local effective_scale=9
        fi
    elif needs_https_proxy "$stream_url"; then
        use_https_proxy=1
        actual_input_url="pipe:0"
        log "HTTPS_PROXY: Will use proxy for HTTPS stream (ffmpeg lacks TLS support)"
        # CUVID hardware decoder (scales 4,3,12,13) cannot handle pipe input — the
        # decoder requires seekable/probeable input.  Use a local override so the
        # global $scale is preserved for future retries on non-HTTPS URLs.
        if [[ "$scale" -eq 4 || "$scale" -eq 3 || "$scale" -eq 12 || "$scale" -eq 13 ]]; then
            log "HTTPS_PROXY: Downgrading scale $scale → 9 (software decode) for pipe input"
            local effective_scale=9
        fi
    fi
    local effective_scale="${effective_scale:-$scale}"

    ffmpeg_cmd=( ffmpeg -loglevel error )
    local scheme
    scheme=$(get_url_scheme "$stream_url")

    # Only add HTTP flags for direct HTTP connections (not for pipe input)
    if [[ "$use_https_proxy" -eq 0 && ("$scheme" == "http" || "$scheme" == "https") ]]; then
        local ua
        ua=$(effective_user_agent "$stream_url")
        ffmpeg_cmd+=( -user_agent "$ua" -rw_timeout 30000000 -reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5 )
    fi

    case "$effective_scale" in
        4|3)
            # GPU: CUDA decode + scale to 1080p + NVENC encode
            # Standard re-encode mode for sources needing normalization
            # (scale 3 aliased here — always scale to ensure consistent 1080p)
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$actual_input_url" )
            ffmpeg_cmd+=( -map 0:v:0 -map 0:a:0? )
            ffmpeg_cmd+=( -vf "scale_npp=1920:1080" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -profile:v high -level:v auto -g 180 -keyint_min 180 -bf 0 )
            ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k -threads 4 )
            ffmpeg_cmd+=( -c:a aac -b:a 192k -ar 48000 -ac 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file+omit_endlist "$output_path" )
            ;;
        9|5|6|10|11)
            # GPU tolerant: Software decode (error tolerant) + GPU scale + NVENC encode
            # For corrupted/RTMP sources where h264_cuvid fails
            # Falls back to full CPU pipeline if GPU is unavailable
            # (scales 5,6,10,11 aliased here)
            ffmpeg_cmd+=( -err_detect ignore_err -fflags +discardcorrupt+genpts )
            ffmpeg_cmd+=( -i "$actual_input_url" )
            ffmpeg_cmd+=( -map 0:v:0 -map 0:a:0? )
            if nvidia-smi >$DEVNULL 2>&1; then
                ffmpeg_cmd+=( -vf "format=nv12,hwupload_cuda,scale_npp=1920:1080" )
                ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune ll -profile:v high -level:v auto -g 180 -keyint_min 180 -bf 0 )
                ffmpeg_cmd+=( -b:v 3500k -maxrate 4000k -bufsize 7000k -threads 4 )
            else
                log "SCALE9: GPU unavailable, falling back to full CPU pipeline"
                ffmpeg_cmd+=( -vf "scale=1920:1080" )
                ffmpeg_cmd+=( -c:v libx264 -preset ultrafast -tune zerolatency -profile:v high -level:v auto -g 180 -keyint_min 180 )
                ffmpeg_cmd+=( -b:v 2500k -maxrate 3000k -bufsize 6000k -threads 4 )
            fi
            ffmpeg_cmd+=( -c:a aac -b:a 192k -ar 48000 -ac 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file+omit_endlist "$output_path" )
            ;;
        12|13)
            # GPU stretch: CUDA decode + stretch-fill to 1920x1080 + NVENC encode
            # For sources with non-16:9 aspect ratios (black bar removal)
            # (scale 13 aliased here)
            ffmpeg_cmd+=( -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i "$actual_input_url" )
            ffmpeg_cmd+=( -map 0:v:0 -map 0:a:0? )
            ffmpeg_cmd+=( -vf "scale_npp=w=1920:h=1080:interp_algo=lanczos" )
            ffmpeg_cmd+=( -c:v h264_nvenc -preset p4 -tune hq -rc vbr -cq 19 -profile:v high -level:v auto -g 180 -keyint_min 180 -bf 2 )
            ffmpeg_cmd+=( -b:v 6000k -maxrate 8000k -bufsize 12000k -threads 4 )
            ffmpeg_cmd+=( -c:a aac -b:a 192k -ar 48000 -ac 2 )
            ffmpeg_cmd+=( -f hls -hls_time 6 )
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file+omit_endlist "$output_path" )
            ;;
        *)
            # Copy: Stream copy, no processing (scales 0, 2, 7, 8 and default)
            # Select first video + first audio only to avoid multi-track issues
            if [[ "$use_https_proxy" -eq 1 ]]; then
                # Pipe input: no -re (data arrives at source rate), add error tolerance
                ffmpeg_cmd+=( -err_detect ignore_err -fflags +discardcorrupt+genpts )
                ffmpeg_cmd+=( -i "$actual_input_url" -map 0:v:0 -map 0:a:0? -c copy -f hls -hls_time 6 )
            else
                ffmpeg_cmd+=( -re -i "$actual_input_url" -map 0:v:0 -map 0:a:0? -c copy -f hls -hls_time 6 )
            fi
            ffmpeg_cmd+=( "${hls_seamless[@]}" -hls_flags delete_segments+temp_file+omit_endlist "$output_path" )
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
    init_url_youtube_metadata "$i" "${url_array[$i]}" "" "1"  # 1 = startup mode (enables stagger)
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

current_url_index="$requested_start_url_index"
total_cycles=0
max_cycles=5
cycle_start_time=0

# Per-URL retry state
declare -a url_retry_counts
declare -a url_costly_short_runs
for ((i=0; i<url_count; i++)); do
    url_retry_counts[$i]=0
    url_costly_short_runs[$i]=0
done

log_console "Starting [$channel_id] with ${url_count} URL(s)"
if [[ $current_url_index -ne 0 ]]; then
    log "START_INDEX: Starting on URL index $current_url_index while preserving primary index 0 routing"
fi

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
        url_costly_short_runs[$i]=0
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

    # If we are leaving Seenshow for a non-Seenshow URL, release slot immediately.
    if [[ "${url_is_seenshow[$previous_index]:-0}" == "1" && "${url_is_seenshow[$current_url_index]:-0}" != "1" ]]; then
        seenshow_release_slot
    fi

    if [[ $previous_index -eq 0 && $current_url_index -ne 0 ]]; then
        # Delay primary health checks after failing over to backup.
        last_primary_check=$(date +%s)
        reset_primary_restore_confirmation "entered backup URL"
        log "PRIMARY_CHECK: Delaying primary checks for ${PRIMARY_CHECK_INTERVAL}s after failover"
    fi

    if [[ $current_url_index -eq 0 ]]; then
        reset_primary_restore_confirmation "returned to primary URL"
        # Completed a full cycle through all URLs
        total_cycles=$((total_cycles + 1))
        log "CYCLE_COMPLETE: Completed URL cycle $total_cycles of $max_cycles"

        # Calculate time spent in this cycle
        local cycle_end_time
        cycle_end_time=$(date +%s)
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

wait_for_pid_exit() {
    local pid="$1"
    local timeout_seconds="${2:-10}"
    local waited=0

    while is_process_running "$pid"; do
        if (( waited >= timeout_seconds )); then
            return 124
        fi
        sleep 1
        waited=$((waited + 1))
    done

    return 0
}

# =============================================================================
# CRITICAL FIX: Check for existing FFmpeg processes before starting new one
# =============================================================================
# Prevents duplicate FFmpeg processes for the same channel which breaks streams
# due to source URL security limiting to 1 connection per URL
# =============================================================================

check_existing_ffmpeg() {
    local escaped_channel_id
    escaped_channel_id=$(printf '%s' "$channel_id" | sed 's/[][\\.^$*+?{}|()]/\\&/g')

    # Check for existing FFmpeg processes for this channel (not started by us)
    local existing_pids
    existing_pids=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master" 2>$DEVNULL || true)

    if [[ -n "$existing_pids" ]]; then
        # Filter out our own FFmpeg (current, recently exited, and slate placeholder)
        for pid in $existing_pids; do
            if [[ "$pid" != "$ffmpeg_pid" && "$pid" != "$last_ffmpeg_pid" && "$pid" != "$$" && "$pid" != "$slate_ffmpeg_pid" ]]; then
                log_error "DUPLICATE_DETECTED: Another FFmpeg (PID $pid) is already running for $channel_id"
                return 1
            fi
        done
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

    # NEW: Check if primary URL is back online (only when on backup).
    # In hot-swap mode, defer failback decisions to the live monitoring loop so
    # we can hand off without stopping the currently running stream first.
    if [[ "$PRIMARY_HOTSWAP_ENABLE" != "1" || $current_url_index -eq 0 || "$channel_id" == .graceful_* ]]; then
        if check_and_fallback_to_primary; then
            log "Switched back to primary URL. Continuing with primary..."
        fi
    fi

    current_url="${url_array[$current_url_index]}"
    current_retries=${url_retry_counts[$current_url_index]}

    # Release any held slot when running a non-Seenshow URL.
    if [[ "${url_is_seenshow[$current_url_index]:-0}" != "1" ]]; then
        seenshow_release_slot
    fi

    # On-demand Seenshow token resolution + semaphore acquire.
    if [[ "${url_is_seenshow[$current_url_index]:-0}" == "1" ]]; then
        if ! prepare_seenshow_url_for_index "$current_url_index"; then
            log_error "SEENSHOW: Failed to prepare URL index $current_url_index. Switching."
            switch_to_next_url "seenshow_prepare_failed"
            continue
        fi
        current_url="${url_array[$current_url_index]}"
    fi

    # On-demand Aloula/KwikMotion token refresh.
    if is_aloula_url "${url_original[$current_url_index]:-}"; then
        if ! prepare_aloula_url_for_index "$current_url_index"; then
            log_error "ALOULA: Failed to prepare URL index $current_url_index. Switching."
            switch_to_next_url "aloula_prepare_failed"
            continue
        fi
        current_url="${url_array[$current_url_index]}"
    fi

    # On-demand elahmad URL refresh.
    if is_elahmad_url "${url_original[$current_url_index]:-}"; then
        if ! prepare_elahmad_url_for_index "$current_url_index"; then
            log_error "ELAHMAD: Failed to prepare URL index $current_url_index. Switching."
            switch_to_next_url "elahmad_prepare_failed"
            continue
        fi
        current_url="${url_array[$current_url_index]}"
    fi

    log "ATTEMPT: URL index $current_url_index, retry $current_retries"

    # Fast-fail unsupported URL schemes (e.g., https when ffmpeg lacks TLS)
    if ! ffmpeg_supports_url "$current_url" "$current_url_index"; then
        scheme=$(get_url_scheme "$current_url")
        log_error "UNSUPPORTED_PROTOCOL: ffmpeg does not support input protocol '$scheme' (URL index $current_url_index). Switching."
        switch_to_next_url "unsupported_protocol"
        continue
    fi

    # Pre-flight URL validation (detect 4xx early) for HTTP/S only.
    # IMPORTANT: for HTTPS inputs that require streamlink proxying, curl preflight
    # can return false 4xx (geo/WAF) while streamlink+tunnel still works. In that
    # case, continue and let the proxy fetch path decide.
    scheme=$(get_url_scheme "$current_url")
    if [[ "$scheme" == "http" || "$scheme" == "https" ]]; then
        if [[ "${url_is_seenshow[$current_url_index]:-0}" == "1" ]]; then
            # Seenshow probe requests create extra account connections. Skip curl
            # preflight entirely and trust resolver freshness/expiry tracking.
            log "SEENSHOW: Skipping preflight probe for URL index $current_url_index"
        else
            preflight_uses_https_proxy=0
            if [[ "$scheme" == "https" ]] && needs_https_proxy "$current_url"; then
                preflight_uses_https_proxy=1
            fi

            http_status=$(validate_url "$current_url")
            log "URL validation status: $http_status"

            if is_4xx_error "$http_status"; then
                if [[ "$preflight_uses_https_proxy" -eq 1 ]]; then
                    log "HTTPS_PROXY: Preflight returned HTTP $http_status for URL index $current_url_index; attempting proxy fetch before failover"
                else
                    log_error "4XX_ERROR: HTTP $http_status on URL index $current_url_index - immediate switch"
                    next_url_index=$(( (current_url_index + 1) % url_count ))
                    attempt_url_hotswap_and_exit_if_success "$next_url_index" "HTTP_${http_status}" || true
                    switch_to_next_url "HTTP_${http_status}"
                    continue
                fi
            fi
        fi
    else
        log "URL validation skipped for non-HTTP scheme: $scheme"
    fi

    # CRITICAL: Check for existing FFmpeg processes before starting new one
    # This prevents duplicate processes which break streams due to source URL limits
    if ! check_existing_ffmpeg; then
        log_error "DUPLICATE_EXIT: Exiting to avoid duplicate FFmpeg processes for $channel_id"
        log_error "DUPLICATE_EXIT: Another instance is already streaming. This script will exit."
        cleanup
        exit 0
    fi

    # Stop slate before starting real stream
    slate_was_active=0
    if [[ -n "$slate_ffmpeg_pid" ]]; then
        slate_was_active=1
        stop_slate_stream
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
    proxy_watchdog_strikes=0
    proxy_cputime_prev=""
    stream_fifo="/dev/shm/stream_pipe_${channel_id}_$$"
    if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
        # =================================================================
        # ALWAYS_FIFO: Persistent FIFO with held-open write FD
        # The feeder writes to the FIFO; the encoder reads from it.
        # A held-open FD prevents EOF when the feeder dies — the encoder
        # just blocks briefly until a new feeder starts writing.
        # =================================================================
        if [[ ! -d "/dev/shm" || ! -w "/dev/shm" ]]; then
            stream_fifo="/tmp/stream_pipe_${channel_id}_$$"
            log "ALWAYS_FIFO: /dev/shm unavailable; using $stream_fifo"
        fi
        rm -f "$stream_fifo" 2>$DEVNULL
        if ! mkfifo "$stream_fifo" 2>$DEVNULL; then
            fallback_fifo="/tmp/stream_pipe_${channel_id}_$$"
            if [[ "$stream_fifo" != "$fallback_fifo" ]]; then
                log "ALWAYS_FIFO: FIFO create failed at $stream_fifo; retrying $fallback_fifo"
                stream_fifo="$fallback_fifo"
                rm -f "$stream_fifo" 2>$DEVNULL
                mkfifo "$stream_fifo" 2>$DEVNULL || stream_fifo=""
            else
                stream_fifo=""
            fi
        fi
        if [[ -z "$stream_fifo" || ! -p "$stream_fifo" ]]; then
            log_error "ALWAYS_FIFO: Failed to create FIFO. Switching URL."
            switch_to_next_url "fifo_failed"
            continue
        fi

        # Hold FIFO open (read-write) so neither side blocks on open, and
        # FFmpeg doesn't get EOF when the feeder dies.
        if ! exec {fifo_write_fd}<>"$stream_fifo"; then
            log_error "ALWAYS_FIFO: Failed to open keepalive FD on FIFO. Switching URL."
            rm -f "$stream_fifo" 2>$DEVNULL
            stream_fifo=""
            switch_to_next_url "fifo_fd_open_failed"
            continue
        fi

        # Start encoder (reads from FIFO, runs for hours/days)
        "${ffmpeg_cmd[@]}" < "$stream_fifo" >> "$logfile" 2>"$ffmpeg_error_file" &
        ffmpeg_pid=$!

        # Start initial feeder (writes to FIFO)
        feeder_restart_count=0
        start_feeder_for_current_url

        log "ALWAYS_FIFO: Encoder PID=$ffmpeg_pid, Feeder PID=$feeder_pid (FD $fifo_write_fd held open)"
    elif [[ "$use_https_proxy" -eq 1 ]]; then
        if [[ ! -d "/dev/shm" || ! -w "/dev/shm" ]]; then
            stream_fifo="/tmp/stream_pipe_${channel_id}_$$"
            log "HTTPS_PROXY: /dev/shm unavailable or not writable; using $stream_fifo"
        fi
        # Create FIFO for reliable PID capture of both proxy and FFmpeg
        rm -f "$stream_fifo" 2>$DEVNULL
        if ! mkfifo "$stream_fifo" 2>$DEVNULL; then
            # /dev/shm can exist but still reject writes due sandboxing/policies.
            # Retry in /tmp before deciding proxy startup is unsafe.
            fallback_fifo="/tmp/stream_pipe_${channel_id}_$$"
            if [[ "$stream_fifo" != "$fallback_fifo" ]]; then
                log "HTTPS_PROXY: FIFO create failed at $stream_fifo; retrying $fallback_fifo"
                stream_fifo="$fallback_fifo"
                rm -f "$stream_fifo" 2>$DEVNULL
                if ! mkfifo "$stream_fifo" 2>$DEVNULL; then
                    log_error "HTTPS_PROXY: Failed to create FIFO in both /dev/shm and /tmp; safe failover to next URL"
                    stream_fifo=""
                fi
            else
                log_error "HTTPS_PROXY: Failed to create FIFO; safe failover to next URL"
                stream_fifo=""
            fi
        fi
        # Hard safety: only use FIFO if it is actually a named pipe
        if [[ -n "$stream_fifo" && ! -p "$stream_fifo" ]]; then
            log_error "HTTPS_PROXY: $stream_fifo is not a FIFO; safe failover to next URL"
            rm -f "$stream_fifo" 2>$DEVNULL
            stream_fifo=""
        fi
        if [[ -z "$stream_fifo" || ! -p "$stream_fifo" ]]; then
            log_error "HTTPS_PROXY: Cannot safely start proxy+ffmpeg pair without FIFO. Switching URL."
            switch_to_next_url "proxy_fifo_unavailable"
            continue
        fi

        if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
            # Use streamlink for resolved YouTube HLS (FFmpeg lacks HTTPS support)
            if ! command -v streamlink >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: streamlink not found for YouTube URL; switching to next URL"
                rm -f "$stream_fifo" 2>$DEVNULL
                switch_to_next_url "proxy_missing"
                continue
            fi
            # Get the resolved HLS manifest URL (already resolved by init_url_youtube_metadata)
            proxy_source_url="${url_array[$current_url_index]}"
            if [[ "$proxy_source_url" == *"youtube.com"* || "$proxy_source_url" == *"youtu.be"* ]]; then
                log_error "HTTPS_PROXY: YouTube URL did not resolve to a stream; switching to next URL"
                rm -f "$stream_fifo" 2>$DEVNULL
                switch_to_next_url "youtube_resolve_failed"
                continue
            fi
            log "HTTPS_PROXY: Starting streamlink pipe for YouTube HLS: ${proxy_source_url:0:80}..."

            # Build streamlink command with optional proxy
            set_streamlink_args "$proxy_source_url"

            # Use FIFO for reliable PID capture
            "${streamlink_args[@]}" > "$stream_fifo" 2>>"$logfile" &
            proxy_pid=$!
            "${ffmpeg_cmd[@]}" < "$stream_fifo" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            log "FFmpeg PID: $ffmpeg_pid, streamlink PID: ${proxy_pid:-unknown}"
        elif [[ "$current_url" == *.m3u8* ]]; then
            if ! command -v streamlink >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: streamlink not found for HLS URL; switching to next URL"
                rm -f "$stream_fifo" 2>$DEVNULL
                switch_to_next_url "proxy_missing"
                continue
            fi
            log "HTTPS_PROXY: Starting streamlink pipe for HLS: $current_url"
            # Build streamlink command with optional proxy
            set_streamlink_args "$current_url"

            "${streamlink_args[@]}" > "$stream_fifo" 2>>"$logfile" &
            proxy_pid=$!
            "${ffmpeg_cmd[@]}" < "$stream_fifo" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            log "FFmpeg PID: $ffmpeg_pid, streamlink PID: ${proxy_pid:-unknown}"
        else
            if ! command -v streamlink >$DEVNULL 2>&1; then
                log_error "HTTPS_PROXY: streamlink not found for HTTPS URL; switching to next URL"
                rm -f "$stream_fifo" 2>$DEVNULL
                switch_to_next_url "proxy_missing"
                continue
            fi
            log "HTTPS_PROXY: Starting streamlink pipe for: $current_url"
            # Build streamlink command with optional proxy
            set_streamlink_args "$current_url"

            "${streamlink_args[@]}" > "$stream_fifo" 2>>"$logfile" &
            proxy_pid=$!
            "${ffmpeg_cmd[@]}" < "$stream_fifo" >> "$logfile" 2>"$ffmpeg_error_file" &
            ffmpeg_pid=$!
            log "FFmpeg PID: $ffmpeg_pid, streamlink PID: ${proxy_pid:-unknown}"
        fi
        # Remove FIFO after both processes are started (they already have file descriptors open)
        [[ -n "$stream_fifo" ]] && rm -f "$stream_fifo" 2>$DEVNULL
    else
        stream_fifo=""  # No FIFO used for direct FFmpeg
        "${ffmpeg_cmd[@]}" >> "$logfile" 2>"$ffmpeg_error_file" &
        ffmpeg_pid=$!
        log "FFmpeg PID: $ffmpeg_pid"
    fi

    while is_process_running "$ffmpeg_pid"; do
        sleep 1

        # SLATE→REAL DISCONTINUITY: After the first real segment appears,
        # inject #EXT-X-DISCONTINUITY so players reset decoders.
        if [[ $slate_was_active -eq 1 ]]; then
            # Check if FFmpeg has produced at least one .ts segment
            dest_dir=$(dirname "$destination")
            if ls "$dest_dir"/*.ts 1>$DEVNULL 2>&1; then
                inject_discontinuity_tag "$destination"
                slate_was_active=0
                log "SLATE: Injected discontinuity tag after slate→real transition"
            fi
        fi

        # FEEDER_MONITOR (ALWAYS_FIFO): Detect dead feeder and restart it.
        # Slate-first: swap to slate IMMEDIATELY so encoder gets data, then retry.
        if [[ "$ALWAYS_FIFO" -eq 1 && -n "$feeder_pid" ]] && ! kill -0 "$feeder_pid" 2>$DEVNULL; then
            wait "$feeder_pid" 2>$DEVNULL || true
            feeder_uptime=0
            if [[ $feeder_last_restart_time -gt 0 ]]; then
                feeder_uptime=$(( $(date +%s) - feeder_last_restart_time ))
            fi
            log "FEEDER_MONITOR: Feeder PID $feeder_pid exited after ${feeder_uptime}s"
            feeder_pid=""
            # Swap to slate immediately — viewers see loading screen, not freeze
            swap_to_slate_feeder || true
            feeder_restart_count=$((feeder_restart_count + 1))
            if [[ $feeder_restart_count -ge $FEEDER_MAX_RESTARTS ]]; then
                log "FEEDER_MONITOR: Max restarts ($FEEDER_MAX_RESTARTS) on current URL. Switching."
                switch_feeder_to_next_url
            else
                backoff=$(calculate_feeder_backoff)
                [[ $backoff -gt 1 ]] && log "FEEDER_MONITOR: Backoff ${backoff}s before restart (slate playing)"
                sleep "$backoff"
                # Kill slate and start real feeder
                kill_feeder
                start_feeder_for_current_url
            fi
        fi

        # PROXY_WATCHDOG: Detect hung streamlink/proxy processes.
        # If the proxy dies while FFmpeg is running, FFmpeg will get EOF on the
        # FIFO and exit on its own. But if the proxy hangs (e.g. stuck on
        # network I/O via torsocks), it consumes CPU forever. Kill FFmpeg so
        # the outer loop can retry with a fresh proxy.
        if [[ "$ALWAYS_FIFO" -ne 1 && -n "$proxy_pid" ]]; then
            if ! kill -0 "$proxy_pid" 2>$DEVNULL; then
                log "PROXY_WATCHDOG: Proxy PID $proxy_pid exited while FFmpeg still running; FFmpeg will get EOF"
                proxy_pid=""
            else
                # Measure instantaneous CPU using /proc/stat (jiffies delta over ~1s).
                # ps %cpu is a lifetime average and won't catch recently-hung processes.
                proxy_cputime_now=$(awk '{print $14+$15}' "/proc/$proxy_pid/stat" 2>$DEVNULL)
                if [[ -n "$proxy_cputime_now" ]]; then
                    if [[ -n "$proxy_cputime_prev" ]]; then
                        cpu_delta=$(( proxy_cputime_now - proxy_cputime_prev ))
                        # ~100 jiffies/sec on most kernels; delta >90 in 1s ≈ >90% CPU
                        if [[ "$cpu_delta" -ge 90 ]]; then
                            proxy_watchdog_strikes=$(( proxy_watchdog_strikes + 1 ))
                            if [[ "$proxy_watchdog_strikes" -ge 60 ]]; then
                                log_error "PROXY_WATCHDOG: Proxy PID $proxy_pid stuck at high CPU for 60+ seconds. Killing."
                                kill -KILL "$proxy_pid" 2>$DEVNULL || true
                                proxy_pid=""
                                proxy_watchdog_strikes=0
                                proxy_cputime_prev=""
                                stop_reason="proxy_hung"
                                kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
                                break
                            fi
                        else
                            proxy_watchdog_strikes=0
                        fi
                    fi
                    proxy_cputime_prev="$proxy_cputime_now"
                fi
            fi
        fi

        # ERROR_LOG_SIZE_LIMIT: Prevent unbounded error log growth
        truncate_error_log_if_needed "$ffmpeg_error_file"

        # SEGMENT_CLEANUP: keep HLS output bounded even if delete_segments fails
        prune_old_segments

        # DISK_GUARD: check partition usage and emergency-prune if needed
        check_disk_space

        # HOT_RELOAD: pick up config edits while streaming (every 60s)
        reload_config_if_changed

        # Keep resolver semaphore slot alive for long-running Seenshow sessions.
        if [[ "${url_is_seenshow[$current_url_index]:-0}" == "1" && -z "$stop_reason" ]]; then
            if ! seenshow_touch_slot_if_needed; then
                log_error "SEENSHOW: Lost resolver slot lease for URL index $current_url_index"
                seenshow_slot_held=0
                seenshow_last_touch=0

                if seenshow_acquire_slot_if_needed "$current_url_index"; then
                    log "SEENSHOW: Slot lease restored for URL index $current_url_index"
                else
                    if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
                        # ALWAYS_FIFO: switch feeder to next URL, encoder stays alive
                        log_error "SEENSHOW: Slot lost. Switching feeder to next URL (encoder stays alive)"
                        switch_feeder_to_next_url
                        # DO NOT break
                    else
                        next_url_index=$(( (current_url_index + 1) % url_count ))
                        attempt_url_hotswap_and_exit_if_success "$next_url_index" "seenshow_slot_lost" || true

                        stop_reason="seenshow_slot_lost"
                        log_error "SEENSHOW: Unable to restore slot lease. Switching away from URL index $current_url_index"

                        # Graceful stop, then force kill as last resort
                        kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
                        pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true
                        for i in {1..10}; do
                            if ! is_process_running "$ffmpeg_pid"; then
                                break
                            fi
                            sleep 1
                        done
                        if is_process_running "$ffmpeg_pid"; then
                            log "SEENSHOW: Force killing FFmpeg PID $ffmpeg_pid after slot loss"
                            kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
                            pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
                        fi
                        break
                    fi
                fi
            fi
        fi

        # PRIMARY_FALLBACK: check primary while on backup (every interval).
        # In hot-swap mode, use graceful handoff to avoid killing the current
        # stream before the replacement path is warmed.
        if [[ -z "$stop_reason" ]]; then
            restore_from_index="$current_url_index"
            if check_and_fallback_to_primary; then
                if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
                    # ALWAYS_FIFO: slate-first, then swap feeder to primary URL
                    log "PRIMARY_RESTORED: Switching feeder to primary (encoder stays alive)"
                    swap_to_slate_feeder || true
                    current_url_index=0
                    current_url="${url_array[0]}"
                    kill_feeder
                    start_feeder_for_current_url
                    feeder_restart_count=0
                    total_cycles=0
                    reset_primary_restore_confirmation "fifo_primary_restored"
                    # DO NOT break — encoder keeps running
                elif can_use_primary_hotswap; then
                    log "PRIMARY_HOTSWAP: Primary confirmed. Attempting seamless handoff..."
                    if run_primary_hotswap_handoff; then
                        log "PRIMARY_HOTSWAP: Handoff completed. Exiting current instance."
                        mark_successful_handoff_exit "primary_hotswap"
                        cleanup
                        exit 0
                    fi

                    # Keep current backup stream when handoff fails.
                    current_url_index="$restore_from_index"
                    log_error "PRIMARY_HOTSWAP: Handoff failed. Staying on backup URL index $current_url_index."
                else
                    stop_reason="primary_restore"
                    log "PRIMARY_RESTORED: Restarting stream to use primary URL..."

                    # Graceful stop, then force kill as a last resort
                    kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
                    pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true
                    for i in {1..10}; do
                        if ! is_process_running "$ffmpeg_pid"; then
                            break
                        fi
                        sleep 1
                    done
                    if is_process_running "$ffmpeg_pid"; then
                        log "PRIMARY_RESTORED: Force killing FFmpeg PID $ffmpeg_pid"
                        kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
                        pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
                    fi
                    break
                fi
            fi
        fi

        # YOUTUBE_REFRESH: check if current YouTube URL needs refresh while streaming
        if [[ -z "$stop_reason" ]] && check_youtube_urls_need_refresh; then
            if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
                # ALWAYS_FIFO: slate-first, then swap feeder with refreshed URL
                log "YOUTUBE_REFRESH: Swapping feeder with refreshed URL (encoder stays alive)"
                swap_to_slate_feeder || true
                kill_feeder
                start_feeder_for_current_url
                feeder_restart_count=0
                # DO NOT break — encoder keeps running
            else
                stop_reason="youtube_refresh"
                log "YOUTUBE_REFRESH: Restarting stream with refreshed URL..."

                # Graceful stop, same as primary_restore
                kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
                pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true
                for i in {1..10}; do
                    if ! is_process_running "$ffmpeg_pid"; then
                        break
                    fi
                    sleep 1
                done
                if is_process_running "$ffmpeg_pid"; then
                    log "YOUTUBE_REFRESH: Force killing FFmpeg PID $ffmpeg_pid"
                    kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
                    pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
                fi
                break
            fi
        fi

        # CPU_GUARD: kill runaway FFmpeg to prevent system overload
        if [[ -z "$stop_reason" ]]; then
            if ! check_ffmpeg_cpu_usage; then
                stop_reason="cpu_guard"
                break
            fi
        fi

        # SEGMENT_STALE: check if output is stale and switch to backup URL
        if [[ -z "$stop_reason" ]] && check_segment_staleness; then
            if [[ "$ALWAYS_FIFO" -eq 1 ]]; then
                # ALWAYS_FIFO: slate-first, then replace feeder — encoder stays alive
                log "SEGMENT_STALE: Swapping to slate, then restarting feeder (encoder stays alive)"
                swap_to_slate_feeder || true
                if [[ $feeder_restart_count -ge $FEEDER_MAX_RESTARTS ]]; then
                    log "SEGMENT_STALE: Max feeder restarts ($FEEDER_MAX_RESTARTS). Switching URL."
                    feeder_restart_count=0
                    switch_feeder_to_next_url
                else
                    backoff=$(calculate_feeder_backoff)
                    [[ $backoff -gt 1 ]] && log "SEGMENT_STALE: Backoff ${backoff}s before feeder restart (slate playing)"
                    sleep "$backoff"
                    # Kill slate and start real feeder
                    kill_feeder
                    start_feeder_for_current_url
                    feeder_restart_count=$((feeder_restart_count + 1))
                fi
                last_segment_check=$(date +%s)
                # DO NOT break — encoder keeps running
            else
                if [[ $url_count -lt 2 ]]; then
                    stop_reason="segment_stale_restart"
                    log "SEGMENT_STALE: Output stale, restarting FFmpeg on current URL (no backups configured)..."
                else
                    next_url_index=$(( (current_url_index + 1) % url_count ))
                    if [[ "$next_url_index" -eq "$current_url_index" ]]; then
                        stop_reason="segment_stale_restart"
                        log "SEGMENT_STALE: Output stale, restarting FFmpeg on current URL (no alternate URL index)..."
                    else
                        attempt_url_hotswap_and_exit_if_success "$next_url_index" "segment_stale" || true

                        stop_reason="segment_stale"
                        log "SEGMENT_STALE: Output stale, switching to backup URL..."
                    fi
                fi

                # Graceful stop
                kill -TERM "$ffmpeg_pid" 2>$DEVNULL || true
                pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true
                for i in {1..10}; do
                    if ! is_process_running "$ffmpeg_pid"; then
                        break
                    fi
                    sleep 1
                done
                if is_process_running "$ffmpeg_pid"; then
                    log "SEGMENT_STALE: Force killing FFmpeg PID $ffmpeg_pid"
                    kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
                    pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
                fi
                break
            fi
        fi
    done

    if is_process_running "$ffmpeg_pid"; then
        wait_for_pid_exit "$ffmpeg_pid" 10 || true
    fi
    if is_process_running "$ffmpeg_pid"; then
        kill -KILL "$ffmpeg_pid" 2>$DEVNULL || true
        pkill -KILL -P "$ffmpeg_pid" 2>$DEVNULL || true
        wait_for_pid_exit "$ffmpeg_pid" 3 || true
    fi
    if ! is_process_running "$ffmpeg_pid"; then
        if wait "$ffmpeg_pid" 2>$DEVNULL; then
            exit_code=0
        else
            exit_code=$?
        fi
    else
        exit_code=143
    fi
    # Clean up any lingering FFmpeg child processes to prevent false duplicate detection
    pkill -TERM -P "$ffmpeg_pid" 2>$DEVNULL || true
    # Clean up proxy process (streamlink/yt-dlp) — it's a sibling, not a child of FFmpeg
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>$DEVNULL; then
        kill -TERM "$proxy_pid" 2>$DEVNULL || true
        sleep 1
        if kill -0 "$proxy_pid" 2>$DEVNULL; then
            kill -KILL "$proxy_pid" 2>$DEVNULL || true
        fi
    fi
    proxy_pid=""
    # Clean up feeder process and held-open FIFO FD (Always-FIFO)
    kill_feeder 2>$DEVNULL || true
    if [[ -n "$fifo_write_fd" ]]; then
        exec {fifo_write_fd}>&- 2>/dev/null || true
        fifo_write_fd=""
    fi
    # Clean up FIFO path
    if [[ -n "$stream_fifo" ]]; then
        rm -f "$stream_fifo" 2>$DEVNULL
        stream_fifo=""
    fi
    last_ffmpeg_pid="$ffmpeg_pid"
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    # Start slate placeholder to keep HLS alive during failover
    if start_slate_stream "$destination"; then
        # Inject discontinuity so players reset decoders after real→slate transition
        inject_discontinuity_tag "$destination"
    fi

    # ==========================================================================
    # CRITICAL FIX: Detect external kill (e.g., by health_monitor)
    # ==========================================================================
    # If FFmpeg was killed externally (SIGKILL=137, SIGTERM=143) and we didn't
    # initiate it (stop_reason is empty), exit the script to avoid race with
    # another instance that health_monitor may have started
    # ==========================================================================
    if [[ -z "$stop_reason" && ($exit_code -eq 137 || $exit_code -eq 143) ]]; then
        log "EXTERNAL_KILL: FFmpeg was killed externally (exit code $exit_code, duration ${duration}s)"
        log "EXTERNAL_KILL: Assuming health_monitor restarted the channel. Exiting this instance."
        cleanup
        exit 0
    fi

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

    # If we killed FFmpeg because the proxy/streamlink process hung, switch URL
    if [[ "$stop_reason" == "proxy_hung" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        log "PROXY_WATCHDOG: Switching to next URL after hung proxy"
        switch_to_next_url "proxy_hung"
        sleep 2
        continue
    fi

    # If CPU guard killed FFmpeg, switch to next URL (may need different scale mode)
    if [[ "$stop_reason" == "cpu_guard" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        log "CPU_GUARD: Switching to next URL after CPU overload"
        switch_to_next_url "cpu_guard"
        sleep 3
        continue
    fi

    # If we stopped FFmpeg due to stale output and there's no alternate URL to switch to, restart in-place.
    if [[ "$stop_reason" == "segment_stale_restart" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        log "SEGMENT_STALE: Restarting current URL due to stale output"
        # Reset segment check timer for new run
        last_segment_check=$(date +%s)
        # Allow error logging again after a stale restart (helps debugging without indefinite suppression).
        rapid_failure_count=0
        sleep 2
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

    if [[ "$stop_reason" == "seenshow_slot_lost" ]]; then
        cleanup_ffmpeg_error_file "$ffmpeg_error_file"
        log "SEENSHOW: Switching to next URL due to slot lease loss"
        switch_to_next_url "seenshow_slot_lost"
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

            # YOUTUBE_STREAM_END: Check if this is a YouTube stream that ended
            # YouTube returns 403/404 when a live stream ends
            if [[ "${url_is_youtube[$current_url_index]}" == "1" ]]; then
                log "YOUTUBE_STREAM_END: YouTube URL failed with 4xx - likely stream ended"
                youtube_stream_ended_detected=1
            else
                cleanup_ffmpeg_error_file "$ffmpeg_error_file"
                next_url_index=$(( (current_url_index + 1) % url_count ))
                attempt_url_hotswap_and_exit_if_success "$next_url_index" "FFmpeg_4xx" || true
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
                url_costly_short_runs[$current_url_index]=0
                # Brief pause to let the new stream stabilize
                sleep 3
                continue
            else
                log_error "YOUTUBE_STREAM_END: Re-fetch failed. Will try backup URLs..."
            fi
        fi

        # No general URL or re-fetch failed - proceed with normal failover
        switch_to_next_url "youtube_stream_ended"
        continue
    fi

    # Determine success/failure based on runtime
    # FIX: Increased from 60s to 300s to prevent flaky sources from resetting
    # retry counters with short "successful" runs (e.g., 61s, 105s)
    if [[ $duration -gt 300 ]]; then
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

        # Track costly short runs (>30s) — these waste viewer time with long freezes
        if [[ $duration -gt $SHORT_RUN_FAST_SWITCH_THRESHOLD ]]; then
            url_costly_short_runs[$current_url_index]=$(( ${url_costly_short_runs[$current_url_index]} + 1 ))
            costly_count=${url_costly_short_runs[$current_url_index]}
            log "SHORT_RUN: Duration ${duration}s (costly #${costly_count}). URL $current_url_index retry count: $current_retries (rapid failures: $rapid_failure_count)"
        else
            log "SHORT_RUN: Duration ${duration}s. URL $current_url_index retry count: $current_retries (rapid failures: $rapid_failure_count)"
        fi

        # Switch URL if: standard 3 retries exhausted, OR 2 costly short runs
        should_switch=0
        if [[ $current_retries -ge 3 ]]; then
            should_switch=1
        elif [[ ${url_costly_short_runs[$current_url_index]} -ge 2 ]]; then
            log "FAST_SWITCH: 2 costly SHORT_RUNs (>${SHORT_RUN_FAST_SWITCH_THRESHOLD}s each) on URL $current_url_index — switching early"
            should_switch=1
        fi

        if [[ $should_switch -eq 1 ]]; then
            next_url_index=$(( (current_url_index + 1) % url_count ))
            attempt_url_hotswap_and_exit_if_success "$next_url_index" "max_retries" || true
            switch_to_next_url "max_retries"
        else
            # Exponential backoff: 2s, 4s, 8s
            backoff=$(get_backoff_delay $((current_retries - 1)))
            log "BACKOFF: Waiting ${backoff}s before retry $current_retries on URL index $current_url_index"
            sleep "$backoff"
        fi
    fi
done
