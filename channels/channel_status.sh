#!/bin/bash

# =============================================================================
# Channel Status Dashboard
# =============================================================================
# Displays the status of all HLS channels in a formatted table
# Usage: ./channel_status.sh [--json]
#
# Fixed Issues:
#   - [BLOCKER] Uses consistent channel_id (HLS directory name) for process detection
#   - Log file lookup uses channel_id correctly
# =============================================================================

HLS_BASE_DIR="/var/www/html/stream/hls"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESTART_TRACKING_DIR="/tmp/stream_health"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Output format
OUTPUT_JSON=false
if [[ "$1" == "--json" ]]; then
    OUTPUT_JSON=true
fi

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

# Resolve log directory for a channel (fallback to /tmp if repo logs not used)
get_log_dir_for_channel() {
    local channel_id="$1"
    local primary="$SCRIPT_DIR/logs"
    local fallback="/tmp/albunyaan-logs"

    if [[ -f "$primary/${channel_id}.log" ]]; then
        echo "$primary"
        return
    fi
    if [[ -f "$fallback/${channel_id}.log" ]]; then
        echo "$fallback"
        return
    fi
    if [[ -d "$primary" ]]; then
        echo "$primary"
        return
    fi
    echo "$fallback"
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
            echo "$pid"
            return 0
        fi
    fi

    # Method 2: Check lock directory (consistent with other scripts)
    if [[ -d "$lockdir" ]]; then
        # Lock exists - check if FFmpeg is writing to this channel
        if pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" >/dev/null 2>&1; then
            local ffmpeg_pid=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>/dev/null | head -1)
            echo "$ffmpeg_pid"
            return 0
        fi
    fi

    # Method 3: Check FFmpeg directly via HLS path (fallback)
    local ffmpeg_pid=$(pgrep -f "ffmpeg.*/${escaped_channel_id}/master\\.m3u8" 2>/dev/null | head -1)
    if [[ -n "$ffmpeg_pid" ]]; then
        echo "$ffmpeg_pid"
        return 0
    fi

    echo ""
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

    local count=0
    while IFS= read -r timestamp; do
        if [[ $timestamp -gt $one_hour_ago ]]; then
            count=$((count + 1))
        fi
    done < "$count_file"

    echo $count
}

# Format duration
format_duration() {
    local seconds=$1
    if [[ $seconds -lt 60 ]]; then
        echo "${seconds}s"
    elif [[ $seconds -lt 3600 ]]; then
        local mins=$((seconds / 60))
        echo "${mins}m"
    else
        local hours=$((seconds / 3600))
        local mins=$(((seconds % 3600) / 60))
        echo "${hours}h ${mins}m"
    fi
}

# Get channel info
get_channel_info() {
    local channel_dir="$1"
    local channel_id=$(get_channel_id "$channel_dir")
    local playlist="$channel_dir/master.m3u8"
    local current_time=$(date +%s)

    local status="UNKNOWN"
    local uptime="-"
    local last_segment="-"
    local url_index="-"
    local restarts=$(get_restart_count "$channel_id")
    local pid="-"

    # Check if process is running using consistent channel_id
    local running_pid=$(is_channel_running "$channel_id")

    if [[ -n "$running_pid" ]]; then
        status="RUNNING"
        pid="$running_pid"

        # Calculate uptime from process start time
        local start_time=$(ps -o etimes= -p "$running_pid" 2>/dev/null | tr -d ' ')
        if [[ -n "$start_time" ]]; then
            uptime=$(format_duration "$start_time")
        fi

        # BLOCKER FIX: Check log for current URL index using channel_id
        local log_dir=$(get_log_dir_for_channel "$channel_id")
        local log_file="$log_dir/${channel_id}.log"
        if [[ -f "$log_file" ]]; then
            local url_line=$(tail -100 "$log_file" 2>/dev/null | grep -E "ATTEMPT:.*URL index|URL_SWITCH:" | tail -1)
            if [[ -n "$url_line" ]]; then
                local idx=$(echo "$url_line" | grep -oE "URL index [0-9]+" | grep -oE "[0-9]+")
                if [[ -z "$idx" ]]; then
                    idx=$(echo "$url_line" | grep -oE "index [0-9]+" | grep -oE "[0-9]+")
                fi
                case "$idx" in
                    0) url_index="Primary" ;;
                    1) url_index="Backup1" ;;
                    2) url_index="Backup2" ;;
                    *) url_index="URL$idx" ;;
                esac
            fi
        fi
    else
        status="STOPPED"
    fi

    # Check segment freshness
    if [[ -f "$playlist" ]]; then
        local newest_segment=$(find "$channel_dir" -name "*.ts" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1)
        if [[ -n "$newest_segment" ]]; then
            local segment_mtime=$(echo "$newest_segment" | cut -d' ' -f1 | cut -d'.' -f1)
            local segment_age=$((current_time - segment_mtime))
            last_segment=$(format_duration "$segment_age")

            if [[ $segment_age -gt 30 && "$status" == "RUNNING" ]]; then
                status="STALE"
            fi
        fi
    fi

    echo "$channel_id|$status|$uptime|$last_segment|$url_index|$restarts|$pid"
}

# Print header
print_header() {
    if [[ "$OUTPUT_JSON" == true ]]; then
        echo '{"channels": ['
        return
    fi

    printf "%-20s | %-8s | %-8s | %-12s | %-8s | %-8s | %-8s\n" \
        "Channel" "Status" "Uptime" "Last Segment" "URL" "Restarts" "PID"
    printf "%s\n" "$(printf '=%.0s' {1..90})"
}

# Print channel row
print_channel() {
    local info="$1"
    local is_last="$2"

    IFS='|' read -r channel status uptime last_segment url_index restarts pid <<< "$info"

    if [[ "$OUTPUT_JSON" == true ]]; then
        printf '  {"channel": "%s", "status": "%s", "uptime": "%s", "last_segment": "%s", "url": "%s", "restarts": %s, "pid": "%s"}' \
            "$channel" "$status" "$uptime" "$last_segment" "$url_index" "$restarts" "$pid"
        if [[ "$is_last" != "true" ]]; then
            printf ","
        fi
        printf "\n"
        return
    fi

    # Color based on status
    local status_color="$NC"
    case "$status" in
        RUNNING) status_color="$GREEN" ;;
        STOPPED) status_color="$RED" ;;
        STALE)   status_color="$YELLOW" ;;
    esac

    printf "%-20s | ${status_color}%-8s${NC} | %-8s | %-12s | %-8s | %-8s | %-8s\n" \
        "$channel" "$status" "$uptime" "$last_segment" "$url_index" "$restarts" "$pid"
}

# Print footer
print_footer() {
    local running="$1"
    local stopped="$2"
    local stale="$3"
    local total="$4"

    if [[ "$OUTPUT_JSON" == true ]]; then
        printf '],\n"summary": {"running": %d, "stopped": %d, "stale": %d, "total": %d}}\n' \
            "$running" "$stopped" "$stale" "$total"
        return
    fi

    printf "%s\n" "$(printf '=%.0s' {1..90})"
    printf "Summary: ${GREEN}%d running${NC}, ${RED}%d stopped${NC}, ${YELLOW}%d stale${NC}, %d total\n" \
        "$running" "$stopped" "$stale" "$total"
}

# Main
main() {
    if [[ ! -d "$HLS_BASE_DIR" ]]; then
        echo "Error: HLS directory not found: $HLS_BASE_DIR"
        exit 1
    fi

    local running=0
    local stopped=0
    local stale=0
    local total=0
    declare -a channel_infos

    # Collect channel info
    for channel_dir in "$HLS_BASE_DIR"/*/; do
        if [[ -d "$channel_dir" ]]; then
            info=$(get_channel_info "$channel_dir")
            channel_infos+=("$info")

            status=$(echo "$info" | cut -d'|' -f2)
            case "$status" in
                RUNNING) running=$((running + 1)) ;;
                STOPPED) stopped=$((stopped + 1)) ;;
                STALE)   stale=$((stale + 1)) ;;
            esac
            total=$((total + 1))
        fi
    done

    # Print output
    print_header

    local count=0
    for info in "${channel_infos[@]}"; do
        count=$((count + 1))
        is_last="false"
        if [[ $count -eq $total ]]; then
            is_last="true"
        fi
        print_channel "$info" "$is_last"
    done

    print_footer "$running" "$stopped" "$stale" "$total"
}

main "$@"
