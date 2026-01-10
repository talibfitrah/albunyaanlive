#!/bin/bash

# =============================================================================
# Disk Space Guard
# =============================================================================
# Proactively frees space when disk usage is high.
# Safe defaults: prune old HLS segments and old logs first.
# Intended to run periodically (e.g., via hls_background_job.sh or cron).
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Thresholds
MIN_FREE_GB="${MIN_FREE_GB:-5}"          # Minimum free space in GB
MIN_FREE_PCT="${MIN_FREE_PCT:-5}"        # Minimum free space percent
HLS_BASE_DIR="${HLS_BASE_DIR:-/var/www/html/stream/hls}"
HLS_PRUNE_AGE_MIN="${HLS_PRUNE_AGE_MIN:-20}"  # Delete .ts older than N minutes when low

# Logging
resolve_log_dir() {
    local preferred="$1"
    local fallback="/tmp/albunyaan-logs-$UID"

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
LOG_FILE="$LOG_DIR/disk_guard.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Cross-platform stat helpers (GNU/BSD compatibility)
get_file_size() {
    local file="$1"
    stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0
}

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
            tail -c "$LOG_FILE_TRIM_BYTES" "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE"
        fi
    fi
}

log() {
    log_maintenance
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

resolve_df_target() {
    local target="$HLS_BASE_DIR"
    if [[ -e "$target" ]]; then
        readlink -f "$target" 2>/dev/null || echo "$target"
        return
    fi
    echo "/"
}

sudo_run() {
    if [[ $(id -u) -eq 0 ]]; then
        "$@"
        return $?
    fi
    if [[ -r "$HOME/.sudo_pass.sh" ]]; then
        "$HOME/.sudo_pass.sh" | sudo -S "$@"
        return $?
    fi
    sudo -n "$@"
}

get_free_bytes() {
    local target
    target=$(resolve_df_target)
    df -PB1 "$target" 2>/dev/null | awk 'NR==2 {print $4}'
}

get_free_pct() {
    local target
    target=$(resolve_df_target)
    df -P "$target" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print 100-$5}'
}

low_space() {
    local free_bytes free_gb free_pct
    free_bytes=$(get_free_bytes)
    free_pct=$(get_free_pct)
    if [[ -z "$free_bytes" || -z "$free_pct" ]]; then
        log "WARN: Unable to determine free space for $HLS_BASE_DIR"
        return 1
    fi
    free_gb=$((free_bytes / 1024 / 1024 / 1024))
    [[ "$free_gb" -lt "$MIN_FREE_GB" || "$free_pct" -lt "$MIN_FREE_PCT" ]]
}

prune_logs() {
    log "PRUNE_LOGS: Starting log cleanup"
    sudo_run rm -f "$SCRIPT_DIR/output.log" "$SCRIPT_DIR/real_output.log" "$SCRIPT_DIR/updates.log" 2>/dev/null || true
    sudo_run rm -rf "$SCRIPT_DIR/log_archive" 2>/dev/null || true
    sudo_run rm -rf "$SCRIPT_DIR/logs_root_"* 2>/dev/null || true
    sudo_run rm -rf "$SCRIPT_DIR/logs" 2>/dev/null || true
    sudo_run rm -rf /tmp/albunyaan-logs 2>/dev/null || true
    sudo_run rm -rf /tmp/albunyaan-logs-* 2>/dev/null || true
    sudo_run rm -f /tmp/ffmpeg_error_*.log 2>/dev/null || true
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
}

prune_hls_segments() {
    [[ -d "$HLS_BASE_DIR" ]] || return
    log "PRUNE_HLS: Removing .ts older than ${HLS_PRUNE_AGE_MIN} minutes"
    sudo_run find "$HLS_BASE_DIR" -type f -name "*.ts" -mmin "+$HLS_PRUNE_AGE_MIN" -delete 2>/dev/null || true
}

main() {
    if ! low_space; then
        exit 0
    fi

    log "LOW_SPACE: Free below thresholds (min ${MIN_FREE_GB}GB or ${MIN_FREE_PCT}%)."
    prune_logs
    prune_hls_segments

    if low_space; then
        log "LOW_SPACE: Still low after cleanup, running aggressive HLS prune"
        sudo_run find "$HLS_BASE_DIR" -type f -name "*.ts" -delete 2>/dev/null || true
        sudo_run find "$HLS_BASE_DIR" -type f -name "*.m3u8" -delete 2>/dev/null || true
    fi
}

main
