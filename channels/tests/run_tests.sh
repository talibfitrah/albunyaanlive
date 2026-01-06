#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# Basic syntax checks
bash -n "$ROOT_DIR/try_start_stream.sh"
bash -n "$ROOT_DIR/generic_channel.sh"
bash -n "$ROOT_DIR/health_monitor.sh"
bash -n "$ROOT_DIR/graceful_restart.sh"
bash -n "$ROOT_DIR/channel_status.sh"
bash -n "$ROOT_DIR/cleanup_orphaned.sh"
bash -n "$ROOT_DIR/run_all_channels.sh"

has_pattern() {
    local pattern="$1"
    local file="$2"
    if command -v rg >/dev/null 2>&1; then
        rg -n -e "$pattern" "$file" >/dev/null
    else
        if grep -nE -- "$pattern" "$file" >/dev/null; then
            return 0
        fi
        local status=$?
        if [[ $status -eq 2 ]]; then
            fail "grep error while searching pattern in $file: $pattern"
        fi
        return 1
    fi
}

# Ensure run_all_channels.sh does not invoke channel scripts via /bin/sh (dash breaks bashisms like [[ ]])
if has_pattern '^[[:space:]]*sh[[:space:]]+channel_' "$ROOT_DIR/run_all_channels.sh"; then
    fail "run_all_channels.sh should not use sh to invoke channel scripts; use ./channel_*.sh instead"
fi

# Ensure all channel scripts referenced in run_all_channels.sh exist and are executable
while IFS= read -r line; do
    line="${line%%#*}"
    read -r cmd _ <<< "$line"
    [[ -z "$cmd" ]] && continue
    if [[ "$cmd" == ./channel_*.sh ]]; then
        script_path="$ROOT_DIR/${cmd#./}"
        if [[ ! -x "$script_path" ]]; then
            fail "run_all_channels.sh references missing or non-executable script: ${cmd#./}"
        fi
    fi
done < "$ROOT_DIR/run_all_channels.sh"

first_line() {
    local pattern="$1"
    local file="$2"
    if command -v rg >/dev/null 2>&1; then
        rg -n -e "$pattern" "$file" | head -1 | cut -d: -f1
    else
        local line
        if line=$(grep -nE -- "$pattern" "$file" | head -1 | cut -d: -f1); then
            echo "$line"
            return 0
        fi
        local status=$?
        if [[ $status -eq 2 ]]; then
            fail "grep error while searching pattern in $file: $pattern"
        fi
        return 1
    fi
}

# Ensure input options are before -i in FFmpeg command templates
if has_pattern '-i "\$stream_url"[[:space:]]+\$base_flags' "$ROOT_DIR/try_start_stream.sh"; then
    fail "base_flags appears after -i in try_start_stream.sh"
fi

# Ensure log directory fallback exists
if ! has_pattern "resolve_log_dir" "$ROOT_DIR/try_start_stream.sh"; then
    fail "resolve_log_dir helper missing in try_start_stream.sh"
fi
if ! has_pattern "/tmp/albunyaan-logs" "$ROOT_DIR/try_start_stream.sh"; then
    fail "log directory fallback path missing in try_start_stream.sh"
fi

# Ensure encoder availability check for libx264 exists when scale 5/6 is used
if ! has_pattern "require_encoder \"libx264\"" "$ROOT_DIR/try_start_stream.sh"; then
    fail "libx264 encoder availability check missing in try_start_stream.sh"
fi

# Ensure PRIMARY_FALLBACK feature exists and is wired
if ! has_pattern 'PRIMARY_CHECK_INTERVAL=.*-300' "$ROOT_DIR/try_start_stream.sh"; then
    fail "primary check interval missing in try_start_stream.sh"
fi
if ! has_pattern 'CONFIG_CHECK_INTERVAL=.*-60' "$ROOT_DIR/try_start_stream.sh"; then
    fail "config check interval missing in try_start_stream.sh"
fi
if ! has_pattern "check_and_fallback_to_primary" "$ROOT_DIR/try_start_stream.sh"; then
    fail "check_and_fallback_to_primary missing in try_start_stream.sh"
fi
if ! has_pattern "PRIMARY_CHECK:" "$ROOT_DIR/try_start_stream.sh"; then
    fail "PRIMARY_CHECK log markers missing in try_start_stream.sh"
fi

# Ensure HOT_RELOAD feature exists and is wired (auto-detect + reload loop)
if ! has_pattern "detect_channel_config_file" "$ROOT_DIR/try_start_stream.sh"; then
    fail "detect_channel_config_file missing in try_start_stream.sh"
fi
if ! has_pattern "HOT_RELOAD: Auto-detected channel config file" "$ROOT_DIR/try_start_stream.sh"; then
    fail "hot-reload auto-detect log marker missing in try_start_stream.sh"
fi
if ! has_pattern "reload_config_if_changed" "$ROOT_DIR/try_start_stream.sh"; then
    fail "reload_config_if_changed missing in try_start_stream.sh"
fi
if ! has_pattern "CONFIG_RELOAD:" "$ROOT_DIR/try_start_stream.sh"; then
    fail "CONFIG_RELOAD log markers missing in try_start_stream.sh"
fi
if ! has_pattern "while is_process_running" "$ROOT_DIR/try_start_stream.sh"; then
    fail "ffmpeg monitor loop missing in try_start_stream.sh (hot-reload won't run during long sessions)"
fi

# Guard against duplicate audio options in a single command block
prev=""
while IFS= read -r line; do
    if [[ "$line" == *"-c:a aac -b:a 192k"* ]]; then
        if [[ "$prev" == *"-c:a aac -b:a 192k"* ]]; then
            fail "duplicate audio options detected in try_start_stream.sh"
        fi
    fi
    prev="$line"
done < "$ROOT_DIR/try_start_stream.sh"

# Ensure graceful restart stops old process before performing swap
stop_line=$(first_line "Stopping old process before swap" "$ROOT_DIR/graceful_restart.sh" || true)
swap_line=$(first_line "Performing atomic playlist swap" "$ROOT_DIR/graceful_restart.sh" || true)
if [[ -z "$stop_line" || -z "$swap_line" ]]; then
    fail "expected log markers not found in graceful_restart.sh"
fi
if [[ "$stop_line" -gt "$swap_line" ]]; then
    fail "playlist swap occurs before stopping old process"
fi

# Ensure graceful restart escapes regex for pkill/pgrep usage
if ! has_pattern "escape_regex" "$ROOT_DIR/graceful_restart.sh"; then
    fail "escape_regex helper missing in graceful_restart.sh"
fi
if ! has_pattern "ESC_CHANNEL_ID" "$ROOT_DIR/graceful_restart.sh"; then
    fail "escaped channel id not used in graceful_restart.sh"
fi

# Ensure regex escaping is used consistently in other process-matching scripts
if ! has_pattern "escape_regex" "$ROOT_DIR/generic_channel.sh"; then
    fail "escape_regex helper missing in generic_channel.sh"
fi
if ! has_pattern "escaped_channel_id" "$ROOT_DIR/generic_channel.sh"; then
    fail "escaped_channel_id not used in generic_channel.sh"
fi
if has_pattern '^[[:space:]]*eval[[:space:]]' "$ROOT_DIR/generic_channel.sh"; then
    fail "eval usage detected in generic_channel.sh"
fi
if has_pattern '^[[:space:]]*eval[[:space:]]' "$ROOT_DIR/graceful_restart.sh"; then
    fail "eval usage detected in graceful_restart.sh"
fi
if ! has_pattern "escape_regex" "$ROOT_DIR/health_monitor.sh"; then
    fail "escape_regex helper missing in health_monitor.sh"
fi
if ! has_pattern "escaped_channel_id" "$ROOT_DIR/health_monitor.sh"; then
    fail "escaped_channel_id not used in health_monitor.sh"
fi
if ! has_pattern "escape_regex" "$ROOT_DIR/cleanup_orphaned.sh"; then
    fail "escape_regex helper missing in cleanup_orphaned.sh"
fi
if ! has_pattern "escaped_channel_id" "$ROOT_DIR/cleanup_orphaned.sh"; then
    fail "escaped_channel_id not used in cleanup_orphaned.sh"
fi

# Lightweight integration test (no real networking/ffmpeg required):
# - Primary starts as 404 -> switches to backup
# - Config hot-reload updates backups
# - Primary becomes 200 -> PRIMARY_RESTORED triggers
# - Cleanup kills any running ffmpeg child on exit
wait_for_log_pattern() {
    local log_file="$1"
    local pattern="$2"
    local timeout_seconds="$3"
    local waited=0

    while (( waited < timeout_seconds )); do
        if [[ -f "$log_file" ]] && grep -Fq -- "$pattern" "$log_file"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    fail "timeout waiting for log pattern: $pattern (log: $log_file)"
}

integration_primary_fallback_and_hot_reload() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: returns http_code based on URL + state file
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"

if [[ "$url" == *primary* ]]; then
    if [[ -f "$state_dir/primary_up" ]]; then
        printf "200"
    else
        printf "404"
    fi
    exit 0
fi

# All backup URLs are healthy in this stub
printf "200"
EOF
    chmod +x "$bin_dir/curl"

    # Stub ffmpeg: run until terminated
    cat > "$bin_dir/ffmpeg" <<'EOF'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-encoders" ]]; then
    cat <<OUT
Encoders:
 V.S..D mpeg2video           MPEG-2 video
 A....D aac                  AAC (Advanced Audio Coding)
OUT
    exit 0
fi

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-protocols" ]]; then
    cat <<OUT
Supported file protocols:
Input:
  file
  http
Output:
  file
OUT
    exit 0
fi

# Record argv for ordering assertions (first non-encoders invocation only)
state_dir="${STATE_DIR:-/tmp}"
args_file="$state_dir/ffmpeg_args"
if [[ ! -f "$args_file" ]]; then
    {
        for arg in "$@"; do
            printf '%s\n' "$arg"
        done
    } > "$args_file"
fi

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    local channel_id="test_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"
    local backup2_url="http://backup2.example/stream.m3u8"

    local config_file="$tmp_dir/channel_test.sh"
    cat > "$config_file" <<EOF
stream_url="$primary_url"
BACKUP_URLS="$backup_url"
EOF

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log="/tmp/albunyaan-logs/${channel_id}.log"
    rm -f "$preferred_log" "$fallback_log" 2>/dev/null || true

    # Run try_start_stream with short intervals
    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -c "$config_file" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    for i in {1..10}; do
        if [[ -f "$fallback_log" ]]; then
            log_file="$fallback_log"
            break
        fi
        if [[ -f "$preferred_log" ]]; then
            log_file="$preferred_log"
            break
        fi
        sleep 1
    done
    if [[ -z "$log_file" ]]; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        fail "try_start_stream.sh did not create a log file (expected $preferred_log or $fallback_log)"
    fi

    # Assert ffmpeg input option ordering via recorded argv
    local args_file="$state_dir/ffmpeg_args"
    for i in {1..10}; do
        if [[ -f "$args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$args_file" ]]; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        fail "ffmpeg argv capture file not found: $args_file"
    fi

    mapfile -t ffmpeg_args < "$args_file"
    find_arg_index() {
        local needle="$1"
        local idx=0
        for arg in "${ffmpeg_args[@]}"; do
            if [[ "$arg" == "$needle" ]]; then
                echo "$idx"
                return 0
            fi
            idx=$((idx + 1))
        done
        echo ""
        return 1
    }

    local i_index
    i_index=$(find_arg_index "-i" || true)
    if [[ -z "$i_index" ]]; then
        fail "ffmpeg argv missing -i (captured in $args_file)"
    fi
    local ua_index
    ua_index=$(find_arg_index "-user_agent" || true)
    if [[ -z "$ua_index" || "$ua_index" -gt "$i_index" ]]; then
        fail "ffmpeg -user_agent must appear before -i (captured in $args_file)"
    fi
    local rw_index
    rw_index=$(find_arg_index "-rw_timeout" || true)
    if [[ -z "$rw_index" || "$rw_index" -gt "$i_index" ]]; then
        fail "ffmpeg -rw_timeout must appear before -i (captured in $args_file)"
    fi
    local reconnect_index
    reconnect_index=$(find_arg_index "-reconnect" || true)
    if [[ -z "$reconnect_index" || "$reconnect_index" -gt "$i_index" ]]; then
        fail "ffmpeg -reconnect must appear before -i (captured in $args_file)"
    fi
    local re_index
    re_index=$(find_arg_index "-re" || true)
    if [[ -n "$re_index" && "$re_index" -gt "$i_index" ]]; then
        fail "ffmpeg -re must appear before -i when present (captured in $args_file)"
    fi

    # Ensure we fall back to backup (primary 404)
    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1" 10

    # Trigger config hot-reload (update backup urls)
    cat > "$config_file" <<EOF
stream_url="$primary_url"
BACKUP_URLS="$backup_url|$backup2_url"
EOF
    wait_for_log_pattern "$log_file" "CONFIG_RELOAD: Backup URLs updated." 10

    # Bring primary online and ensure PRIMARY_RESTORED is logged
    touch "$state_dir/primary_up"
    wait_for_log_pattern "$log_file" "PRIMARY_RESTORED:" 10

    # Capture any FFmpeg pids we spawned
    local ffmpeg_pids
    ffmpeg_pids=$(grep -oE "FFmpeg PID: [0-9]+" "$log_file" 2>/dev/null | awk '{print $3}' | sort -u || true)

    # Stop the runner and ensure children are cleaned up
    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true

    if [[ -n "$ffmpeg_pids" ]]; then
        for pid in $ffmpeg_pids; do
            if kill -0 "$pid" 2>/dev/null; then
                fail "orphaned ffmpeg process detected after cleanup: pid=$pid"
            fi
        done
    fi

    rm -rf "$tmp_dir" 2>/dev/null || true
}

integration_skips_unsupported_protocol_urls() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: primary=404, others=200
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"

if [[ "$url" == *primary* ]]; then
    printf "404"
    exit 0
fi

printf "200"
EOF
    chmod +x "$bin_dir/curl"

    # Stub ffmpeg: provide protocols without https, and run until terminated
    cat > "$bin_dir/ffmpeg" <<'EOF'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-encoders" ]]; then
    cat <<OUT
Encoders:
 V.S..D mpeg2video           MPEG-2 video
 A....D aac                  AAC (Advanced Audio Coding)
OUT
    exit 0
fi

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-protocols" ]]; then
    cat <<OUT
Supported file protocols:
Input:
  file
  http
Output:
  file
OUT
    exit 0
fi

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    local channel_id="test_proto_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url="http://primary.example/stream.m3u8"
    local bad_backup_url="https://backup.example/stream.m3u8"
    local good_backup_url="http://backup2.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log="/tmp/albunyaan-logs/${channel_id}.log"
    rm -f "$preferred_log" "$fallback_log" 2>/dev/null || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$bad_backup_url|$good_backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    for i in {1..10}; do
        if [[ -f "$fallback_log" ]]; then
            log_file="$fallback_log"
            break
        fi
        if [[ -f "$preferred_log" ]]; then
            log_file="$preferred_log"
            break
        fi
        sleep 1
    done
    if [[ -z "$log_file" ]]; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        fail "try_start_stream.sh did not create a log file for protocol test"
    fi

    wait_for_log_pattern "$log_file" "UNSUPPORTED_PROTOCOL:" 10
    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 2" 10

    local ffmpeg_pids
    ffmpeg_pids=$(grep -oE "FFmpeg PID: [0-9]+" "$log_file" 2>/dev/null | awk '{print $3}' | sort -u || true)

    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true

    if [[ -n "$ffmpeg_pids" ]]; then
        for pid in $ffmpeg_pids; do
            if kill -0 "$pid" 2>/dev/null; then
                fail "orphaned ffmpeg process detected after protocol test cleanup: pid=$pid"
            fi
        done
    fi

    rm -rf "$tmp_dir" 2>/dev/null || true
}

integration_file_scheme_omits_http_flags() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub ffmpeg: provide file protocol, record argv, and run until terminated
    cat > "$bin_dir/ffmpeg" <<'EOF'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-protocols" ]]; then
    cat <<OUT
Supported file protocols:
Input:
  file
Output:
  file
OUT
    exit 0
fi

state_dir="${STATE_DIR:-/tmp}"
args_file="$state_dir/ffmpeg_args"
if [[ ! -f "$args_file" ]]; then
    {
        for arg in "$@"; do
            printf '%s\n' "$arg"
        done
    } > "$args_file"
fi

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    local channel_id="test_file_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local file_url="$tmp_dir/input.mp4"
    touch "$file_url"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log="/tmp/albunyaan-logs/${channel_id}.log"
    rm -f "$preferred_log" "$fallback_log" 2>/dev/null || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" \
        "$ROOT_DIR/try_start_stream.sh" -u "$file_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    for i in {1..10}; do
        if [[ -f "$fallback_log" ]]; then
            log_file="$fallback_log"
            break
        fi
        if [[ -f "$preferred_log" ]]; then
            log_file="$preferred_log"
            break
        fi
        sleep 1
    done
    if [[ -z "$log_file" ]]; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        fail "try_start_stream.sh did not create a log file for file-scheme test"
    fi

    wait_for_log_pattern "$log_file" "URL validation skipped for non-HTTP scheme: file" 10

    local args_file="$state_dir/ffmpeg_args"
    for i in {1..10}; do
        if [[ -f "$args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$args_file" ]]; then
        kill -TERM "$runner_pid" 2>/dev/null || true
        wait "$runner_pid" 2>/dev/null || true
        fail "ffmpeg argv capture file not found for file-scheme test"
    fi

    mapfile -t ffmpeg_args < "$args_file"
    for forbidden in -user_agent -http_persistent -rw_timeout -reconnect -reconnect_streamed -reconnect_delay_max; do
        for arg in "${ffmpeg_args[@]}"; do
            if [[ "$arg" == "$forbidden" ]]; then
                fail "file-scheme ffmpeg args should not include HTTP flag $forbidden"
            fi
        done
    done

    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true

    rm -rf "$tmp_dir" 2>/dev/null || true
}

integration_primary_fallback_and_hot_reload
integration_skips_unsupported_protocol_urls
integration_file_scheme_omits_http_flags

echo "All tests passed."
