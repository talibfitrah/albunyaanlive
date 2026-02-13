#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEVNULL="/dev/null"
if [[ ! -c /dev/null || ! -w /dev/null ]]; then
    DEVNULL="${TMPDIR:-/tmp}/albunyaan-dev-null.$$"
    : > "$DEVNULL" || true
fi

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
if [[ -f "$ROOT_DIR/provider_sync.js" ]]; then
    node --check "$ROOT_DIR/provider_sync.js"
fi
if [[ -f "$ROOT_DIR/import_youtube_cookies.sh" ]]; then
    bash -n "$ROOT_DIR/import_youtube_cookies.sh"
fi
if [[ -f "$ROOT_DIR/start_youtube_resolver.sh" ]]; then
    bash -n "$ROOT_DIR/start_youtube_resolver.sh"
fi
if [[ -f "$ROOT_DIR/youtube_resolver_login.sh" ]]; then
    bash -n "$ROOT_DIR/youtube_resolver_login.sh"
fi

has_pattern() {
    local pattern="$1"
    local file="$2"
    if command -v rg >"$DEVNULL" 2>&1; then
        rg -n -e "$pattern" "$file" >"$DEVNULL"
    else
        if grep -nE -- "$pattern" "$file" >"$DEVNULL"; then
            return 0
        fi
        local status=$?
        if [[ $status -eq 2 ]]; then
            fail "grep error while searching pattern in $file: $pattern"
        fi
        return 1
    fi
}

# Ensure sensitive playlist exports are ignored by git (they contain credentialized URLs).
if command -v git >"$DEVNULL" 2>&1 && git -C "$ROOT_DIR/.." rev-parse --is-inside-work-tree >"$DEVNULL" 2>&1; then
    git_status_output=$(git -C "$ROOT_DIR/.." status --short --untracked-files=all || true)
    if command -v rg >"$DEVNULL" 2>&1; then
        if printf '%s\n' "$git_status_output" | rg -q '^\?\? playlists/.*\.m3u$'; then
            fail "playlist exports under playlists/*.m3u must be git-ignored (credential exposure risk)"
        fi
    else
        if printf '%s\n' "$git_status_output" | grep -qE '^\?\? playlists/.*\.m3u$'; then
            fail "playlist exports under playlists/*.m3u must be git-ignored (credential exposure risk)"
        fi
    fi
fi

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

# Basic channel config sanity checks to catch accidental source drift.
for script_path in "$ROOT_DIR"/channel_*.sh; do
    script_name="$(basename "$script_path")"
    if [[ "$script_name" == "channel_status.sh" || "$script_name" == "channel_youtube_example.sh" ]]; then
        continue
    fi

    for required_var in stream_url stream_url_backup1 stream_url_backup2 rtmp_url; do
        if ! has_pattern "^${required_var}=" "$script_path"; then
            fail "$script_name missing required assignment: ${required_var}"
        fi
    done

    stream_url_value=$(awk -F'"' '/^stream_url="/ { print $2; exit }' "$script_path")
    if [[ -z "$stream_url_value" ]]; then
        fail "$script_name has empty stream_url"
    fi

    rtmp_url_value=$(awk -F'"' '/^rtmp_url="/ { print $2; exit }' "$script_path")
    if [[ -z "$rtmp_url_value" || "$rtmp_url_value" != /var/www/html/stream/hls/*/master.m3u8 ]]; then
        fail "$script_name has invalid rtmp_url: $rtmp_url_value"
    fi
done

# Seenshow-backed channel mapping must stay stable to avoid accidental source drift.
declare -A expected_seenshow_hls_paths=(
    ["channel_maassah_revised.sh"]="2120779/LIVE-013-MASA"
    ["channel_almajd_kids_revised.sh"]="2120822/LIVE-009-KIDS"
    ["channel_almajd_quran_revised.sh"]="2120829/LIVE-002-QURAN"
    ["channel_basmah_revised.sh"]="2120817/LIVE-010-BASMA"
    ["channel_rawdah_revised.sh"]="2120823/LIVE-011-RAWDA"
    ["channel_almajd_aamah_revised.sh"]="2120825/LIVE-001-ALMAJD"
    ["channel_almajd_doc_revised.sh"]="2120826/LIVE-006-WASEQYA"
    ["channel_almajd_nature_revised.sh"]="2120827/LIVE-007-TABEEYA"
    ["channel_daal_revised.sh"]="2120828/LIVE-008-DAL"
    ["channel_almajd_science_revised.sh"]="2120830/LIVE-004-ELMIA"
)

for script_name in "${!expected_seenshow_hls_paths[@]}"; do
    script_path="$ROOT_DIR/$script_name"
    if [[ ! -f "$script_path" ]]; then
        fail "missing expected Seenshow-backed channel script: $script_name"
    fi
    expected_path="${expected_seenshow_hls_paths[$script_name]}"
    if ! has_pattern "live\\.seenshow\\.com/hls/live/${expected_path}/" "$script_path"; then
        fail "$script_name does not reference expected Seenshow path ${expected_path}"
    fi
done

first_line() {
    local pattern="$1"
    local file="$2"
    if command -v rg >"$DEVNULL" 2>&1; then
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

test_log_fallback_dir() {
    local uid_value
    uid_value="${UID:-$(id -u)}"
    echo "/tmp/albunyaan-logs-${uid_value}"
}

fallback_log_path_for_channel() {
    local channel_id="$1"
    echo "$(test_log_fallback_dir)/${channel_id}.log"
}

legacy_fallback_log_path_for_channel() {
    local channel_id="$1"
    echo "/tmp/albunyaan-logs/${channel_id}.log"
}

wait_for_log_file_any_location() {
    local preferred_log="$1"
    local fallback_log="$2"
    local legacy_fallback_log="$3"
    local attempts="${4:-10}"

    for _ in $(seq 1 "$attempts"); do
        if [[ -f "$fallback_log" ]]; then
            echo "$fallback_log"
            return 0
        fi
        if [[ -f "$legacy_fallback_log" ]]; then
            echo "$legacy_fallback_log"
            return 0
        fi
        if [[ -f "$preferred_log" ]]; then
            echo "$preferred_log"
            return 0
        fi
        sleep 1
    done

    return 1
}

# Ensure input options are before -i in FFmpeg command templates
# shellcheck disable=SC2016
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

# HLS playlists must never be finalized, otherwise some clients stop permanently and require a refresh.
if ! has_pattern "omit_endlist" "$ROOT_DIR/try_start_stream.sh"; then
    fail "try_start_stream.sh missing HLS omit_endlist flag (required for no-cut swaps)"
fi

# Ensure PRIMARY_FALLBACK feature exists and is wired
if ! has_pattern 'PRIMARY_CHECK_INTERVAL=.*-3600' "$ROOT_DIR/try_start_stream.sh"; then
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
if ! has_pattern "seenshow_touch_slot_if_needed" "$ROOT_DIR/try_start_stream.sh"; then
    fail "Seenshow slot heartbeat helper missing in try_start_stream.sh"
fi
if ! has_pattern "SEENSHOW_SLOT_TOUCH_INTERVAL" "$ROOT_DIR/try_start_stream.sh"; then
    fail "Seenshow slot heartbeat interval missing in try_start_stream.sh"
fi
if ! has_pattern "SEENSHOW_SLOT_CHANNEL_ID" "$ROOT_DIR/try_start_stream.sh"; then
    fail "Seenshow slot identity override missing in try_start_stream.sh"
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
if ! has_pattern "GRACEFUL_SKIP_CALLER_KILL" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing caller-preserving hot-swap guard"
fi
if ! has_pattern "GRACEFUL_CALLER_PID" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing caller PID wiring for hot-swap safety"
fi
if ! has_pattern "GRACEFUL_REQUIRED_SEGMENTS" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing configurable segment warmup threshold"
fi
if ! has_pattern "GRACEFUL_MAX_WAIT_SECONDS" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing configurable warmup timeout"
fi
if ! has_pattern "GRACEFUL_OVERRIDE_START_INDEX" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing override start index support"
fi
if ! has_pattern "TRY_START_ADOPT_LOCK" "$ROOT_DIR/try_start_stream.sh"; then
    fail "try_start_stream.sh missing lock-adoption support for handoff"
fi
if ! has_pattern "TRY_START_ADOPT_LOCK=1" "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing lock-adoption wiring for replacement runner"
fi
# shellcheck disable=SC2016
if ! has_pattern 'SEENSHOW_SLOT_CHANNEL_ID="\$CHANNEL_ID"' "$ROOT_DIR/graceful_restart.sh"; then
    fail "graceful_restart.sh missing canonical slot identity wiring for handoff runners"
fi
if ! has_pattern "TRY_START_INITIAL_URL_INDEX" "$ROOT_DIR/try_start_stream.sh"; then
    fail "try_start_stream.sh missing startup URL index override support"
fi
if ! has_pattern "GRACEFUL_OVERRIDE_START_INDEX" "$ROOT_DIR/try_start_stream.sh"; then
    fail "try_start_stream.sh missing graceful handoff start-index wiring"
fi
if ! has_pattern 'url_hotswap_primary_url="\$\{url_original\[0\]:-\$\{url_array\[0\]\}\}"' "$ROOT_DIR/try_start_stream.sh"; then
    fail "URL hot-swap plan must preserve canonical primary URL ordering (using url_original with url_array fallback)"
fi
# shellcheck disable=SC2016
if ! has_pattern 'attempt_url_hotswap_and_exit_if_success "\$next_url_index" "HTTP_\$\{http_status\}"' "$ROOT_DIR/try_start_stream.sh"; then
    fail "HTTP 4xx failover path missing URL hot-swap attempt"
fi
# shellcheck disable=SC2016
if ! has_pattern 'attempt_url_hotswap_and_exit_if_success "\$next_url_index" "FFmpeg_4xx"' "$ROOT_DIR/try_start_stream.sh"; then
    fail "FFmpeg 4xx failover path missing URL hot-swap attempt"
fi
# shellcheck disable=SC2016
if ! has_pattern 'attempt_url_hotswap_and_exit_if_success "\$next_url_index" "max_retries"' "$ROOT_DIR/try_start_stream.sh"; then
    fail "max_retries failover path missing URL hot-swap attempt"
fi
if ! has_pattern "No live output state detected" "$ROOT_DIR/try_start_stream.sh"; then
    fail "URL hot-swap cold-handoff guard missing in try_start_stream.sh"
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

if [[ -f "$ROOT_DIR/provider_sync.js" ]]; then
    if ! has_pattern "validateProviderConfigShape" "$ROOT_DIR/provider_sync.js"; then
        fail "provider_sync.js missing credentials schema validation helper"
    fi
    if ! has_pattern "sanitizeRegistryChannel" "$ROOT_DIR/provider_sync.js"; then
        fail "provider_sync.js missing registry sanitization helper"
    fi
    if ! has_pattern "PROVIDER_CREDENTIALS_FILE" "$ROOT_DIR/provider_sync.js"; then
        fail "provider_sync.js missing PROVIDER_CREDENTIALS_FILE override"
    fi
    if ! has_pattern "computeServiceStatus" "$ROOT_DIR/provider_sync.js"; then
        fail "provider_sync.js missing health status derivation helper"
    fi
fi

if [[ -f "$ROOT_DIR/seenshow_resolver.js" ]]; then
    if [[ ! -f "$ROOT_DIR/seenshow_credentials.example.json" ]]; then
        fail "seenshow_credentials.example.json missing (required deployment template)"
    fi
    if ! has_pattern "candidateMatchesChannel" "$ROOT_DIR/seenshow_resolver.js"; then
        fail "seenshow_resolver.js missing channel-scoped candidate filtering"
    fi
    if ! has_pattern "validateCredentialsShape" "$ROOT_DIR/seenshow_resolver.js"; then
        fail "seenshow_resolver.js missing strict credentials shape validation"
    fi
fi

if [[ -f "$ROOT_DIR/channel_registry.json" ]] && command -v jq >"$DEVNULL" 2>&1; then
    registry_vlc_primary_count=$(jq '[.channels | to_entries[] | select((.value.vlc_as_backup | not) and (.value.preferred_credential | length > 0))] | length' "$ROOT_DIR/channel_registry.json")
    if command -v rg >"$DEVNULL" 2>&1; then
        vlc_channel_count=$(rg -l '^stream_url="http://vlc\.news:' "$ROOT_DIR"/channel_*.sh | wc -l | tr -d ' ')
    else
        vlc_channel_count=$(grep -lE '^stream_url="http://vlc\.news:' "$ROOT_DIR"/channel_*.sh | wc -l | tr -d ' ')
    fi

    if [[ "$registry_vlc_primary_count" != "$vlc_channel_count" ]]; then
        fail "channel_registry.json vlc-primary count ($registry_vlc_primary_count) does not match vlc-primary channel scripts ($vlc_channel_count)"
    fi

    if ! jq -e '.channels | has("nada")' "$ROOT_DIR/channel_registry.json" >"$DEVNULL"; then
        fail "channel_registry.json missing nada channel entry"
    fi

    while IFS=$'\t' read -r cfg uses_vlc_as_backup pref_cred; do
        if [[ ! -f "$ROOT_DIR/$cfg" ]]; then
            fail "channel_registry.json references missing config file: $cfg"
        fi

        stream_url_value=$(awk -F'"' '/^stream_url="/ { print $2; exit }' "$ROOT_DIR/$cfg")
        if [[ -z "$stream_url_value" ]]; then
            fail "$cfg is missing stream_url assignment"
        fi

        # Non-vlc-only channels (no preferred_credential) may use any primary
        if [[ -z "$pref_cred" ]]; then
            continue
        fi

        if [[ "$uses_vlc_as_backup" == "true" ]]; then
            if [[ "$stream_url_value" == http://vlc.news:* ]]; then
                fail "$cfg expects non-vlc primary because vlc_as_backup=true, but stream_url points to vlc.news"
            fi
        else
            if [[ "$stream_url_value" != http://vlc.news:* ]]; then
                fail "$cfg expects vlc.news primary because vlc_as_backup is false, but stream_url is: $stream_url_value"
            fi
        fi
    done < <(jq -r '.channels | to_entries[] | [.value.config_file, (.value.vlc_as_backup == true), (.value.preferred_credential // "")] | @tsv' "$ROOT_DIR/channel_registry.json")
fi

if [[ -f "$ROOT_DIR/youtube_browser_resolver_v2.js" ]]; then
    if ! has_pattern "userDataDir:[[:space:]]*USER_DATA_DIR" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js must launch Chromium with persistent userDataDir"
    fi
    if ! has_pattern "YT_RESOLVER_MAX_SESSIONS" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing session capacity guard"
    fi
    if ! has_pattern "session capacity reached" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing 429 capacity response"
    fi
    if ! has_pattern "buildSegmentCacheKey" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing session-scoped segment cache keys"
    fi
    if ! has_pattern "decodeSegmentUrl" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing hardened segment URL decoding"
    fi
    if ! has_pattern "validateSegmentProxyUrl" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing segment target host allowlist validation"
    fi
    if ! has_pattern "parseRequestUrl" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing hardened request URL parsing"
    fi
    if ! has_pattern "YT_RESOLVER_SEGMENT_CACHE_MAX_BYTES" "$ROOT_DIR/youtube_browser_resolver_v2.js"; then
        fail "youtube_browser_resolver_v2.js missing bounded cache size setting"
    fi
fi

if [[ -f "$ROOT_DIR/youtube_browser_resolver.js" ]]; then
    if ! has_pattern "YT_RESOLVER_MAX_SESSIONS" "$ROOT_DIR/youtube_browser_resolver.js"; then
        fail "youtube_browser_resolver.js missing session capacity guard"
    fi
    if ! has_pattern "session capacity reached" "$ROOT_DIR/youtube_browser_resolver.js"; then
        fail "youtube_browser_resolver.js missing 429 capacity response"
    fi
    if ! has_pattern "parseRequestUrl" "$ROOT_DIR/youtube_browser_resolver.js"; then
        fail "youtube_browser_resolver.js missing hardened request URL parsing"
    fi
fi

if [[ -f "$ROOT_DIR/youtube-resolver.service" ]]; then
    if ! has_pattern "YT_RESOLVER_USER_DATA_DIR" "$ROOT_DIR/youtube-resolver.service"; then
        fail "youtube-resolver.service missing YT_RESOLVER_USER_DATA_DIR environment setting"
    fi
fi

if [[ -f "$ROOT_DIR/youtube_resolver_login.sh" ]]; then
    trap_line=$(first_line '^[[:space:]]*trap[[:space:]]+on_exit[[:space:]]+EXIT[[:space:]]+INT[[:space:]]+TERM' "$ROOT_DIR/youtube_resolver_login.sh" || true)
    stop_line=$(first_line 'systemctl stop youtube-resolver\.service' "$ROOT_DIR/youtube_resolver_login.sh" || true)
    if [[ -z "$trap_line" || -z "$stop_line" ]]; then
        fail "youtube_resolver_login.sh missing expected trap or service stop lines"
    fi
    if [[ "$trap_line" -gt "$stop_line" ]]; then
        fail "youtube_resolver_login.sh must register trap before stopping service"
    fi
fi

if [[ -f "$ROOT_DIR/start_youtube_resolver.sh" ]]; then
    if ! has_pattern "PID_FILE=.*youtube_browser_resolver_" "$ROOT_DIR/start_youtube_resolver.sh"; then
        fail "start_youtube_resolver.sh missing resolver pidfile management"
    fi
    if ! has_pattern "is_pid_running_for_script" "$ROOT_DIR/start_youtube_resolver.sh"; then
        fail "start_youtube_resolver.sh missing script-specific running-process check"
    fi
    if has_pattern 'pgrep -f "youtube_browser_resolver"' "$ROOT_DIR/start_youtube_resolver.sh"; then
        fail "start_youtube_resolver.sh should not use broad youtube_browser_resolver process matching"
    fi
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

wait_for_file() {
    local file_path="$1"
    local timeout_seconds="$2"
    local waited=0

    while (( waited < timeout_seconds )); do
        if [[ -f "$file_path" ]]; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    fail "timeout waiting for file: $file_path"
}

wait_for_process_exit() {
    local pid="$1"
    local timeout_seconds="$2"
    local waited=0

    while (( waited < timeout_seconds )); do
        if ! kill -0 "$pid" 2>"$DEVNULL"; then
            wait "$pid" 2>"$DEVNULL" || true
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    fail "timeout waiting for process exit: pid=$pid"
}

stop_runner_process() {
    local runner_pid="$1"

    kill -TERM "$runner_pid" 2>"$DEVNULL" || true
    # Ensure any child proxy/ffmpeg processes are signaled too.
    pkill -TERM -P "$runner_pid" 2>"$DEVNULL" || true

    for _ in {1..15}; do
        if ! kill -0 "$runner_pid" 2>"$DEVNULL"; then
            wait "$runner_pid" 2>"$DEVNULL" || true
            return 0
        fi
        sleep 1
    done

    kill -KILL "$runner_pid" 2>"$DEVNULL" || true
    pkill -KILL -P "$runner_pid" 2>"$DEVNULL" || true

    for _ in {1..5}; do
        if ! kill -0 "$runner_pid" 2>"$DEVNULL"; then
            break
        fi
        sleep 1
    done

    wait "$runner_pid" 2>"$DEVNULL" || true
}

integration_graceful_restart_real_handoff_smoke() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    local hls_base="$tmp_dir/hls"
    mkdir -p "$bin_dir" "$state_dir" "$hls_base"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

state_dir="${STATE_DIR:-/tmp}"
dest="${@: -1}"
dest_dir="$(dirname "$dest")"
mkdir -p "$dest_dir"

counter_file="$state_dir/ffmpeg_counter"
counter=0
if [[ -f "$counter_file" ]]; then
    counter=$(cat "$counter_file" 2>/dev/null || echo 0)
fi
counter=$((counter + 1))
printf '%s\n' "$counter" > "$counter_file"

segment_name="seg_$(printf '%04d' "$counter").ts"
touch "$dest_dir/$segment_name"
cat > "$dest" <<OUT
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:100
$segment_name
OUT

printf '%s\n' "$dest" >> "$state_dir/ffmpeg_dests"

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail
trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/streamlink"

    local channel_id="test-graceful-${RANDOM}${RANDOM}"
    local channel_dir="$hls_base/$channel_id"
    mkdir -p "$channel_dir"
    cat > "$channel_dir/master.m3u8" <<'EOF'
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:1
old_0001.ts
EOF
    : > "$channel_dir/old_0001.ts"

    local channel_script="$ROOT_DIR/channel_${channel_id}_revised.sh"
    cat > "$channel_script" <<EOF
#!/bin/bash
stream_name="$channel_id"
stream_url="http://primary.example/live.m3u8"
stream_url_backup1=""
stream_url_backup2=""
rtmp_url="/var/www/html/stream/hls/${channel_id}/master.m3u8"
stream_id="/var/www/html/stream/hls/${channel_id}/master.m3u8"
scale=0
EOF
    chmod +x "$channel_script"

    local run_log="$state_dir/graceful_restart.log"
    local failure_msg=""

    rm -f "/tmp/stream_${channel_id}.pid" "/tmp/stream_.graceful_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" "/tmp/stream_.graceful_${channel_id}.lock" 2>"$DEVNULL" || true

    if ! PATH="$bin_dir:$PATH" STATE_DIR="$state_dir" \
        GRACEFUL_HLS_BASE_DIR="$hls_base" GRACEFUL_REQUIRED_SEGMENTS=1 GRACEFUL_MAX_WAIT_SECONDS=20 \
        GRACEFUL_OVERRIDE_STREAM_URL="http://primary.example/live.m3u8" \
        "$ROOT_DIR/graceful_restart.sh" "$channel_id" > "$run_log" 2>&1; then
        failure_msg="graceful_restart.sh smoke run failed for $channel_id"
    fi

    if [[ -z "$failure_msg" ]] && ! grep -Fq "SUCCESS: Channel $channel_id restarted successfully" "$run_log"; then
        failure_msg="graceful_restart.sh did not report successful restart for $channel_id"
    fi
    if [[ -z "$failure_msg" ]] && [[ ! -s "$channel_dir/master.m3u8" ]]; then
        failure_msg="graceful restart did not produce live playlist at $channel_dir/master.m3u8"
    fi
    if [[ -z "$failure_msg" ]] && ! find "$channel_dir" -maxdepth 1 -type f -name "*.ts" -print -quit | grep -q .; then
        failure_msg="graceful restart did not produce any segments in $channel_dir"
    fi

    local pid=""
    pid=$(cat "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>"$DEVNULL"; then
        kill -TERM "$pid" 2>"$DEVNULL" || true
        pkill -TERM -P "$pid" 2>"$DEVNULL" || true
        for _ in {1..10}; do
            if ! kill -0 "$pid" 2>"$DEVNULL"; then
                break
            fi
            sleep 1
        done
        kill -KILL "$pid" 2>"$DEVNULL" || true
        pkill -KILL -P "$pid" 2>"$DEVNULL" || true
    fi

    local temp_pid=""
    temp_pid=$(cat "/tmp/stream_.graceful_${channel_id}.pid" 2>"$DEVNULL" || true)
    if [[ -n "$temp_pid" ]] && kill -0 "$temp_pid" 2>"$DEVNULL"; then
        kill -TERM "$temp_pid" 2>"$DEVNULL" || true
        pkill -TERM -P "$temp_pid" 2>"$DEVNULL" || true
        sleep 1
        kill -KILL "$temp_pid" 2>"$DEVNULL" || true
        pkill -KILL -P "$temp_pid" 2>"$DEVNULL" || true
    fi

    rm -f "/tmp/stream_${channel_id}.pid" "/tmp/stream_.graceful_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" "/tmp/stream_.graceful_${channel_id}.lock" 2>"$DEVNULL" || true
    rm -f "$channel_script" 2>"$DEVNULL" || true

    if [[ -n "$failure_msg" ]]; then
        cat "$run_log" >&2 || true
        rm -rf "$tmp_dir" 2>"$DEVNULL" || true
        fail "$failure_msg"
    fi

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
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
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    # Run try_start_stream with short intervals
    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 PRIMARY_RESTORE_MEDIA_PROBE=0 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -c "$config_file" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file (expected $preferred_log or $fallback_log or $legacy_fallback_log)"
    fi

    # Assert ffmpeg input option ordering via recorded argv
    local args_file="$state_dir/ffmpeg_args"
    for _ in {1..10}; do
        if [[ -f "$args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$args_file" ]]; then
        stop_runner_process "$runner_pid"
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
    ffmpeg_pids=$(grep -oE "FFmpeg PID: [0-9]+" "$log_file" 2>"$DEVNULL" | awk '{print $3}' | sort -u || true)

    # Stop the runner and ensure children are cleaned up
    stop_runner_process "$runner_pid"

    if [[ -n "$ffmpeg_pids" ]]; then
        for pid in $ffmpeg_pids; do
            if kill -0 "$pid" 2>"$DEVNULL"; then
                fail "orphaned ffmpeg process detected after cleanup: pid=$pid"
            fi
        done
    fi

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_skips_unsupported_protocol_urls() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: primary=404, proxied HTTPS backup=403 (preflight false negative), backup2=200
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"

if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    printf '{"granted":true,"slot":1,"remaining":3}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi

if [[ "$url" == *primary* ]]; then
    printf "404"
    exit 0
fi

if [[ "$url" == *live.seenshow.com* ]]; then
    printf "403"
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

    # Stub streamlink so HTTPS HLS can be proxied deterministically
    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
args_file="$state_dir/streamlink_args"
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
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_proto_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url="http://primary.example/stream.m3u8"
    local bad_backup_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"
    local good_backup_url="http://backup2.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$bad_backup_url|$good_backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for protocol test"
    fi

    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1" 10
    wait_for_log_pattern "$log_file" "SEENSHOW: Skipping preflight probe for URL index 1" 10
    wait_for_log_pattern "$log_file" "HTTPS_PROXY: Starting streamlink pipe for HLS:" 10

    local streamlink_args_file="$state_dir/streamlink_args"
    for _ in {1..10}; do
        if [[ -f "$streamlink_args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$streamlink_args_file" ]]; then
        stop_runner_process "$runner_pid"
        fail "streamlink args capture file not found for protocol test"
    fi
    if ! grep -Fq -- "Referer=https://live.seenshow.com/" "$streamlink_args_file"; then
        stop_runner_process "$runner_pid"
        fail "seenshow streamlink request missing Referer header"
    fi
    if ! grep -Fq -- "Origin=https://live.seenshow.com" "$streamlink_args_file"; then
        stop_runner_process "$runner_pid"
        fail "seenshow streamlink request missing Origin header"
    fi

    if grep -Fq "URL_SWITCH: Switching to URL index 2 (reason: HTTP_403)" "$log_file"; then
        fail "proxied HTTPS backup should not be skipped on preflight 403"
    fi

    local ffmpeg_pids
    ffmpeg_pids=$(grep -oE "FFmpeg PID: [0-9]+" "$log_file" 2>"$DEVNULL" | awk '{print $3}' | sort -u || true)

    stop_runner_process "$runner_pid"

    if [[ -n "$ffmpeg_pids" ]]; then
        for pid in $ffmpeg_pids; do
            if kill -0 "$pid" 2>"$DEVNULL"; then
                fail "orphaned ffmpeg process detected after protocol test cleanup: pid=$pid"
            fi
        done
    fi

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_https_seenshow_forces_proxy_even_with_native_https() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: primary=404, seenshow backup preflight=403, backup2=200.
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

url="${@: -1}"
if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    printf '{"granted":true,"slot":1,"remaining":3}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi
if [[ "$url" == *primary* ]]; then
    printf "404"
    exit 0
fi
if [[ "$url" == *live.seenshow.com* ]]; then
    printf "403"
    exit 0
fi
printf "200"
EOF
    chmod +x "$bin_dir/curl"

    # Stub ffmpeg: include native https support.
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
  https
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

    # Stub streamlink to capture args.
    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
args_file="$state_dir/streamlink_args"
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
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_seenshow_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url="http://primary.example/stream.m3u8"
    local seenshow_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"
    local backup2_url="http://backup2.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$seenshow_url|$backup2_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for seenshow proxy test"
    fi

    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1" 10
    wait_for_log_pattern "$log_file" "SEENSHOW: Skipping preflight probe for URL index 1" 10
    wait_for_log_pattern "$log_file" "HTTPS_PROXY: Starting streamlink pipe for HLS:" 10

    local streamlink_args_file="$state_dir/streamlink_args"
    for _ in {1..10}; do
        if [[ -f "$streamlink_args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$streamlink_args_file" ]]; then
        stop_runner_process "$runner_pid"
        fail "streamlink args capture file not found for seenshow proxy test"
    fi
    if ! grep -Fq -- "Referer=https://live.seenshow.com/" "$streamlink_args_file"; then
        stop_runner_process "$runner_pid"
        fail "seenshow proxy path missing Referer header when ffmpeg supports https"
    fi
    if ! grep -Fq -- "Origin=https://live.seenshow.com" "$streamlink_args_file"; then
        stop_runner_process "$runner_pid"
        fail "seenshow proxy path missing Origin header when ffmpeg supports https"
    fi

    if grep -Fq "URL_SWITCH: Switching to URL index 2 (reason: HTTP_403)" "$log_file"; then
        stop_runner_process "$runner_pid"
        fail "seenshow URL should not be skipped on preflight 403 when proxy path is available"
    fi

    stop_runner_process "$runner_pid"
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_https_proxy_fifo_failure_fails_safe() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: primary=404, HTTPS backup=403 (proxy path), backup2=200.
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

url="${@: -1}"
if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    printf '{"granted":true,"slot":1,"remaining":3}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi
if [[ "$url" == *primary* ]]; then
    printf "404"
    exit 0
fi
if [[ "$url" == *live.seenshow.com* ]]; then
    printf "403"
    exit 0
fi
printf "200"
EOF
    chmod +x "$bin_dir/curl"

    # Force FIFO creation failure to exercise safe failover path.
    cat > "$bin_dir/mkfifo" <<'EOF'
#!/bin/bash
set -euo pipefail
exit 1
EOF
    chmod +x "$bin_dir/mkfifo"

    # Stub ffmpeg so runner can continue on non-HTTPS URLs.
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

    # Streamlink should never be invoked when FIFO creation fails.
    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail
state_dir="${STATE_DIR:-/tmp}"
touch "$state_dir/streamlink_called"
trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_fifo_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url="http://primary.example/stream.m3u8"
    local bad_backup_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"
    local good_backup_url="http://backup2.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$bad_backup_url|$good_backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for FIFO test"
    fi

    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 2 (reason: proxy_fifo_unavailable)" 10

    if [[ -f "$state_dir/streamlink_called" ]]; then
        stop_runner_process "$runner_pid"
        fail "streamlink must not start when HTTPS proxy FIFO initialization fails"
    fi

    stop_runner_process "$runner_pid"
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_seenshow_primary_acquires_slot() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"

if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    touch "$state_dir/acquire_called"
    printf '{"granted":true,"slot":1,"remaining":3}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    touch "$state_dir/release_called"
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    touch "$state_dir/resolve_called"
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi

printf "200"
EOF
    chmod +x "$bin_dir/curl"

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
  https
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

    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
touch "$state_dir/streamlink_called"
trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_ss_primary_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=120 CONFIG_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for Seenshow-primary slot test"
    fi

    wait_for_log_pattern "$log_file" "SEENSHOW: Acquired resolver slot for $channel_id" 12
    wait_for_log_pattern "$log_file" "SEENSHOW: Refreshed tokenized URL for index 0" 12
    wait_for_file "$state_dir/acquire_called" 12
    wait_for_file "$state_dir/resolve_called" 12
    wait_for_file "$state_dir/streamlink_called" 12

    stop_runner_process "$runner_pid"
    wait_for_file "$state_dir/release_called" 12

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_seenshow_slot_identity_override() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"

if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    printf '%s\n' "$url" > "$state_dir/acquire_url"
    printf '{"granted":true,"slot":1,"remaining":3}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    printf '%s\n' "$url" > "$state_dir/release_url"
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi

printf "200"
EOF
    chmod +x "$bin_dir/curl"

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
  https
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

    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail
trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_ss_slot_id_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"
    local slot_owner="canonical-slot-owner"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        SEENSHOW_SLOT_CHANNEL_ID="$slot_owner" \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for Seenshow slot identity test"
    fi

    wait_for_log_pattern "$log_file" "SEENSHOW: Acquired resolver slot for $slot_owner (runner: $channel_id)" 12
    wait_for_file "$state_dir/acquire_url" 12

    if ! grep -Fq "/acquire/${slot_owner}" "$state_dir/acquire_url"; then
        stop_runner_process "$runner_pid"
        fail "expected acquire call to use canonical slot identity ($slot_owner)"
    fi

    stop_runner_process "$runner_pid"
    wait_for_file "$state_dir/release_url" 12
    if ! grep -Fq "/release/${slot_owner}" "$state_dir/release_url"; then
        fail "expected release call to use canonical slot identity ($slot_owner)"
    fi

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_seenshow_slot_touch_denied_switches_away() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
url="${@: -1}"
count_file="$state_dir/acquire_count"
count=0
if [[ -f "$count_file" ]]; then
    count=$(cat "$count_file" 2>/dev/null || echo 0)
fi

if [[ "$url" == http://127.0.0.1:8090/acquire/* ]]; then
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    touch "$state_dir/acquire_called"
    if [[ "$count" -eq 1 ]]; then
        printf '{"granted":true,"slot":1,"remaining":3}'
    else
        printf '{"granted":false,"reason":"max_concurrent_reached","max":1}'
    fi
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/release/* ]]; then
    touch "$state_dir/release_called"
    printf '{"released":true,"remaining":4}'
    exit 0
fi
if [[ "$url" == http://127.0.0.1:8090/resolve/* ]]; then
    touch "$state_dir/resolve_called"
    printf '{"url":"https://live.seenshow.com/hls/live/test/live/hdntl=exp=9999999999~acl=%2fhls%2flive%2ftest%2flive%2f*~hmac=x/3.m3u8"}'
    exit 0
fi

printf "200"
EOF
    chmod +x "$bin_dir/curl"

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
  https
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

    cat > "$bin_dir/streamlink" <<'EOF'
#!/bin/bash
set -euo pipefail
state_dir="${STATE_DIR:-/tmp}"
touch "$state_dir/streamlink_called"
trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/streamlink"

    local channel_id="test_ss_touch_deny_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="https://live.seenshow.com/hls/live/test/live/master.m3u8"
    local backup_url="http://backup.example/live.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        URL_HOTSWAP_ENABLE=0 SEENSHOW_SLOT_TOUCH_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for Seenshow slot-loss test"
    fi

    wait_for_log_pattern "$log_file" "SEENSHOW: Lost resolver slot lease for URL index 0" 15
    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1 (reason: seenshow_slot_lost)" 15
    wait_for_log_pattern "$log_file" "ATTEMPT: URL index 1, retry 0" 15

    acquire_count=$(cat "$state_dir/acquire_count" 2>"$DEVNULL" || echo 0)
    if [[ "$acquire_count" -lt 3 ]]; then
        stop_runner_process "$runner_pid"
        fail "expected at least 3 acquire calls (initial + heartbeat + re-acquire), got $acquire_count"
    fi

    sleep 2
    if ! kill -0 "$runner_pid" 2>"$DEVNULL"; then
        fail "runner exited after Seenshow slot loss; expected fallback stream to continue"
    fi

    stop_runner_process "$runner_pid"
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_primary_hotswap_success_exits_runner() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

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

printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

state_dir="${STATE_DIR:-/tmp}"
echo "$$" >> "$state_dir/ffmpeg_pids"

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    cat > "$bin_dir/hotswap_ok.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
channel_id="${1:-}"
replacement_pid=424242
if [[ -n "$channel_id" ]]; then
    mkdir -p "/tmp/stream_${channel_id}.lock"
    printf '%s\n' "$replacement_pid" > "/tmp/stream_${channel_id}.pid"
fi
touch "$state_dir/hotswap_called"
printf 'skip=%s caller=%s replacement_pid=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" "$replacement_pid" > "$state_dir/hotswap_env"
exit 0
EOF
    chmod +x "$bin_dir/hotswap_ok.sh"

    local channel_id="test_hotswap_ok_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_RESTORE_CONFIRMATIONS=1 PRIMARY_RESTORE_MEDIA_PROBE=0 \
        PRIMARY_HOTSWAP_ENABLE=1 PRIMARY_HOTSWAP_SCRIPT="$bin_dir/hotswap_ok.sh" \
        PRIMARY_HOTSWAP_TIMEOUT=15 PRIMARY_HOTSWAP_COOLDOWN=120 URL_HOTSWAP_ENABLE=0 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for hot-swap success test"
    fi

    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1" 10
    touch "$state_dir/primary_up"
    wait_for_log_pattern "$log_file" "PRIMARY_HOTSWAP: Starting seamless handoff via $bin_dir/hotswap_ok.sh $channel_id" 12
    wait_for_file "$state_dir/hotswap_called" 12
    if ! grep -qE '^skip=1 caller=[0-9]+ replacement_pid=424242$' "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "hot-swap success test did not receive caller-preserving environment"
    fi
    wait_for_log_pattern "$log_file" "PRIMARY_HOTSWAP: Handoff completed. Exiting current instance." 12
    wait_for_process_exit "$runner_pid" 12

    if [[ ! -f "/tmp/stream_${channel_id}.pid" ]]; then
        fail "runner cleanup removed replacement pidfile after successful hot-swap"
    fi
    if ! grep -Fxq "424242" "/tmp/stream_${channel_id}.pid"; then
        fail "replacement pidfile content changed unexpectedly after successful hot-swap"
    fi
    if [[ ! -d "/tmp/stream_${channel_id}.lock" ]]; then
        fail "runner cleanup removed replacement lockdir after successful hot-swap"
    fi

    rm -f "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" 2>"$DEVNULL" || true

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_primary_hotswap_failure_stays_on_backup() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

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

printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

    cat > "$bin_dir/hotswap_fail.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
touch "$state_dir/hotswap_called"
printf 'skip=%s caller=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" > "$state_dir/hotswap_env"
exit 42
EOF
    chmod +x "$bin_dir/hotswap_fail.sh"

    local channel_id="test_hotswap_fail_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=2 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_RESTORE_CONFIRMATIONS=1 PRIMARY_RESTORE_MEDIA_PROBE=0 \
        PRIMARY_HOTSWAP_ENABLE=1 PRIMARY_HOTSWAP_SCRIPT="$bin_dir/hotswap_fail.sh" \
        PRIMARY_HOTSWAP_TIMEOUT=15 PRIMARY_HOTSWAP_COOLDOWN=600 URL_HOTSWAP_ENABLE=0 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for hot-swap failure test"
    fi

    wait_for_log_pattern "$log_file" "URL_SWITCH: Switching to URL index 1" 10
    touch "$state_dir/primary_up"
    wait_for_log_pattern "$log_file" "PRIMARY_HOTSWAP: Starting seamless handoff via $bin_dir/hotswap_fail.sh $channel_id" 12
    wait_for_file "$state_dir/hotswap_called" 12
    if ! grep -qE '^skip=1 caller=[0-9]+$' "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "hot-swap failure test did not receive caller-preserving environment"
    fi
    wait_for_log_pattern "$log_file" "PRIMARY_HOTSWAP: Handoff failed. Staying on backup URL index 1." 12

    sleep 4
    if ! kill -0 "$runner_pid" 2>"$DEVNULL"; then
        fail "runner exited after failed hot-swap; expected it to keep backup stream"
    fi

    stop_runner_process "$runner_pid"
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_config_reload_primary_updates_ffmpeg_input() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    # Stub curl: always healthy (200)
    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf "200"
EOF
    chmod +x "$bin_dir/curl"

    # Stub ffmpeg:
    # - supports -protocols and -encoders discovery calls
    # - records the input URL passed to -i on each invocation
    # - does NOT create segments, so SEGMENT_STALE triggers and forces restart
    cat > "$bin_dir/ffmpeg" <<'EOF'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "-hide_banner" && "${2:-}" == "-encoders" ]]; then
    cat <<OUT
Encoders:
 V.S..D mpeg2video           MPEG-2 video
 V....D libx264              libx264 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10
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

state_dir="${STATE_DIR:-/tmp}"
inputs_file="$state_dir/ffmpeg_inputs"

input=""
prev=""
for arg in "$@"; do
    if [[ "$prev" == "-i" ]]; then
        input="$arg"
        break
    fi
    prev="$arg"
done

if [[ -n "$input" ]]; then
    printf '%s\n' "$input" >> "$inputs_file"
fi

trap 'exit 0' TERM INT
while true; do
    sleep 1
done
EOF
    chmod +x "$bin_dir/ffmpeg"

    local channel_id="test_primary_reload_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"

    local primary_url_1="http://primary1.example/stream.m3u8"
    local primary_url_2="http://primary2.example/stream.m3u8"

    local config_file="$tmp_dir/channel_test.sh"
    cat > "$config_file" <<EOF
stream_url="$primary_url_1"
EOF

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 PRIMARY_RESTORE_MEDIA_PROBE=0 \
        SEGMENT_STALE_THRESHOLD=2 SEGMENT_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url_1" -d "$dest" -c "$config_file" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for primary reload test"
    fi

    wait_for_file "$state_dir/ffmpeg_inputs" 10
    if ! grep -Fq -- "$primary_url_1" "$state_dir/ffmpeg_inputs"; then
        stop_runner_process "$runner_pid"
        fail "primary reload test did not start ffmpeg with initial primary URL"
    fi

    # Change primary URL in config; runner must pick it up and apply it on the next restart.
    cat > "$config_file" <<EOF
stream_url="$primary_url_2"
EOF
    wait_for_log_pattern "$log_file" "CONFIG_RELOAD: Primary URL changed! Old:" 10

    # Ensure segment-stale restart path triggers for single-URL channels.
    wait_for_log_pattern "$log_file" "SEGMENT_STALE: Output stale, restarting FFmpeg on current URL (no backups configured)..." 12

    local waited=0
    while (( waited < 15 )); do
        if grep -Fq -- "$primary_url_2" "$state_dir/ffmpeg_inputs"; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if (( waited >= 15 )); then
        stop_runner_process "$runner_pid"
        fail "primary reload test did not apply updated primary URL to ffmpeg input after restart"
    fi

    stop_runner_process "$runner_pid"
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_segment_stale_hotswap_success_exits_runner() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

    cat > "$bin_dir/segment_hotswap_ok.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
channel_id="${1:-}"
replacement_pid=434343
if [[ -n "$channel_id" ]]; then
    mkdir -p "/tmp/stream_${channel_id}.lock"
    printf '%s\n' "$replacement_pid" > "/tmp/stream_${channel_id}.pid"
fi
touch "$state_dir/hotswap_called"
{
    printf 'skip=%s caller=%s replacement_pid=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" "$replacement_pid"
    printf 'stream=%s\n' "${GRACEFUL_OVERRIDE_STREAM_URL:-}"
    printf 'backups=%s\n' "${GRACEFUL_OVERRIDE_BACKUP_URLS:-}"
    printf 'start_index=%s\n' "${GRACEFUL_OVERRIDE_START_INDEX:-}"
} > "$state_dir/hotswap_env"
exit 0
EOF
    chmod +x "$bin_dir/segment_hotswap_ok.sh"

    local channel_id="test_seg_hotswap_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_HOTSWAP_ENABLE=0 URL_HOTSWAP_ENABLE=1 URL_HOTSWAP_SCRIPT="$bin_dir/segment_hotswap_ok.sh" \
        URL_HOTSWAP_TIMEOUT=15 URL_HOTSWAP_COOLDOWN=120 SEGMENT_STALE_THRESHOLD=2 SEGMENT_CHECK_INTERVAL=1 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for segment stale hot-swap test"
    fi

    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Attempting seamless handoff from index 0 to 1 (reason: segment_stale)" 12
    wait_for_file "$state_dir/hotswap_called" 12
    if ! grep -qE '^skip=1 caller=[0-9]+ replacement_pid=434343$' "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "segment stale hot-swap test missing caller-preserving environment"
    fi
    if ! grep -Fxq "stream=$primary_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "segment stale hot-swap should preserve canonical primary URL as override stream"
    fi
    if ! grep -Fxq "backups=$backup_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "segment stale hot-swap should preserve canonical backup ordering"
    fi
    if ! grep -Fxq "start_index=1" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "segment stale hot-swap missing override start index for target URL"
    fi
    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Handoff completed. Exiting current instance." 12
    wait_for_process_exit "$runner_pid" 12

    rm -f "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" 2>"$DEVNULL" || true

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_http_4xx_hotswap_success_exits_runner() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail

url="${@: -1}"
if [[ "$url" == *primary* ]]; then
    printf "403"
    exit 0
fi
printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

    cat > "$bin_dir/http_hotswap_ok.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
channel_id="${1:-}"
replacement_pid=454545
if [[ -n "$channel_id" ]]; then
    mkdir -p "/tmp/stream_${channel_id}.lock"
    printf '%s\n' "$replacement_pid" > "/tmp/stream_${channel_id}.pid"
fi
touch "$state_dir/hotswap_called"
{
    printf 'skip=%s caller=%s replacement_pid=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" "$replacement_pid"
    printf 'stream=%s\n' "${GRACEFUL_OVERRIDE_STREAM_URL:-}"
    printf 'backups=%s\n' "${GRACEFUL_OVERRIDE_BACKUP_URLS:-}"
    printf 'start_index=%s\n' "${GRACEFUL_OVERRIDE_START_INDEX:-}"
} > "$state_dir/hotswap_env"
exit 0
EOF
    chmod +x "$bin_dir/http_hotswap_ok.sh"

    local channel_id="test_http_hotswap_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    # Simulate existing live output so URL hot-swap path is eligible.
    cat > "$dest" <<'EOF'
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:100
old_0100.ts
EOF
    : > "$dest_dir/old_0100.ts"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_HOTSWAP_ENABLE=0 URL_HOTSWAP_ENABLE=1 URL_HOTSWAP_SCRIPT="$bin_dir/http_hotswap_ok.sh" \
        URL_HOTSWAP_TIMEOUT=15 URL_HOTSWAP_COOLDOWN=120 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for HTTP 4xx hot-swap test"
    fi

    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Attempting seamless handoff from index 0 to 1 (reason: HTTP_403)" 12
    wait_for_file "$state_dir/hotswap_called" 12
    if ! grep -qE '^skip=1 caller=[0-9]+ replacement_pid=454545$' "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "HTTP 4xx hot-swap test missing caller-preserving environment"
    fi
    if ! grep -Fxq "stream=$primary_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "HTTP 4xx hot-swap should preserve canonical primary URL as override stream"
    fi
    if ! grep -Fxq "backups=$backup_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "HTTP 4xx hot-swap should preserve canonical backup ordering"
    fi
    if ! grep -Fxq "start_index=1" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "HTTP 4xx hot-swap missing override start index for target URL"
    fi
    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Handoff completed. Exiting current instance." 12
    wait_for_process_exit "$runner_pid" 12

    rm -f "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" 2>"$DEVNULL" || true
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_max_retries_hotswap_success_exits_runner() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

# Fail quickly to trigger short-run retries and max_retries failover path.
sleep 1
exit 1
EOF
    chmod +x "$bin_dir/ffmpeg"

    cat > "$bin_dir/maxretry_hotswap_ok.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
channel_id="${1:-}"
replacement_pid=464646
if [[ -n "$channel_id" ]]; then
    mkdir -p "/tmp/stream_${channel_id}.lock"
    printf '%s\n' "$replacement_pid" > "/tmp/stream_${channel_id}.pid"
fi
touch "$state_dir/hotswap_called"
{
    printf 'skip=%s caller=%s replacement_pid=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" "$replacement_pid"
    printf 'stream=%s\n' "${GRACEFUL_OVERRIDE_STREAM_URL:-}"
    printf 'backups=%s\n' "${GRACEFUL_OVERRIDE_BACKUP_URLS:-}"
    printf 'start_index=%s\n' "${GRACEFUL_OVERRIDE_START_INDEX:-}"
} > "$state_dir/hotswap_env"
exit 0
EOF
    chmod +x "$bin_dir/maxretry_hotswap_ok.sh"

    local channel_id="test_maxretry_hotswap_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    # Simulate existing live output so URL hot-swap path is eligible.
    cat > "$dest" <<'EOF'
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:100
old_0100.ts
EOF
    : > "$dest_dir/old_0100.ts"

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_HOTSWAP_ENABLE=0 URL_HOTSWAP_ENABLE=1 URL_HOTSWAP_SCRIPT="$bin_dir/maxretry_hotswap_ok.sh" \
        URL_HOTSWAP_TIMEOUT=15 URL_HOTSWAP_COOLDOWN=120 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for max_retries hot-swap test"
    fi

    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Attempting seamless handoff from index 0 to 1 (reason: max_retries)" 20
    wait_for_file "$state_dir/hotswap_called" 20
    if ! grep -qE '^skip=1 caller=[0-9]+ replacement_pid=464646$' "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "max_retries hot-swap test missing caller-preserving environment"
    fi
    if ! grep -Fxq "stream=$primary_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "max_retries hot-swap should preserve canonical primary URL as override stream"
    fi
    if ! grep -Fxq "backups=$backup_url" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "max_retries hot-swap should preserve canonical backup ordering"
    fi
    if ! grep -Fxq "start_index=1" "$state_dir/hotswap_env"; then
        stop_runner_process "$runner_pid"
        fail "max_retries hot-swap missing override start index for target URL"
    fi
    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Handoff completed. Exiting current instance." 20
    wait_for_process_exit "$runner_pid" 20

    rm -f "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" 2>"$DEVNULL" || true
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_max_retries_hotswap_without_live_state() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local bin_dir="$tmp_dir/bin"
    local state_dir="$tmp_dir/state"
    mkdir -p "$bin_dir" "$state_dir"

    cat > "$bin_dir/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
printf "200"
EOF
    chmod +x "$bin_dir/curl"

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

sleep 1
exit 1
EOF
    chmod +x "$bin_dir/ffmpeg"

    cat > "$bin_dir/maxretry_hotswap_nolive.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

state_dir="${STATE_DIR:-/tmp}"
channel_id="${1:-}"
replacement_pid=565656
if [[ -n "$channel_id" ]]; then
    mkdir -p "/tmp/stream_${channel_id}.lock"
    printf '%s\n' "$replacement_pid" > "/tmp/stream_${channel_id}.pid"
fi
touch "$state_dir/hotswap_called"
printf 'skip=%s caller=%s replacement_pid=%s\n' "${GRACEFUL_SKIP_CALLER_KILL:-}" "${GRACEFUL_CALLER_PID:-}" "$replacement_pid" > "$state_dir/hotswap_env"
exit 0
EOF
    chmod +x "$bin_dir/maxretry_hotswap_nolive.sh"

    local channel_id="test_maxretry_nolive_${RANDOM}${RANDOM}"
    local dest_dir="$tmp_dir/$channel_id"
    mkdir -p "$dest_dir"
    local dest="$dest_dir/master.m3u8"
    local primary_url="http://primary.example/stream.m3u8"
    local backup_url="http://backup.example/stream.m3u8"

    # Do not pre-seed any output playlist/segments: this validates cold handoff behavior.
    rm -f "$dest" "$dest_dir"/*.ts 2>"$DEVNULL" || true

    local preferred_log="$ROOT_DIR/logs/${channel_id}.log"
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" PRIMARY_CHECK_INTERVAL=600 CONFIG_CHECK_INTERVAL=1 \
        PRIMARY_HOTSWAP_ENABLE=0 URL_HOTSWAP_ENABLE=1 URL_HOTSWAP_SCRIPT="$bin_dir/maxretry_hotswap_nolive.sh" \
        URL_HOTSWAP_TIMEOUT=15 URL_HOTSWAP_COOLDOWN=120 \
        "$ROOT_DIR/try_start_stream.sh" -u "$primary_url" -b "$backup_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for max_retries cold-handoff test"
    fi

    wait_for_log_pattern "$log_file" "URL_HOTSWAP: No live output state detected (reason: max_retries). Attempting cold handoff to avoid hard switch." 20
    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Attempting seamless handoff from index 0 to 1 (reason: max_retries)" 20
    wait_for_file "$state_dir/hotswap_called" 20
    wait_for_log_pattern "$log_file" "URL_HOTSWAP: Handoff completed. Exiting current instance." 20
    wait_for_process_exit "$runner_pid" 20

    rm -f "/tmp/stream_${channel_id}.pid" 2>"$DEVNULL" || true
    rmdir "/tmp/stream_${channel_id}.lock" 2>"$DEVNULL" || true
    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
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
    local fallback_log
    fallback_log="$(fallback_log_path_for_channel "$channel_id")"
    local legacy_fallback_log
    legacy_fallback_log="$(legacy_fallback_log_path_for_channel "$channel_id")"
    rm -f "$preferred_log" "$fallback_log" "$legacy_fallback_log" 2>"$DEVNULL" || true

    STATE_DIR="$state_dir" PATH="$bin_dir:$PATH" \
        "$ROOT_DIR/try_start_stream.sh" -u "$file_url" -d "$dest" -n "$channel_id" &
    local runner_pid=$!

    local log_file=""
    if ! log_file="$(wait_for_log_file_any_location "$preferred_log" "$fallback_log" "$legacy_fallback_log" 10)"; then
        stop_runner_process "$runner_pid"
        fail "try_start_stream.sh did not create a log file for file-scheme test"
    fi

    wait_for_log_pattern "$log_file" "URL validation skipped for non-HTTP scheme: file" 10

    local args_file="$state_dir/ffmpeg_args"
    for _ in {1..10}; do
        if [[ -f "$args_file" ]]; then
            break
        fi
        sleep 1
    done
    if [[ ! -f "$args_file" ]]; then
        stop_runner_process "$runner_pid"
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

    stop_runner_process "$runner_pid"

    rm -rf "$tmp_dir" 2>"$DEVNULL" || true
}

integration_primary_fallback_and_hot_reload
integration_graceful_restart_real_handoff_smoke
integration_skips_unsupported_protocol_urls
integration_https_seenshow_forces_proxy_even_with_native_https
integration_https_proxy_fifo_failure_fails_safe
integration_seenshow_primary_acquires_slot
integration_seenshow_slot_identity_override
integration_seenshow_slot_touch_denied_switches_away
integration_primary_hotswap_success_exits_runner
integration_primary_hotswap_failure_stays_on_backup
integration_config_reload_primary_updates_ffmpeg_input
integration_segment_stale_hotswap_success_exits_runner
integration_http_4xx_hotswap_success_exits_runner
integration_max_retries_hotswap_success_exits_runner
integration_max_retries_hotswap_without_live_state
integration_file_scheme_omits_http_flags

if [[ -f "$ROOT_DIR/tests/provider_sync.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/provider_sync.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/segment_cache.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/segment_cache.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/resolver_utils.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/resolver_utils.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/resolver_request_parse.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/resolver_request_parse.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/session_slots.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/session_slots.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/page_setup.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/page_setup.unit.test.js"
fi
if [[ -f "$ROOT_DIR/tests/seenshow_resolver.unit.test.js" ]]; then
    node --test "$ROOT_DIR/tests/seenshow_resolver.unit.test.js"
fi

# ---------------------------------------------------------------------------
# Aloula/KwikMotion variant URL resolution tests
# Tests the URL-joining logic in resolve_aloula_url for:
#   1. Relative variant path (existing behavior)
#   2. Absolute URI (full https:// URL) — must use as-is
#   3. Absolute path (starts with /) — must join with origin
# ---------------------------------------------------------------------------
echo "--- Aloula variant URL resolution tests ---"
aloula_test_pass=0
aloula_test_fail=0

# Extract the real _resolve_hls_variant_url function from try_start_stream.sh
# so the test always runs production code (no drift risk from a copy).
# Shared temp dir for function extraction (cleaned up by trap below KwikMotion section).
_test_shim_tmpdir=$(mktemp -d)

sed -n '/^_resolve_hls_variant_url()/,/^}/p' "$ROOT_DIR/try_start_stream.sh" > "$_test_shim_tmpdir/aloula_shim.sh"
# shellcheck source=/dev/null
source "$_test_shim_tmpdir/aloula_shim.sh"

# Wrapper to match existing test callsites
_resolve_variant_url() {
    _resolve_hls_variant_url "$@"
}

_aloula_assert() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS: $desc"
        ((aloula_test_pass++)) || true
    else
        echo "  FAIL: $desc"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        ((aloula_test_fail++)) || true
    fi
}

# Test 1: Relative variant path (standard case)
_aloula_assert "relative variant path" \
    "https://live.kwikmotion.com/live/ch7/variant_high.m3u8" \
    "$(_resolve_variant_url \
        "https://live.kwikmotion.com/live/ch7/playlist_dvr.m3u8?hdnts=exp=999~hmac=abc" \
        "variant_high.m3u8")"

# Test 2: Absolute URI — variant is a full https:// URL (HLS spec compliant)
_aloula_assert "absolute URI variant" \
    "https://cdn.kwikmotion.com/live/ch7/variant_high.m3u8?token=xyz" \
    "$(_resolve_variant_url \
        "https://live.kwikmotion.com/live/ch7/playlist_dvr.m3u8?hdnts=exp=999~hmac=abc" \
        "https://cdn.kwikmotion.com/live/ch7/variant_high.m3u8?token=xyz")"

# Test 3: Absolute path — starts with /
_aloula_assert "absolute path variant" \
    "https://live.kwikmotion.com/other/path/variant.m3u8" \
    "$(_resolve_variant_url \
        "https://live.kwikmotion.com/live/ch7/playlist_dvr.m3u8?hdnts=exp=999~hmac=abc" \
        "/other/path/variant.m3u8")"

# Test 4: Relative with query string on variant
_aloula_assert "relative variant with query" \
    "https://live.kwikmotion.com/live/ch7/high.m3u8?hdntl=tok" \
    "$(_resolve_variant_url \
        "https://live.kwikmotion.com/live/ch7/master.m3u8" \
        "high.m3u8?hdntl=tok")"

# Test 5: Master URL with no query string
_aloula_assert "master without query string" \
    "https://live.kwikmotion.com/live/ch7/variant.m3u8" \
    "$(_resolve_variant_url \
        "https://live.kwikmotion.com/live/ch7/playlist_dvr.m3u8" \
        "variant.m3u8")"

# Test 6: HTTP master (not HTTPS)
_aloula_assert "http master with absolute path" \
    "http://live.kwikmotion.com/alt/variant.m3u8" \
    "$(_resolve_variant_url \
        "http://live.kwikmotion.com/live/ch7/master.m3u8" \
        "/alt/variant.m3u8")"

if [[ $aloula_test_fail -gt 0 ]]; then
    fail "Aloula variant URL resolution: ${aloula_test_fail} test(s) failed"
fi
echo "PASS: All ${aloula_test_pass} Aloula variant URL resolution tests passed."

# ---------------------------------------------------------------------------
# KwikMotion expiry extraction tests (portability: uses sed, not grep -P)
# ---------------------------------------------------------------------------
echo "--- KwikMotion expiry extraction tests ---"

# Source just the url_decode and extract_kwikmotion_expiry functions.
# We reuse the shared temp dir created above for function extraction.
trap 'rm -rf "$_test_shim_tmpdir"' EXIT

cat > "$_test_shim_tmpdir/kwik_shim.sh" << 'SHIMEOF'
#!/bin/bash
DEVNULL=/dev/null
url_decode() {
    local encoded="$1"
    printf '%b' "${encoded//%/\\x}"
}
SHIMEOF

# Extract extract_kwikmotion_expiry from try_start_stream.sh
sed -n '/^extract_kwikmotion_expiry()/,/^}/p' "$ROOT_DIR/try_start_stream.sh" >> "$_test_shim_tmpdir/kwik_shim.sh"

kwik_test_pass=0
kwik_test_fail=0

_kwik_assert() {
    local desc="$1" expected="$2" url="$3"
    local actual
    actual=$(bash -c "source '$_test_shim_tmpdir/kwik_shim.sh'; extract_kwikmotion_expiry '$url'" 2>/dev/null || true)
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS: $desc"
        ((kwik_test_pass++)) || true
    else
        echo "  FAIL: $desc"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        ((kwik_test_fail++)) || true
    fi
}

# Test 1: hdntl path token with url-encoded expiry
_kwik_assert "hdntl path token" "1771023456" \
    "https://live.kwikmotion.com/live/ch7/hdntl=exp%3D1771023456~acl%3D%2f/variant.m3u8"

# Test 2: hdnts query token
_kwik_assert "hdnts query token" "1771099999" \
    "https://live.kwikmotion.com/live/ch7/master.m3u8?hdnts=exp%3D1771099999~hmac%3Dabc"

# Test 3: No token present
_kwik_assert "no token returns 0" "0" \
    "https://live.kwikmotion.com/live/ch7/variant.m3u8"

# Test 4: hdntl with tilde-separated fields (not url-encoded)
_kwik_assert "hdntl plain tilde" "1771023400" \
    "https://live.kwikmotion.com/live/ch7/hdntl=exp=1771023400~acl=%2f/variant.m3u8"

if [[ $kwik_test_fail -gt 0 ]]; then
    fail "KwikMotion expiry extraction: ${kwik_test_fail} test(s) failed"
fi
echo "PASS: All ${kwik_test_pass} KwikMotion expiry extraction tests passed."

# ---------------------------------------------------------------------------
# Token persistence gate: no hdntl= or hdnts= tokens may be persisted in
# the channel registry or channel config scripts.  Tokens are resolved at
# runtime by try_start_stream.sh via the seenshow resolver.
# ---------------------------------------------------------------------------
echo "--- Token persistence gate ---"
token_hits=$(grep -rn 'hdntl=\|hdnts=' "$ROOT_DIR/channel_registry.json" "$ROOT_DIR"/channel_*.sh 2>/dev/null || true)
if [[ -n "$token_hits" ]]; then
    echo "FAIL: Persisted seenshow/kwikmotion tokens found in config files:"
    echo "$token_hits"
    exit 1
fi
echo "PASS: No persisted tokens in registry or channel configs."

echo "All tests passed."
