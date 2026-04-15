#!/bin/bash
# channels/reflex/state.sh
# Per-channel state file I/O with atomic writes + flock serialization.
# State files live at $STATE_DIR/<channel_id>.json (default /var/run/albunyaan/state).

STATE_DIR="${STATE_DIR:-/var/run/albunyaan/state}"
# Persistent sidecar for "sticky" state that must survive tmpfs wipes
# (circuit-breaker DEGRADED, crash-loop resilience). Backed by disk via
# systemd StateDirectory=albunyaan. Overridable for tests.
STATE_PERSIST_DIR="${STATE_PERSIST_DIR:-/var/lib/albunyaan}"
# Sticky entries expire after this many seconds. DEGRADED doesn't auto-
# clear, but after ~24h we assume any latent fault has been fixed (or the
# channel has been removed) and stop re-loading a stale breaker trip.
STATE_PERSIST_TTL_SEC="${STATE_PERSIST_TTL_SEC:-86400}"

_state_path()  { echo "$STATE_DIR/$1.json"; }
_state_lock()  { echo "$STATE_DIR/$1.lock"; }
_state_sticky_path() { echo "$STATE_PERSIST_DIR/$1.sticky.json"; }

_state_default_json() {
    local ch="$1" now; now=$(date -Iseconds)
    cat <<EOF
{
  "channel_id": "$ch",
  "state": "LIVE",
  "current_source_url": null,
  "current_source_role": null,
  "last_transition": "$now",
  "grace_until": "$now",
  "identity_status": "unknown",
  "identity_checked_at": null,
  "reverify_requested": false,
  "primary_probe": {
    "last_attempt": null,
    "consecutive_failures": 0,
    "consecutive_successes": 0,
    "next_attempt_after": "$now"
  },
  "backup_walk_cursor": 0,
  "excluded_backups": [],
  "slate_retry_count": 0,
  "transition_history": []
}
EOF
}

# state_write_sticky <channel_id> <jq_expr> [jq args...]
# Persists "sticky" state to STATE_PERSIST_DIR. Separate from the main
# state file so tmpfs wipes (systemd Restart, reboot) don't clear the
# circuit breaker. Each call overwrites with a fresh timestamp.
state_write_sticky() {
    local ch="$1" expr="$2"
    shift 2
    mkdir -p "$STATE_PERSIST_DIR" 2>/dev/null || return 1
    local path tmp now
    path=$(_state_sticky_path "$ch")
    tmp="${path}.tmp.$$"
    now=$(date +%s)
    local base="{}"
    [[ -r "$path" ]] && jq -e . "$path" >/dev/null 2>&1 && base=$(cat "$path")
    if ! jq --argjson ts "$now" "$@" "$expr | .persisted_at = \$ts" <<<"$base" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    mv -f "$tmp" "$path"
}

# _state_sticky_read <ch>
# Echoes sticky JSON if it exists and is within STATE_PERSIST_TTL_SEC.
# Otherwise echoes empty.
_state_sticky_read() {
    local ch="$1" path; path=$(_state_sticky_path "$ch")
    [[ -r "$path" ]] || return 1
    jq -e . "$path" >/dev/null 2>&1 || return 1
    local now ts age; now=$(date +%s)
    ts=$(jq -r '.persisted_at // 0' "$path" 2>/dev/null)
    age=$(( now - ts ))
    (( age <= STATE_PERSIST_TTL_SEC )) || return 1
    cat "$path"
}

# state_init <channel_id>
# Ensures a valid state file exists. If the file is missing OR unparseable,
# (re-)creates it with defaults. Corrupt files are quarantined as .broken.<ts>.
# On first create, rehydrates sticky fields (DEGRADED breaker) from disk.
state_init() {
    local ch="$1" path; path=$(_state_path "$ch")
    mkdir -p "$STATE_DIR"
    if [[ -f "$path" ]]; then
        if jq -e . "$path" >/dev/null 2>&1; then
            return 0
        fi
        local ts; ts=$(date +%s)
        mv "$path" "${path}.broken.${ts}"
    fi
    local tmp="${path}.tmp.$$"
    _state_default_json "$ch" > "$tmp"
    mv -f "$tmp" "$path"
    # Rehydrate sticky fields (currently: DEGRADED breaker). The sticky
    # file persists across tmpfs wipes; without this step, a systemd
    # crash loop (OOM + Restart=always) would silently reset the
    # breaker every 5s and re-enable auto-actions on a genuinely
    # flapping channel.
    local sticky; sticky=$(_state_sticky_read "$ch") || return 0
    local state_val; state_val=$(jq -r '.state // empty' <<<"$sticky")
    if [[ "$state_val" == "DEGRADED" ]]; then
        state_modify "$ch" '.state = "DEGRADED"'
    fi
}

# state_read_field <channel_id> <jq_expr>
# Returns the field as a plain string (jq -r).
state_read_field() {
    local ch="$1" expr="$2" path; path=$(_state_path "$ch")
    [[ -f "$path" ]] || { echo ""; return 1; }
    jq -r "$expr" "$path" 2>/dev/null
}

# state_modify <channel_id> <jq_expr> [jq args...]
# Applies the jq expression to the state file under flock. Atomic via
# temp-file-then-rename. Extra arguments are passed through to jq —
# use --arg/--argjson pairs to inject untrusted values (URLs, reasons,
# channel IDs, etc.) WITHOUT splicing them into the jq program text.
# Example:
#   state_modify "$ch" '.current_source_url = $u' --arg u "$url"
state_modify() {
    local ch="$1" expr="$2"
    shift 2
    local path lock tmp
    path=$(_state_path "$ch"); lock=$(_state_lock "$ch")
    mkdir -p "$STATE_DIR"
    exec 200>"$lock"
    flock -x 200
    [[ -f "$path" ]] || _state_default_json "$ch" > "$path"
    tmp="${path}.tmp.$$"
    if ! jq "$@" "$expr" "$path" > "$tmp"; then
        rm -f "$tmp"
        exec 200>&-
        return 1
    fi
    mv -f "$tmp" "$path"
    exec 200>&-
}

# state_write_field <channel_id> <jq_expr_path> <jq_value_expr>
# Convenience wrapper: state_write_field ch ".state" '"SLATE"'
state_write_field() {
    local ch="$1" jpath="$2" jvalue="$3"
    state_modify "$ch" "${jpath} = ${jvalue}"
}
