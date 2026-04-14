#!/bin/bash
# Albunyaan reflex watcher — Phase 1a (observe-only).
# Probes HLS segment freshness per channel + system resources every N seconds.
# Emits a JSON state file that Claude (in-loop) reads on each wake.
# Does NOT touch playlists or feeders. Action layer comes in Phase 1b.

set -u
shopt -s nullglob

SCHEMA_VERSION=1

HLS_ROOT="${HLS_ROOT:-/var/www/html/stream/hls}"
STATE_FILE="${STATE_FILE:-/tmp/albunyaan-watcher-state.json}"
LOG_FILE="${LOG_FILE:-/home/msa/Development/scripts/albunyaan/channels/logs/reflex_watcher.log}"
INTERVAL="${INTERVAL:-3}"
SEGMENT_DURATION="${SEGMENT_DURATION:-6}"

# Telegram alerting: plain-language pings on status transitions. Fast
# layer below the brain — no LLM involved. Cooldown prevents flapping
# channels from spamming.
TELEGRAM_ENV="${TELEGRAM_ENV_FILE:-$HOME/.claude/channels/telegram/.env}"
ALERT_COOLDOWN_S="${ALERT_COOLDOWN_S:-600}"
ALERT_MIN_OBSERVATIONS="${ALERT_MIN_OBSERVATIONS:-2}"   # require N-in-a-row before alerting
# Startup grace: for the first N ticks after watcher start, observe only —
# seed PRIOR_STATUS from current reality so pre-existing stalls don't
# announce as fresh transitions.
ALERT_STARTUP_GRACE_TICKS="${ALERT_STARTUP_GRACE_TICKS:-5}"

if [[ -r "$TELEGRAM_ENV" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$TELEGRAM_ENV"
    set +a
fi

# Shared bilingual alert helper: user (EN) always, colleague (AR) on severe.
# shellcheck source=tg_alert.sh
source "$(dirname "${BASH_SOURCE[0]}")/tg_alert.sh"

# Map a channel/resource status to a tg_alert severity.
severity_of_status() {
    case "$1" in
        stalled|no_segments|critical) echo "severe" ;;
        warn)                         echo "warn" ;;
        healthy|*)                    echo "info" ;;
    esac
}

declare -A PRIOR_STATUS=()           # kind → last-known status
declare -A PENDING_COUNT=()          # kind → consecutive observations of new status
declare -A LAST_ALERT_TS=()          # kind → unix ts of last telegram send
declare -A PENDING_STATUS=()         # kind → status being debounced
TICK_COUNT=0

STALL_WARN=$((SEGMENT_DURATION * 2))
STALL_CRIT=$((SEGMENT_DURATION * 4))

MEM_WARN=75; MEM_CRIT=90
CPU_WARN=70; CPU_CRIT=90
GPU_WARN=75; GPU_CRIT=90
DISK_WARN=80; DISK_CRIT=90

mkdir -p "$(dirname "$LOG_FILE")"

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG_FILE"; }

json_escape() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

newest_segment_age() {
    local dir="$1" newest age
    newest=$(ls -t "$dir"/*.ts 2>/dev/null | head -1)
    [[ -z "$newest" ]] && { echo "-1"; return; }
    local mtime now
    mtime=$(stat -c %Y "$newest" 2>/dev/null || echo 0)
    now=$(date +%s)
    age=$((now - mtime))
    echo "$age"
}

classify_age() {
    local age="$1"
    if [[ "$age" -lt 0 ]]; then echo "no_segments"
    elif [[ "$age" -ge "$STALL_CRIT" ]]; then echo "stalled"
    elif [[ "$age" -ge "$STALL_WARN" ]]; then echo "warn"
    else echo "healthy"; fi
}

mem_used_pct() {
    awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2} END{ if(t>0) printf "%d", (t-a)*100/t; else print 0 }' /proc/meminfo
}

cpu_load_pct() {
    local cores load5
    cores=$(nproc 2>/dev/null || echo 1)
    load5=$(awk '{print $2}' /proc/loadavg)
    awk -v l="$load5" -v c="$cores" 'BEGIN{ printf "%d", (l/c)*100 }'
}

gpu_mem_pct() {
    command -v nvidia-smi >/dev/null 2>&1 || { echo "-1"; return; }
    timeout 2 nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null \
      | awk -F', *' 'NR==1{ if($2>0) printf "%d", ($1*100)/$2; else print 0 }'
}

disk_pct() {
    local mount="$1"
    df -P "$mount" 2>/dev/null | awk 'NR==2{ gsub("%","",$5); print $5 }'
}

classify_pct() {
    local pct="$1" warn="$2" crit="$3"
    if [[ "$pct" -lt 0 ]]; then echo "unknown"
    elif [[ "$pct" -ge "$crit" ]]; then echo "critical"
    elif [[ "$pct" -ge "$warn" ]]; then echo "warn"
    else echo "healthy"; fi
}

emit_state() {
    local tmp="${STATE_FILE}.tmp"
    local now ts
    now=$(date +%s); ts=$(date -Iseconds)

    local channels_json="" first=1
    for dir in "$HLS_ROOT"/*/; do
        local ch="$(basename "$dir")"
        [[ "$ch" == "slate" ]] && continue
        local age status
        age=$(newest_segment_age "$dir")
        status=$(classify_age "$age")
        [[ $first -eq 1 ]] && first=0 || channels_json+=","
        channels_json+=$(printf '{"id":"%s","segment_age_s":%d,"status":"%s"}' \
          "$(json_escape "$ch")" "$age" "$status")
    done

    local mem cpu gpu disk_root disk_hls
    mem=$(mem_used_pct); cpu=$(cpu_load_pct); gpu=$(gpu_mem_pct)
    disk_root=$(disk_pct "/"); disk_hls=$(disk_pct "$HLS_ROOT")
    [[ -z "$disk_root" ]] && disk_root=-1
    [[ -z "$disk_hls"  ]] && disk_hls=-1

    {
      printf '{'
      printf '"schema":%d,"ts":"%s","unix":%d,' "$SCHEMA_VERSION" "$ts" "$now"
      printf '"thresholds":{"stall_warn_s":%d,"stall_crit_s":%d,' "$STALL_WARN" "$STALL_CRIT"
      printf '"mem_warn":%d,"mem_crit":%d,"cpu_warn":%d,"cpu_crit":%d,' "$MEM_WARN" "$MEM_CRIT" "$CPU_WARN" "$CPU_CRIT"
      printf '"gpu_warn":%d,"gpu_crit":%d,"disk_warn":%d,"disk_crit":%d},' "$GPU_WARN" "$GPU_CRIT" "$DISK_WARN" "$DISK_CRIT"
      printf '"system":{'
      printf '"mem_pct":%d,"mem_status":"%s",'   "$mem" "$(classify_pct "$mem" "$MEM_WARN" "$MEM_CRIT")"
      printf '"cpu_pct":%d,"cpu_status":"%s",'   "$cpu" "$(classify_pct "$cpu" "$CPU_WARN" "$CPU_CRIT")"
      printf '"gpu_mem_pct":%d,"gpu_status":"%s",' "$gpu" "$(classify_pct "$gpu" "$GPU_WARN" "$GPU_CRIT")"
      printf '"disk_root_pct":%d,"disk_root_status":"%s",' "$disk_root" "$(classify_pct "$disk_root" "$DISK_WARN" "$DISK_CRIT")"
      printf '"disk_hls_pct":%d,"disk_hls_status":"%s"' "$disk_hls" "$(classify_pct "$disk_hls" "$DISK_WARN" "$DISK_CRIT")"
      printf '},'
      printf '"channels":[%s]' "$channels_json"
      printf '}\n'
    } > "$tmp"

    mv -f "$tmp" "$STATE_FILE"
}

# consider_transition <kind> <new_status> <en_msg> <ar_msg>
# Alerts only if:
#   - status differs from last-known good status for this kind
#   - the new status has been observed ALERT_MIN_OBSERVATIONS ticks in a row
#     (debounces segment-age noise and brief nvidia-smi hiccups)
#   - ALERT_COOLDOWN_S has passed since last alert for this kind
# Severity is derived from new_status: severe/warn/info. Colleague only
# sees severe transitions (via tg_alert's routing).
consider_transition() {
    local kind="$1" new_status="$2" en_msg="$3" ar_msg="$4"
    local now; now=$(date +%s)

    # Startup grace: silently seed PRIOR_STATUS so a cold-start watcher
    # doesn't announce pre-existing stalls as fresh transitions.
    if (( TICK_COUNT < ALERT_STARTUP_GRACE_TICKS )); then
        PRIOR_STATUS[$kind]="$new_status"
        PENDING_STATUS[$kind]=""
        PENDING_COUNT[$kind]=0
        return
    fi

    local prior="${PRIOR_STATUS[$kind]:-healthy}"

    if [[ "$new_status" == "$prior" ]]; then
        PENDING_STATUS[$kind]=""
        PENDING_COUNT[$kind]=0
        return
    fi

    # New status still pending debounce?
    if [[ "${PENDING_STATUS[$kind]:-}" != "$new_status" ]]; then
        PENDING_STATUS[$kind]="$new_status"
        PENDING_COUNT[$kind]=1
        return
    fi
    PENDING_COUNT[$kind]=$((PENDING_COUNT[$kind] + 1))
    if [[ "${PENDING_COUNT[$kind]}" -lt "$ALERT_MIN_OBSERVATIONS" ]]; then
        return
    fi

    local last="${LAST_ALERT_TS[$kind]:-0}"
    if (( now - last < ALERT_COOLDOWN_S )); then
        # Still silent by cooldown; but commit the state so we don't
        # keep counting forever.
        PRIOR_STATUS[$kind]="$new_status"
        PENDING_STATUS[$kind]=""
        PENDING_COUNT[$kind]=0
        return
    fi

    local severity; severity=$(severity_of_status "$new_status")
    tg_alert "$severity" "$en_msg" "$ar_msg"
    log "alert kind=$kind prior=$prior new=$new_status severity=$severity"
    PRIOR_STATUS[$kind]="$new_status"
    LAST_ALERT_TS[$kind]="$now"
    PENDING_STATUS[$kind]=""
    PENDING_COUNT[$kind]=0
}

channel_msg_en() {
    local ch="$1" status="$2" age="$3"
    case "$status" in
        healthy)     echo "Channel ${ch} recovered." ;;
        warn)        echo "Channel ${ch} lagging — last segment ${age}s ago. Monitoring." ;;
        stalled)     echo "Channel ${ch} stalled — last segment ${age}s ago." ;;
        no_segments) echo "Channel ${ch} is producing no segments." ;;
        *)           echo "Channel ${ch} status changed to ${status} (segment age ${age}s)." ;;
    esac
}

channel_msg_ar() {
    local ch="$1" status="$2" age="$3"
    case "$status" in
        healthy)     echo "قناة ${ch} عادت للعمل." ;;
        warn)        echo "قناة ${ch} متأخرة — آخر صورة منذ ${age} ثانية. أتابع." ;;
        stalled)     echo "قناة ${ch} توقفت — آخر صورة منذ ${age} ثانية." ;;
        no_segments) echo "قناة ${ch} لا تُنتج أي صور." ;;
        *)           echo "قناة ${ch} تغيّر حالها إلى ${status} (عمر آخر صورة: ${age} ثانية)." ;;
    esac
}

resource_msg_en() {
    local kind="$1" status="$2" pct="$3"
    local name
    case "$kind" in
        system-mem)       name="Memory" ;;
        system-cpu)       name="CPU" ;;
        system-gpu)       name="GPU memory" ;;
        system-disk-root) name="Root disk" ;;
        system-disk-hls)  name="HLS disk" ;;
        *) name="$kind" ;;
    esac
    case "$status" in
        healthy)  echo "${name} back to normal." ;;
        warn)     echo "Warning: ${name} at ${pct}%." ;;
        critical) echo "Critical: ${name} at ${pct}%." ;;
        *)        echo "${name}: ${status} (${pct}%)." ;;
    esac
}

resource_msg_ar() {
    local kind="$1" status="$2" pct="$3"
    local name
    case "$kind" in
        system-mem)       name="الذاكرة" ;;
        system-cpu)       name="المعالج" ;;
        system-gpu)       name="ذاكرة كرت الشاشة" ;;
        system-disk-root) name="القرص الرئيسي" ;;
        system-disk-hls)  name="قرص HLS" ;;
        *) name="$kind" ;;
    esac
    case "$status" in
        healthy)  echo "${name} عادت لوضع طبيعي." ;;
        warn)     echo "تحذير: ${name} عند ${pct}٪." ;;
        critical) echo "تنبيه حرج: ${name} عند ${pct}٪." ;;
        *)        echo "${name}: ${status} (${pct}٪)." ;;
    esac
}

check_alerts() {
    # Per-channel
    for dir in "$HLS_ROOT"/*/; do
        local ch; ch="$(basename "$dir")"
        [[ "$ch" == "slate" ]] && continue
        local age status
        age=$(newest_segment_age "$dir")
        status=$(classify_age "$age")
        consider_transition "ch-$ch" "$status" \
            "$(channel_msg_en "$ch" "$status" "$age")" \
            "$(channel_msg_ar "$ch" "$status" "$age")"
    done
    # System resources — only alert at warn/critical transitions (skip info churn)
    local mem cpu gpu dr dh st
    mem=$(mem_used_pct); st=$(classify_pct "$mem" "$MEM_WARN" "$MEM_CRIT")
    consider_transition "system-mem" "$st" \
        "$(resource_msg_en system-mem "$st" "$mem")" \
        "$(resource_msg_ar system-mem "$st" "$mem")"
    cpu=$(cpu_load_pct); st=$(classify_pct "$cpu" "$CPU_WARN" "$CPU_CRIT")
    consider_transition "system-cpu" "$st" \
        "$(resource_msg_en system-cpu "$st" "$cpu")" \
        "$(resource_msg_ar system-cpu "$st" "$cpu")"
    gpu=$(gpu_mem_pct)
    if [[ "$gpu" -ge 0 ]]; then
        st=$(classify_pct "$gpu" "$GPU_WARN" "$GPU_CRIT")
        consider_transition "system-gpu" "$st" \
            "$(resource_msg_en system-gpu "$st" "$gpu")" \
            "$(resource_msg_ar system-gpu "$st" "$gpu")"
    fi
    dr=$(disk_pct "/")
    if [[ -n "$dr" ]]; then
        st=$(classify_pct "$dr" "$DISK_WARN" "$DISK_CRIT")
        consider_transition "system-disk-root" "$st" \
            "$(resource_msg_en system-disk-root "$st" "$dr")" \
            "$(resource_msg_ar system-disk-root "$st" "$dr")"
    fi
    dh=$(disk_pct "$HLS_ROOT")
    if [[ -n "$dh" ]]; then
        st=$(classify_pct "$dh" "$DISK_WARN" "$DISK_CRIT")
        consider_transition "system-disk-hls" "$st" \
            "$(resource_msg_en system-disk-hls "$st" "$dh")" \
            "$(resource_msg_ar system-disk-hls "$st" "$dh")"
    fi
}

log_anomalies() {
    local mem cpu gpu disk_root disk_hls
    for dir in "$HLS_ROOT"/*/; do
        local ch="$(basename "$dir")"
        [[ "$ch" == "slate" ]] && continue
        local age status
        age=$(newest_segment_age "$dir")
        status=$(classify_age "$age")
        [[ "$status" != "healthy" ]] && log "channel=$ch age=${age}s status=$status"
    done
    mem=$(mem_used_pct);  [[ "$(classify_pct "$mem" "$MEM_WARN" "$MEM_CRIT")"         != "healthy" ]] && log "mem_pct=$mem"
    cpu=$(cpu_load_pct);  [[ "$(classify_pct "$cpu" "$CPU_WARN" "$CPU_CRIT")"         != "healthy" ]] && log "cpu_pct=$cpu"
    gpu=$(gpu_mem_pct);   [[ "$gpu" -ge 0 && "$(classify_pct "$gpu" "$GPU_WARN" "$GPU_CRIT")" != "healthy" ]] && log "gpu_mem_pct=$gpu"
    disk_root=$(disk_pct "/");       [[ -n "$disk_root" && "$(classify_pct "$disk_root" "$DISK_WARN" "$DISK_CRIT")" != "healthy" ]] && log "disk_root_pct=$disk_root"
    disk_hls=$(disk_pct "$HLS_ROOT"); [[ -n "$disk_hls"  && "$(classify_pct "$disk_hls"  "$DISK_WARN" "$DISK_CRIT")"  != "healthy" ]] && log "disk_hls_pct=$disk_hls"
}

log "reflex_watcher started (interval=${INTERVAL}s, stall_warn=${STALL_WARN}s, stall_crit=${STALL_CRIT}s)"
trap 'log "reflex_watcher stopping"; exit 0' INT TERM

while true; do
    emit_state
    log_anomalies
    check_alerts
    TICK_COUNT=$((TICK_COUNT + 1))
    sleep "$INTERVAL"
done
