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
    sleep "$INTERVAL"
done
