#!/bin/bash
# Logo-presence sampler — one round across all LIVE channels.
#
# Runs every 3 minutes via systemd timer. For each channel whose state
# file says state=LIVE, this script:
#   1. Finds the latest HLS segment in /var/www/html/stream/hls/<ch>/
#   2. Extracts one frame with ffmpeg
#   3. Runs logo_probe.py on the frame
#   4. Appends the result to the channel's state file under
#      `logo_history`, capped at the most recent 7 entries
#
# The brain wake (every 3h) reads `logo_history` and applies rule 10
# from the lessons DB: do not flag mismatch unless the last 5 rounds
# all report logo_present=false.
#
# This script is read-only from the reflex watcher's perspective — it
# touches only the `logo_history` field of each state file, under the
# same flock that the watcher uses (via state_modify), so concurrent
# writes are safe.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HLS_ROOT="${HLS_ROOT:-/var/www/html/stream/hls}"
STATE_DIR="${REFLEX_STATE_DIR:-/var/run/albunyaan/state}"
PROBE_PY="$SCRIPT_DIR/logo_probe.py"
SAMPLE_DIR="${SAMPLE_DIR:-/tmp/albunyaan-logo-samples}"
HISTORY_CAP="${LOGO_HISTORY_CAP:-7}"
FFMPEG_BIN="${FFMPEG_BIN:-ffmpeg}"
LOG_FILE="${LOGO_SAMPLER_LOG:-$REPO_ROOT/channels/brain/logo_sampler.log}"

# shellcheck source=../reflex/state.sh
source "$REPO_ROOT/channels/reflex/state.sh"

mkdir -p "$SAMPLE_DIR" "$(dirname "$LOG_FILE")"

log() { echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"; }

# Given a channel id, returns 0 if the state file says state=LIVE.
# Non-LIVE channels are skipped — a SLATE/BACKUP channel is not
# showing the real feed, so sampling its logo would pollute history.
_is_live() {
    local ch="$1" st
    st=$(jq -r '.state // "UNKNOWN"' "$STATE_DIR/$ch.json" 2>/dev/null) || return 1
    [[ "$st" == "LIVE" ]]
}

# Append one sample entry to the channel's state file under
# logo_history. Caps at the most recent HISTORY_CAP entries. Uses
# state_modify, which is already flock-serialized with the reflex
# watcher — no race.
_append_sample() {
    local ch="$1" present="$2" variance="$3" edges="$4" confidence="$5" ts
    ts=$(date -Iseconds)
    state_modify "$ch" '
        (.logo_history // []) as $h
        | .logo_history = ((($h + [{
            ts: $ts,
            logo_present: ($p == "true"),
            variance: ($v | tonumber),
            edge_density: ($e | tonumber),
            confidence: ($c | tonumber)
          }])) | .[- ($cap | tonumber):])
    ' --arg ts "$ts" --arg p "$present" --arg v "$variance" \
       --arg e "$edges" --arg c "$confidence" --arg cap "$HISTORY_CAP"
}

# Sample a single channel. Returns 0 always (failures are logged and
# skipped; one bad channel shouldn't block the rest).
_sample_one() {
    local ch="$1"
    local hls_dir="$HLS_ROOT/$ch"
    local latest_ts
    latest_ts=$(ls -t "$hls_dir"/master*.ts 2>/dev/null | head -1)
    if [[ -z "$latest_ts" ]]; then
        log "WARN $ch: no .ts segments in $hls_dir"
        return 0
    fi
    # Extract the first frame of the segment (keyframe at t=0 is always
    # present and decodes cheaply). PNG output sidesteps the mjpeg
    # encoder's "Non full-range YUV is non-standard" rejection that
    # blocks JPEG on some HLS sources (basmah/nada/sunnah/uthaymeen).
    # `-update 1` is required for single-file output without a pattern;
    # no `-ss` because short segments (~7.2s) sometimes overshoot with
    # fast seek and produce an empty output.
    local frame="$SAMPLE_DIR/${ch}_$(date +%s).png"
    if ! "$FFMPEG_BIN" -y -loglevel error -i "$latest_ts" \
            -frames:v 1 -update 1 "$frame" 2>>"$LOG_FILE"; then
        log "WARN $ch: ffmpeg frame extract failed"
        rm -f "$frame"
        return 0
    fi
    local result
    if ! result=$(python3 "$PROBE_PY" "$frame" 2>>"$LOG_FILE"); then
        log "WARN $ch: logo_probe failed"
        rm -f "$frame"
        return 0
    fi
    # Parse probe output.
    local present variance edges confidence
    present=$(jq -r '.logo_present // "false"' <<< "$result")
    variance=$(jq -r '.variance // 0' <<< "$result")
    edges=$(jq -r '.edge_density // 0' <<< "$result")
    confidence=$(jq -r '.confidence // 0' <<< "$result")
    # Append to state and clean up the sample frame.
    if _append_sample "$ch" "$present" "$variance" "$edges" "$confidence"; then
        log "OK $ch: present=$present v=$variance e=$edges c=$confidence"
    else
        log "WARN $ch: state_modify failed"
    fi
    rm -f "$frame"
}

# Iterate LIVE channels. Use registry as the canonical channel list
# (state files without a registry entry are stale and should be
# ignored).
main() {
    local registry="$REPO_ROOT/channels/channel_registry.json"
    if [[ ! -r "$registry" ]]; then
        log "FATAL registry unreadable: $registry"
        return 2
    fi
    local channels
    channels=$(jq -r '.channels | keys[]' "$registry" 2>/dev/null)
    if [[ -z "$channels" ]]; then
        log "FATAL no channels in registry"
        return 2
    fi
    local started_at processed=0
    started_at=$(date +%s)
    while IFS= read -r ch; do
        [[ -z "$ch" ]] && continue
        _is_live "$ch" || { log "SKIP $ch (state != LIVE)"; continue; }
        _sample_one "$ch"
        processed=$((processed + 1))
    done <<< "$channels"
    log "round done: processed=$processed duration=$(( $(date +%s) - started_at ))s"
    # Rotate log at 5 MB.
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -c %s "$LOG_FILE") -gt 5242880 ]]; then
        mv "$LOG_FILE" "$LOG_FILE.1"
    fi
    # Clean up orphan sample frames older than 10 min (should be 0
    # normally since _sample_one removes on completion, but belt+braces
    # for crashes mid-sample).
    find "$SAMPLE_DIR" -maxdepth 1 -name '*.jpg' -mmin +10 -delete 2>/dev/null
}

main "$@"
