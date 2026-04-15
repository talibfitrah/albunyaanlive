#!/bin/bash
# Stub channel supervisor for reflex E2E tests.
#
# Mimics the parts of channels/try_start_stream.sh that the reflex watcher
# and signals.sh actually interact with:
#
#   - Writes its PID to $REFLEX_PID_DIR/$CH.pid so signals.sh can find it.
#   - Filename literally contains "try_start_stream" so signals.sh's
#     _pid_is_try_start_stream() cmdline guard passes.
#   - Traps SIGUSR1 ("slate") and SIGUSR2 ("swap") and appends to a
#     per-channel signal log for the scenario runner to assert on.
#   - In mode=live, polls the active upstream with curl and touches a
#     fresh HLS segment file on success. When the upstream stops
#     responding, the segment mtime freezes → freshness.sh sees stale.
#   - SIGUSR2 reads $REFLEX_CMD_DIR/$CH.target_url and switches the poll
#     target to it, returning mode to live. SIGUSR1 switches to mode=slate
#     which keeps output "fresh" but via a slate.ts file.
#
# Arguments:
#   $1  channel_id (required)
#   $2  primary upstream URL (required)
set -u

CHANNEL_ID="${1:?channel_id required}"
PRIMARY_URL="${2:?primary upstream URL required}"

PID_DIR="${REFLEX_PID_DIR:-/tmp/reflex-e2e/pid}"
CMD_DIR="${REFLEX_CMD_DIR:-/tmp/reflex-e2e/cmd}"
HLS_DIR="${HLS_ROOT:-/tmp/reflex-e2e/hls}/$CHANNEL_ID"
LOG_DIR="${STUB_LOG_DIR:-/tmp/reflex-e2e/logs}"
SIG_LOG="$LOG_DIR/stub.$CHANNEL_ID.signals.log"

mkdir -p "$PID_DIR" "$CMD_DIR" "$HLS_DIR" "$LOG_DIR"
echo $$ > "$PID_DIR/$CHANNEL_ID.pid"
: > "$SIG_LOG"

current_url="$PRIMARY_URL"
mode=live

_cleanup() {
    rm -f "$PID_DIR/$CHANNEL_ID.pid"
    exit 0
}
trap _cleanup EXIT TERM INT

on_usr1() {
    printf '%s signal=slate\n' "$(date +%s.%N)" >> "$SIG_LOG"
    mode=slate
}
on_usr2() {
    local target=""
    [[ -r "$CMD_DIR/$CHANNEL_ID.target_url" ]] && target=$(cat "$CMD_DIR/$CHANNEL_ID.target_url")
    printf '%s signal=swap target=%s\n' "$(date +%s.%N)" "$target" >> "$SIG_LOG"
    if [[ -n "$target" ]]; then
        current_url="$target"
        mode=live
    fi
}
trap on_usr1 USR1
trap on_usr2 USR2

seq=0
while true; do
    case "$mode" in
        live)
            if curl -sf --max-time 1 -o /dev/null "$current_url"; then
                seq=$((seq+1))
                printf '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:%d\n#EXTINF:2.0,\nseg%d.ts\n' "$seq" "$seq" > "$HLS_DIR/master.m3u8"
                printf 'seg%d' "$seq" > "$HLS_DIR/seg${seq}.ts"
                # Prune old segments so the dir doesn't fill.
                (cd "$HLS_DIR" && ls seg*.ts 2>/dev/null | sort -V | head -n -3 | xargs -r rm -f)
            fi
            ;;
        slate)
            printf 'slate-%s' "$(date +%s)" > "$HLS_DIR/slate.ts"
            printf '#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n#EXTINF:2.0,\nslate.ts\n' > "$HLS_DIR/master.m3u8"
            ;;
    esac
    # bash's trap only fires between commands; use sleep-in-background +
    # wait so SIGUSR1/USR2 interrupt the sleep promptly.
    sleep 0.5 &
    wait $! 2>/dev/null || true
done
