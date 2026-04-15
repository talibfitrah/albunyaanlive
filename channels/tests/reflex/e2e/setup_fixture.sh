#!/bin/bash
# Creates /tmp/reflex-e2e/hls/{primary,backup1} with short pre-rendered HLS
# loops each, then starts python3 http.server on 127.0.0.1:18080 + 127.0.0.1:18081.
# Runs as the current user — no sudo, no touching /var or /srv.
#
# DEVIATION from plan: plan specified nginx, but nginx 1.18 (Ubuntu 22.04)
# can't fully escape /var/log/nginx/ for its bootstrap error log without -e
# (added in nginx 1.19.5), and needs sudo to create /srv/reflex-test/.
# python3 http.server is stdlib, runs unprivileged, binds to 127.0.0.1, and
# serves static files — which is all the state-machine test needs.
#
# DEVIATION from plan: plan specified libx264, but this host's ffmpeg lacks
# it (only h264_nvenc/v4l2m2m/vaapi). Switched to mpeg2video in TS —
# HLS-compatible, no NVENC session contention with production streams.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=/tmp/reflex-e2e
PRIMARY_PORT=18080
BACKUP1_PORT=18081

command -v ffmpeg  >/dev/null || { echo "ffmpeg required"  >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# Fail loud if anything is still running from a previous aborted test.
# Match the exact python http.server invocation so we don't match unrelated
# processes that happen to have '18080' in their cmdline.
if pgrep -f "http\.server.*${PRIMARY_PORT}"  >/dev/null 2>&1 \
|| pgrep -f "http\.server.*${BACKUP1_PORT}" >/dev/null 2>&1; then
    echo "http.server for reflex-e2e already running — run teardown_fixture.sh first" >&2
    exit 1
fi
if [[ -e "$ROOT" ]]; then
    echo "$ROOT already exists — run teardown_fixture.sh first" >&2
    exit 1
fi

mkdir -p "$ROOT"/upstream/primary "$ROOT"/upstream/backup1 \
         "$ROOT"/hls "$ROOT"/state "$ROOT"/pid "$ROOT"/cmd "$ROOT"/logs

# Generate 30 s HLS in each upstream (different color bars so a human can
# tell them apart by eye if debugging visually). mpeg2video+aac in TS is
# HLS-compatible and doesn't need libx264 or NVENC.
for v in primary:red backup1:blue; do
    dir=${v%%:*}; color=${v##*:}
    pushd "$ROOT/upstream/$dir" >/dev/null
    ffmpeg -y -f lavfi -i "color=c=${color}:s=640x360:d=30:r=25" \
           -f lavfi -i "sine=frequency=1000:d=30" \
           -c:v mpeg2video -b:v 500k \
           -c:a aac -b:a 64k \
           -f hls -hls_time 2 -hls_list_size 0 -hls_flags delete_segments \
           master.m3u8 >/dev/null 2>&1
    popd >/dev/null
done

# Start both upstream servers. Redirect stderr so the background processes
# don't spam the parent shell if something goes wrong mid-test.
python3 -m http.server --bind 127.0.0.1 --directory "$ROOT/upstream/primary"  "$PRIMARY_PORT"  >"$ROOT/logs/primary.log"  2>&1 &
echo $! >"$ROOT/primary.pid"
python3 -m http.server --bind 127.0.0.1 --directory "$ROOT/upstream/backup1" "$BACKUP1_PORT" >"$ROOT/logs/backup1.log" 2>&1 &
echo $! >"$ROOT/backup1.pid"

# Wait briefly for both servers to bind sockets.
for _ in {1..20}; do
    if curl -sf -o /dev/null http://127.0.0.1:${PRIMARY_PORT}/master.m3u8 \
    && curl -sf -o /dev/null http://127.0.0.1:${BACKUP1_PORT}/master.m3u8; then
        echo "Fixture ready: primary=http://127.0.0.1:${PRIMARY_PORT} backup1=http://127.0.0.1:${BACKUP1_PORT}"
        echo "Isolated env: HLS_ROOT=$ROOT/hls STATE_DIR=$ROOT/state REFLEX_PID_DIR=$ROOT/pid"
        exit 0
    fi
    sleep 0.25
done

echo "Fixture FAILED to come up within 5s" >&2
echo "--- primary.log ---" >&2; cat "$ROOT/logs/primary.log"  >&2 || true
echo "--- backup1.log ---" >&2; cat "$ROOT/logs/backup1.log" >&2 || true
exit 2
