#!/bin/bash
# channels/reflex/probe.sh
# Lightweight URL health check for primary/backup sources.
# Returns 0 if the URL responds acceptably within <timeout> seconds, else 1.
# HTTP(S): HEAD → 200 OK.
# Non-HTTP (rtmp/rtsp/etc.): ffprobe with hard timeout.

probe_url() {
    local url="$1" timeout="${2:-2}"
    if [[ "$url" =~ ^https?:// ]]; then
        local code
        code=$(curl -sI --max-time "$timeout" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")
        [[ "$code" == "200" ]]
    else
        # ffprobe -timeout takes microseconds
        local us=$(( timeout * 1000000 ))
        ffprobe -v error -timeout "$us" -i "$url" \
                -select_streams v:0 -show_entries stream=codec_type -of csv=p=0 \
                >/dev/null 2>&1
    fi
}
