#!/bin/bash
# channels/reflex/probe.sh
# Lightweight URL health check for primary/backup sources.
#
# Return codes:
#   0 = healthy (HTTP 200, or ffprobe reports video stream)
#   1 = unhealthy (non-200, timeout, refused)
#   2 = unknown — cannot be probed from here (resolver scheme the
#       supervisor handles internally, e.g. elahmad:/aloula:/seenshow:,
#       or a blocklisted local/internal address we refuse to touch).
#       Callers MUST treat rc=2 as "no info, do not change state" —
#       never as a failure.

_probe_scheme_is_resolver() {
    # The supervisor (try_start_stream.sh + youtube_browser_resolver_v2.js)
    # handles these internally; reflex has no way to exercise them. Probing
    # them via ffprobe always returns non-zero, which would (falsely) climb
    # consecutive_failures and trip the circuit breaker on a healthy channel.
    # Seen with Makkah (elahmad:makkahtv) on 2026-04-15 — state showed
    # consecutive_failures=9 while the actual ffmpeg pipeline was fine.
    local url="$1"
    case "$url" in
        elahmad:*|aloula:*|seenshow:*|youtube:*) return 0 ;;
        *) return 1 ;;
    esac
}

_probe_url_is_blocklisted() {
    # Defensive: HLS upstreams should never be local. Refuse to probe
    # anything pointing at loopback, RFC1918, or link-local — writes to
    # channel_*.sh already imply RCE, but belt-and-suspenders matters.
    local url="$1"
    case "$url" in
        http://127.*|http://localhost*|http://10.*|http://169.254.*|http://[::1]*) return 0 ;;
        https://127.*|https://localhost*|https://10.*|https://169.254.*|https://[::1]*) return 0 ;;
        http://192.168.*|https://192.168.*) return 0 ;;
        http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) return 0 ;;
        https://172.1[6-9].*|https://172.2[0-9].*|https://172.3[01].*) return 0 ;;
    esac
    return 1
}

probe_url() {
    local url="$1" timeout="${2:-2}"

    # Exempt the E2E test fixture: reflex_e2e.sh needs to probe
    # 127.0.0.1:18080/18081 against the local python http.server.
    # Anything else matching the blocklist is refused.
    if [[ "${REFLEX_ALLOW_LOCAL_PROBE:-0}" != "1" ]]; then
        _probe_url_is_blocklisted "$url" && return 2
    fi

    _probe_scheme_is_resolver "$url" && return 2

    if [[ "$url" =~ ^https?:// ]]; then
        # Retry once. Single-shot HTTP probes against cross-WAN origins
        # hit ~5% transient failure from normal packet loss / queuing.
        # With a 2 s timeout and strict SLATE→LIVE gating (needs 2
        # consecutive successes), that pushed live production into
        # persistent-spurious-SLATE tonight (2026-04-15). One retry per
        # call absorbs the blips without doubling the happy-path cost
        # (only runs when the first attempt failed). Accept 2xx AND
        # 3xx — Xtream Codes / vlc.news origins return 302 to CDN
        # edge. 405 also accepted (nginx-rtmp variants reject HEAD).
        local attempt code
        for attempt in 1 2; do
            code=$(curl -sI --max-time "$timeout" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")
            [[ "$code" =~ ^(2..|3..|405)$ ]] && return 0
        done
        return 1
    else
        # ffprobe -timeout takes microseconds
        local us=$(( timeout * 1000000 ))
        ffprobe -v error -timeout "$us" -i "$url" \
                -select_streams v:0 -show_entries stream=codec_type -of csv=p=0 \
                >/dev/null 2>&1
    fi
}
