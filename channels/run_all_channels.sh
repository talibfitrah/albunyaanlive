#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Default to local browser resolver for all YouTube URLs (safe fallback if service absent)
export YOUTUBE_BROWSER_RESOLVER="${YOUTUBE_BROWSER_RESOLVER:-http://127.0.0.1:8088}"

# Clean stale locks/pidfiles left by previous crashes or reboots.
# Validates PID ownership via /proc/cmdline to handle PID recycling on ext4 /tmp.
for lockdir in /tmp/stream_*.lock; do
    [[ -d "$lockdir" ]] || continue
    channel=$(basename "$lockdir" .lock | sed 's/^stream_//')
    pidfile="/tmp/stream_${channel}.pid"
    is_stale=1
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            # PID is alive — verify it actually belongs to try_start_stream for this channel
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || true
            if echo "$cmd" | grep -qF "try_start_stream" && echo "$cmd" | grep -qF "$channel"; then
                is_stale=0  # legitimate owner
            fi
        fi
    fi
    if [[ $is_stale -eq 1 ]]; then
        echo "Removing stale lock: $lockdir"
        rmdir "$lockdir" 2>/dev/null
        rm -f "$pidfile" 2>/dev/null
    fi
done

CHANNELS=(
    channel_almajd_aamah_revised.sh
    channel_almajd_kids_revised.sh
    channel_almajd_doc_revised.sh
    channel_maassah_revised.sh
    channel_almajd_quran_revised.sh
    channel_almajd_science_revised.sh
    channel_almajd_nature_revised.sh
    channel_basmah_revised.sh
    channel_mecca_quran_revised.sh
    channel_daal_revised.sh
    channel_rawdah_revised.sh
    channel_sunnah_revised.sh
    channel_zaad_revised.sh
    channel_anees_revised.sh
    channel_almajd_news.sh
    channel_arrahmah.sh
    channel_almajd_hadith.sh
    channel_quran.sh
    channel_nada_revised.sh
    channel_ajaweed_revised.sh
    channel_uthaymeen_revised.sh
    channel_saad_revised.sh
)

# Stagger channel starts by 2 seconds to avoid overwhelming providers
# with simultaneous connections (which can cause 502 errors)
for script in "${CHANNELS[@]}"; do
    ./"$script" &
    sleep 2
done

wait
