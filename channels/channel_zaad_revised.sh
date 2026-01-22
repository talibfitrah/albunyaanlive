#!/bin/bash

# =============================================================================
# Channel: Zaad
# =============================================================================

# Use Tor SOCKS5 proxy for yt-dlp to bypass YouTube bot detection (allow overrides)
export YTDLP_PROXY="${YTDLP_PROXY:-socks5://127.0.0.1:9050}"

stream_name="play_4504673_039e9fbc150af973ecc0"
stream_url="rtmp://live.restream.io/pull/play_4504673_039e9fbc150af973ecc0"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://vlc.news:80/302285257136/978830670357/1434"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/zaad/master.m3u8"
stream_id="/var/www/html/stream/hls/zaad/master.m3u8"
scale=10

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
