#!/bin/bash

# =============================================================================
# Channel: Sunnah
# =============================================================================

# Use Tor proxy to bypass YouTube rate limiting (allow overrides)
export YTDLP_PROXY="${YTDLP_PROXY:-socks5://127.0.0.1:9050}"

stream_name="sunnah"
stream_url="https://www.youtube.com/@SaudiSunnahTv/live"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1=""
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/sunnah/master.m3u8"
stream_id="/var/www/html/stream/hls/sunnah/master.m3u8"
scale=3

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
