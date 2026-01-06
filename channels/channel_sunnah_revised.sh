#!/bin/bash

# =============================================================================
# Channel: Sunnah
# =============================================================================

stream_name="705729222787/345515312457/1435"
stream_url="http://vlc.news:9000/705729222787/345515312457/1435"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://www.youtube.com/@SaudiSunnahTv/live"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/sunnah/master.m3u8"
stream_id="/var/www/html/stream/hls/sunnah/master.m3u8"
scale=3

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
