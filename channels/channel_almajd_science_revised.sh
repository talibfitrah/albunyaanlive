#!/bin/bash

# =============================================================================
# Channel: Almajd Islamic Science
# =============================================================================

stream_name="828906198094/071131245596/1408"
stream_url="http://vlc.news:9000/828906198094/071131245596/1408"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://live.seenshow.com/hls/live/2120830/LIVE-004-ELMIA/master.m3u8"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/almajd-islamic-science/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-islamic-science/master.m3u8"
scale=0

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
