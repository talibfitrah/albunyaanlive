#!/bin/bash

# =============================================================================
# Channel: Zaad
# =============================================================================

stream_name="644050331081/609064105728/1434"
stream_url="https://www.youtube.com/@ZadTVchannel/live"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://vlc.news:9000/644050331081/609064105728/1434"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/zaad/master.m3u8"
stream_id="/var/www/html/stream/hls/zaad/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
