#!/bin/bash

# =============================================================================
# Channel: Almajd News
# =============================================================================

stream_name="851925540325/933449753495/1415"
stream_url="http://vlc.news:9000/851925540325/933449753495/1415"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1=""
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/almajd-news/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-news/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
