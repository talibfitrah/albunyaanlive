#!/bin/bash

# =============================================================================
# Channel: Almajd News
# =============================================================================

stream_name="851925540325/933449753495/1415"
stream_url="http://vlc.news:80/851925540325/933449753495/1415"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1=""
stream_url_backup2=""
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/almajd-news/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-news/master.m3u8"
# NOTE: scale 4 uses h264_cuvid (GPU decode) which is strict and can hang on
# corrupted/irregular transport streams. For Almajd News, prefer the more
# error-tolerant software decode path (scale 9) to keep HLS output advancing.
scale=9

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
