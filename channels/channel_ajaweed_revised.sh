#!/bin/bash

# =============================================================================
# Channel: Ajaweed
# =============================================================================

stream_name="166164109628/967788242228/1408"
stream_url="http://vlc.news:80/166164109628/967788242228/1408"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://eg.ayyadonline.net:80/farouq60226/eqegh1wakb/1302160"
stream_url_backup2=""
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/ajaweed/master.m3u8"
stream_id="/var/www/html/stream/hls/ajaweed/master.m3u8"
scale=0

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
