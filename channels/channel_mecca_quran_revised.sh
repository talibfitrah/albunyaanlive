#!/bin/bash

# =============================================================================
# Channel: Mekkah Quran
# =============================================================================

stream_name="mekkah-quran"
stream_url="http://vlc.news:80/578724520142/157164334731/1438"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://vlc.news:80/578724520142/157164334731/1419"
stream_url_backup2="http://vlc.news:80/034120793341/390247405461/1418"

rtmp_url="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
stream_id="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
scale=12

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
