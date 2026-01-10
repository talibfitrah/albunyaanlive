#!/bin/bash

# =============================================================================
# Channel: Mekkah Quran
# =============================================================================

stream_name="mekkah-quran"
stream_url="https://www.youtube.com/@SaudiQuranTv/live"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://vlc.news:9000/861810342668/356085849311/1418"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
stream_id="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
scale=0

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
