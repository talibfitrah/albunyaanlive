#!/bin/bash

# =============================================================================
# Channel: Daal
# =============================================================================

stream_name="373914605863/721271717458/1409"
stream_url="http://vlc.news:9000/373914605863/721271717458/1409"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://live.seenshow.com/hls/live/2120828/LIVE-008-DAL/master.m3u8"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/daal/master.m3u8"
stream_id="/var/www/html/stream/hls/daal/master.m3u8"
scale=0

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
