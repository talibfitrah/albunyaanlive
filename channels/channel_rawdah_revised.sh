#!/bin/bash

# =============================================================================
# Channel: Rawdah
# =============================================================================

stream_name="elkhatabi5/39u7j5t14h/77333"
stream_url="http://ts3.eagtop.vip:80/elkhatabi5/39u7j5t14h/77333"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://live.seenshow.com/hls/live/2120823/LIVE-011-RAWDA/master.m3u8"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/rawdah/master.m3u8"
stream_id="/var/www/html/stream/hls/rawdah/master.m3u8"
scale=2

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
