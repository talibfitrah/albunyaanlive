#!/bin/bash

# =============================================================================
# Channel: Al Majd Documentary
# =============================================================================

stream_name="elkhatabi8/bneb5gifvk/77337"
stream_url="http://ts3.eagtop.vip:80/elkhatabi8/bneb5gifvk/77337"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://live.seenshow.com/hls/live/2120826/LIVE-006-WASEQYA/master.m3u8"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/almajd-documentary/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-documentary/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
