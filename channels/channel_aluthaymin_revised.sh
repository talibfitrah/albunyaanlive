#!/bin/bash

# =============================================================================
# Channel: Aluthaymin
# =============================================================================

stream_name="@alafasy"
stream_url="https://hls.edgar-kirchner.workers.dev/streams/@alafasy/master.m3u8"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1=""
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/aluthaymin/master.m3u8"
stream_id="/var/www/html/stream/hls/aluthaymin/master.m3u8"

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
