#!/bin/bash

# =============================================================================
# Channel: YouTube Live Channel Example
# =============================================================================
# YouTube URLs work just like any other stream URL - just put them in
# stream_url or stream_url_backup1/backup2. The system automatically detects
# YouTube URLs and handles them appropriately.
#
# YouTube URL Types (auto-detected):
#
#   GENERAL URLs (recommended for 24/7 restreaming):
#      https://www.youtube.com/@ChannelName/live
#      - Automatically redirects to the latest live stream
#      - When broadcast ends and new one starts, auto-fetches new stream
#
#   SPECIFIC URLs:
#      https://www.youtube.com/watch?v=VIDEO_ID
#      - Points to a specific live video
#      - When stream ends, system tries to derive general URL for re-fetch
#
# For 24/7 channels, use GENERAL URLs (@channel/live format).
# =============================================================================

stream_name="youtube-example"

# Just use stream_url like any other channel - YouTube URLs are auto-detected
stream_url="https://www.youtube.com/@ZadTVchannel/live"

# Backup URLs - can mix YouTube and regular HLS URLs
stream_url_backup1=""
stream_url_backup2=""

# Output destination
rtmp_url="/var/www/html/stream/hls/youtube-example/master.m3u8"
stream_id="/var/www/html/stream/hls/youtube-example/master.m3u8"

# Scale 9 recommended for YouTube (software decode handles YouTube's encoding better)
scale=9

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
