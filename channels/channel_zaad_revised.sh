#!/bin/bash

# =============================================================================
# Channel: Zaad
# =============================================================================

stream_name="zaad"
# 2026-04-13: ayyadonline promoted to primary (user request, this time
# applied to stream_url as well — earlier edit only updated the comment).
# Clean full-rate feed (tested at 50fps / SD 720x576). YouTube kept as
# backup1 for HD failover; restream.io demoted to backup2 after confirmed
# upstream frame starvation.
stream_url="http://eg.ayyadonline.net:80/farouq200226/tqidc6qejy/77065"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://www.youtube.com/@ZadTVchannel/live"
stream_url_backup2="rtmp://live.restream.io/pull/play_4504673_039e9fbc150af973ecc0"
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/zaad/master.m3u8"
stream_id="/var/www/html/stream/hls/zaad/master.m3u8"
scale=9

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
