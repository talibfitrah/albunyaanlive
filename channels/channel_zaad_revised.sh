#!/bin/bash

# =============================================================================
# Channel: Zaad
# =============================================================================

stream_name="zaad"
# 2026-04-13: YouTube promoted to primary after restream.io source was found
# delivering ~12fps instead of 25fps (frame rate starvation = visible stutter).
# Restream.io kept as backup2 in case YouTube resolver struggles.
stream_url="https://www.youtube.com/@ZadTVchannel/live"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://eg.ayyadonline.net:80/farouq200226/tqidc6qejy/77065"
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
