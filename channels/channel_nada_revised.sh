#!/bin/bash

# =============================================================================
# Channel: Nada
# =============================================================================

stream_name="elkhatabi3/g2ng8pd5a5/75516"
stream_url="http://vlc.news:80/988897949345/176479189352/1437"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://eg.ayyadonline.net:80/farouq190226/k977aq53gw/75516"
stream_url_backup2=""
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/nada/master.m3u8"
stream_id="/var/www/html/stream/hls/nada/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
