#!/bin/bash

# =============================================================================
# Channel: Hadith Almajd
# =============================================================================

stream_name="034120793341/390247405461/1406"
stream_url="http://vlc.news:80/034120793341/390247405461/1406"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://ts3.eagtop.vip:80/elkhatabi3/g2ng8pd5a5/2474"
stream_url_backup2="http://ts3.eagtop.vip:80/live/elkhatabi3/g2ng8pd5a5/2474.m3u8"

rtmp_url="/var/www/html/stream/hls/hadith-almajd/master.m3u8"
stream_id="/var/www/html/stream/hls/hadith-almajd/master.m3u8"
scale=0

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
