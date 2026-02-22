#!/bin/bash

# =============================================================================
# Channel: Al Majd 3aamah
# =============================================================================

stream_name="166063150075/508173937110/1404"
stream_url="http://vlc.news:80/166063150075/508173937110/1404"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://live.seenshow.com/hls/live/2120825/LIVE-001-ALMAJD/3.m3u8"
stream_url_backup2=""
stream_url_backup3=""

# Configure Tor proxy for seenshow.com URLs (geo-blocked)
YTDLP_PROXY="${YTDLP_PROXY:-socks5://127.0.0.1:9050}"
export YTDLP_PROXY

rtmp_url="/var/www/html/stream/hls/almajd-3aamah/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-3aamah/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
