#!/bin/bash

# =============================================================================
# Channel: Anees
# =============================================================================

stream_name="861810342668/356085849311/360333"
stream_url="http://vlc.news:80/861810342668/356085849311/360333"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="http://eeijvvut.qastertv.xyz:900/TN8PTWSD/3W9C5S3B/370"
stream_url_backup2="https://www.youtube.com/channel/UClhc_0qfdQHMmiHRii5TOPA/live"

stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/anees/master.m3u8"
stream_id="/var/www/html/stream/hls/anees/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
