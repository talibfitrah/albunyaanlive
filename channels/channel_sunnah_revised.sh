#!/bin/bash

# =============================================================================
# Channel: Sunnah
# =============================================================================

# Optional proxy for YouTube resolution; leave empty to use direct IP
YTDLP_PROXY="${YTDLP_PROXY:-}"
export YTDLP_PROXY

# Use POT token provider for YouTube bot detection bypass
YTDLP_EXTRACTOR_ARGS="youtubepot-bgutilhttp:base_url=http://127.0.0.1:4416"
export YTDLP_EXTRACTOR_ARGS

stream_name="sunnah"
stream_url="https://www.youtube.com/@SaudiSunnahTv/live"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="aloula:6"
stream_url_backup2="http://eg.ayyadonline.net:80/farouq160226/46wqc9ajio/50230"
stream_url_backup3=""

rtmp_url="/var/www/html/stream/hls/sunnah/master.m3u8"
stream_id="/var/www/html/stream/hls/sunnah/master.m3u8"
scale=12

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
