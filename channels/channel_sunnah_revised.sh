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
stream_url="http://vlc.news:80/964683414160/920593191620/1420"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://www.youtube.com/@SaudiSunnahTv/live"
stream_url_backup2=""

rtmp_url="/var/www/html/stream/hls/sunnah/master.m3u8"
stream_id="/var/www/html/stream/hls/sunnah/master.m3u8"
scale=3

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
