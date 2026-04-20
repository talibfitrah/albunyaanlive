#!/bin/bash

# =============================================================================
# Channel: Makkah
# =============================================================================

stream_name="705729222787/345515312457/1421"
# 2026-04-14: failed over to ayyad — vlc.news was emitting audio packets with
# ~95k-sec PTS offset vs video, blanking Android/ExoPlayer clients.
# Config now mirrors the running pipeline (ayyad primary, vlc.news demoted to
# backup2). audio_resync_mode=1 activates wallclock-based input timestamps +
# aresample=async=1 so returning to vlc.news will no longer blank clients.
stream_url="http://vlc.news:80/705729222787/345515312457/1421"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="elahmad:makkahtv"
stream_url_backup2="http://eg.ayyadonline.net:80/farouq70226/g7mt67ciwg/28179"
stream_url_backup3=""

# Audio resync: protects against upstreams with intermittent bad audio PTS
# (see try_start_stream.sh audio_resync_mode block). 1=on, 0=off.
# Currently 0: ayyad upstream has clean PTS; the wallclock-timestamps flag
# was causing video stutter (colleague reported "picture freezes then
# resumes repeatedly" 2026-04-14 20:09). Re-enable to 1 only when reverting
# to vlc.news, whose bad audio PTS is what the patch was designed to absorb.
audio_resync_mode=1

rtmp_url="/var/www/html/stream/hls/makkah/master.m3u8"
stream_id="/var/www/html/stream/hls/makkah/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
