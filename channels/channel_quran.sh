#!/bin/bash

# =============================================================================
# Channel: Makkah
# =============================================================================

stream_name="705729222787/345515312457/1421"
# Current layout (2026-04-19 operator rotation):
#   primary  = vlc.news, backup1 = elahmad, backup2 = ayyad.
# History:
#   2026-04-14 — vlc.news emitted ~95k-sec audio-PTS offset vs video,
#                blanking Android/ExoPlayer clients; failed over to ayyad.
#   2026-04-14..2026-04-19 — ayyad was primary, vlc.news backup2.
#   2026-04-19 — operator rotated vlc.news back to primary (with
#                audio_resync_mode=1 active to absorb its PTS quirk).
stream_url="http://vlc.news:80/705729222787/345515312457/1421"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="elahmad:makkahtv"
stream_url_backup2="http://eg.ayyadonline.net:80/farouq70226/g7mt67ciwg/28179"
stream_url_backup3=""

# Audio resync: wallclock-based input timestamps + aresample=async=1
# (see try_start_stream.sh audio_resync_mode block). 1=on, 0=off.
# Required when vlc.news is primary — absorbs its intermittent audio-PTS
# corruption. When ayyad was primary (2026-04-14..2026-04-19) this was 0,
# since the wallclock flag caused stutter on ayyad's clean PTS. Current
# rotation back to vlc.news requires this to be 1.
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
