#!/bin/bash

# =============================================================================
# Channel: Zaad
# =============================================================================

stream_name="zaad"
# Current layout (2026-04-19 operator rotation):
#   primary  = restream.io, backup1 = YouTube (HD), backup2 = ayyad.
# History:
#   2026-04-13 — restream.io delivered 144 frames/12s (expected ~300 @
#                25fps); freezes confirmed upstream frame starvation
#                (TROUBLESHOOTING.md §2026-04-13). Demoted to backup2.
#   2026-04-13..2026-04-19 — ayyad primary, YouTube backup1.
#   2026-04-19 — operator re-promoted restream.io to primary. If frame
#                starvation recurs, revert: ayyad primary, restream.io
#                back to backup2.
stream_url="rtmp://live.restream.io/pull/play_4504673_039e9fbc150af973ecc0"

# Backup URLs (optional) - leave empty if not available
stream_url_backup1="https://www.youtube.com/@ZadTVchannel/live"
stream_url_backup2="http://eg.ayyadonline.net:80/farouq200226/tqidc6qejy/77065"
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
