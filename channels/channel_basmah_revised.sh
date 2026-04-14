#!/bin/bash

# =============================================================================
# Channel: Basmah
# =============================================================================

stream_name="444180075026/066620053514/1412"
# Primary: vlc.news; Backup1: seenshow (geo-bypassed via tun1 VPN + local proxy)
stream_url="http://vlc.news:80/444180075026/066620053514/1412"

# Backup URLs (optional)
stream_url_backup1="https://live.seenshow.com/hls/live/2120817/LIVE-010-BASMA/3.m3u8"
# ayyad shows hadith instead of basmah (provider mapping error, confirmed 2026-02-26)
stream_url_backup2="http://eg.ayyadonline.net:80/farouq50226/0fbyqin6jo/77338"
stream_url_backup3=""

# seenshow.com geo-block bypassed via /etc/hosts + tun1 VPN routing
# No Tor proxy needed — live.seenshow.com resolves to UAE Akamai edge (104.110.191.166)
# which routes through tun1 (NordVPN UAE) automatically
YTDLP_PROXY=""
export YTDLP_PROXY

rtmp_url="/var/www/html/stream/hls/basmah/master.m3u8"
stream_id="/var/www/html/stream/hls/basmah/master.m3u8"
scale=4

# Build backup URL string (pipe-separated)
backup_urls=""
[[ -n "$stream_url_backup1" ]] && backup_urls="$stream_url_backup1"
[[ -n "$stream_url_backup2" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup2"
[[ -n "$stream_url_backup3" ]] && backup_urls="${backup_urls:+$backup_urls|}$stream_url_backup3"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
