#!/bin/bash
# Channel config for the reflex E2E test_channel. Mirrors channel_*.sh shape.
# All paths isolated to /tmp/reflex-e2e/ — no /var/www, no sudo.

stream_name="test_channel"
stream_url="http://127.0.0.1:18080/master.m3u8"
stream_url_backup1="http://127.0.0.1:18081/master.m3u8"
stream_url_backup2=""
stream_url_backup3=""

rtmp_url="/tmp/reflex-e2e/hls/test_channel/master.m3u8"
stream_id="/tmp/reflex-e2e/hls/test_channel/master.m3u8"
scale=0

backup_urls="$stream_url_backup1"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale" "$backup_urls"
