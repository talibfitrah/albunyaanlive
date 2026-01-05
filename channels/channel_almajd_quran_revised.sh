#!/bin/bash

stream_name="504447960310/322125944085/1405"
stream_url="http://vlc.news:9000/504447960310/322125944085/1405"
rtmp_url="/var/www/html/stream/hls/almajd-quran/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-quran/master.m3u8"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"

