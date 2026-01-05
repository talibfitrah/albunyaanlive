#!/bin/bash

stream_name="602779426000/905284947079/1413"
stream_url="http://vlc.news:9000/602779426000/905284947079/1413"
rtmp_url="/var/www/html/stream/hls/almajd-kids/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-kids/master.m3u8"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"

