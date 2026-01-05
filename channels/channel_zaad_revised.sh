#!/bin/bash

stream_name="644050331081/609064105728/1434"
stream_url="http://vlc.news:9000/644050331081/609064105728/1434"
rtmp_url="/var/www/html/stream/hls/zaad/master.m3u8"
stream_id="/var/www/html/stream/hls/zaad/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
