#!/bin/bash

stream_name="705729222787/345515312457/1435"
stream_url="http://vlc.news:9000/705729222787/345515312457/1435"
rtmp_url="/var/www/html/stream/hls/sunnah/master.m3u8"
stream_id="/var/www/html/stream/hls/sunnah/master.m3u8"
scale=3

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
