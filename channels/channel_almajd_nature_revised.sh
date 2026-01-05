#!/bin/bash

stream_name="301821324699/496492171518/1403"
stream_url="http://vlc.news:9000/301821324699/496492171518/1403"
rtmp_url="/var/www/html/stream/hls/natural/master.m3u8"
stream_id="/var/www/html/stream/hls/natural/master.m3u8"
scale=7

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"

