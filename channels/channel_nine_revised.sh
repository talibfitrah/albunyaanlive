#!/bin/bash

stream_name="alqanat9/alqanat9.m3u8"
stream_url="https://cdn.bestream.io:19360/alqanat9/alqanat9.m3u8"
rtmp_url="/var/www/html/stream/hls/nine/master.m3u8"
stream_id="/var/www/html/stream/hls/nine/master.m3u8"
scale=0

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
