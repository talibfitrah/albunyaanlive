#!/bin/bash

stream_name="elkhatabi5/39u7j5t14h/77333"
stream_url="http://ts3.eagtop.vip:80/elkhatabi5/39u7j5t14h/77333"
rtmp_url="/var/www/html/stream/hls/rawdah/master.m3u8"
stream_id="/var/www/html/stream/hls/rawdah/master.m3u8"
scale=2

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
