#!/bin/bash

stream_name="elkhatabi2/l1x6jfek5o/28183"
stream_url="http://ts3.eagtop.vip:80/elkhatabi2/l1x6jfek5o/28183"
rtmp_url="/var/www/html/stream/hls/arrahmah/master.m3u8"
stream_id="/var/www/html/stream/hls/arrahmah/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
