#!/bin/bash

stream_name="elkhatabi6/pencj6s26i/1302160"
stream_url="http://ts3.eagtop.vip:80/elkhatabi6/pencj6s26i/1302160"
rtmp_url="/var/www/html/stream/hls/ajaweed/master.m3u8"
stream_id="/var/www/html/stream/hls/ajaweed/master.m3u8"
scale=0

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
