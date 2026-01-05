#!/bin/bash

stream_name="elkhatabi7/5wzhcs8n68/201250"
stream_url="http://ts3.eagtop.vip:8080/elkhatabi7/5wzhcs8n68/201250"
rtmp_url="/var/www/html/stream/hls/assalam/master.m3u8"
stream_id="/var/www/html/stream/hls/assalam/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
