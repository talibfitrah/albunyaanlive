#!/bin/bash

stream_name="elkhatabi3/g2ng8pd5a5/75516"
stream_url="http://ts3.eagtop.vip:8080/elkhatabi3/g2ng8pd5a5/75516"
rtmp_url="/var/www/html/stream/hls/nada/master.m3u8"
stream_id="/var/www/html/stream/hls/nada/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
