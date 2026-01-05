#!/bin/bash

stream_name="elkhatabi1/6w92wjh6ex/223"
stream_url="http://ts3.eagtop.vip:8080/elkhatabi1/6w92wjh6ex/223"
rtmp_url="/var/www/html/stream/hls/safa/master.m3u8"
stream_id="/var/www/html/stream/hls/safa/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
