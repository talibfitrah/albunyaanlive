#!/bin/bash

stream_name="elkhatabi8/pencj6s26i/170860"
stream_url="http://ts3.eagtop.vip:2082/elkhatabi8/pencj6s26i/170860"
rtmp_url="/var/www/html/stream/hls/saad/master.m3u8"
stream_id="/var/www/html/stream/hls/saad/master.m3u8"
scale=3

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
