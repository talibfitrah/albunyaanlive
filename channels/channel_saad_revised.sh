#!/bin/bash

stream_name="saad/chunklist_w1900001839.m3u8"
stream_url="https://win.holol.com/live/saad/chunklist_w1900001839.m3u8"
rtmp_url="/var/www/html/stream/hls/saad/master.m3u8"
stream_id="/var/www/html/stream/hls/saad/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
