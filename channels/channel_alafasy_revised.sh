#!/bin/bash

stream_name="@alafasy"
stream_url="https://hls.edgar-kirchner.workers.dev/streams/@alafasy/master.m3u8"
rtmp_url="/var/www/html/stream/hls/alafasy/master.m3u8"
stream_id="/var/www/html/stream/hls/alafasy/master.m3u8"
scale=8

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"

