#!/bin/bash

stream_name="828906198094/071131245596/1408"
stream_url="http://vlc.news:9000/828906198094/071131245596/1408"
rtmp_url="/var/www/html/stream/hls/almajd-islamic-science/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-islamic-science/master.m3u8"
scale=0

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"

