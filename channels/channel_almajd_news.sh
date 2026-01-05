#!/bin/bash

stream_name="851925540325/933449753495/1415"
stream_url="http://vlc.news:9000/851925540325/933449753495/1415"
rtmp_url="/var/www/html/stream/hls/almajd-news/master.m3u8"
stream_id="/var/www/html/stream/hls/almajd-news/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
