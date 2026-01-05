#!/bin/bash

stream_name="034120793341/390247405461/1406"
stream_url="http://vlc.news:9000/034120793341/390247405461/1406"
rtmp_url="/var/www/html/stream/hls/hadith-almajd/master.m3u8"
stream_id="/var/www/html/stream/hls/hadith-almajd/master.m3u8"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"

