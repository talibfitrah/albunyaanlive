#!/bin/bash

stream_name="861810342668/356085849311/1418"
stream_url="http://vlc.news:9000/861810342668/356085849311/1418"
rtmp_url="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
stream_id="/var/www/html/stream/hls/mekkah-quran/master.m3u8"
scale=0


./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
