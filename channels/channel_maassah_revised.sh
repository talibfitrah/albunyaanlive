#!/bin/bash

stream_name="143958390914/114461032166/1414"
stream_url="http://vlc.news:9000/143958390914/114461032166/1414"
rtmp_url="/var/www/html/stream/hls/maassah/master.m3u8"
stream_id="/var/www/html/stream/hls/maassah/master.m3u8"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"
