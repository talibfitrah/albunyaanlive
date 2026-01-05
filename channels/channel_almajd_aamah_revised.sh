#!/bin/bash

stream_name="166063150075/508173937110/1404"
stream_url="http://vlc.news:9000/166063150075/508173937110/1404"
rtmpURL="/var/www/html/stream/hls/almajd-3aamah/master.m3u8"
streamID="/var/www/html/stream/hls/almajd-3aamah/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$streamID" "$stream_url" "$rtmpURL" "$scale"

