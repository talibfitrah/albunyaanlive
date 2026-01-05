#!/bin/bash

stream_name="elkhatabi9/3brcoih0n0/28179"
stream_url="http://ts3.eagtop.vip:80/elkhatabi9/3brcoih0n0/28179"
rtmp_url="/var/www/html/stream/hls/makkah/master.m3u8"
stream_id="/var/www/html/stream/hls/makkah/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
