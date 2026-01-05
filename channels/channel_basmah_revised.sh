#!/bin/bash

stream_name="444180075026/066620053514/1412"
stream_url="http://vlc.news:9000/444180075026/066620053514/1412"
rtmp_url="/var/www/html/stream/hls/basmah/master.m3u8"
stream_id="/var/www/html/stream/hls/basmah/master.m3u8"
scale=3

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
