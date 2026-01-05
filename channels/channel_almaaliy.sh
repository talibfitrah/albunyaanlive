#!/bin/bash

stream_name="TN8PTWSD/3W9C5S3B/29531"
stream_url="http://eeijvvut.qastertv.xyz:900/TN8PTWSD/3W9C5S3B/29531"
rtmp_url="/var/www/html/stream/hls/maaliy/master.m3u8"
stream_id="/var/www/html/stream/hls/maaliy/master.m3u8"
scale=0

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url" "$scale"
