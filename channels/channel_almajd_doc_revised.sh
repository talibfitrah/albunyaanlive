#!/bin/bash

stream_name="elkhatabi8/bneb5gifvk/77337"
stream_url="http://ts3.eagtop.vip:80/elkhatabi8/bneb5gifvk/77337"
rtmpURL="/var/www/html/stream/hls/almajd-documentary/master.m3u8"
streamID="/var/www/html/stream/hls/almajd-documentary/master.m3u8"
scale=4

./generic_channel.sh "$stream_name" "$streamID" "$stream_url" "$rtmpURL" "$scale"
