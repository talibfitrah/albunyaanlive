#!/bin/bash

stream_name="4baffbd95a10046b106ba6e3884a0ee58bc23adfa"
stream_url="https://streannlivehadif.cachefly.net/Protected/sp=1;dirmatch=true;ip=82.169.157.32/4baffbd95a10046b106ba6e3884a0ee58bc23adfa2670c671d0dd7498f2c0cdb/HADIF5/HADIF5_abr/HADIF5/HADIF5_3/chunks.m3u8"
rtmp_url="/var/www/html/stream/hls/taghareed/master.m3u8"
stream_id="/var/www/html/stream/hls/taghareed/master.m3u8"
./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"
