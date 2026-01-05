#!/bin/bash

stream_name="373914605863/721271717458/1409"
stream_url="http://vlc.news:9000/373914605863/721271717458/1409"
rtmp_url="/var/www/html/stream/hls/daal/master.m3u8"
stream_id="/var/www/html/stream/hls/daal/master.m3u8"

./generic_channel.sh "$stream_name" "$stream_id" "$stream_url" "$rtmp_url"

