#!/bin/bash

# Ensure channelId and channel_basmah_revised.sh are passed as command line arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <channelId> <channel>"
    exit 1
fi

channelId="$1"
channel="$2"

output=$(node ~/Development/hlsextractor/extract_hls_urls.js "$channelId")

# Read the output line by line
while IFS= read -r line; do
    # Check if the line contains a URL
    if [[ $line == http* ]]; then
        stream_url=$line
    else
        name_of_stream=$line
    fi
done <<< "$output"

echo "Stream url is [$stream_url]"
echo "Name of stream is [$name_of_stream]"

# Update channel_basmah_revised.sh with the stream name and URL
sed -i "s#stream_name=\".*\"#stream_name=\"$name_of_stream\"#g" "$channel"
sed -i "s#stream_url=\".*\"#stream_url=\"$stream_url\"#g" "$channel"
