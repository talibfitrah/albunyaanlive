#!/bin/bash
# Generate a 60-second looping slate video for failover placeholder
SLATE_DIR="/var/www/html/stream/hls/slate"
mkdir -p "$SLATE_DIR"

ffmpeg -y \
  -f lavfi -i "color=c=0x1a1a2e:s=1920x1080:r=30:d=60" \
  -f lavfi -i "anullsrc=r=48000:cl=stereo" \
  -map 0:v:0 -map 1:a:0 \
  -vf "drawtext=text='Live stream will return shortly':fontsize=42:fontcolor=white:x=(w-tw)/2:y=(h-th)/2:font=monospace" \
  -c:v libx264 -preset ultrafast -profile:v high -level 4.1 \
  -g 180 -keyint_min 180 -bf 0 \
  -b:v 500k -maxrate 800k -bufsize 1600k \
  -c:a aac -b:a 128k -ar 48000 -ac 2 \
  -t 60 \
  "$SLATE_DIR/slate_loop.mp4"

echo "Slate video generated at $SLATE_DIR/slate_loop.mp4"
