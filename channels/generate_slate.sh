#!/bin/bash
# Generate a 60-second looping slate video for failover placeholder.
# NOTE: drawtext filter requires libfreetype (not available on this build).
# The slate is a dark blue screen with a lighter center panel as a visual
# indicator. To add text overlay, rebuild FFmpeg with --enable-libfreetype
# and uncomment the drawtext vf below.
SLATE_DIR="/var/www/html/stream/hls/slate"
mkdir -p "$SLATE_DIR"

ffmpeg -y \
  -f lavfi -i "color=c=0x1a1a2e:s=1920x1080:r=30:d=60" \
  -f lavfi -i "anullsrc=r=48000:cl=stereo" \
  -map 0:v:0 -map 1:a:0 \
  -vf "drawbox=x=660:y=490:w=600:h=100:color=0x2a2a4e:t=fill" \
  -c:v h264_nvenc -preset p4 -profile:v high -level:v auto \
  -g 180 -keyint_min 180 -bf 0 \
  -b:v 500k -maxrate 800k -bufsize 1600k \
  -c:a aac -b:a 128k -ar 48000 -ac 2 \
  -t 60 \
  "$SLATE_DIR/slate_loop.mp4"

echo "Slate video generated at $SLATE_DIR/slate_loop.mp4"
