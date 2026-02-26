#!/bin/bash
# Generate a 60-second looping slate video with animated spinner and bilingual text.
# Requires: python3 with PIL/Pillow, ffmpeg with h264_nvenc
#
# Design:
#   - Dark blue background (#1a1a2e) with lighter center panel (#2a2a4e)
#   - Animated spinner: 8 dots in a circle, one highlighted per frame (rotating)
#   - Arabic text: "البث سيعود بعد قليل إن شاء الله"
#   - English text: "Stream will return shortly"
#   - 60 frames @ 30fps = 2s animation, looped 30x = 60s total
set -euo pipefail

SLATE_DIR="/var/www/html/stream/hls/slate"
FRAME_DIR="/tmp/slate_frames_$$"
OUTPUT="$SLATE_DIR/slate_loop.mp4"

# Clean up temp frame directory on any exit (success, error, or signal)
trap 'rm -rf "$FRAME_DIR"' EXIT INT TERM

mkdir -p "$SLATE_DIR"
rm -rf "$FRAME_DIR"
mkdir -p "$FRAME_DIR"

# Step 1: Generate 60 PNG frames with Python PIL
python3 - "$FRAME_DIR" <<'PYEOF'
import sys, os, math
from PIL import Image, ImageDraw, ImageFont

frame_dir = sys.argv[1]
WIDTH, HEIGHT = 1920, 1080
BG_COLOR = (26, 26, 46)        # #1a1a2e
PANEL_COLOR = (42, 42, 78)     # #2a2a4e
DOT_DIM = (100, 100, 140)      # dim dot color
DOT_BRIGHT = (120, 180, 255)   # highlighted dot color
TEXT_COLOR = (255, 255, 255)
NUM_DOTS = 8
DOT_RADIUS = 10
SPINNER_RADIUS = 50
SPINNER_CY = 420               # vertical center of spinner
TOTAL_FRAMES = 60              # 2s at 30fps

# Panel dimensions
PANEL_W, PANEL_H = 800, 340
PANEL_X = (WIDTH - PANEL_W) // 2
PANEL_Y = 350

# Load fonts
try:
    font_arabic = ImageFont.truetype("/usr/share/fonts/truetype/kacst-one/KacstOne.ttf", 42)
except Exception:
    font_arabic = ImageFont.load_default()
try:
    font_english = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 30)
except Exception:
    font_english = ImageFont.load_default()

arabic_text = "البث سيعود بعد قليل إن شاء الله"
english_text = "Stream will return shortly"

for frame_idx in range(TOTAL_FRAMES):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Draw center panel with rounded corners
    draw.rounded_rectangle(
        [PANEL_X, PANEL_Y, PANEL_X + PANEL_W, PANEL_Y + PANEL_H],
        radius=20, fill=PANEL_COLOR
    )

    # Draw spinner dots
    active_dot = frame_idx * NUM_DOTS // TOTAL_FRAMES
    cx = WIDTH // 2
    for i in range(NUM_DOTS):
        angle = (2 * math.pi * i / NUM_DOTS) - (math.pi / 2)  # start from top
        dx = cx + int(SPINNER_RADIUS * math.cos(angle))
        dy = SPINNER_CY + int(SPINNER_RADIUS * math.sin(angle))
        color = DOT_BRIGHT if i == active_dot else DOT_DIM
        r = DOT_RADIUS + 3 if i == active_dot else DOT_RADIUS
        draw.ellipse([dx - r, dy - r, dx + r, dy + r], fill=color)

    # Draw Arabic text (centered)
    bbox_ar = draw.textbbox((0, 0), arabic_text, font=font_arabic)
    ar_w = bbox_ar[2] - bbox_ar[0]
    ar_x = (WIDTH - ar_w) // 2
    ar_y = 520
    draw.text((ar_x, ar_y), arabic_text, fill=TEXT_COLOR, font=font_arabic)

    # Draw English text (centered, below Arabic)
    bbox_en = draw.textbbox((0, 0), english_text, font=font_english)
    en_w = bbox_en[2] - bbox_en[0]
    en_x = (WIDTH - en_w) // 2
    en_y = 590
    draw.text((en_x, en_y), english_text, fill=TEXT_COLOR, font=font_english)

    img.save(os.path.join(frame_dir, f"frame_{frame_idx:03d}.png"))

print(f"Generated {TOTAL_FRAMES} frames in {frame_dir}")
PYEOF

# Step 2: Encode frames into a 60s looping MP4
# 60 frames = 2s animation at 30fps. Loop 29 additional times = 30 × 2s = 60s.
# Add silent audio track for HLS compatibility.
ffmpeg -y \
  -framerate 30 -i "$FRAME_DIR/frame_%03d.png" \
  -f lavfi -i "anullsrc=r=48000:cl=stereo" \
  -filter_complex "[0:v]loop=29:size=60:start=0,setpts=N/30/TB[v]" \
  -map "[v]" -map 1:a \
  -c:v h264_nvenc -preset p4 -profile:v high -level:v auto \
  -g 180 -keyint_min 180 -bf 0 \
  -b:v 500k -maxrate 800k -bufsize 1600k \
  -pix_fmt yuv420p \
  -c:a aac -b:a 128k -ar 48000 -ac 2 \
  -t 60 \
  -shortest \
  "$OUTPUT"

# Cleanup handled by EXIT trap
echo "Slate video generated at $OUTPUT"
