#!/bin/bash

url=""
key=""
destination=""
channel_name=""
scale=""
logfile_dir="/home/msa/Development/scripts/albunyaan/channels/logs"

mkdir -p "$logfile_dir"
logfile="$logfile_dir/${channel_name}.log"

while getopts 'hu:d:k:n:s:' OPTION; do
	case "$OPTION" in
		h)
			echo "options:"
			echo "-u, specify the source url (HLS link)"
			echo "-d, specify the destination (RTMP or HLS path)"
			echo "-k, specify the stream key (if needed)"
			echo "-n, specify the channel name"
			echo "-s, specify the scale/variant"
			exit 0
			;;
		u) url=$OPTARG ;;
		d) destination=$OPTARG ;;
		k) key=$OPTARG ;;
		n) channel_name=$OPTARG ;;
		s) scale=$OPTARG ;;
		\?)
			echo "Unsupported flag. Use -h for help."
			exit 1
			;;
	esac
done

if [[ -z $url || -z $destination ]]; then
	echo "Missing required -u (url) or -d (destination). Use -h for help."
	exit 1
fi

# Enforce full HLS file path
if [[ "$destination" != *.m3u8 ]]; then
	destination="${destination%/}/master.m3u8"
fi

# Anti-bot stealth headers
base_flags="-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\" -http_persistent 1 -rw_timeout 15000000"

# Default stream copy
cmd="ffmpeg -loglevel error -re -i \"$url\" $base_flags -c copy -f hls -hls_time 6 -hls_flags delete_segments \"$destination\""

case "$scale" in
	2)
		cmd="ffmpeg -loglevel error -re -i \"$url\" $base_flags -c copy -f hls -hls_time 10 -threads 2 -hls_flags delete_segments \"$destination\""
		;;
	3)
		cmd="ffmpeg -loglevel error -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i \"$url\" $base_flags \
		-c:v h264_nvenc -preset p2 -b:v 3500k \
		-c:a aac -b:a 192k \
		-f hls -hls_time 6 -hls_flags delete_segments+append_list \"$destination\""
		;;
	4)
		cmd="ffmpeg -loglevel error -hwaccel cuda -hwaccel_output_format cuda -c:v h264_cuvid -i \"$url\" $base_flags \
		-vf \"scale_npp=1920:1080\" \
		-c:v h264_nvenc -preset p2 -b:v 3500k \
		-c:a aac -b:a 192k \
		-f hls -hls_time 6 -hls_flags delete_segments+append_list \"$destination\""
		;;
	5)
		cmd="ffmpeg -loglevel error -i \"$url\" $base_flags \
		-c:v libx264 -preset ultrafast -tune film \
		-c:a aac -b:a 128k -bufsize 16M -b:v 2500k -g 60 -threads 2 \
		-f hls -hls_time 6 -hls_flags delete_segments \"$destination\""
		;;
	6)
		cmd="ffmpeg -loglevel error -i \"$url\" $base_flags \
		-vf scale=1920:1080 -c:v libx264 -preset ultrafast -tune film \
		-c:a aac -b:a 128k -bufsize 16M -b:v 2500k -g 60 -threads 2 \
		-f hls -hls_time 6 -hls_flags delete_segments \"$destination\""
		;;
	7)
		cmd="ffmpeg -loglevel error -re -i \"$url\" $base_flags \
		-c copy -f hls -hls_time 10 -hls_list_size 10 \
		-hls_flags delete_segments+program_date_time -bufsize 5000k \"$destination\""
		;;
	8)
		cmd="ffmpeg -loglevel error -hwaccel cuda -i \"$url\" $base_flags \
		-c copy -f hls -hls_time 10 -hls_list_size 10 \
		-hls_flags delete_segments+program_date_time -bufsize 5000k \"$destination\""
		;;
esac

echo "▶️ Starting [$channel_name] with command:"
echo $cmd

# Run in background with auto-restart on failure
#until eval "$cmd"; do
#    echo "⛔️ [$channel_name] ffmpeg crashed. Restarting..." >> "$logfile"
#    sleep 2
#done >> "$logfile" 2>&1 &

# 👇 Place it right here
if [[ -f "$logfile" && $(stat -c%s "$logfile") -gt 100000000 ]]; then
    mv "$logfile" "$logfile.old"
    echo "🔁 Log rotated due to size >100MB." >> "$logfile"
fi

max_retries=10
retry_count=0

until bash -c "$cmd" >> "$logfile" 2>&1; do
    echo "⛔️ [$channel_name] ffmpeg crashed. Restarting..." >> "$logfile"
    retry_count=$((retry_count + 1))
    if [[ $retry_count -ge $max_retries ]]; then
        echo "❌ [$channel_name] reached max retries. Exiting." >> "$logfile"
        break
    fi
    sleep 2
done &
