#!/bin/bash

TEMP_THRESHOLD=85
LIMIT=65

function throttle_ffmpeg {
    pids=$(pgrep ffmpeg)
    for pid in $pids; do
	echo "$pid is being limited"
        sudo cpulimit -p $pid -l $LIMIT &
    done
}

throttle_ffmpeg
#while true; do
#    CPU_TEMP=$(sensors | grep 'Package id 0:' | awk '{print $4}' | cut -d'+' -f2 | cut -d'.' -f1)
#    if [ "$CPU_TEMP" -ge "$TEMP_THRESHOLD" ]; then
#        echo "CPU temperature $CPU_TEMP°C exceeds threshold. Applying limits to ffmpeg processes."
#        throttle_ffmpeg
#    fi
#    sleep 5
#done
