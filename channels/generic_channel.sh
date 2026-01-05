#!/bin/bash

streamName="$1"
streamID="$2"
streamURL="$3"
rtmpURL="$4"
scale="$5"

result=$(pgrep -f "try_start_stream.sh.*${streamName}.*${streamID}" | wc -l)

if [ $result -eq 0 ]; then
    ffmpegProcess=$(pgrep -f "ffmpeg.*${streamID}" | wc -l)

    if [ $ffmpegProcess -ge 1 ]; then
        pkill -f "ffmpeg.*${streamID}"
    fi

    cmd="./try_start_stream.sh -u ${streamURL} -d ${rtmpURL} -n ${streamName}"
   
    if [ ! -z "${scale}" ] && [ "${scale}" -ge 1 ] 
    	then
		cmd="./try_start_stream.sh -u ${streamURL} -d ${rtmpURL} -n ${streamName} -s ${scale}"
    fi

    echo "Running command [$cmd] ..."

    pkill -f "try_start_stream.sh.*${streamName}.*${streamID}"

    $cmd
else
    echo "Script for ${streamName} already running. Exiting."
fi
