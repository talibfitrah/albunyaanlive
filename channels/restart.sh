#!/bin/bash

# Set the path to the script's directory
SCRIPT_DIR="/home/msa/Development/scripts/albunyaan/channels"

# Change the working directory to the script's directory
cd "$SCRIPT_DIR" || exit

LOG_FILE="output.log"

./stop_all.sh
./start_all_streams.sh >> "$LOG_FILE" 2>&1 &
#./start_all_streams.sh
