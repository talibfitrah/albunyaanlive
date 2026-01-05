#!/bin/bash

# Set the path to the script's directory
SCRIPT_DIR="/home/msa/Development/scripts/albunyaan/channels"

# Change the working directory to the script's directory
cd "$SCRIPT_DIR" || exit

LOG_FILE="output.log"
ARCHIVE_DIR="log_archive"

# Create archive directory if it doesn't exist
mkdir -p "$ARCHIVE_DIR"

# Generate timestamp for the current date
TIMESTAMP=$(date '+%Y%m%d')

# Move the current log file to the archive directory with a timestamp
mv "$LOG_FILE" "$ARCHIVE_DIR/$LOG_FILE.$TIMESTAMP"

# Create a new empty log file
touch "$LOG_FILE"
chmod 777 "$LOG_FILE"
