#!/bin/bash

# Set the path to the script's directory
SCRIPT_DIR="/home/msa/Development/scripts/albunyaan/channels"

# Change the working directory to the script's directory
cd "$SCRIPT_DIR" || exit

node  ~/Development/hlsextractor/hls_url_updater.js
