#!/bin/bash

SCRIPT_DIR="/home/msa/Development/scripts/albunyaan/channels"
cd "$SCRIPT_DIR" || exit

ARCHIVE_DIR="log_archive"
LOGS_SUBDIR="logs"
TIMESTAMP=$(date '+%Y%m%d')
RETENTION_DAYS=7

mkdir -p "$ARCHIVE_DIR" "$LOGS_SUBDIR"

rotate_one() {
    local path="$1"
    [[ -f "$path" && -s "$path" ]] || return 0
    local base="$(basename "$path")"
    mv "$path" "$ARCHIVE_DIR/${base}.${TIMESTAMP}"
    touch "$path"
    chmod 644 "$path"
}

rotate_one "output.log"

for f in "$LOGS_SUBDIR"/*.log; do
    rotate_one "$f"
done

find "$ARCHIVE_DIR" -type f -name '*.log.*' -mtime +${RETENTION_DAYS} -delete
