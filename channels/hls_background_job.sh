#!/bin/bash

while true;
do
	./run_all_channels.sh
	if [[ -f ./disk_guard.sh ]]; then
		bash ./disk_guard.sh
	fi
	echo "-------------------------------------------"
	echo ""
	echo ""
	echo ""
	echo ""
	sleep 1m
done
