#!/bin/bash

# YouTube Resolver Login Helper
# =============================
# This script helps you log into YouTube with a visible browser.
# After login, the session is saved and reused by the headless resolver.
#
# Requirements:
# - X11 display (run this on desktop or via VNC/X11 forwarding)
# - Or use a remote desktop like noVNC
#
# Usage:
# 1. Make sure you have X11 access (e.g., ssh -X user@server)
# 2. Run this script: ./youtube_resolver_login.sh
# 3. A browser window will open - log into YouTube
# 4. After login, close the browser
# 5. Restart the resolver in headless mode: systemctl restart youtube-resolver

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
RESOLVER_PID=""
SERVICE_WAS_ACTIVE=0
CLEANED_UP=0
PROFILE_DIR="${YT_RESOLVER_USER_DATA_DIR:-$HOME/.config/youtube-resolver-chrome}"

on_exit() {
    if [[ "$CLEANED_UP" -eq 1 ]]; then
        return
    fi
    CLEANED_UP=1

    if [[ -n "$RESOLVER_PID" ]] && kill -0 "$RESOLVER_PID" 2>/dev/null; then
        kill "$RESOLVER_PID" 2>/dev/null || true
        wait "$RESOLVER_PID" 2>/dev/null || true
    fi

    echo ""
    echo "Login session saved to: $PROFILE_DIR"
    echo ""

    if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
        echo "Restarting resolver in headless mode..."
        SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl start youtube-resolver.service
        echo "Done! Check status with: curl http://127.0.0.1:8088/health"
    else
        echo "youtube-resolver.service was not running before login helper; not auto-starting it."
    fi
}

trap on_exit EXIT INT TERM

# Check for display
if [[ -z "${DISPLAY:-}" ]]; then
    echo "ERROR: No DISPLAY environment variable set."
    echo ""
    echo "You need an X11 display to log in. Options:"
    echo ""
    echo "1. SSH with X11 forwarding:"
    echo "   ssh -X user@server"
    echo "   ./youtube_resolver_login.sh"
    echo ""
    echo "2. Use VNC:"
    echo "   Start a VNC server on the machine, connect via VNC client"
    echo ""
    echo "3. Direct desktop access:"
    echo "   Run this script from the machine's desktop"
    echo ""
    exit 1
fi

# Stop the systemd service if running
if SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl is-active --quiet youtube-resolver.service 2>/dev/null; then
    SERVICE_WAS_ACTIVE=1
    echo "Stopping systemd youtube-resolver service..."
    SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl stop youtube-resolver.service 2>/dev/null || true
else
    echo "youtube-resolver.service is not active."
fi

# Kill any existing resolver processes
pkill -f "youtube_browser_resolver" 2>/dev/null || true
sleep 2

echo ""
echo "========================================="
echo "  YouTube Resolver Login Mode"
echo "========================================="
echo ""
echo "A Chrome browser will open shortly."
echo "Please log into your YouTube/Google account."
echo ""
echo "After logging in:"
echo "1. Visit https://www.youtube.com to verify you're logged in"
echo "2. Close the browser window"
echo "3. The script will restart the resolver in headless mode"
echo ""
echo "Press Enter to continue..."
if ! read -r; then
    echo "No interactive input detected; aborting login flow."
    exit 1
fi

# Run in visible (non-headless) mode
export YT_RESOLVER_HEADLESS=false
export YT_RESOLVER_PORT=8088
export YT_RESOLVER_HOST=127.0.0.1
export YT_RESOLVER_USER_DATA_DIR="$PROFILE_DIR"
export YT_RESOLVER_MAX_SESSIONS="${YT_RESOLVER_MAX_SESSIONS:-64}"
export YT_RESOLVER_SESSION_IDLE_SEC="${YT_RESOLVER_SESSION_IDLE_SEC:-21600}"

echo "Starting browser in visible mode..."
node "$SCRIPT_DIR/youtube_browser_resolver_v2.js" &
RESOLVER_PID=$!

# Wait for it to start
sleep 5

# Open the login endpoint
echo "Opening YouTube login page..."
curl -s "http://127.0.0.1:8088/login" || true

echo ""
echo "Browser should be open now. Log into YouTube."
echo "When done, press Ctrl+C to exit this script."
echo ""
# Wait for user to finish
wait "$RESOLVER_PID" 2>/dev/null || true
