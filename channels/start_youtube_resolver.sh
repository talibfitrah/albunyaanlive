#!/bin/bash
set -euo pipefail

# Wrapper to start the browser-backed YouTube resolver in the background.
# Usage: ./start_youtube_resolver.sh [PORT] [HOST]
# Defaults: PORT=8088 HOST=127.0.0.1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-${YT_RESOLVER_PORT:-8088}}"
HOST="${2:-${YT_RESOLVER_HOST:-127.0.0.1}}"
LOG_FILE="${YT_RESOLVER_LOG:-/tmp/youtube_browser_resolver.log}"
CHROME_BIN="${YT_RESOLVER_CHROME:-/usr/bin/chromium-browser}"
USER_DATA_DIR="${YT_RESOLVER_USER_DATA_DIR:-$HOME/.config/youtube-resolver-chrome}"
MAX_SESSIONS="${YT_RESOLVER_MAX_SESSIONS:-64}"
SESSION_IDLE_SEC="${YT_RESOLVER_SESSION_IDLE_SEC:-21600}"

if ! command -v node >/dev/null 2>&1; then
  echo "node is required. Install Node.js and retry." >&2
  exit 1
fi

if ! [ -x "$CHROME_BIN" ]; then
  echo "Chromium not found at $CHROME_BIN. Set YT_RESOLVER_CHROME to your chromium path." >&2
  exit 1
fi

export YT_RESOLVER_PORT="$PORT"
export YT_RESOLVER_HOST="$HOST"
export YT_RESOLVER_CHROME="$CHROME_BIN"
export YT_RESOLVER_USER_DATA_DIR="$USER_DATA_DIR"
export YT_RESOLVER_MAX_SESSIONS="$MAX_SESSIONS"
export YT_RESOLVER_SESSION_IDLE_SEC="$SESSION_IDLE_SEC"

# Use v2 with full segment proxying
RESOLVER_SCRIPT="$SCRIPT_DIR/youtube_browser_resolver_v2.js"
if [ ! -f "$RESOLVER_SCRIPT" ]; then
  RESOLVER_SCRIPT="$SCRIPT_DIR/youtube_browser_resolver.js"
fi

if [ ! -f "$RESOLVER_SCRIPT" ]; then
  echo "ERROR: Resolver script not found. Expected one of:" >&2
  echo "  $SCRIPT_DIR/youtube_browser_resolver_v2.js" >&2
  echo "  $SCRIPT_DIR/youtube_browser_resolver.js" >&2
  exit 1
fi

resolver_dependencies_available() {
  local resolver_script="$1"

  if [[ "$resolver_script" == *"youtube_browser_resolver_v2.js" ]]; then
    if node -e "try { require.resolve('puppeteer-extra'); require.resolve('puppeteer-extra-plugin-stealth'); process.exit(0); } catch (_) {} try { require.resolve('puppeteer-core'); process.exit(0); } catch (_) {} try { require.resolve('puppeteer'); process.exit(0); } catch (_) {} process.exit(1);" >/dev/null 2>&1; then
      return 0
    fi
    echo "Resolver dependencies missing for v2. Install one of:" >&2
    echo "  1) puppeteer-extra + puppeteer-extra-plugin-stealth (recommended)" >&2
    echo "  2) puppeteer-core" >&2
    echo "  3) puppeteer" >&2
    echo "Run: (cd $SCRIPT_DIR && npm install puppeteer-extra puppeteer-extra-plugin-stealth puppeteer-core)" >&2
    return 1
  fi

  if node -e "try { require.resolve('puppeteer-core'); process.exit(0); } catch (_) {} try { require.resolve('puppeteer'); process.exit(0); } catch (_) {} process.exit(1);" >/dev/null 2>&1; then
    return 0
  fi

  echo "Resolver dependencies missing for legacy resolver. Install puppeteer-core or puppeteer." >&2
  echo "Run: (cd $SCRIPT_DIR && npm install puppeteer-core)" >&2
  return 1
}

if ! resolver_dependencies_available "$RESOLVER_SCRIPT"; then
  exit 1
fi

PID_FILE="${YT_RESOLVER_PID_FILE:-/tmp/youtube_browser_resolver_${PORT}.pid}"

is_pid_running_for_script() {
  local pid="$1"
  [[ -n "$pid" ]] || return 1
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 1
  fi
  if [[ -r "/proc/$pid/cmdline" ]]; then
    if tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$RESOLVER_SCRIPT"; then
      return 0
    fi
  fi
  return 1
}

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$existing_pid" =~ ^[0-9]+$ ]] && is_pid_running_for_script "$existing_pid"; then
    echo "Resolver already running (PID $existing_pid, pidfile: $PID_FILE)."
    exit 0
  fi
  rm -f "$PID_FILE"
fi

escaped_script="$(printf '%s' "$RESOLVER_SCRIPT" | sed 's/[][\\.^$*+?{}|()]/\\&/g')"
matched_pid="$(pgrep -f "node .*${escaped_script}" | head -n 1 || true)"
if [[ -n "$matched_pid" ]] && is_pid_running_for_script "$matched_pid"; then
  echo "$matched_pid" > "$PID_FILE"
  echo "Resolver already running (PID $matched_pid, script: $RESOLVER_SCRIPT)."
  exit 0
fi

echo "Starting resolver on http://$HOST:$PORT (log: $LOG_FILE, profile: $USER_DATA_DIR, pidfile: $PID_FILE)..."
nohup node "$RESOLVER_SCRIPT" >>"$LOG_FILE" 2>&1 &
resolver_pid=$!
echo "$resolver_pid" > "$PID_FILE"
echo "Resolver PID: $resolver_pid"
