#!/bin/bash

# Import YouTube Cookies to Browser Resolver
# ==========================================
# This script imports YouTube cookies from Firefox or a cookies.txt file
# into the Chrome profile used by the resolver.
#
# Usage:
# 1. From Firefox profile (auto-detect):
#    ./import_youtube_cookies.sh
#
# 2. From specific Firefox profile:
#    ./import_youtube_cookies.sh /path/to/firefox/profile
#
# 3. From Netscape cookies.txt file:
#    ./import_youtube_cookies.sh /path/to/cookies.txt

set -euo pipefail

CHROME_PROFILE="${YT_RESOLVER_USER_DATA_DIR:-$HOME/.config/youtube-resolver-chrome}"
COOKIES_OUTPUT="$CHROME_PROFILE/Default/Cookies"
ALLOW_PROFILE_IN_USE="${YT_RESOLVER_IMPORT_ALLOW_PROFILE_IN_USE:-0}"

require_command() {
    local cmd="$1"
    local hint="${2:-}"
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi
    echo "ERROR: Required command not found: $cmd" >&2
    if [[ -n "$hint" ]]; then
        echo "Hint: $hint" >&2
    fi
    return 1
}

is_profile_in_use() {
    local escaped_profile
    escaped_profile="$(printf '%s' "$CHROME_PROFILE" | sed 's/[][(){}.^$*+?|\\/]/\\&/g')"

    if command -v pgrep >/dev/null 2>&1; then
        # Resolver process is treated as profile-in-use because it continuously touches cookie state.
        if pgrep -af "youtube_browser_resolver(_v2)?\\.js" >/dev/null 2>&1; then
            return 0
        fi
        if pgrep -af "chrom(e|ium).*${escaped_profile}" >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

ensure_profile_not_in_use() {
    if [[ "$ALLOW_PROFILE_IN_USE" == "1" ]]; then
        return 0
    fi

    if is_profile_in_use; then
        echo "ERROR: Resolver/Chromium appears to be using profile: $CHROME_PROFILE" >&2
        echo "Stop the resolver first, then rerun import." >&2
        echo "Example: SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl stop youtube-resolver.service" >&2
        echo "Override (unsafe): YT_RESOLVER_IMPORT_ALLOW_PROFILE_IN_USE=1 $0 <source>" >&2
        return 1
    fi
}

# Detect Firefox profile
find_firefox_profile() {
    local profiles_dir="$HOME/.mozilla/firefox"
    if [[ -d "$HOME/snap/firefox/common/.mozilla/firefox" ]]; then
        profiles_dir="$HOME/snap/firefox/common/.mozilla/firefox"
    fi

    if [[ ! -d "$profiles_dir" ]]; then
        echo ""
        return 1
    fi

    # Find default profile
    local default_profile
    default_profile=$(find "$profiles_dir" -maxdepth 1 -type d -name "*.default*" | head -1)
    if [[ -n "$default_profile" && -f "$default_profile/cookies.sqlite" ]]; then
        echo "$default_profile"
        return 0
    fi

    echo ""
    return 1
}

# Extract cookies from Firefox sqlite to Netscape format
extract_firefox_cookies() {
    local profile="$1"
    local output="$2"
    local cookies_db="$profile/cookies.sqlite"

    require_command sqlite3 "Install sqlite3 to read Firefox cookies.sqlite files." || return 1

    if [[ ! -f "$cookies_db" ]]; then
        echo "ERROR: Firefox cookies database not found: $cookies_db"
        return 1
    fi

    # Copy to temp to avoid locking issues
    local temp_db="/tmp/firefox_cookies_$$.sqlite"
    cp "$cookies_db" "$temp_db"

    # Extract YouTube cookies
    sqlite3 -separator $'\t' "$temp_db" "
        SELECT
            CASE WHEN host LIKE '.%' THEN host ELSE '.' || host END,
            CASE WHEN host LIKE '.%' THEN 'TRUE' ELSE 'FALSE' END,
            path,
            CASE isSecure WHEN 1 THEN 'TRUE' ELSE 'FALSE' END,
            expiry,
            name,
            value
        FROM moz_cookies
        WHERE host LIKE '%youtube.com' OR host LIKE '%google.com'
        ORDER BY expiry DESC
    " > "$output"

    rm -f "$temp_db"

    local count
    count=$(wc -l < "$output")
    echo "Extracted $count cookies from Firefox"
}

# Import cookies.txt to Chrome profile
import_to_chrome() {
    local cookies_file="$1"
    local cookies_dir
    local temp_cookies_db
    local backup_db

    require_command python3 "Install python3 to import cookies into Chromium profile DB." || return 1

    if [[ ! -f "$cookies_file" ]]; then
        echo "ERROR: Cookies file not found: $cookies_file"
        return 1
    fi

    ensure_profile_not_in_use || return 1

    # Create Chrome profile directory if needed
    cookies_dir="$CHROME_PROFILE/Default"
    mkdir -p "$cookies_dir"

    temp_cookies_db=$(mktemp "$cookies_dir/Cookies.import.XXXXXX")
    if [[ -f "$COOKIES_OUTPUT" ]]; then
        cp "$COOKIES_OUTPUT" "$temp_cookies_db"
    fi

    # Chrome stores cookies in a SQLite database
    # We'll create a Python script to import them
    local import_script="/tmp/import_cookies_$$.py"

    cat > "$import_script" << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
import sys
import sqlite3
import os
import time

def parse_netscape_cookies(cookies_file):
    cookies = []
    with open(cookies_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) >= 7:
                domain, _, path, secure, expires, name, value = parts[:7]
                cookies.append({
                    'domain': domain,
                    'path': path,
                    'secure': secure.upper() == 'TRUE',
                    'expires': int(expires) if expires.isdigit() else int(time.time()) + 86400*365,
                    'name': name,
                    'value': value,
                })
    return cookies

def import_to_chrome_cookies_db(cookies, db_path):
    # Create or connect to Chrome cookies database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table if not exists (simplified Chrome cookies schema)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cookies (
            creation_utc INTEGER NOT NULL,
            host_key TEXT NOT NULL,
            top_frame_site_key TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            encrypted_value BLOB NOT NULL DEFAULT X'',
            path TEXT NOT NULL,
            expires_utc INTEGER NOT NULL,
            is_secure INTEGER NOT NULL,
            is_httponly INTEGER NOT NULL DEFAULT 0,
            last_access_utc INTEGER NOT NULL,
            has_expires INTEGER NOT NULL DEFAULT 1,
            is_persistent INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 1,
            samesite INTEGER NOT NULL DEFAULT -1,
            source_scheme INTEGER NOT NULL DEFAULT 0,
            source_port INTEGER NOT NULL DEFAULT -1,
            last_update_utc INTEGER NOT NULL DEFAULT 0,
            is_same_party INTEGER NOT NULL DEFAULT 0,
            source_type INTEGER NOT NULL DEFAULT 0,
            UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, source_port)
        )
    ''')

    # Chrome uses microseconds since 1601-01-01
    CHROME_EPOCH = 11644473600000000
    now_chrome = int(time.time() * 1000000) + CHROME_EPOCH

    inserted = 0
    for cookie in cookies:
        try:
            expires_chrome = int(cookie['expires'] * 1000000) + CHROME_EPOCH
            cursor.execute('''
                INSERT OR REPLACE INTO cookies
                (creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            ''', (
                now_chrome,
                cookie['domain'],
                cookie['name'],
                cookie['value'],
                cookie['path'],
                expires_chrome,
                1 if cookie['secure'] else 0,
                now_chrome,
            ))
            inserted += 1
        except Exception as e:
            print(f"Warning: Failed to import cookie {cookie['name']}: {e}", file=sys.stderr)

    conn.commit()
    conn.close()
    return inserted

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: script.py <cookies.txt> <output.db>")
        sys.exit(1)

    cookies_file = sys.argv[1]
    db_path = sys.argv[2]

    cookies = parse_netscape_cookies(cookies_file)
    print(f"Parsed {len(cookies)} cookies from {cookies_file}")

    inserted = import_to_chrome_cookies_db(cookies, db_path)
    print(f"Imported {inserted} cookies to {db_path}")
PYTHON_SCRIPT

    chmod +x "$import_script"
    if ! python3 "$import_script" "$cookies_file" "$temp_cookies_db"; then
        rm -f "$import_script" "$temp_cookies_db"
        return 1
    fi
    rm -f "$import_script"

    if [[ -f "$COOKIES_OUTPUT" ]]; then
        backup_db="${COOKIES_OUTPUT}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$COOKIES_OUTPUT" "$backup_db"
    fi

    mv -f "$temp_cookies_db" "$COOKIES_OUTPUT"
    chmod 600 "$COOKIES_OUTPUT" 2>/dev/null || true
}

echo "YouTube Cookie Importer"
echo "======================="
echo ""

INPUT_PATH="${1:-}"

if [[ -z "$INPUT_PATH" ]]; then
    echo "Attempting to auto-detect Firefox profile..."
    FIREFOX_PROFILE=$(find_firefox_profile)

    if [[ -z "$FIREFOX_PROFILE" ]]; then
        echo "ERROR: Could not find Firefox profile."
        echo ""
        echo "Usage:"
        echo "  $0 /path/to/firefox/profile   - Import from Firefox profile"
        echo "  $0 /path/to/cookies.txt       - Import from Netscape cookies file"
        exit 1
    fi

    echo "Found Firefox profile: $FIREFOX_PROFILE"

    # Export to temp file then import
    TEMP_COOKIES="/tmp/youtube_cookies_$$.txt"
    extract_firefox_cookies "$FIREFOX_PROFILE" "$TEMP_COOKIES"
    import_to_chrome "$TEMP_COOKIES"
    rm -f "$TEMP_COOKIES"

elif [[ -d "$INPUT_PATH" ]]; then
    # It's a Firefox profile directory
    echo "Using Firefox profile: $INPUT_PATH"
    TEMP_COOKIES="/tmp/youtube_cookies_$$.txt"
    extract_firefox_cookies "$INPUT_PATH" "$TEMP_COOKIES"
    import_to_chrome "$TEMP_COOKIES"
    rm -f "$TEMP_COOKIES"

elif [[ -f "$INPUT_PATH" ]]; then
    # Check if it's a cookies.txt or cookies.sqlite
    if file "$INPUT_PATH" | grep -q "SQLite"; then
        # It's a Firefox cookies.sqlite
        TEMP_DIR=$(mktemp -d)
        TEMP_PROFILE="$TEMP_DIR"
        cp "$INPUT_PATH" "$TEMP_PROFILE/cookies.sqlite"
        TEMP_COOKIES="/tmp/youtube_cookies_$$.txt"
        extract_firefox_cookies "$TEMP_PROFILE" "$TEMP_COOKIES"
        import_to_chrome "$TEMP_COOKIES"
        rm -rf "$TEMP_DIR" "$TEMP_COOKIES"
    else
        # Assume it's a Netscape cookies.txt
        echo "Using cookies file: $INPUT_PATH"
        import_to_chrome "$INPUT_PATH"
    fi
else
    echo "ERROR: Path not found: $INPUT_PATH"
    exit 1
fi

echo ""
echo "Cookies imported to: $CHROME_PROFILE"
echo ""
echo "Restart the resolver to use the new cookies:"
echo "  SUDO_ASKPASS=~/.sudo_pass.sh sudo -A systemctl restart youtube-resolver.service"
echo ""
echo "Check login status with:"
echo "  curl http://127.0.0.1:8088/health"
