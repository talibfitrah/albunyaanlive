#!/bin/bash
set -euo pipefail
# =============================================================================
# Seenshow VPN Route Setup
# =============================================================================
# Adds persistent routes through tun1 for seenshow geo-bypass.
# Called by the systemd service after tun1 comes up.
# Exits non-zero if any route cannot be applied (fail-fast for systemd).
#
# Routes:
#   104.110.191.166/32 — UAE Akamai edge (live.seenshow.com)
#   2.18.244.0/24      — NL Akamai range (seenshow CDN)
#   172.213.176.248/32  — api.seenshow.com
# =============================================================================

DEV="${1:-tun1}"
FAILED=0

# Single source of truth for all seenshow routes
ROUTES=(
    "104.110.191.166/32"   # UAE Akamai edge (live.seenshow.com)
    "2.18.244.0/24"        # NL Akamai range (seenshow CDN)
    "172.213.176.248/32"   # api.seenshow.com
)

ensure_route() {
    local cidr="$1"
    if ip route show "$cidr" dev "$DEV" 2>/dev/null | grep -q .; then
        echo "[$(date -Iseconds)] Route already exists: $cidr dev $DEV"
    else
        if ip route replace "$cidr" dev "$DEV"; then
            echo "[$(date -Iseconds)] Added route: $cidr dev $DEV"
        else
            echo "[$(date -Iseconds)] FAILED to add route: $cidr dev $DEV" >&2
            FAILED=1
        fi
    fi
}

for cidr in "${ROUTES[@]}"; do
    ensure_route "$cidr"
done

if [[ "$FAILED" -ne 0 ]]; then
    echo "[$(date -Iseconds)] ERROR: One or more routes failed to apply" >&2
    exit 1
fi

# Post-apply verification
for cidr in "${ROUTES[@]}"; do
    if ! ip route show "$cidr" dev "$DEV" 2>/dev/null | grep -q .; then
        echo "[$(date -Iseconds)] VERIFY FAILED: Route $cidr dev $DEV is missing after apply" >&2
        exit 1
    fi
done

echo "[$(date -Iseconds)] All routes verified on $DEV"
