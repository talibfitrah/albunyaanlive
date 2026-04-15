#!/bin/bash
# Tear down the reflex E2E fixture. No sudo — kills only servers started
# by setup_fixture.sh (identified via their written pid files; pgrep
# fallback for aborted setups that never wrote one).
set -u

ROOT=/tmp/reflex-e2e

for f in "$ROOT/primary.pid" "$ROOT/backup1.pid"; do
    [[ -f "$f" ]] || continue
    pid=$(cat "$f" 2>/dev/null || true)
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
done

# Fallback: match the exact python http.server invocation so we don't
# misfire on unrelated processes.
pkill -f "http\.server.*1808[01]" 2>/dev/null || true
sleep 0.3
rm -rf "$ROOT"
echo "Fixture torn down."
