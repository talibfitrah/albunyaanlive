#!/bin/bash
# Regression tests for lessons.sh. Creates a throwaway DB in /tmp so the
# live brain DB is never touched. Each test is a one-line assertion that
# increments a pass/fail counter.
#
# Run with:  bash channels/brain_loop/test_lessons.sh
# Exit 0 only if every assertion passes.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
CLI="$SCRIPT_DIR/lessons.sh"
TEST_DB="/tmp/lessons_test_$$.db"

PASS=0
FAIL=0

assert_eq() {
    # assert_eq <got> <expected> <label>
    local got="$1" expected="$2" label="$3"
    if [[ "$got" == "$expected" ]]; then
        PASS=$((PASS + 1))
        # echo "  [PASS] $label"
    else
        FAIL=$((FAIL + 1))
        echo "  [FAIL] $label"
        echo "     got:      $got"
        echo "     expected: $expected"
    fi
}

assert_matches() {
    # assert_matches <text> <regex> <label>
    local text="$1" regex="$2" label="$3"
    if echo "$text" | grep -qE "$regex"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  [FAIL] $label"
        echo "     text: $text"
        echo "     regex: $regex"
    fi
}

assert_nonzero_rc() {
    # assert_nonzero_rc <cmd...>  — last arg is label
    local label="${@: -1}"
    set -- "${@:1:$(($# - 1))}"
    if "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL + 1))
        echo "  [FAIL] $label — expected non-zero exit, got 0"
    else
        PASS=$((PASS + 1))
    fi
}

cleanup() {
    rm -f "$TEST_DB" "$TEST_DB"-wal "$TEST_DB"-shm
}
trap cleanup EXIT

echo "=== lessons.sh regression suite ==="
echo "DB: $TEST_DB"

# -----------------------------------------------------------------------
# 1. init + schema
# -----------------------------------------------------------------------
echo "--- init + schema ---"
LESSONS_DB_PATH="$TEST_DB" "$CLI" init >/dev/null 2>&1
assert_matches "$(LESSONS_DB_PATH="$TEST_DB" "$CLI" version)" '^[0-9]+$' "version returns integer"
TABLE_COUNT=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
assert_eq "$TABLE_COUNT" "5" "schema creates 5 tables (rules, rule_firings, schema_meta, pending_confirmations, sqlite_sequence)"

# -----------------------------------------------------------------------
# 2. add — happy path + input validation
# -----------------------------------------------------------------------
echo "--- add + input validation ---"
OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" add \
    --category identity --rule-text "test rule A" \
    --source operator --priority 3 2>&1)
assert_matches "$OUT" "added rule id=[0-9]+" "add happy path"

# Length cap
LONG=$(python3 -c 'print("x" * 2500)')
assert_nonzero_rc "$CLI" add --category identity --rule-text "$LONG" \
    --source operator "add rejects rule_text > 2000 chars"

# Invalid category
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" add \
    --category bogus --rule-text "x" --source operator \
    "add rejects invalid category"

# Invalid source
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" add \
    --category identity --rule-text "x" --source attacker \
    "add rejects invalid source"

# Priority out of range
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" add \
    --category identity --rule-text "x" --source operator --priority 99 \
    "add rejects priority > 10"

# -----------------------------------------------------------------------
# 3. SQL injection attempts (from pass 1 + pass 2 reviews)
# -----------------------------------------------------------------------
echo "--- SQL injection armor ---"
# Pass 1: list --category
LESSONS_DB_PATH="$TEST_DB" "$CLI" list --category "x'; DROP TABLE rules; --" >/dev/null 2>&1 || true
TABLE_STILL_THERE=$(sqlite3 "$TEST_DB" "SELECT name FROM sqlite_master WHERE name='rules';")
assert_eq "$TABLE_STILL_THERE" "rules" "list --category injection leaves rules table intact"

# Pass 1: outcome --firing-id
FID=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" fire --rule-ids 1 --print-ids 2>/dev/null | head -1)
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" outcome \
    --firing-id "1; DROP TABLE rule_firings; --" --outcome no_effect \
    "outcome rejects non-integer firing-id injection"
FIRINGS_STILL_THERE=$(sqlite3 "$TEST_DB" "SELECT name FROM sqlite_master WHERE name='rule_firings';")
assert_eq "$FIRINGS_STILL_THERE" "rule_firings" "outcome injection leaves rule_firings intact"

# Pass 1: supersede --old/--new
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" supersede \
    --old "1; DROP TABLE rules; --" --new "1" \
    "supersede rejects non-integer --old"

# Pass 2: self-supersede
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" supersede \
    --old 1 --new 1 \
    "supersede rejects self-supersede"

# Pass 2: supersede with archived replacement
LESSONS_DB_PATH="$TEST_DB" "$CLI" add --category identity \
    --rule-text "to be archived" --source operator >/dev/null 2>&1
RID_ARCH=$(sqlite3 "$TEST_DB" "SELECT MAX(id) FROM rules;")
LESSONS_DB_PATH="$TEST_DB" "$CLI" archive --id "$RID_ARCH" >/dev/null 2>&1
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" supersede \
    --old 1 --new "$RID_ARCH" \
    "supersede rejects archived replacement"

# -----------------------------------------------------------------------
# 4. fire — FK enforcement (pass 2 I-1)
# -----------------------------------------------------------------------
echo "--- fire FK enforcement ---"
OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" fire --rule-ids 99999 --channel test 2>&1)
assert_matches "$OUT" "skipped.*99999" "fire skips orphan rule_id (PRAGMA foreign_keys)"
# Even with FK rejection, rule_firings should still exist and not have orphan
ORPHAN_COUNT=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM rule_firings WHERE rule_id = 99999;")
assert_eq "$ORPHAN_COUNT" "0" "orphan rule_id NOT inserted despite call"

# -----------------------------------------------------------------------
# 5. round-trip: add → fire → outcome → effectiveness
# -----------------------------------------------------------------------
echo "--- round-trip ---"
# add rule and fire against it
LESSONS_DB_PATH="$TEST_DB" "$CLI" add --category identity \
    --rule-text "round-trip test rule" --source operator --priority 2 >/dev/null
RTR_ID=$(sqlite3 "$TEST_DB" "SELECT MAX(id) FROM rules;")
FID=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" fire --rule-ids "$RTR_ID" --channel test --print-ids)
assert_matches "$FID" '^[0-9]+$' "fire --print-ids returns integer"
# outcome
LESSONS_DB_PATH="$TEST_DB" "$CLI" outcome --firing-id "$FID" --outcome confirmed_flag \
    --notes "round-trip test" >/dev/null 2>&1
OC=$(sqlite3 "$TEST_DB" "SELECT outcome FROM rule_firings WHERE id = $FID;")
assert_eq "$OC" "confirmed_flag" "outcome writes correct value"
# times_applied incremented
TA=$(sqlite3 "$TEST_DB" "SELECT times_applied FROM rules WHERE id = $RTR_ID;")
assert_eq "$TA" "1" "fire increments times_applied"

# -----------------------------------------------------------------------
# 6. pending-record / pending-resolve atomicity
# -----------------------------------------------------------------------
echo "--- pending confirmations ---"
FID2=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" fire --rule-ids "$RTR_ID" --channel test --print-ids)
LESSONS_DB_PATH="$TEST_DB" "$CLI" pending-record \
    --chat-id 12345 --firing-ids "$FID2" --channel-id test \
    --expires-hours 6 >/dev/null
PID=$(sqlite3 "$TEST_DB" "SELECT MAX(id) FROM pending_confirmations;")
assert_matches "$PID" '^[0-9]+$' "pending-record creates a row"

# Reject non-numeric chat_id
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" pending-record \
    --chat-id "bogus" --firing-ids "$FID2" \
    "pending-record rejects non-numeric chat_id"

# Reject firing_id that doesn't exist
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" pending-record \
    --chat-id 12345 --firing-ids "99999999" \
    "pending-record rejects firing_id not in DB"

# Resolve atomically writes outcome to linked firings
LESSONS_DB_PATH="$TEST_DB" "$CLI" pending-resolve \
    --id "$PID" --outcome wrong --reply-text "test" --by poller >/dev/null
OC2=$(sqlite3 "$TEST_DB" "SELECT outcome FROM rule_firings WHERE id = $FID2;")
STATUS=$(sqlite3 "$TEST_DB" "SELECT status FROM pending_confirmations WHERE id = $PID;")
assert_eq "$OC2" "wrong" "pending-resolve writes outcome to linked firing"
assert_eq "$STATUS" "resolved" "pending-resolve marks pending as resolved"

# Second resolve is idempotent (no-op)
OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" pending-resolve \
    --id "$PID" --outcome confirmed_flag --by operator 2>&1)
assert_matches "$OUT" "already resolved" "pending-resolve is idempotent on resolved row"

# -----------------------------------------------------------------------
# 7. report
# -----------------------------------------------------------------------
echo "--- report ---"
OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" report --top 3 2>&1)
assert_matches "$OUT" "Effectiveness Report" "report prints header"
assert_matches "$OUT" "SUMMARY"             "report has SUMMARY section"
assert_matches "$OUT" "MOST-USED RULES"     "report has most-used section"

OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" report --top 3 --json 2>&1)
assert_matches "$OUT" '"summary"'           "report --json has summary key"
assert_matches "$OUT" '"most_used"'         "report --json has most_used array"

# -----------------------------------------------------------------------
# 8. help + version invariants
# -----------------------------------------------------------------------
echo "--- help + version ---"
OUT=$(LESSONS_DB_PATH="$TEST_DB" "$CLI" help 2>&1)
assert_matches "$OUT" "pending-record"      "help mentions pending-record"
assert_matches "$OUT" "report"              "help mentions report"

# Unknown subcommand errors out
assert_nonzero_rc env LESSONS_DB_PATH="$TEST_DB" "$CLI" "foobar" \
    "unknown subcommand returns non-zero"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo
echo "=== $PASS/$TOTAL passed ==="
if [[ "$FAIL" -gt 0 ]]; then
    echo "FAIL: $FAIL assertion(s) failed"
    exit 1
fi
echo "All assertions passed."
