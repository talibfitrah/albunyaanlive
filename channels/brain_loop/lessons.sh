#!/bin/bash
# Albunyaan brain — lessons-learned CLI.
#
# Subcommands:
#   init                      Create DB from schema (idempotent). Seeds from learned_rules.md on first init.
#   add                       Add a rule interactively (with --json for automation).
#   list [--category C] [--channel CH] [--status S] [--limit N]
#                             Print active rules as a table.
#   query --channels CH,CH,...
#                             Print rules relevant to a wake — global + channel-scoped + recent.
#                             Output is markdown bullets ready to inject into the prompt.
#   fire --rule-ids I,I,...
#                             Record that rules fired this wake (for telemetry).
#   outcome --firing-id N --outcome O [--notes TEXT]
#                             Mark a past firing as prevented_fp / confirmed_flag / no_effect / wrong.
#   supersede --old ID --new ID
#                             Mark old rule superseded by new rule.
#   archive --id ID
#                             Set rule to archived (soft delete).
#   prune [--days N]
#                             Archive rules expired by TTL or idle for N days (default 90).
#   version                   Print schema version.
#
# The CLI is the only recommended way to touch the DB. Do not hand-edit
# with sqlite3 shell unless you know what you're doing.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DB_PATH="${LESSONS_DB_PATH:-$REPO_ROOT/channels/brain/lessons.db}"
SCHEMA_PATH="$SCRIPT_DIR/lessons_schema.sql"
SEED_PATH="$SCRIPT_DIR/learned_rules.md"

die() { echo "lessons: $*" >&2; exit 2; }

require_sqlite() {
    command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 not installed; apt-get install sqlite3"
}

init_db() {
    require_sqlite
    mkdir -p "$(dirname "$DB_PATH")"
    sqlite3 "$DB_PATH" < "$SCHEMA_PATH" || die "schema apply failed"
    # The DB carries operator free-text that is injected into the brain
    # prompt; write access = prompt-writing access. Restrict to owner.
    chmod 600 "$DB_PATH" 2>/dev/null || true
    # WAL sidecar files if present (created on first write).
    chmod 600 "$DB_PATH-wal" "$DB_PATH-shm" 2>/dev/null || true

    # Seed from learned_rules.md ONLY if the DB is empty. On later inits,
    # this is a no-op — we don't want to re-seed and duplicate.
    local rule_count
    rule_count="$(sqlite3 "$DB_PATH" 'SELECT COUNT(*) FROM rules;' 2>/dev/null || echo 0)"
    if [[ "$rule_count" -eq 0 && -r "$SEED_PATH" ]]; then
        echo "seeding lessons.db from learned_rules.md..."
        seed_from_markdown
        rule_count="$(sqlite3 "$DB_PATH" 'SELECT COUNT(*) FROM rules;')"
        echo "seeded $rule_count rules."
    else
        echo "lessons.db ready at $DB_PATH ($rule_count rules)."
    fi
}

seed_from_markdown() {
    # Parse the ### Rule N: ... (date) headers from learned_rules.md and
    # insert each as a separate rule. This is a one-shot bootstrap — later
    # additions come through `lessons.sh add`.
    python3 - "$SEED_PATH" "$DB_PATH" <<'PYEOF'
import sys, re, sqlite3

md_path, db_path = sys.argv[1], sys.argv[2]
with open(md_path) as f:
    text = f.read()

# Detect section -> category mapping based on the H2 headings.
section_categories = {
    'Identity Verification':  'identity',
    'Provider Knowledge':     'provider',
    'Operational':            'operational',
}

# Split by "## " to get sections.
current_section = None
current_category = 'other'
rules = []

# Per-rule: ### Rule N: <title> (YYYY-MM-DD)\n<body...>
rule_header_re = re.compile(r'^###\s+Rule\s+\d+:\s+(.+?)(?:\s+\((\d{4}-\d{2}-\d{2})\))?\s*$', re.MULTILINE)

# Walk the file line-by-line so we can associate each ### block with the
# nearest preceding ## section.
section_re = re.compile(r'^##\s+(.+?)\s*$', re.MULTILINE)

# Find all section and rule headers with their positions, then zip them.
headers = []
for m in section_re.finditer(text):
    headers.append(('section', m.start(), m.group(1).strip()))
for m in rule_header_re.finditer(text):
    date = m.group(2) or ''
    headers.append(('rule', m.start(), m.group(1).strip(), date, m.end()))

headers.sort(key=lambda h: h[1])

# Determine section for each rule, and slice its body up to the next header.
for i, h in enumerate(headers):
    if h[0] != 'rule':
        continue
    # Find nearest preceding section.
    section = 'other'
    for prev in reversed(headers[:i]):
        if prev[0] == 'section':
            section = prev[2]
            break
    category = section_categories.get(section, 'other')

    title = h[2]
    date = h[3] if len(h) > 3 else ''
    body_start = h[4]
    body_end = headers[i + 1][1] if i + 1 < len(headers) else len(text)
    body = text[body_start:body_end].strip()

    # Normalize: collapse whitespace but preserve paragraph breaks.
    body_clean = re.sub(r'\n{3,}', '\n\n', body).strip()

    rule_text = f"{title}\n\n{body_clean}"
    created = (date + 'T00:00:00') if date else None
    rules.append((category, None, rule_text, None, 'seed', created, 3))

if not rules:
    print("no rules parsed from markdown; nothing to seed", file=sys.stderr)
    sys.exit(0)

con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
for cat, ch, text, rationale, source, created, prio in rules:
    if created:
        cur.execute(
            "INSERT INTO rules(category, channel_id, rule_text, rationale, source, created_at, priority) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cat, ch, text, rationale, source, created, prio))
    else:
        cur.execute(
            "INSERT INTO rules(category, channel_id, rule_text, rationale, source, priority) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cat, ch, text, rationale, source, prio))
con.commit()
con.close()
PYEOF
}

add_rule() {
    # Args: --category C --rule-text T [--channel CH] [--rationale R]
    #       [--source S] [--priority N] [--expires ISO] [--incident-id I]
    # OR --json '{"category":"...", ...}' for automation.
    require_sqlite
    local json=""
    local category="" channel="" rule_text="" rationale=""
    local source="operator" priority=5 expires="" incident=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)         json="$2"; shift 2 ;;
            --category)     category="$2"; shift 2 ;;
            --channel)      channel="$2"; shift 2 ;;
            --rule-text)    rule_text="$2"; shift 2 ;;
            --rationale)    rationale="$2"; shift 2 ;;
            --source)       source="$2"; shift 2 ;;
            --priority)     priority="$2"; shift 2 ;;
            --expires)      expires="$2"; shift 2 ;;
            --incident-id)  incident="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done

    python3 - "$DB_PATH" "$json" "$category" "$channel" "$rule_text" \
             "$rationale" "$source" "$priority" "$expires" "$incident" <<'PYEOF'
import sys, json, sqlite3

db_path, raw_json = sys.argv[1], sys.argv[2]

if raw_json:
    d = json.loads(raw_json)
else:
    keys = ['category', 'channel_id', 'rule_text', 'rationale',
            'source', 'priority', 'expires_at', 'incident_id']
    vals = sys.argv[3:]
    d = {k: v for k, v in zip(keys, vals) if v}

if 'category' not in d or 'rule_text' not in d:
    print("error: --category and --rule-text are required", file=sys.stderr)
    sys.exit(2)

valid_cats = {'identity', 'overlay', 'source', 'provider',
              'operational', 'tone', 'escalation', 'other'}
if d['category'] not in valid_cats:
    print(f"error: category must be one of {sorted(valid_cats)}", file=sys.stderr)
    sys.exit(2)

valid_sources = {'colleague', 'operator', 'brain', 'seed'}
src = d.get('source', 'operator')
if src not in valid_sources:
    print(f"error: source must be one of {sorted(valid_sources)}", file=sys.stderr)
    sys.exit(2)

prio = int(d.get('priority', 5))
if not 1 <= prio <= 10:
    print("error: priority must be 1..10", file=sys.stderr)
    sys.exit(2)

con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
cur.execute("""
    INSERT INTO rules(category, channel_id, rule_text, rationale, source,
                      priority, expires_at, incident_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (d['category'], d.get('channel_id') or None, d['rule_text'],
      d.get('rationale') or None, src, prio,
      d.get('expires_at') or None, d.get('incident_id') or None))
rule_id = cur.lastrowid
con.commit()
con.close()
print(f"added rule id={rule_id} category={d['category']} priority={prio}")
PYEOF
}

list_rules() {
    require_sqlite
    local category="" channel="" status="active" limit=50
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category) category="$2"; shift 2 ;;
            --channel)  channel="$2"; shift 2 ;;
            --status)   status="$2"; shift 2 ;;
            --limit)    limit="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done

    python3 - "$DB_PATH" "$status" "$category" "$channel" "$limit" <<'PYEOF'
import sys, sqlite3
db_path, status, category, channel, limit = sys.argv[1:6]
try:
    limit = int(limit)
    if limit < 1 or limit > 10000:
        limit = 50
except ValueError:
    limit = 50

sql = "SELECT id, category, COALESCE(channel_id, '*') AS ch, source, " \
      "priority, times_applied, substr(rule_text, 1, 80) AS preview " \
      "FROM rules WHERE status = ?"
params = [status]
if category:
    sql += " AND category = ?"
    params.append(category)
if channel:
    sql += " AND (channel_id = ? OR channel_id IS NULL)"
    params.append(channel)
sql += " ORDER BY priority ASC, id DESC LIMIT ?"
params.append(limit)

con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
rows = cur.execute(sql, params).fetchall()
headers = ["id", "category", "ch", "source", "prio", "fires", "preview"]
widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0)) for i, h in enumerate(headers)]
print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
print("  ".join("-" * w for w in widths))
for r in rows:
    print("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))
con.close()
PYEOF
}

query_rules() {
    # Args: --channels ch1,ch2,...
    # Emits markdown bullets for injection into the brain's prompt.
    require_sqlite
    local channels=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --channels) channels="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done

    python3 - "$DB_PATH" "$channels" <<'PYEOF'
import sys, sqlite3

db_path, chans_csv = sys.argv[1], sys.argv[2]
channels = [c.strip() for c in chans_csv.split(',') if c.strip()]

con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
con.row_factory = sqlite3.Row
cur = con.cursor()

# Global rules + rules for the given channels, ordered by priority then
# recency. Skip expired. Limit to 50 so the prompt doesn't blow up.
if channels:
    placeholders = ','.join('?' * len(channels))
    sql = f"""
        SELECT id, category, channel_id, rule_text, source, priority, created_at
        FROM rules
        WHERE status = 'active'
          AND (expires_at IS NULL OR expires_at > datetime('now'))
          AND (channel_id IS NULL OR channel_id IN ({placeholders}))
        ORDER BY priority ASC, datetime(created_at) DESC
        LIMIT 50
    """
    rows = cur.execute(sql, channels).fetchall()
else:
    sql = """
        SELECT id, category, channel_id, rule_text, source, priority, created_at
        FROM rules
        WHERE status = 'active'
          AND (expires_at IS NULL OR expires_at > datetime('now'))
          AND channel_id IS NULL
        ORDER BY priority ASC, datetime(created_at) DESC
        LIMIT 50
    """
    rows = cur.execute(sql).fetchall()

if not rows:
    print("(no active rules)")
    con.close()
    sys.exit(0)

# Group by category for readability.
from collections import defaultdict
by_cat = defaultdict(list)
for r in rows:
    by_cat[r['category']].append(r)

for cat in sorted(by_cat.keys()):
    print(f"### {cat}")
    for r in by_cat[cat]:
        scope = f"[{r['channel_id']}]" if r['channel_id'] else "[global]"
        src = r['source']
        # First line of the rule text (which is the title) + up to 600 chars.
        text = r['rule_text'].strip()
        if len(text) > 600:
            text = text[:600] + "..."
        print(f"- **rule {r['id']}** {scope} (priority {r['priority']}, source {src}): {text}")
    print()

con.close()
PYEOF
}

fire_rules() {
    # Args: --rule-ids id,id,... [--channel ch]
    require_sqlite
    local ids="" channel=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rule-ids) ids="$2"; shift 2 ;;
            --channel)  channel="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done
    [[ -n "$ids" ]] || die "--rule-ids is required"

    python3 - "$DB_PATH" "$ids" "$channel" <<'PYEOF'
import sys, sqlite3
db_path, ids_csv, channel = sys.argv[1], sys.argv[2], sys.argv[3] or None
ids = [int(x) for x in ids_csv.split(',') if x.strip().isdigit()]
if not ids:
    print("no valid rule ids", file=sys.stderr)
    sys.exit(2)
con = sqlite3.connect(db_path)
# FK ON so rule_firings.rule_id -> rules(id) rejects orphan inserts.
# Without this, a hallucinated or archived rule_id from the brain would
# silently become orphan telemetry.
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
recorded = 0
skipped = []
for rid in ids:
    try:
        cur.execute("INSERT INTO rule_firings(rule_id, channel_id) VALUES (?, ?)",
                    (rid, channel))
        cur.execute("UPDATE rules SET times_applied = times_applied + 1, "
                    "last_applied_at = datetime('now') WHERE id = ?", (rid,))
        recorded += 1
    except sqlite3.IntegrityError:
        skipped.append(rid)
con.commit()
con.close()
print(f"recorded {recorded} firings" + (f", skipped (no such rule): {skipped}" if skipped else ""))
if skipped:
    sys.exit(1)
PYEOF
}

set_outcome() {
    require_sqlite
    local firing_id="" outcome="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --firing-id) firing_id="$2"; shift 2 ;;
            --outcome)   outcome="$2"; shift 2 ;;
            --notes)     notes="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done
    [[ -n "$firing_id" && -n "$outcome" ]] || die "--firing-id and --outcome are required"
    case "$outcome" in
        prevented_fp|confirmed_flag|no_effect|wrong) ;;
        *) die "outcome must be prevented_fp|confirmed_flag|no_effect|wrong" ;;
    esac

    python3 - "$DB_PATH" "$firing_id" "$outcome" "$notes" <<'PYEOF'
import sys, sqlite3
db_path, firing_id, outcome, notes = sys.argv[1:5]
try:
    firing_id = int(firing_id)
except ValueError:
    print(f"error: --firing-id must be an integer, got {firing_id!r}", file=sys.stderr)
    sys.exit(2)
con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
cur.execute(
    "UPDATE rule_firings SET outcome = ?, outcome_at = datetime('now'), notes = ? WHERE id = ?",
    (outcome, notes or None, firing_id))
changed = cur.rowcount
con.commit()
con.close()
if changed == 0:
    print(f"no firing found with id={firing_id}", file=sys.stderr)
    sys.exit(1)
print(f"outcome recorded for firing {firing_id}")
PYEOF
}

supersede_rule() {
    require_sqlite
    local old_id="" new_id=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --old) old_id="$2"; shift 2 ;;
            --new) new_id="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done
    [[ -n "$old_id" && -n "$new_id" ]] || die "--old and --new are required"

    python3 - "$DB_PATH" "$old_id" "$new_id" <<'PYEOF'
import sys, sqlite3
db_path, old_id, new_id = sys.argv[1:4]
try:
    old_id = int(old_id)
    new_id = int(new_id)
except ValueError:
    print("error: --old and --new must be integers", file=sys.stderr)
    sys.exit(2)
if old_id == new_id:
    print(f"error: cannot supersede rule {old_id} by itself", file=sys.stderr)
    sys.exit(2)
con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
# Sanity check: new rule must exist AND be active. Superseding a live
# rule with an archived/superseded replacement silently turns off the
# behaviour with no live rule in its place.
row = cur.execute("SELECT status FROM rules WHERE id = ?", (new_id,)).fetchone()
if row is None:
    print(f"error: rule {new_id} does not exist", file=sys.stderr)
    sys.exit(2)
if row[0] != 'active':
    print(f"error: replacement rule {new_id} is {row[0]}, not active", file=sys.stderr)
    sys.exit(2)
cur.execute(
    "UPDATE rules SET status = 'superseded', superseded_by = ? WHERE id = ?",
    (new_id, old_id))
changed = cur.rowcount
con.commit()
con.close()
if changed == 0:
    print(f"no rule found with id={old_id}", file=sys.stderr)
    sys.exit(1)
print(f"rule {old_id} superseded by {new_id}")
PYEOF
}

archive_rule() {
    require_sqlite
    local rid=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --id) rid="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done
    [[ -n "$rid" ]] || die "--id is required"

    python3 - "$DB_PATH" "$rid" <<'PYEOF'
import sys, sqlite3
db_path, rid = sys.argv[1:3]
try:
    rid = int(rid)
except ValueError:
    print("error: --id must be an integer", file=sys.stderr)
    sys.exit(2)
con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()
cur.execute("UPDATE rules SET status = 'archived' WHERE id = ?", (rid,))
changed = cur.rowcount
con.commit()
con.close()
if changed == 0:
    print(f"no rule found with id={rid}", file=sys.stderr)
    sys.exit(1)
print(f"rule {rid} archived")
PYEOF
}

prune_rules() {
    require_sqlite
    local days=90
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --days) days="$2"; shift 2 ;;
            *) die "unknown flag: $1" ;;
        esac
    done

    python3 - "$DB_PATH" "$days" <<'PYEOF'
import sys, sqlite3
db_path, days = sys.argv[1], sys.argv[2]
try:
    days = int(days)
    if days < 1:
        raise ValueError
except ValueError:
    print("error: --days must be a positive integer", file=sys.stderr)
    sys.exit(2)
con = sqlite3.connect(db_path)
con.execute("PRAGMA foreign_keys = ON")
# Wrap both UPDATEs in a single transaction so queries can't see a
# half-pruned state.
con.execute("BEGIN")
cur = con.cursor()
# Expired rules. Priority 1 ("always on") is exempted from TTL archival —
# if a priority-1 rule has a TTL, that's almost certainly a mistake.
cur.execute("""
    UPDATE rules SET status = 'archived'
    WHERE status = 'active'
      AND priority > 1
      AND expires_at IS NOT NULL
      AND expires_at <= datetime('now')
""")
expired_count = cur.rowcount
# Idle rules: never applied and older than --days. Priority 1 exempt.
cur.execute("""
    UPDATE rules SET status = 'archived'
    WHERE status = 'active'
      AND priority > 1
      AND times_applied = 0
      AND datetime(created_at) <= datetime('now', ?)
""", (f'-{days} days',))
idle_count = cur.rowcount
con.commit()
con.close()
print(f"pruned: {expired_count} expired, {idle_count} idle (> {days} days)")
PYEOF
}

print_version() {
    require_sqlite
    if [[ ! -f "$DB_PATH" ]]; then
        echo "(not initialised; run: $0 init)"
        return
    fi
    sqlite3 "$DB_PATH" "SELECT value FROM schema_meta WHERE key = 'version';"
}

cmd="${1:-}"
shift 2>/dev/null || true
case "$cmd" in
    init)       init_db "$@" ;;
    add)        add_rule "$@" ;;
    list)       list_rules "$@" ;;
    query)      query_rules "$@" ;;
    fire)       fire_rules "$@" ;;
    outcome)    set_outcome "$@" ;;
    supersede)  supersede_rule "$@" ;;
    archive)    archive_rule "$@" ;;
    prune)      prune_rules "$@" ;;
    version)    print_version ;;
    ""|help|-h|--help)
        sed -n '/^# Subcommands:/,/^# The CLI/p' "$0" | sed 's/^# \?//'
        ;;
    *)
        die "unknown subcommand: $cmd (try: $0 help)"
        ;;
esac
