-- Albunyaan brain — lessons-learned database schema
--
-- Purpose: persist operator/colleague corrections and ground-truth
-- observations across wakes so the brain self-improves instead of
-- making the same mistake every cycle.
--
-- Written to channels/brain/lessons.db (msa-owned, alongside state.json).
-- wake.sh queries relevant rules at the start of each wake and injects
-- them into the brain prompt as a LEARNED_RULES block.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- Rules: one row per learned correction.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Classification. The brain filters by category at query time —
    -- e.g. "give me identity rules + provider rules relevant to this wake".
    category        TEXT NOT NULL CHECK(category IN (
                        'identity',      -- how to judge channel identity
                        'overlay',       -- seasonal/program overlays, what to ignore
                        'source',        -- source-specific behaviour/preferences
                        'provider',      -- provider nicknames and quirks
                        'operational',   -- procedural rules (fix X like so)
                        'tone',          -- communication style
                        'escalation',    -- when to escalate / who to ask
                        'other'
                    )),

    -- Optional channel scoping. NULL = applies globally.
    channel_id      TEXT,

    -- The rule itself. Short, declarative, actionable.
    rule_text       TEXT NOT NULL,

    -- Why this rule exists — the incident or observation behind it.
    rationale       TEXT,

    -- Who taught this rule to the system.
    source          TEXT NOT NULL CHECK(source IN (
                        'colleague',  -- ground truth from on-site observer
                        'operator',   -- terminal session user
                        'brain',      -- brain learned this itself
                        'seed'        -- bootstrapped from learned_rules.md
                    )),

    -- Timestamps.
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,  -- NULL = permanent; ISO-8601 UTC for TTL rules

    -- Optional link to the incident that spawned this rule.
    incident_id     TEXT,

    -- Priority in query ranking when we have to truncate by token budget.
    -- 1 = always include; 5 = default; 10 = include only when directly relevant.
    priority        INTEGER NOT NULL DEFAULT 5 CHECK(priority BETWEEN 1 AND 10),

    -- Lifecycle.
    status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN (
                        'active',
                        'archived',      -- expired or retired via decay
                        'superseded'     -- replaced by a newer rule
                    )),
    superseded_by   INTEGER REFERENCES rules(id),

    -- Usage telemetry.
    times_applied   INTEGER NOT NULL DEFAULT 0,
    last_applied_at TEXT
);

-- Query indexes. The hot paths are:
--   SELECT ... WHERE status='active' AND category IN (...) AND (channel_id IS NULL OR channel_id=?)
-- so we index on status + the two filter keys.
CREATE INDEX IF NOT EXISTS idx_rules_active_cat ON rules(status, category);
CREATE INDEX IF NOT EXISTS idx_rules_active_ch  ON rules(status, channel_id);

-- ---------------------------------------------------------------------------
-- Rule firings: one row per wake × rule application.
--
-- Populated by wake.sh when a rule is injected into the brain's prompt.
-- Outcome is filled in later — either by the brain (if it acts on a rule
-- and the action succeeds/fails) or by operator sessions learning from
-- incidents.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rule_firings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    wake_ts     TEXT NOT NULL DEFAULT (datetime('now')),
    channel_id  TEXT,

    outcome     TEXT CHECK(outcome IN (
                    'prevented_fp',    -- rule caught a would-be false positive
                    'confirmed_flag',  -- rule correctly raised a real issue
                    'no_effect',       -- rule fired but didn't change verdict
                    'wrong'            -- rule led to a bad call — review the rule
                )),
    outcome_at  TEXT,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_firings_rule ON rule_firings(rule_id);
CREATE INDEX IF NOT EXISTS idx_firings_wake ON rule_firings(wake_ts);

-- ---------------------------------------------------------------------------
-- Schema version. Bump when changing anything above and write a migration.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', '1');
