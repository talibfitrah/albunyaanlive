# Phase 3 (Brain Loop) and Phase 5 (Security Cadence) — Design

Drafted 2026-04-13. Companion to `V4_OPERATOR_BUILD.md`. Phase 3 is
design-only at this point; Phase 5 has open decisions flagged with
`DECIDE:` that need user input before cron wiring.

---

## Phase 3 — Brain loop

### Goal

Continuous Claude operation that, every wake, reads the reflex watcher
state, runs visual identity + frame-integrity checks, dispatches
sub-agents, takes action where Phase 1b allows, and pushes a Telegram
update if (and only if) something changed or warrants attention.

### Hosting model — pick one

Three viable shapes:

**A. `gstack /schedule` cron-triggered remote agent.**
Cron fires a fresh Claude session every N minutes. Each wake reads
state files, does its work, exits. No persistent process.
- Pros: survives indefinitely, immune to context bloat, restartable
  via cron at any time, works with the existing remote-trigger
  infrastructure used elsewhere in the user's setup.
- Cons: cold start every wake (no warm prompt cache); each wake pays
  the full session-init cost. Telegram followups across wakes need
  state-file persistence, no in-memory.

**B. Long-running `claude` `/loop` in a tmux/systemd session.**
One Claude session loops forever, calling `ScheduleWakeup` between
iterations.
- Pros: warm prompt cache (cheaper per iteration); in-memory state
  for incident tracking.
- Cons: session bloat over time; if it dies (OOM, network blip,
  /compact going wrong) the operator goes offline silently. Needs
  a watchdog. Anthropic 5-min cache TTL means anything past a
  ~270s sleep is a cache miss anyway.

**C. systemd timer → `claude --headless` invocation per wake.**
Same as A but bypasses gstack/cron, using systemd's own timer.
- Pros: tightest integration with the host (already running watcher
  via systemd), no extra moving parts.
- Cons: same cold-start cost as A; loses the gstack agent UX (status,
  list, manual run).

**Recommendation: A.** The 24/7 reliability requirement outweighs the
prompt-cache savings of B. A single restart of the host or one bad
session kills B silently; A self-recovers on the next cron tick. C is
acceptable if the user prefers no gstack dependency, but A's
operability tooling (`/schedule list`, `/schedule run <id>`) is
worth the dependency.

### Wake-up cadence

Per v4, two phases:

| Phase | When | Cadence |
|---|---|---|
| Bootstrap | First 14 days | Every 2 min, full sweep |
| Steady state | After bootstrap | Full segment+resource sweep every 10 min, visual identity hourly, daily report at 08:00 Europe/Amsterdam |

Incident escalation: if a previous wake recorded an open incident in
`/var/lib/albunyaan-brain/state.json`, the next cron tick should fire
sooner. With option A this is implemented by having TWO scheduled
agents — a "normal" 10-minute one and a "fast" 1-minute one — where
the fast one no-ops unless an incident flag is set in the state file.
Both read the same state.

### Per-wake checklist (in order)

1. **Heartbeat sanity.** Read `/tmp/albunyaan-watcher-state.json`. If
   `state.unix` age > 30s, restart `albunyaan-watcher.service` and
   alert via Telegram. Skip remaining steps this wake.
2. **Segment freshness scan.** Already in watcher state — pull the
   per-channel statuses. Flag any channel != `healthy`.
3. **Frame-integrity probe** (per flagged channel). Run
   `ffprobe -count_frames -select_streams v:0 -show_entries
   stream=nb_read_frames` against the current segment. If
   nb_read_frames is far below `fps × duration`, the upstream is
   frame-starved (the stutter case from observation #197).
4. **Visual identity** (full sweep hourly, OR per channel on-demand).
   Run `channels/sample_thumbnails.sh`, then dispatch one sub-agent
   per channel with `{thumbnail_path, expected_genre,
   expected_logo_description, baseline_thumb_path}` from
   `identity_manifest.json`. Sub-agent returns
   `{verdict: "match"|"mismatch"|"slate"|"unknown", confidence,
   reasoning}`. Embarrassingly parallel — 22 sub-agents in one
   message.
5. **Slate correctness.** If any channel is currently in slate
   (Phase 1b sentinel present), confirm the slate frame is rotating
   (frame hash differs vs last wake) and probe the live source —
   swap back as soon as it recovers. Long slates are a Telegram
   alert.
6. **Resource trends.** Read watcher's system block (mem, cpu, gpu,
   disk). If any field has been at `warn` for > 3 consecutive wakes,
   alert. If `crit`, alert immediately and (Phase 4b) take action.
7. **Incident bookkeeping.** Read brain state file. For each open
   incident: did it close? Did its symptoms move? Update the entry,
   close on resolution, escalate on age.
8. **Telegram report decision.** Send a message ONLY if: state changed
   in a viewer-affecting way, an incident opened/escalated/closed, or
   it's the 08:00 daily-report wake. No-op wakes stay quiet.
9. **Persist state and exit.**

### Sub-agent contract for thumbnail verification

```
Input:
  thumbnail_path:        /tmp/albunyaan-thumbs/thumb_<id>.png
  expected_genre:        from identity_manifest.json
  expected_logo:         description string
  baseline_thumb_path:   channels/baselines/thumb_<id>.png
  notes:                 channel-specific gotchas (e.g. anees slate)

Output (JSON):
  verdict:    "match" | "mismatch" | "slate" | "unknown"
  confidence: 0..1
  reasoning:  one or two sentences
  detected_text: any visible Arabic/English text (helps detect
                 slates like the anees maintenance message)
```

Dispatched in parallel (one tool message, N Agent calls). Brain
collects results, decides escalations, writes verdicts to brain state.

### Brain state file

`/var/lib/albunyaan-brain/state.json` (mode 0640, owned by the brain
user). Schema v1:

```json
{
  "schema": 1,
  "ts": "2026-04-13T22:30:00+02:00",
  "last_full_sweep_unix": 1776099000,
  "last_visual_sweep_unix": 1776099000,
  "incidents": [
    { "id": "...", "channel": "zaad", "kind": "stall|frame_starved|content_mismatch|resource",
      "opened_unix": ..., "last_seen_unix": ..., "severity": "info|warn|crit",
      "notes": "..." }
  ],
  "channel_history": {
    "<id>": { "last_verdict": "match", "last_confidence": 0.91,
              "last_thumb_hash": "sha1...", "consecutive_mismatches": 0 }
  }
}
```

Incident IDs are stable across wakes (e.g. `zaad-stall-20260413T2230`)
so dedup is trivial.

### Action policy (interaction with Phase 1b)

Brain WRITES to the Phase 1b sentinel
(`/tmp/albunyaan-watcher-slate-request/<channel>`) when:
- Visual sub-agent returns `mismatch` with confidence >= 0.8 on two
  consecutive visual wakes (1-hour window), OR
- Frame-integrity probe shows < 50% of expected frames for a channel
  the watcher classifies as `healthy` (silent-swap blind spot).

Brain DELETES the sentinel when:
- The triggering condition has cleared for two consecutive wakes AND
  visual identity is back to `match`.

Brain NEVER directly writes the live HLS playlist. That is Phase 1b's
job — single-writer guarantee.

### What this design does NOT include

- Auto-restart of try_start_stream processes. The watcher hasn't
  earned that trust yet; do it manually until baseline data is in.
- Slate transcode pipeline. That's Phase 1b's deliverable.
- Daily report contents — Phase 4a defines that.

### Telegram tone

All Telegram alerts and reports must be plain Arabic/English at the
non-technical level. See `feedback_telegram_tone.md`. No paths, no
process IDs. Examples:

- BAD: "Channel `zaad` segment_age_s=45 (threshold=24)"
- GOOD: "Zaad TV is stuck — picture hasn't moved for 45 seconds.
  Investigating."

---

## Phase 5 — Security cadence

### Goal

Run the gstack security suite on a fixed cadence so issues are
surfaced before they become incidents. Findings get triaged into
`TODOS.md` (already actively used — see existing entries) and, for
high-severity items, pinged via Telegram.

### Mechanism

`gstack /schedule` to register N remote-trigger agents on cron.
Each agent runs one skill, captures its output, and appends a
findings stub to `TODOS.md` or a dated security log.

Required investigation before wiring (next session): exact `/schedule`
invocation syntax + how findings are captured (skill stdout vs a
file the skill writes vs Telegram).

### Proposed schedule

| Skill | Cadence | Why this cadence |
|---|---|---|
| `/cso` | Weekly, Sunday 03:00 local | Full infra audit; weekly is the v4 prompt's spec |
| `/health` | Monthly, 1st of month 03:00 | Composite quality dashboard; monthly enough for trend tracking |
| `/review` | DECIDE — see below | Per v4: "before every code change lands". This repo commits direct to main, no PRs. |
| `/devex-review` | DECIDE — see below | Quarterly per v4. Single-developer infra project — value is unclear |

### `DECIDE:` open questions

**Q1. `/review` trigger — what fires it?**

This repo's workflow is direct commits to `main`, not PRs. Options:

- **A.** Post-commit git hook that runs `/review` against the new
  commit's diff. Catches issues before push. Cost: every commit
  blocks for ~30-60s on review. May be intolerable during rapid
  iteration sessions.
- **B.** Nightly cron at 03:00 that runs `/review` against
  `git diff HEAD~24h..HEAD`. Async, cheaper. Findings appear next
  morning. Loses the "before it lands" property entirely — review
  becomes archaeology.
- **C.** Skip `/review` entirely; rely on `/cso` weekly and `/health`
  monthly for security/quality coverage. Honest choice if the v4
  prompt's per-PR shape doesn't match this repo's reality.
- **D.** Manual invocation only. User runs `/review` before risky
  changes.

**Recommendation: A** with a `--quick` mode if it exists, OR **D**
if the per-commit latency is a problem in practice. **B** is the
worst option — it has the cost of automation without the benefit.

**Q2. `/devex-review` — keep or drop?**

It's a doc/onboarding audit. This is a single-developer infra
project; there's no onboarding flow to audit. Drop unless a
collaborator joins, OR repurpose it as a quarterly "is the
TROUBLESHOOTING.md still accurate?" check.

**Recommendation: drop for now.**

**Q3. Findings destination and severity routing.** DECIDED 2026-04-13.

Severity ladder (gstack security tools use these): `info`, `minor`,
`medium`, `major`, `blocking`, `critical`.

Routing:

- **All findings** → append to
  `channels/security/findings_<YYYY-MM-DD>.md` (new dir, one file
  per run). Complete history, never truncated.
- **`medium`, `major`, `blocking`, `critical`** → also appended as
  a checklist item to `TODOS.md` under a `## Security` H2 so they
  enter the existing follow-up workflow.
- **`medium`, `major`, `blocking`, `critical`** → Telegram message
  with the full picture in plain Arabic/English: what was found,
  where, why it matters, suggested fix. NOT a one-line ping —
  the user wants real detail, just in non-technical language.
- **`minor`, `info`** → file only, no Telegram, no TODO.

This keeps the three destinations aligned: anything serious enough
to act on (medium+) lands in all three; trivia stays in the history
file only.

### Build steps once Q1/Q2/Q3 are answered

1. Create `channels/security/` dir with a `.gitkeep`.
2. Add `## Security` H2 to `TODOS.md` (or leave it for the first
   real finding to create).
3. Register the schedules:
   - `/schedule` weekly `/cso` — Sunday 03:00, append findings to
     `channels/security/findings_$(date).md` and TODOS.md, ping
     Telegram on `crit`.
   - `/schedule` monthly `/health` — same shape.
   - Per Q1 outcome, set up `/review` (post-commit hook OR cron OR
     manual OR nothing).
4. Manually run each schedule once via `/schedule run <id>` to
   verify findings capture and Telegram routing work end-to-end.

### Failure modes to design around

- gstack agent runs out of credits/quota mid-audit → audit silently
  truncates. Mitigation: agent's last action should write a "audit
  complete" sentinel; absence of sentinel triggers a Telegram alert
  on the next brain wake.
- Findings file grows without bound. Mitigation: rotate after 90
  days (extend the existing `channels/rotate_logs.sh`).
- Cron clock skew on the host. Use `OnCalendar` (systemd timer) or
  `gstack /schedule` cron, both of which are anchored to wall clock,
  not relative.

---

## Out of scope for this design

- Phase 1b action policy thresholds (waiting on Phase 1a baseline data)
- Phase 4a daily-report format and content
- Phase 4b threshold-enforcement actions
