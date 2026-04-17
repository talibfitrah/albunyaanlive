# Learned Rules — Bootstrap Seed (historical snapshot, NOT authoritative)

> **⚠️ THIS FILE IS BOOTSTRAP-ONLY.**
>
> The authoritative lessons-learned store is the SQLite database at
> `channels/brain/lessons.db`. This markdown file was the original
> scratch-pad and is imported by `lessons.sh init` **only on a
> fresh install** when the DB is empty. After that, it is a frozen
> historical snapshot — edits here do NOT flow into the brain.
>
> **To add a rule:** `channels/brain_loop/lessons.sh add --category ... --rule-text ...`
> **To view active rules:** `channels/brain_loop/lessons.sh list`
> **To query the rules the brain sees each wake:** `channels/brain_loop/lessons.sh query --channels <csv>`
>
> See `channels/brain_loop/lessons_schema.sql` for schema. Rules below
> were seeded as priority=3 from `seed` source on first init.

---

## Identity Verification

### Rule 1: Only the top-right corner logo determines identity (2026-04-16)

The ONLY reliable identity marker is the channel's persistent logo
in the top-right corner of the frame. All other on-screen elements
— donation tickers, program titles, hashtag bars, lower-thirds,
presenter names, Eid/Ramadan seasonal banners — are NOT identity
signals. They change with programming and must be ignored.

**Origin:** Basmah channel was false-flagged as "AlmajdKids" because
both use similar-style colored badge clusters. Colleague confirmed
Basmah was correct. The badge CONTENT matters, not just its position
or style.

### Rule 2: Seasonal overlays are expected, not mismatches (2026-04-17)

Channels add festive overlays during Islamic holidays (Eid, Ramadan,
etc.) — e.g. "عيدكم مبارك" stickers, special lower-third designs,
modified color schemes. These are NORMAL. Al Majd channels in
particular redesign their entire overlay style for these events.

**Origin:** almajd-3aamah was false-flagged as mismatched because the
brain saw an Eid-specific on-screen tag it hadn't seen before. The
المجد logo was clearly visible top-right the entire time. User
confirmed: "Almajd logo is working as intended. Learn from this."

### Rule 3: Commercial breaks hide logos — don't flag mismatch (2026-04-16)

During commercial breaks or full-screen content (e.g. movie scenes,
documentary footage), the channel logo may temporarily disappear.
This is normal and must NOT be treated as a mismatch. If no logo
is visible: verdict = `unknown`, NOT `mismatch`. Sample 3–4 frames
at ~3-minute intervals before concluding a logo is truly absent.

### Rule 4: Colleague confirmation is ground truth (2026-04-16)

When the colleague confirms a channel is showing correct content
(via Telegram), that confirmation overrides any automated verdict.
If the brain flagged a mismatch but the colleague says it's fine,
the flag is a false positive — clear it. Don't re-flag the same
channel on the next wake without NEW logo-based evidence (not
the same overlay the colleague already confirmed).

---

## Provider Knowledge

### Rule 5: vlc.news = "Egyptian source" (الروابط المصرية), ayyad = "Moroccan source" (الروابط المغربية) (2026-04-16)

The colleague refers to vlc.news as "مصدر مصر" or "الروابط المصرية"
(Egyptian source/links) and ayyad (eg.ayyadonline.net) as "الروابط
المغربية" (Moroccan links). Use these terms when communicating
about sources.

### Rule 6: Upstream broadcaster misroutes affect ALL providers equally (2026-04-16)

When a channel shows wrong content, both vlc.news AND ayyad may
serve the same wrong content — because the upstream broadcaster
(e.g. Al Majd Network) is misrouting at the source. Before swapping
providers, probe BOTH to check if the wrong content is identical.
If it is, no provider swap will fix it — the issue is upstream.

Al Majd family channels (almajd-news, almajd-quran, almajd-3aamah,
almajd-kids, almajd-islamic-science, almajd-hadith, natural) all
originate from the same broadcaster and are at higher risk of
coordinated misroutes.

---

## Operational

### Rule 7: Do not dispatch identity_mismatch without logo_detected=true (reinforced 2026-04-17)

The existing PROMPT.md rule (HARD CONTRACT) already says this, but
it bears repeating after two false positives in 24 hours (basmah
2026-04-16, almajd-3aamah 2026-04-17): never emit
`identity_status=mismatch` in `identity_updates` unless the
sub-agent returned `logo_detected=true` AND named a specific
competing channel's logo. Overlays, seasonal graphics, and absent
logos are NOT grounds for mismatch.

### Rule 8: Arabic communications must use Fusha only (2026-04-16)

All Arabic text (Telegram messages, reports, any colleague-facing
output) must use Modern Standard Arabic (Fusha / الفصحى). No
dialect or colloquial forms. Use: الآن (not الحين), لم أتمكّن
(not ما قدرت), سوف/سـ (not راح), هذه الفترة (not هالفترة).
