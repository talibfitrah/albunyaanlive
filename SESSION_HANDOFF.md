# Session Handoff Log

Append-only coordination log between the SRE/dev session and the dedicated Telegram session.

## Convention

- New entries go at the bottom, newest last.
- Format: `## YYYY-MM-DD HH:MM TZ — <topic>`
- Body: what changed; what (if anything) the Telegram session needs to do.
- Status tags (optional, at end): `[NEW]`, `[ACK]` (other session has read), `[DONE]` (other session has acted), `[OBSOLETE]`.

## Log

## 2026-04-15 — Reflex loop plan started

Implementation plan for the autonomous reflex loop is at `docs/superpowers/plans/2026-04-15-reflex-loop.md`. Will land in phases 1–8; each phase ends with a handoff entry summarizing what the Telegram session may see (new state-file fields, new alert shapes, etc.). [NEW]
