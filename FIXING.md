# Fixing — Core 1.15.149

This release closes the remaining Scheduler review items L19, L24, and L25.

## In scope

- L19 — prove behaviorally that occurrences predating a schedule revision are consumed before missed/grace evaluation and never create synthetic missed rows.
- L24 — align migration-time Scheduler target canonicalisation with the runtime target contract while preserving immutable run-history snapshots.
- L25 — make `agent_id` the persisted endpoint identity for existing saved schedules, with ambiguous numeric PK/agent-id references failing closed.

## Out of scope

- Trust-policy closure items.
- Backup/archive-history closure items.
- UI changes.
- D2/D3 restore decision cleanup.
