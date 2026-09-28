# Tec-Tac Core 1.15.161

## Tracker behavioural closure — L10, L15, L24, L25

This release is deliberately limited to executable regression closure for four tracker rows whose production fixes were already present.

- **L10 — backup sidecar publication:** exercises local, FTP, rclone and SCP publication paths and forces final archive publication to fail after the sidecar step. Every transport must leave no newly published final archive without its sidecar, and remote transports must roll back the published sidecar when the final archive cannot be published.
- **L15 — restore disk preflight:** measures a real host snapshot source through `_preflight_host_snapshot_bytes()` and proves those measured bytes materially change the production `validate_target_preflight()` disk decision.
- **L24 — Scheduler migration 0015:** executes the real migration canonicalizer over representative legacy client/site/endpoint/dynamic rows, proves its successful outputs are accepted unchanged by the runtime normalizer, proves a generic `id` alias fails closed, and proves immutable run history is never accessed.
- **L25 — endpoint identity:** executes the real Resource Directory helpers to prove legacy Agent PKs remain authorized for existing schedules/history, new saves canonicalize to `agent_id`, ambiguous PK/agent-id tokens fail closed, and Scheduler scope snapshots retain both legacy PK and canonical `agent_id` aliases.

## Verification

- Added `tests/tracker-behavior-closure-1.15.161.py` and wired it into the review-hygiene runner.
- No unrelated Core behavior changes are included in this release.
