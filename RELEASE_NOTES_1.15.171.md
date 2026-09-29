# Tec-Tac Core 1.15.171

Tracker acceptance closure release for D2, D3, L10, F4 and F11.

## F4 — authenticated Tactical UI context
- Core continues to publish the current Tactical `agent_dblclick_action`, `url_action_id` and URL-action permission through `/api/tfd/ui/context/`.
- The public browser contract now documents the direct `register(context).context` surface as well as the compatibility `state.context` path.
- UI 0.12.65 carries these fields through runtime normalization and passes the same context object directly to authenticated module registration.

## F11 — Swagger / OpenAPI grouping
- Core groups known framework areas under stable `Tec-Tac · <area>` labels.
- Only prefixes matching a registered extension ID are labelled `Tec-Tac Module · <module-id>`.
- Unknown `/api/tfd/<prefix>/` routes now use the real `Tec-Tac · Framework` fallback instead of being guessed as module-owned.
- Tactical routes outside `/api/tfd/` remain untouched.
- Registry discovery failure degrades safely to Framework grouping and cannot affect Tactical startup.

## D2 / D3 / L10 acceptance evidence
- The existing recovery downgrade/identity/continuity behavior is unchanged.
- UI 0.12.65 adds a production validate -> job -> confirmation -> restore workflow regression.
- `tests/l10-publication-atomicity-1.15.171.py` directly exercises local, FTP, rclone and SCP final-archive failure paths and verifies no orphaned published sidecar/final archive is left behind.

## Regression coverage
- `tests/tracker-final-closure-1.15.171.py`
- `tests/l10-publication-atomicity-1.15.171.py`
- inherited D2/D3, backup publication, My Account, Resource Directory and contract suites
