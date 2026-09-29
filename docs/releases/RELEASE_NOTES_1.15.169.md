# Tec-Tac Core 1.15.169

Tracker closure and Swagger grouping release.

## D2 / D3 / L10 closure evidence
- Re-runs the existing behavioral restore downgrade/identity/continuity regressions for D2 and D3.
- Re-runs the existing local, FTP, rclone and SCP sidecar-first publication failure regression for L10. No stable restore/backup production behavior is changed in this release.

## F4 — Tactical UI preferences in module context
- `/api/tfd/ui/context/` now publishes a lightweight `tactical_ui` object containing `agent_dblclick_action`, `url_action_id`, and `can_run_url_actions`.
- Authenticated modules therefore receive the operator's Tactical UI defaults through the normal Core runtime state without calling Tactical directly.

## F11 — Swagger / OpenAPI grouping
- Installs a drf-spectacular post-processing hook during Core startup.
- Every `/api/tfd/` operation is grouped into a deterministic Core subsystem tag or `Tec-Tac Module · <module-id>` tag.
- Dynamically mounted module endpoints are grouped automatically; module authors still own summaries and request/response schemas.
- Non-Tec-Tac Tactical endpoints are left untouched.

## Regression coverage
- `tests/tracker-open-closure-1.15.169.py`
- `tests/tracker-feature-closure-1.15.169.py`
