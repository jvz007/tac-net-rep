# Tec-Tac Core 1.15.172

Tracker done-when closure release for D2, D3, L10, F1, F2, F5, F6, F7 and F11.

## L10 — executable publication atomicity
- Replaces the ineffective 1.15.171 L10 acceptance stub with real local, FTP, rclone and SCP failure-path execution.
- Each transport proves sidecar-first publication and rollback when the final archive cannot be published.
- Backup transport behavior itself is unchanged.

## F11 — endpoint-owner Swagger grouping
- Module grouping now uses drf-spectacular endpoint callback ownership through each installed extension's registered Django app namespace.
- API path segments no longer need to equal the stable module ID.
- This correctly groups cases such as module `serverhealth` owning `/api/tfd/server-health/`.
- Known Core areas remain Core-owned, unknown Tec-Tac routes remain in `Tec-Tac · Framework`, and Tactical routes are untouched.

## F1/F2/F5/F6/F7 — real HTTP boundary evidence
- Adds a portable regression that executes the actual My Account and Resource Directory DRF view methods.
- Password/TOTP requests are proven to dispatch the expected proof/session inputs.
- Site/client deletion dispatches the relocation destination through the real HTTP views.
- Client/site custom-field GET/PATCH dispatch and bounded request validation are exercised.

## D2 / D3 — explicit final acceptance runner
- Runs the existing portable downgrade, recovery identity/trust and service-state regressions together.
- When CI is root, the acceptance runner executes those child regressions as `nobody` where available so portability cannot be masked by root.

## Regression coverage
- `tests/l10-publication-atomicity-1.15.172.py`
- `tests/f11-openapi-ownership-1.15.172.py`
- `tests/tracker-http-feature-boundary-1.15.172.py`
- `tests/d2-d3-final-acceptance-1.15.172.py`
