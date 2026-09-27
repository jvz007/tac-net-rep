# Core 1.15.142

## Public contract and access/session hygiene

- **U4 — Account-security policy public contract:** the live Core HTTP contract catalog now publishes `GET` and `PUT /api/tfd/access/security-policy/`, including authorization, request/response fields and the stable error semantics consumed by the UI.
- **L50 — Administrator MFA recovery documentation:** `docs/session-security.md` now documents the concrete read-only GET response (`user`, `status`, `can_invalidate`), the status fields, cache behavior, and that protected-account authorization happens before status is read or mutation occurs.
- **L51 — Stale import regression:** executable coverage ensures the unused `timedelta` import does not return to `framwork/tec_tac/views.py`.
- **L54 — Safe pagination errors:** behavioral regressions exercise both session-audit and administrative login-session views and verify malformed pagination returns the fixed `Invalid pagination parameters.` response without exposing raw `int()`/`ValueError` text.

## Tests

- Added `tests/access-contract-hygiene-1.15.142.py`.
- Wired the regression into the Core contract and session-security foundation runners.
