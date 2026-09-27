# FIXING.md — Core 1.15.142

Review-hygiene release closing U4, L50, L51 and L54.

- Publishes `/api/tfd/access/security-policy/` in the live HTTP contract catalog with GET/PUT authorization, request/response shapes and error semantics.
- Documents the administrator MFA recovery endpoint's exact read-only GET response and protected-account authorization boundary.
- Locks out the stale unused `timedelta` import regression.
- Adds behavioral coverage proving malformed session-history/login-session pagination returns fixed 400 text rather than raw Python conversion errors.
