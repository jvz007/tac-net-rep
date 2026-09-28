# Tec-Tac Core 1.15.88

## D5 — unified Tactical resource scope

- Tactical roles with both `can_view_clients` and `can_view_sites` empty now consistently mean full scope across Scheduler target authorization, runtime authorization re-checks and Resource Directory writes.
- Site-only roles remain restricted: parent-client read visibility does not become whole-client Scheduler or client-write authority.
- Explicit client grants authorize that client and its sites; explicit site grants authorize only those sites.
- Scheduler health now reports `AuthorizationRevoked` skips from the last 24 hours, including the latest affected schedule, so revoked runtime authorization is visible to operators.
- Added focused regression coverage for unrestricted, site-only and client-scoped roles.

## Low-risk cleanup

- Native UI context now exposes `list_clients` so the Clients & Sites navigation item can follow Tactical `can_list_clients` instead of being universally visible.
- Removed an unused `timedelta` import from Core views.
