# Tec-Tac Core 1.15.114

## Review scope
M16 + L42 + L43 + L44 + L45 + L08 remainder.

## Changes
- New clients are created atomically with a `Default Site`; restricted creators are granted explicit client scope.
- Site moves cannot leave the source client with zero sites.
- Resource Directory and Session Security page numbers are upper-bounded.
- Global trusted Resource Directory service contexts require a persisted strict Core audit record.
- Client/site updates preserve Tactical `modified_by` and `modified_time` when using `update_fields`.
- Tactical Django validation failures surface through the stable Resource Directory validation boundary instead of HTTP 500.
- `core.resources` public contract advances to 1.2.0 and publishes Clients/Sites paging query/response details in metadata, Markdown and text exports.

## Tests
Behavioral tests cover client/default-site atomic creation, restricted creator scope, last-site move denial, Tactical audit-field update lists, model-validation translation, global-service-context audit failure, pagination bounds, and published paging rows.

## Rebuild fix
- Fix PostgreSQL site-move locking by serializing on the source client row and using an unlocked `COUNT(*)`; this avoids PostgreSQL rejecting `SELECT COUNT(*) ... FOR UPDATE`.
- Add a real Django/PostgreSQL HTTP regression covering an allowed move from a two-site client (HTTP 200) and denial of moving the final site (HTTP 400).
