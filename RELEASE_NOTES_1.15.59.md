# Tec-Tac Framework 1.15.59

## Core Resource Directory writes

- Extended `core.resources` to contract version `1.1.0` without changing the accepted 1.0 read operations or stable resource record shapes.
- Added Core-owned `create_client`, `update_client`, `create_site` and `update_site` Python operations.
- Added `POST`/`PATCH` HTTP support for client and site resources while keeping agent resources read-only.
- Added Core RBAC permissions `core.resources.clients.manage` and `core.resources.sites.manage` to the normal Tec-Tac Access permission catalogue.
- Client writes require Tactical `can_manage_clients` plus `core.resources.clients.manage`; site writes require Tactical `can_manage_sites` plus `core.resources.sites.manage`.
- Update operations remain constrained to the authenticated user's Tactical resource scope, and site create/move operations require the destination client to be in scope.
- Trusted service contexts remain read-only; unattended code does not receive self-asserted resource mutation authority.
- Added stable `resource_conflict` handling for duplicate Tactical client/site identities without exposing ORM/database exceptions.
- Kept Tactical model mutation details isolated in `tec_tac.resources_adapter`; consuming modules continue to receive stable Core records only.
- Updated live Public Contracts exports with write support, RBAC requirements, authorization semantics and HTTP methods.
- Added regression coverage for client/site create/update, write RBAC, Tactical manage permissions, scope isolation, conflicts, stable shapes and service-context write denial.

Resource deletion and agent mutation are intentionally not part of this release and will be designed separately.


## Rebuild 1 security correction

- Corrected the Resource Directory client/site mutation boundary so write authorization no longer reuses Tactical's broader `filter_by_role()` read visibility.
- Client updates and site destination-client checks now mirror Tactical `_has_perm_on_client` semantics.
- Site update targets now mirror Tactical `_has_perm_on_site` semantics.
- A role that can explicitly view a site under another client can still read the parent client where Tactical permits that, but cannot use that transitive visibility to rename the parent client, create a site under it, or move another site into it.
- Added regression coverage for `allowed_clients={1}` with `allowed_sites={21}` where site 21 belongs to client 2; update-client(2), create-site(client 2), and moving site 11 to client 2 are all denied/not found.
