# Tec-Tac Framework 1.15.58

## Core Resource Directory

- Added the versioned `core.resources` 1.0.0 public contract for read-only client, site and agent discovery.
- Added stable `tec_tac.resources` Python operations for scoped list/get/resolve access without exposing Tactical ORM objects.
- Added `tec_tac.resources_adapter` as Core's only Tactical Client/Site/Agent model compatibility boundary.
- Added explicit interactive user contexts and trusted service contexts; no-user calls never receive implicit global access.
- Enforced Tactical list permissions together with Tactical `filter_by_role(user)` resource scope for interactive callers.
- Added pagination, search, client/site filtering and documented active/deleted semantics.
- Added authenticated HTTP resource representations for browser/external callers under `/api/tfd/resources/`.
- Registered `core.resources` as a discoverable Core capability and documented it in live JSON, Markdown and text Public Contracts exports.
- Added a development rule requiring feature modules to consume Core resource identity instead of importing Tactical Client, Site or Agent models directly.
- Added independent Resource Directory contract, scope, pagination, stable-shape and adapter-isolation regression coverage.

This release is read-only. Customer-management workflows remain module-owned and can migrate to the Core identity/read layer separately.
