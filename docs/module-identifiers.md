# Tec-Tac module identifier contract

Tec-Tac module identifiers are **case-sensitive and case-preserving**.

Core does not lowercase, case-fold, slugify, alias, or otherwise rewrite an installed module ID. The exact identifier declared by an extension is the identifier used by the paired reportset, module state, RBAC permission namespace, capability namespace, dependency graph, licensing checks, scheduler ownership and UI metadata.

For a module with the canonical ID `securityWAF`, the supported identity is therefore exactly:

```text
module_id: securityWAF
capability: securityWAF.waf
permissions: securityWAF.read, securityWAF.manage
API root: /api/tfd/securityWAF/
UI route: /extensions/securityWAF
extension path: extensions/securityWAF/
reportset path: reportsets/securityWAF/
```

`securityWAF` and `securitywaf` are different identifiers. Modules must use one canonical spelling consistently across every manifest and runtime registration.

Core does not provide a generic alias from `security` to `securityWAF`. An alias or migration shim must only be introduced when a real deployed upgrade path requires one, and should then be explicit and narrowly scoped.

## Identity surfaces

The following surfaces must preserve the identifier exactly:

- extension and reportset directory names;
- `tec_tac.json` IDs;
- `tec_tac_ui.json` IDs and routes;
- module-state keys;
- dependency and optional-dependency keys;
- capability provider IDs and capability prefixes;
- extension permission prefixes and RBAC storage;
- licensing module/product metadata passed to an entitlement provider;
- scheduler action module IDs and owned-schedule `owner_module` values;
- repository catalogue module IDs;
- navigation/module metadata supplied by the module.

Uppercase ASCII letters are supported by the Core module-ID validators. Permission and capability prefixes are compared case-sensitively against the owning module ID.

## Explicit module identity migration (rename-upgrade)

Changing a module ID is not a normal version upgrade. Because module IDs are
case-sensitive stable identities, a package with a new ID is treated as a new
module unless the extension manifest explicitly declares an identity migration.

Example:

```json
{
  "id": "securityWAF",
  "type": "extension",
  "version": "0.2.2",
  "migration": {
    "previous_module_ids": ["security"],
    "permissions": {
      "security.read": "securityWAF.read",
      "security.manage": "securityWAF.manage"
    },
    "scheduler_actions": {
      "security.scan": "securityWAF.scan"
    },
    "ui_routes": {
      "/extensions/security": "/extensions/securityWAF"
    },
    "dashboard_widgets": {
      "security.summary": "securityWAF.summary"
    }
  }
}
```

When exactly one declared previous ID is installed and the destination ID is
not installed, Module Manager classifies the operation as `rename` rather than
`install`. The lifecycle transaction:

1. backs up the old and destination module roots plus module state;
2. removes the old extension/reportset roots from the live registry namespace;
3. installs and verifies the new extension/reportset pair;
4. migrates the old module-state record to the new ID;
5. migrates explicitly mapped persisted RBAC permissions;
6. migrates scheduler `module_id` / `owner_module` and explicitly mapped action IDs;
7. updates exact mapped navigation routes and dashboard widget IDs;
8. refreshes UI/runtime workers; and
9. rolls code/state and database identity changes back if the lifecycle fails.

Core deliberately does **not** create a permanent alias between the old and new
IDs. After a successful rename, the old identity is gone.

### Rename preflight rules

A rename is blocked when:

- both the old and new module IDs are already installed (Core will not guess how
  to merge two deployed identities);
- more than one declared previous ID is installed;
- another enabled module not included in the same update transaction still has
  a hard dependency on the old ID;
- persisted RBAC rows exist in the old permission namespace without an explicit
  `migration.permissions` mapping;
- persisted schedules refer to old namespaced action IDs without an explicit
  `migration.scheduler_actions` mapping; or
- persisted destination permission/scheduler ownership already exists and would
  make the migration ambiguous.

If dependent modules must change from an old dependency ID to the new ID, ship
them together in one bundle/batch so the dependency graph can be validated as a
single lifecycle transaction.

Historical scheduler run rows are not rewritten; they remain an audit record of
the identity/action that existed when those runs occurred.
