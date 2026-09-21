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
