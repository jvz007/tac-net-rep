# Tec-Tac Framework 1.15.32

## Developer contract catalogue health-probe isolation

- fixes framework upgrades stalling or timing out while verifying the Developer Contract Catalog when installed module capabilities expose slow/network-backed health callbacks;
- adds a metadata-only `check_health=False` capability discovery mode while keeping normal capability resolution health-authoritative by default;
- makes Public Contracts and installer contract verification use the non-probing snapshot so documentation generation cannot execute provider/network health checks;
- keeps normal `capability_status()`, `get_capability()`, `has_capability()` and default `list_capabilities()` behavior unchanged;
- extends installer verification to assert the Core audit Python contract and `/api/tfd/audit/record/` route introduced in 1.15.31;
- adds regression coverage proving metadata-only capability listing does not invoke provider health callbacks.
