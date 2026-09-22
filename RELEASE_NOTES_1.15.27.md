# Tec-Tac Framework 1.15.27

## Optional module runtime discovery

- `GET /api/tfd/ui/context/` now includes a lightweight `module_status` snapshot covering installed extension identity, version and enabled/active state.
- The snapshot deliberately avoids the full Module Manager catalogue and is intended for cheap browser-runtime discovery of optional integrations.
- Added `docs/optional-module-integrations.md`, including the CyberCNS + Endpoints pattern and the required backend capability fallback.
- Public Contracts, repeated Module Manager calls and direct private imports are explicitly not runtime discovery mechanisms.
