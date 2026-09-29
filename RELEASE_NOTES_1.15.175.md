# Tec-Tac Core 1.15.175

## Tracker closure: F10 public contract

- **F10 — Clients & Sites module context actions:** the Core Public Contracts catalog now explicitly publishes `client.context-menu` and `site.context-menu` as supported `contextActions` placements.
- The contract now defines the consumer-owned context shape for each placement. Client actions receive `resource_type`, `resource`, `client` and `selection`; site actions receive `resource_type`, `resource`, `site`, parent `client` and `selection`.
- This makes the Clients & Sites placements discoverable from the authoritative Core contract instead of existing only in UI documentation.

## Regression coverage

- Added `tests/f9-f10-browser-contract-1.15.175.py` and included it in the normal review-hygiene gate.
- The regression parses the production `BROWSER_CONTRACTS` definition and fails if the client/site placements or their context shapes are removed.

Companion UI release: `0.12.69`.
