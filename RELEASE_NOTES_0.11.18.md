# Tec-Tac UI 0.11.18

## Module availability runtime

- Authenticated modules now receive a Core-owned read-only `modules` service.
- Lookups are backed by the startup context snapshot and make no HTTP requests.
- The service distinguishes installed/enabled/active state when paired with Framework 1.15.27 and safely falls back to active-only discovery with older Core versions.
- Added version constraint checks and Public Contracts visibility.
- Added `docs/module-status.md`; optional UI integration is explicitly presentation-only and backend capabilities remain authoritative.
