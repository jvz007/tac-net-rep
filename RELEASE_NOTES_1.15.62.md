# Tec-Tac Framework 1.15.62

## Capability health authorization hardening

- Changed browser capability discovery to metadata-only by default so ordinary authenticated users cannot trigger provider health callbacks or downstream network/API work.
- Added explicit `?live=true` capability health inspection for operators with `core.privileged_operations` authority only.
- Non-privileged callers requesting live health receive HTTP 403 before any provider health callback executes.
- Capability payloads continue to expose `health_checked` so consumers can distinguish metadata-only discovery from a live provider health result.
