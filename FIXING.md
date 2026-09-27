# FIXING.md — Core 1.15.140

## Review scope

This release is intentionally limited to **L01, L02, L03 and L04** from the current Core tracker.

### L01 — standalone batch package identity comes from verified bytes
Standalone Module Management v2 batch artifacts no longer trust the mutable job/request `id`. The worker takes the module id and version from the root verifier's authenticated `artifact_modules` result and requires exactly one authenticated module for a standalone package.

### L02 — uninstaller config is data, not shell
The existing safe config-loader behavior is now covered by a behavioral regression. `uninstall.sh` sources only `scripts/tec-tac-config.sh`; a config value containing command substitution remains literal data and is not executed.

### L03 — fixed Python interpreter paths
The existing recovery/install hardening is now covered by an executable regression that rejects any return to bare `python3` from `PATH`. Recovery scripts use `/usr/bin/python3 -I` or Tactical's configured virtualenv Python.

### L04 — no-follow v1 staged metadata
The v1 module worker reads `staged/<upload_id>.json` through the existing `O_NOFOLLOW|O_NONBLOCK` bounded JSON reader. A staged metadata symlink/FIFO is rejected rather than followed or blocked on.

No other tracker findings are intentionally changed.
