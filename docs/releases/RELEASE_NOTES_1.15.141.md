# Tec-Tac Core 1.15.141

## Public contract and compatibility closure

- U2: The generated public HTTP contract now documents the stable `console_required` response returned by `PUT /api/tfd/system/updates/trust-policy/`, including `status`, `requested_level`, `environment`, `command`, `help_article`, and `help_url`.
- L06: Added executable view-level regressions proving no-parameter Module v2 job history and session-audit requests retain the historical bounded 200-row compatibility path while paged calls continue to use the newer page-size defaults.
- L07: The existing fixed-list/root-owned Bash resolver checks for all privileged helpers are now wired into the normal contract foundation runner, preventing an unnoticed return to `/usr/bin/bash`-only execution.

## Regression coverage

- Added `tests/core-contract-compat-1.15.141.py`.
- Wired `tests/root-bash-boundary.py` and `tests/open-list-closure-1.15.118.py` into `tests/contracts-foundation.sh`.
- Documented the trust-policy console guidance object in `docs/trusted-publisher-verification.md`.

No database migration is required.
