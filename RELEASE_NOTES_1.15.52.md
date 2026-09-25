# Tec-Tac Framework 1.15.52

Corrective rebuild of rejected 1.15.52-1.

## Blocking review fix

- Creates `/var/lib/tec-tac/module-manager/module-state.lock` as `root:<tactical-group>` mode `0664` immediately after the Tactical service account is detected, before the Tec-Tac bootstrap is written to `local_settings.py` and before any `manage.py` invocation.
- Shared module-state reads tolerate a missing lock during bootstrap and read the state without locking while emitting a warning. Corrupt state still fails closed, and exclusive/mutating paths still require the managed lock.
- Adds regressions for `load_state()` with no lock present and for installer ordering so the lock must exist before bootstrap/settings import.

## Supersedes

- `1.15.52` — rejected during review.
- `1.15.52-1` — rejected because first Django settings import could occur before the module-state lock existed.

All intended hardening from 1.15.52-1 is retained.
