# Tec-Tac Framework 1.15.66

## Privileged helper environment hardening

- Completed the remaining S1 privileged-environment boundary across System Updates and module lifecycle workers.
- `system-update-helper.py`, `module-job-helper.py`, and `module-v2-job-helper.py` now use only the fixed `/opt/tec-tac/etc/tec-tac.conf` path for privileged configuration.
- Root helpers reject symlinked, non-regular, non-root-owned, or group/world-writable Tec-Tac configuration files.
- Caller-supplied `TEC_TAC_*` process variables are stripped before privileged installers, module lifecycle scripts, UI sync, identity migration, hotfix verification, and root publisher verification are executed; only narrowly required Core-generated values are re-added.
- System Update signed-release minimum-version policy no longer accepts process-environment overrides and is read only from root-owned configuration/defaults.
- The root publisher verifier now validates both the Tec-Tac config and trust-policy file before trusting their contents.
- Added `tests/privileged-helper-environment.py` covering malicious environment overrides, fixed config paths, explicit safe child variables, minimum-version policy, writable config rejection, and symlink rejection.

No public capability/API contract changes are introduced.
