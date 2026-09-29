# Tec-Tac Core 1.15.163

## Tracker closure: L07 and L76

- Hardened the privileged Bash boundary in all five root helpers. Bash is still resolved once at process startup from `/bin/bash` or `/usr/bin/bash`, but candidate validation now opens the executable with `O_NOFOLLOW` and validates the opened descriptor with `fstat` before retaining the path. Non-root-owned, group/world-writable, non-regular and non-executable candidates are rejected, with safe fallback to the second fixed candidate.
- Hardened recovery-key trust-root creation. A missing configured trust directory is created only beneath an already-existing root-owned, real, non-group/world-writable parent; `mkdir(parents=True)` no longer follows or creates an unchecked parent chain.
- Added behavioral regressions for Bash fallback/rejection, recovery-key shebang isolation against hostile `PYTHONPATH`, installer-selected recovery trust roots, and unsafe trust-directory parents.

No Backup/Restore API or UI behavior changes are included in this release.
