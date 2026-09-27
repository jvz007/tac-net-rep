# FIXING.md — Core 1.15.117

This build continues from the review-passed 1.15.115-1 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass.

## M18 — shared version ordering for release rebuilds

- Numeric `-N` release rebuild suffixes now sort after the suffix-free base release.
- Rebuild suffixes compare numerically (`-10` is newer than `-2`).
- Ordinary nonnumeric prerelease suffixes retain below-release ordering.
- Module dependency resolution, capability version checks, repository candidate selection and System Update release ordering now use compatible rebuild semantics.

## L61 — module-management foundation follows the current atomic state writer

- Removed the stale structural assertion for the superseded inline temporary-file chmod implementation.
- The foundation now requires `atomic_json(STATE_FILE, state)` and verifies the final module-state file is restored to `0644`.

## Regression coverage

- `tests/version-rebuild-ordering.py`
- `tests/module-management-foundation.sh`
