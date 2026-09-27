# Tec-Tac Core 1.15.117

## Scope

This release follows the agreed **maximum 1 Medium + 5 Low** cadence. The reviewer-held non-blocking list was not present in the approved 1.15.115-1 artifact, so this pass contains one fresh-audit Medium and one Low test-hygiene correction.

## Fixed

### M18 - numeric rebuild versions were ordered as prereleases

Core's shared module/capability/repository version comparator treated a numeric release rebuild such as `1.15.115-1` as older than the suffix-free `1.15.115`, and compared rebuild values lexically so `-10` sorted before `-2`.

Tec-Tac uses numeric `-N` suffixes as release rebuilds. The shared comparator now follows the same ordering already used by System Updates:

- `1.15.115 < 1.15.115-1 < 1.15.115-2 < 1.15.115-10 < 1.15.117`;
- ordinary nonnumeric prerelease suffixes remain below the suffix-free release;
- dependency constraints, capability constraints and online module update selection therefore agree with release-pipeline ordering.

### L61 - stale module-management structural assertion

The module-management foundation still required the old inline `os.chmod(tmp, 0o644)` implementation even though module-state cleanup now publishes through the shared `atomic_json()` helper and applies the runtime-readable mode to the final state file. The structural regression now checks the current atomic publication boundary and final `0644` mode instead of an obsolete implementation detail.

## Regression coverage

- `tests/version-rebuild-ordering.py` verifies base-to-rebuild ordering, numeric rebuild ordering, next-core-version ordering, prerelease compatibility and exact rebuild constraints.
- `tests/module-management-foundation.sh` now validates the current atomic module-state cleanup implementation and runtime-readable final mode.

## Review follow-up

- M13: added regression coverage proving dynamic scheduler filters reject Tactical scope aliases when they are encoded as nested filter values, while ordinary module-owned filter fields remain valid.
- L02: added a release guard proving uninstall uses the safe config loader and never sources the Tec-Tac config file as shell code.
- L03: added a release guard requiring fixed `/usr/bin/python3` for privileged installer and recovery Python calls.
- L50: documented the administrator MFA recovery status/invalidation endpoint and its authorization boundary.
- L51: guarded removal of the obsolete `timedelta` import from `views.py`.
- L54: added a release guard for stable pagination validation messages so raw `int()` exception text is never returned.
