# FIXING.md — Core 1.15.108

## Review scope

This release is intentionally scoped to **M10** from the 27 September 2026 Claude tracker.

### M10 — invalid legacy `/var/lib` trust-policy state blocks Core upgrades

Review that this release:

1. Treats the historic `/var/lib/tec-tac/policy/update-trust-policy.json` as migration input only, not current authority.
2. Quarantines an invalid legacy policy beside the legacy path and continues migration rather than aborting the upgrade.
3. Covers malformed JSON, invalid/non-numeric schema, invalid level, final-component symlink, and non-regular legacy files through the same invalid-legacy path.
4. Does not follow a quarantined legacy symlink or alter its target.
5. Continues with the stricter of the valid current `/etc` policy and the environment default when legacy state is invalid.
6. Preserves a stronger valid current policy byte-for-byte.
7. Still fails closed if the authoritative current `/etc/tec-tac/policy/update-trust-policy.json` is corrupt.
8. Logs the legacy quarantine to stderr/install logs, including source, quarantine path, and bounded reason.
9. Includes executable behavioral coverage in `tests/trust-policy-upgrade-migration.py`.

## Primary files changed

- `scripts/trust-policy-migration.py`
- `tests/trust-policy-upgrade-migration.py`
- `install.sh`
- `docs/trusted-publisher-verification.md`

## Explicitly out of scope

No other Medium or Low tracker item is intended to be closed by this release.
