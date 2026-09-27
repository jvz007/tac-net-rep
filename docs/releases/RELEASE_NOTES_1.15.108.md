# Tec-Tac Core 1.15.108

## M10 — resilient legacy trust-policy migration

- Invalid historic trust-policy state under `/var/lib/tec-tac/policy/` no longer blocks every Core upgrade.
- The migration helper quarantines invalid legacy policy files beside the legacy path and continues using the strongest valid current/environment floor.
- Malformed JSON, invalid/non-numeric schema, invalid levels, symlinks and non-regular legacy files are handled as invalid migration input.
- Legacy symlinks are quarantined without following or modifying their targets.
- Corruption of the authoritative current `/etc/tec-tac/policy/update-trust-policy.json` remains fatal.
- Added behavioral regression coverage for quarantine, stronger-current preservation, environment fallback and authoritative-current failure.
