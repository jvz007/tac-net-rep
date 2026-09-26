# Tec-Tac Core 1.15.76

## Monotonic trust-policy upgrade migration

This release fixes the upgrade regression where the historic trust-policy
location could contain a stricter administrator floor such as `secure_signed`,
while a newer install created the current policy at its environment default and
therefore silently weakened the effective policy.

- The installer now reconciles the current root-owned policy at
  `/etc/tec-tac/policy/update-trust-policy.json` with the historic policy at
  `/var/lib/tec-tac/policy/update-trust-policy.json`.
- Migration is monotonic: the strongest valid level among the current policy,
  the legacy policy and the environment default wins.
- A legacy `secure_signed` policy is therefore preserved across the policy-path
  relocation.
- A weaker legacy/current policy cannot lower the environment security floor.
- Existing stronger current policy files are not rewritten when they already
  win, preserving administrator metadata.
- Policy inputs must be valid schema-1 regular non-symlink files; malformed or
  redirected policy state fails the upgrade rather than silently weakening it.
- The migrated current policy is written atomically and fsynced before install
  continues.

No public contract change is required.
