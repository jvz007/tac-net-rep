# Tec-Tac Core 1.15.159

## Tracker closure: L07 and L63

- **L07:** privileged helpers now resolve the trusted Bash executable once per helper process and reuse the validated path. The regression executes all five production resolver functions with a counted fake filesystem boundary and proves the filesystem is consulted only on the first call.
- **L63:** restored the original clean-version release notes for 1.15.84, 1.15.86, 1.15.87, 1.15.88 and 1.15.89 from Git history. Release archive integrity now requires an unbroken clean-version archive from 1.15.83 through the release immediately preceding the current Core version.

## Scope

No public API or capability contract changes. This is a tracker-closure release only.
