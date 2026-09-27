# Tec-Tac Core 1.15.115

## System Update reliability

- Fixed a successful Framework installer run being reported as exit status 1 by making the successful installer boundary explicit after all verification/service checks complete.
- Offline System Updates now accept a signed release set as three uploads: the release archive plus `tec-tac-release.json` and `tec-tac-release.json.sig`.
- Detached signing sidecars are staged independently, size-bounded, claimed by the root update helper without trusting Tactical-writable paths, injected only into the root-private extracted tree, and re-verified by the existing signed-tree trust boundary before deployment.
- Ambiguous signing input (sidecars both inside and outside the archive), incomplete sidecar pairs, duplicate archives, and unsupported extra files are rejected.

## Compatibility

- Existing single-file archives with embedded `tec-tac-release.json` and `tec-tac-release.json.sig` remain supported.
- Existing online GitHub release/branch staging is unchanged.

## Installer resource-contract compatibility fix

- Fixed upgrade rollback caused by installer self-checks pinning `core.resources` to exactly `1.1.0` after the public contract advanced to `1.2.0`.
- Installer verification now imports `CONTRACT_ID` and `CONTRACT_VERSION` from `tec_tac.resources`, validates the supported compatibility range `>=1.1.0,<2.0.0`, and compares catalog metadata/capability status to the registered constant.
- Added descriptive assertion messages to installer verification snippets so future self-check failures identify the failed invariant instead of logging a bare `AssertionError`.
- Added `tests/installer-resource-contract-version.py` to fail if installer expectations drift from the registered Core Resource Directory contract/capability version.

## Rebuild note

- Rebuild of 1.15.115 as 1.15.115 so the release pipeline sees a version increment.
- No additional functional changes in this rebuild.
