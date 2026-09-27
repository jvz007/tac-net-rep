# Tec-Tac Core 1.15.115

## System Update reliability

- Fixed a successful Framework installer run being reported as exit status 1 by making the successful installer boundary explicit after all verification/service checks complete.
- Offline System Updates now accept a signed release set as three uploads: the release archive plus `tec-tac-release.json` and `tec-tac-release.json.sig`.
- Detached signing sidecars are staged independently, size-bounded, claimed by the root update helper without trusting Tactical-writable paths, injected only into the root-private extracted tree, and re-verified by the existing signed-tree trust boundary before deployment.
- Ambiguous signing input (sidecars both inside and outside the archive), incomplete sidecar pairs, duplicate archives, and unsupported extra files are rejected.

## Compatibility

- Existing single-file archives with embedded `tec-tac-release.json` and `tec-tac-release.json.sig` remain supported.
- Existing online GitHub release/branch staging is unchanged.
