# Tec-Tac Core 1.15.78-1

## Security: signed bundle file-to-module mapping

This release closes the Module Management v2 bundle identity boundary where a Tactical-writable job could still provide the child `package_files` mapping after the outer bundle had been root-verified.

- The privileged trust verifier now derives an authenticated child mapping from the root-verified bundle bytes: child archive path, module id and module version.
- `tec_tac_bundle.json` is authoritative for the child file list. Filename-only entries remain supported; module identity/version are then derived from the child package's own `tec_tac.json`.
- Object entries that declare `file`, `id` and/or `version` must match the child package manifest or verification fails.
- Duplicate child archive members, duplicate module ids and unsafe child paths fail closed.
- Bundle and mixed-batch expansion consume only `artifact_package_files` returned by the privileged verifier. Mutable job `package_files` values are no longer used to select or label child packages.
- Final install-plan validation still binds order/actions/version/renames to the authenticated module facts returned by the privileged verifier.

### Regression coverage

`tests/module-v2-signed-bundle-mapping.py` verifies that a deliberately false/reversed job mapping cannot change the child file-to-module mapping for either standalone bundle installs or bundle artifacts inside a mixed batch. It also covers filename-only manifest entries, nested bundle manifests and signed id mismatch rejection.

## Rebuild security fix: exact verified bytes lifecycle

- V2 bundle, batch-bundle and standalone batch artifacts are copied into the final root-owned execution directory before privileged trust verification.
- Root verification, bundle extraction and module installation now consume only those execution snapshots; the claimed/request paths are never recopied after verification.
- The verifier-returned `package_sha256` is enforced immediately before bundle extraction or standalone package installation, so any mutation after verification fails closed.
- Added regression coverage for swapping the artifact between verification and extraction/install; mutated bytes cannot reach `install_packages`.
