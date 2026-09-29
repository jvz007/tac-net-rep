# Tec-Tac Core 1.15.166

Decision-closure release for tracker items D2 and D3. No restore mechanism or API contract changes are introduced in this release; the existing Core restore behavior is retained and its decision-level acceptance evidence is made fully behavioral and ordinary-CI portable.

## D2 — restoring to an older Core version

- The real non-destructive restore validation operation is exercised with a backup that declares an older Core version.
- Validation returns the current and restored Core versions, marks the transition as a downgrade, and emits the explicit `This restore puts Core back to X.` notice consumed by the accepted UI 0.12.59 Backup & Restore page.
- The restored-Core verifier is exercised after the payload transition and accepts only when the effective installed Core version exactly matches the older version declared by the recovery manifest.
- Existing restore security-state protections remain covered by the D2/D3 continuity regression: target superuser protection and stricter trust state win over older backup state, and removed publishers are not resurrected.

## D3 — seamless restore identity and confirmation

- The real restore-validation result is exercised and required to expose source `server_name`, `installation_id`, recovery signer key ID and signer SHA-256 fingerprint.
- The decision regression runs successfully as an ordinary unprivileged CI user.
- UI 0.12.59 remains the accepted matching UI baseline. Its Backup & Restore flow displays those Core-supplied identity fields, requires successful validation before restore, and presents the exact downgrade target before destructive confirmation.

## Regression coverage

- `tests/server-backup-decision-closure-1.15.166.py` exercises the real validation result path and exact restored-Core version verification, and passes as an unprivileged user.
- `tests/server-backup-d2-d3.py` remains the cryptographic/trust/security-state continuity regression and no longer relies on source-grep assertions for D2/D3 closure.
- Existing Backup/Restore HTTP, registered-destination, recovery-trust and version-transition regressions remain part of the inherited review suite.
