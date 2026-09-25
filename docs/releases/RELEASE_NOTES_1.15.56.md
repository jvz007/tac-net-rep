# Tec-Tac Framework 1.15.56

## Managed hotfix privileged boundary

- Adds detached Ed25519 publisher verification to managed module hotfix staging using the root-owned trust policy and trusted-publisher store.
- Requires hotfix signers to hold `module.install`; production/development acceptance continues to follow the configured trust floor.
- Freezes the hotfix ZIP, detached signature and release metadata into a root-private working set with no-follow file opens before privileged verification.
- Verifies and executes only the root-private package copy, binding the exact bytes checked by the publisher verifier to the bytes later parsed and applied.
- Rejects symlinked staged hotfix artifacts and verifies the private package SHA-256 against the queued job before execution.
- Claims queued hotfix jobs into root-only storage; Tactical-visible job files remain status mirrors rather than execution authority.
- Writes job mirrors and other privileged JSON state with random fd-backed temporary files, applying ownership and mode through `fchown`/`fchmod` before atomic replacement.
- Derives privileged staged package/signature/metadata names from the validated upload UUID instead of trusting caller-supplied paths.
- Uses only the fixed root-owned `/opt/tec-tac/etc/tec-tac.conf` for privileged hotfix configuration.
- Records the root-side publisher trust result with each applied hotfix for audit and troubleshooting.
