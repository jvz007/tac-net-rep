# Tec-Tac Framework 1.15.38

## Stable release signing visibility

- Stable release discovery now resolves the release tag to an exact commit and inspects the publisher-tool v0.2.0 signed-tree manifest and detached signature.
- Core verifies the detached Ed25519 signature over the exact manifest bytes against the local trusted-publisher policy before reporting an available release as signed.
- Discovery exposes a lightweight `release_trust` preview containing publisher/key identity, algorithm, manifest file count, and trust details.
- The discovery signal intentionally does not claim that the full source tree is verified. Complete signed-tree verification still happens after download/inspection and again at the execution boundary before `install.sh`.
- Release trust discovery is persisted in the existing 24-hour stable-release cache so normal UI refreshes do not repeatedly query GitHub.
