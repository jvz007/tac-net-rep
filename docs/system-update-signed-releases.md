# Signed System Update Source Releases

Framework 1.15.37 supports the Tec-Tac publisher tool v0.2.0 tree-signing format for GitHub source updates.

A signed repository root contains `tec-tac-release.json` (schema 2) and `tec-tac-release.json.sig`. The detached Ed25519 signature covers the exact manifest bytes. The manifest covers every release file by canonical relative path, byte size and SHA-256. Only root `.git` metadata and the two root signing outputs are excluded.

System Updates first downloads the exact GitHub `/zipball/{commit}` archive. If either signing file is present, both are mandatory and verification is fail-closed. Core resolves the manifest publisher and active key against `/etc/tec-tac/trusted-publishers/<publisher_id>/`, enforces the server/publisher environment, verifies the Ed25519 signature, checks component and VERSION, and compares the complete extracted tree with the manifest before installation can be queued.

The privileged update worker independently checks the staged package SHA-256, re-checks the extracted signed tree, resets/fetches the source checkout to the resolved commit, and then checks that checkout against the exact verified manifest and signature hashes before `install.sh` can execute. Existing backup and rollback behavior remains unchanged.

Stable Framework releases older than the configured cutoff can continue as `Unsigned / legacy`. The default cutoff is `1.15.37` and can be changed with `TEC_TAC_FRAMEWORK_SIGNED_RELEASE_MIN_VERSION`. Branch and offline updates remain available during the transition, but any source that contains partial or invalid signed-tree material is rejected rather than downgraded to unsigned.

Private signing keys never belong on a Tec-Tac server. Only public publisher policy and public verification keys are installed in the root-managed trust store.
