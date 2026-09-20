# Tec-Tac Framework 1.15.9

## Tactical backup privileged output ownership

- Fixes the Core narrow Tactical backup privilege bridge so root-collected files are handed to the configured Tactical service UID/GID before upstream `backup.sh` archives its workspace.
- Collected privileged members remain mode `0600`; they are not made group- or world-readable.
- Every privileged write verifies final UID, GID, exact mode, owner readability, and absence of group/other access before the privileged operation returns.
- Keeps `validate_tactical_native_archive()` unchanged as the post-`backup.sh` trust boundary, so missing privileged members still fail the complete backup before hashing, bundling, or upload.
