# Tec-Tac Core 1.15.155

## Recovery public-key export path hardening

- `tec-tac-recovery-key export` no longer resolves and follows the final output path before writing.
- Existing symlink, directory, device, FIFO, or other non-regular output targets are rejected instead of being followed or overwritten as root.
- Public recovery-key exports now use a unique same-directory temporary file, fsync the payload, atomically replace a regular destination, and fsync the containing directory.
- Added executable regression coverage that plants the requested export path as a symlink to a protected victim file and verifies the victim remains untouched.

No public Core contract changes are introduced in this release.
