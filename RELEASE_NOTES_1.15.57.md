# Tec-Tac Framework 1.15.57

## Server-maintenance privileged job boundary

- Claims each queued privileged server-maintenance job into root-private storage before detached execution begins.
- Executes registered actions and parameters only from the claimed root-owned job, so later changes to the Tactical-visible job file cannot alter privileged execution.
- Keeps `jobs/<id>.json` as a status mirror only and continuously repairs it from the root-private authority record.
- Uses no-follow reads while claiming the original queued job and rejects non-regular state files.
- Writes root-owned status mirrors with random fd-backed temporary files, `fchmod`/`fchown`, fsync and atomic replacement rather than predictable path-based temporary files.
- Stores claimed jobs as root-only `0600` files beneath a root-only `running/` directory.
- Applies cancellation state to the claimed authority record first and mirrors the result afterward, preserving the same security boundary through cancellation.
- Adds regression coverage proving post-dispatch public-job parameter replacement cannot change executed arguments and predictable temporary-file symlinks cannot redirect root writes.
