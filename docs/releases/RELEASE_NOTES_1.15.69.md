# Tec-Tac Framework 1.15.69

## Security: System Update root extraction boundary (R2)

This release closes the remaining privileged System Update extraction and mode-handling gap identified in the Core 1.15.67 security status review.

### Root-private temporary extraction

- System Update extraction now runs inside a per-job `RUNNING_ROOT/<job>.work` directory that is explicitly `root:root` mode `0700`.
- The work directory is managed by a context boundary and is removed after both successful use and exceptions/failures.
- Stale work from the same job identity is removed before a new private extraction directory is created.

### Release ownership and mode normalization

After the signed release tree has been copied into the root-managed source checkout and independently re-verified, Core now normalizes the release payload before any root installer executes:

- every release file/directory is made `root:root`;
- setuid and setgid bits are removed;
- group-write and world-write bits are removed;
- unexpected symlinks or special filesystem objects are rejected rather than followed;
- existing `.git` metadata is excluded because it is retained from the pre-existing root-managed checkout and is not package payload content.

Normal executable/read permission bits are preserved, so legitimate installer executability is not changed.

### Regression coverage

`tests/system-update-root-extraction-boundary.py` proves that:

- the private extraction directory is exactly mode `0700` while active;
- it disappears after normal completion;
- it disappears after an exception;
- setuid/setgid and group/world-write bits from package metadata cannot survive into installer execution;
- every release payload path is assigned root ownership;
- unexpected release symlinks are rejected.

No public capability or API contract changes are introduced by this release.
