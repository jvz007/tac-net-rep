# Tec-Tac Core 1.15.73

## Security: System Update staged-artifact claim boundary (R6)

Core no longer moves a Tactical-writable System Update package inode into the
privileged running area. The root helper now treats the queued `upload_id` as
the only package identity authority and accepts exactly one direct staged file
named `<upload_id>.zip`, `<upload_id>.tgz`, or `<upload_id>.tar.gz`.

The privileged claim now:

- opens the managed staging directory with `O_DIRECTORY|O_NOFOLLOW`;
- opens staged metadata and package files relative to that directory fd with
  `O_NOFOLLOW` and requires regular files;
- ignores Tactical-writable `metadata.package_path` as privileged path authority;
- copies the package into a new `root:root 0600` inode and `fsync`s it;
- installs/verifies only from that private snapshot;
- removes the original staged entry only when its `st_dev`/`st_ino` still match
  the file descriptor that was copied; and
- rejects symlinked staging roots, symlinked package/metadata entries and
  ambiguous multiple-package staging for one upload id.

Module v1/v2 claim paths were re-reviewed and already use the equivalent
root-private directory-fd snapshot boundary introduced in 1.15.70/1.15.70-1,
so this release changes only the remaining System Update claim path.

No public contract changes are required.
