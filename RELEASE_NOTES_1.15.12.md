# Tec-Tac Framework 1.15.12

- Bumps `core.server_backup` to 1.5.1.
- Replaces blanket TAR link rejection with archive-namespace-safe symlink/hardlink validation.
- Allows relative symlinks whose resolved target stays inside the archive namespace, including common Tactical archive layouts.
- Allows hardlinks only when their normalized target remains inside the namespace and names a member in the same archive.
- Continues to reject absolute/escaping links, duplicate normalized member paths, FIFOs, devices, sockets and other unsupported special members.
- Uses the shared TAR member validator for Tactical native/nested archive validation and Tec-Tac recovery payload extraction.
- Adds regressions for safe internal links, escaping/absolute links, missing hardlink targets, special files and real payload extraction through an internal symlink.
