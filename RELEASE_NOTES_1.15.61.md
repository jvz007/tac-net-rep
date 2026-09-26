# Tec-Tac Framework 1.15.61

## Module hotfix history path hardening

- Fixed the remaining C13 item from the Core security review: `list_applied_hotfixes(module_id)` now validates module identifiers with the same `MODULE_RE` boundary used by the rest of the managed-hotfix lifecycle before constructing an applied-history path.
- Invalid or traversal-style module identifiers are rejected instead of being joined beneath the privileged hotfix history root.
- The hotfix list HTTP endpoint now returns a bounded `400` response for an invalid module identifier rather than allowing an internal exception to escape.
- Added regression coverage for traversal, absolute/path-separator, dotted and otherwise invalid module identifiers while preserving valid module history listing.

This release contains no public contract change.
