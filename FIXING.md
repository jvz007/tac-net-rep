# FIXING.md — Core 1.15.136

## Review scope

This release is intentionally limited to **L55–L59** from the current Core tracker.

### L55 — aliased ZIP members

Module v2 validates every bundle member before extraction. Paths containing empty, `.` or `..` segments, backslashes, absolute paths, canonical collisions, or ZIP symlink entries are rejected before `extractall()` can write anything.

### L56 — failed claim/snapshot cleanup

The root-private running request and `<job>.claimed` bridge directory are now removed if immutable execution snapshotting or root trust verification fails before lifecycle execution begins. Normal completion uses the same cleanup helper.

### L57 — component validation ordering

System Update compares staged preview component identity with the queued request immediately after no-follow metadata read and before `_copy_staged_package()` consumes the staged package or signing sidecars.

### L58 — configured framework root ownership

`privileged-trust.py` resolves `TEC_TAC_FRAMEWORK_ROOT` from the root-owned Core config and validates the real ancestor chain through the configured runtime root. It no longer assumes `/opt/tec-tac` when the installer uses a custom layout.

### L59 — Mesh permission task commit ordering

The account guard installs a narrow proxy only in Tactical's `accounts.views` module. Calls to `sync_mesh_perms_task.delay()` made while a Core guard transaction is open are registered with `transaction.on_commit`; calls outside a transaction retain Tactical's normal immediate behavior.

## Expected review outcome

- A bundle containing both `packages/x.zip` and `./packages/x.zip` is rejected before extraction.
- Snapshot/trust failure leaves neither the root-private request nor `.claimed` bridge directory.
- A staged framework package requested as UI is rejected without consuming the staged package.
- A custom `TEC_TAC_FRAMEWORK_ROOT` is used for privileged import ownership validation.
- Tactical Mesh permission synchronization is queued only after the account/role guard transaction commits.

No other tracker findings are intentionally changed.
