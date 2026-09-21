# Tec-Tac Framework 1.15.20

## Module lifecycle state cleanup

- Successful single-module removal now removes that module from `/var/lib/tec-tac/module-manager/module-state.json`.
- State cleanup happens before UI-module synchronization, so a deleted extension cannot remain marked enabled and poison later UI/system updates.
- The lifecycle worker preserves the runtime-readable `0644` mode when rewriting module state.
- Foundation coverage includes a behavioural cleanup test.

Module data-purge semantics are unchanged.
