# Tec-Tac Framework 1.2.2

## Persistent UI deployment coordination

Tec-Tac UI 0.2.2 moves its deployed application and extension UI modules outside Tactical's replaceable `/var/www/rmm/dist` tree.

The framework module manager now records an explicit UI deployment root in `/etc/tec-tac/module-manager.conf`:

```text
UI_ROOT=/var/lib/tec-tac/ui/tec-tac
```

When extension lifecycle jobs finish successfully, the privileged module helper passes that deployment root to the UI module synchronizer. This keeps module installation/removal aligned with the persistent UI deployment without requiring Tactical frontend assets to be rebuilt after a Tactical upgrade.

No Tactical tracked source files are modified by this change.
