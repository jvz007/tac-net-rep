# Tec-Tac Framework 1.13.0

## Source/runtime separation

- Separates Git source checkouts from the installed Tec-Tac runtime.
- Framework source: `/opt/tec-tac-src/framework`.
- UI source: `/opt/tec-tac-src/ui`.
- Framework runtime: `/opt/tec-tac/framework`.
- Installed extensions/reportsets remain under `/opt/tec-tac/extensions` and `/opt/tec-tac/reportsets`.
- Authoritative application configuration is `/opt/tec-tac/etc/tec-tac.conf`.
- Compiled UI remains `/var/lib/tec-tac/ui/tec-tac`.

## Update and recovery hardening

- System Updates now replace source checkouts and then invoke the common installer to deploy runtime.
- Dynamic module trees are verified against the runtime before and after framework updates and rollback.
- Module workers, recovery tools and lifecycle scripts read the shared Tec-Tac layout configuration.
- Recovery option 4 now replaces an exact missing module path instead of nesting a restored directory inside an existing directory.
- Recovery option 4 validates module pairing and Django after restoring code.
- Adds `scripts/migrate-layout.sh` for one-run migration from the legacy mixed Git/runtime layout.
