# Tec-Tac Framework 1.12.1

Recovery Toolkit packaging corrective release.

## Recovery Toolkit execution

- Keeps all recovery commands exclusively under `/opt/tec-tac/scripts/recovery/`.
- Repairs every recovery `*.sh` file to mode `0755` during framework installation before any recovery helper is sourced or invoked.
- Verifies every Recovery Toolkit shell script is executable and fails the framework install clearly if the repair did not succeed.
- Removes the `tec-tac-repair` and `tec-tac-diagnostics` `/usr/local/sbin` symlinks created by 1.12.0 when those symlinks still point at this framework's Recovery Toolkit.
- Does not remove or overwrite unrelated administrator-managed files in `/usr/local/sbin`.

## Packaging regression coverage

- Recovery foundation tests now require the installer to repair executable bits explicitly, protecting offline ZIP update paths where archive extraction may not retain POSIX modes.
- Recovery foundation tests prevent future reintroduction of `/usr/local/sbin` convenience links.

No Scheduler, Module Manager data model, module registry, or UI behavior changes are included in this corrective release.
