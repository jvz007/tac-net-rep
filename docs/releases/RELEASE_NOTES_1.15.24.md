# Tec-Tac Core 1.15.24

## Initial-install bootstrap modules

Core installation can now include trusted Tec-Tac module packages in a
`bootstrap-modules/` subdirectory beside `install.sh`.

When supported package archives are present, `install.sh` completes the Core
Module Manager infrastructure first and then submits the packages through the
normal Module Manager lifecycle. Bootstrap packages therefore receive the same
archive validation, manifest validation, licensing enforcement, dependency
planning, ordered installation, rollback, persistent lifecycle job state and
audit history as modules installed later from the Tec-Tac UI.

The bootstrap path supports `.zip`, `.tgz`, and `.tar.gz` module packages and
supports multiple packages in one initial installation. Multi-package intake is
resolved through Module Manager v2 so declared dependencies determine the
installation sequence.

An empty or missing `bootstrap-modules/` directory leaves normal Core-only
installation unchanged. Symlinked packages, nested directories, unsupported
file types, invalid dependency plans, licensing failures, and failed module
lifecycle jobs fail the installation visibly rather than being ignored.

Example:

```text
tac-net-rep-1.15.24/
  install.sh
  bootstrap-modules/
    userinvite-0.6.0.zip
```

This mechanism is generic Core infrastructure and contains no UserInvite- or
other module-specific installation logic.
