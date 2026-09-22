# Bootstrap modules

Place trusted Tec-Tac module package archives in this directory when they must be
installed as part of the initial Core installation.

Supported package formats:

- `.zip`
- `.tgz`
- `.tar.gz`

`install.sh` installs Core and its privileged lifecycle infrastructure first,
then submits every package in this directory through the normal Module Manager
inspection, dependency planning, licensing validation, rollback, audit, and
privileged lifecycle path.

The directory may be empty. An empty directory leaves Core installation
unchanged.

Example initial-install payload:

```text
bootstrap-modules/
  userinvite-0.6.0.zip
```

Do not unpack modules into this directory. Nested directories and symlinked
packages are rejected.
