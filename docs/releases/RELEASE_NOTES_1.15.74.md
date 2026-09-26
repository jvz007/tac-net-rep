# Tec-Tac Core 1.15.74

## Security: system cryptography dependency is now a true preflight (R7)

Core now verifies the root-side signature-verification dependency before the
installer performs any runtime, migration, policy, sudoers or privileged-helper
mutation.

The installer now:

- requires the fixed `/usr/bin/python3` interpreter during preflight;
- imports `cryptography` through `/usr/bin/python3 -I` so caller-controlled
  Python environment/site paths cannot satisfy or influence the check;
- runs the dependency check immediately after source-layout validation and
  before the first deployment filesystem mutation; and
- removes the former late dependency check from the privileged-trust install
  section.

`tests/installer-cryptography-preflight.sh` enforces that there is exactly one
check and that it remains before deployment mutations, migrations, trust-policy
writes and sudoers work. The regression is also invoked by the existing root
Python privilege-boundary suite.

No public contract changes are required.
