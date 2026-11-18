# Tec-Tac Framework 1.18.0

Date: 16 November 2026. This release marks the production line. It changes no code and no behaviour.

Johan asked for the version number to move to 1.18.0 so that `dev` can be promoted to `main`. The only content in this release is this note and one test. The code is the same as Core 1.17.124.

## Why a minor version

The version number is a label for the production line. It does not claim new features. Moving from 1.17.x to 1.18.0 gives `main` a clean starting point. UI 0.13.0 (which will require Core 1.18.0 or newer) is a separate UI release.

## What changed on dev since main

`main` holds Core 1.17.110 and UI 0.12.127. The UI is unchanged. Core moved from 1.17.110 to 1.17.124. In plain English:

* **Delegated start of a module's own scheduled action (1.17.111).** Maintenance can now start a Windows patching profile install through its schedule. This is the only delegated action allowed.
* **Server maintenance jobs (1.17.112).** Jobs have an input channel. A job that waits for a person no longer holds the global lock, so other work is not blocked.
* **A module's own root program (1.17.113 and 1.17.114).** Core checks the `requires.framework` version first and passes secrets to the program safely (`secret_inputs`). It shipped switched off in 1.17.113 and switched on in 1.17.114 under AD-62.
* **Schedules and uninstall (1.17.115).** Core shows the next run of a schedule. It offers a public check for an active superuser. The rule for secrets at uninstall is now stated.
* **The `core.sandbox` foundation (1.17.116 to 1.17.124).** This covers the launch path, the unit builder, the canary and nine rounds of canary fixes (AD-63). `SANDBOX_ENABLED` is `False`, so nothing can run in the sandbox.

The notes for each version are in `docs/releases/`.

## Module-facing

No contract, capability, endpoint or import changes in 1.18.0. Every installed module declares `requires.framework` with an upper bound of `<2.0.0`, so 1.18.0 satisfies them all. Core compares versions as numbers, so 1.18.0 sorts after 1.17.124 and after any 1.17.124-N rebuild.

## What is not in this release

* The sandbox stays off.
* Licensing enforcement stays log-only.
* Module-category enforcement is not switched on.

The last two wait for Johan to name the release. The `core.sandbox` canary on dev02 is still open.

## What happens next

Signing, promotion to `main` and any public announcement stay with Johan and the release manager. Nothing here has been signed or packed.
