# Tec-Tac Core 1.15.113

## Scope

This release follows the agreed **1 Medium + 5 Low** cadence and contains only:

- **M15** - hotfix publisher-permission enforcement
- **L31** - module repository proxy support
- **L32** - controlled invalid repository-port validation
- **L33** - staged hotfix ZIP cleanup
- **L34** - Tactical Python syntax validation for hotfixes
- **L60** - metadata-only capability availability semantics

## Fixed

### M15 - target module publisher permissions are mandatory for hotfixes

The root-owned hotfix verifier now authenticates the exact hotfix bytes with the base `module.install` permission, derives the hotfix target module from the authenticated package, reads the installed root-owned extension manifest, and then requires every `publisher_permissions` entry declared by that target module. An unsigned hotfix cannot target a module that declares additional publisher permissions.

### L31 - repository fetches honor service proxy settings

Module repository fetches now honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`. Core still resolves and applies its repository SSRF policy to every destination and redirect before proxy transport is selected. Proxy requests use the already-approved pinned destination address.

### L32 - invalid URL ports fail cleanly

Malformed, zero, or out-of-range repository/proxy ports now raise a stable `ModuleRepositoryError` instead of leaking `urllib.parse.ParseResult.port` `ValueError` exceptions.

### L33 - successful hotfix apply removes staged ZIP

A successful managed hotfix apply now deletes the original staged `<upload-id>.zip` together with the staged signature, release metadata, and stage JSON.

### L34 - hotfix syntax checks use Tactical Python

Python hotfix targets are syntax-checked with the configured Tactical interpreter (`TACTICAL_PYTHON`) under the Tactical service account. The check parses/compiles the source AST without creating `__pycache__` files and no longer uses `/usr/bin/python3`.

### L60 - metadata-only capability discovery is not runtime availability

`capability_status(..., check_health=False)` and metadata-only capability listings no longer report `available:true`. They return `available:false`, `state=health-unchecked`, `health_checked:false`, and do not call provider health callbacks. Runtime resolution remains authoritative and performs live health checks.

## Tests

- `tests/module-hotfix-privilege-boundary.py` now proves a correctly signed hotfix is rejected when the signer lacks the installed target module's additional publisher permission, then accepted after that permission is granted.
- `tests/m15-low-batch.py` exercises proxy selection and transport, invalid repository ports, and Tactical-Python hotfix syntax validation.
- `tests/module-hotfix-foundation.sh` verifies the original staged ZIP is removed after successful apply.
- `tests/capability-foundation.sh` verifies metadata-only discovery does not run health callbacks and does not claim runtime availability.
- Existing hotfix, capability, public-contract, and repository-bundle regressions remain green.
