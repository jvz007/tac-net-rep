# Tec-Tac Framework 1.17.10

Core now checks what a module registers at run time against what its manifest declares, so a replacement that publishes the wrong version of a capability is refused instead of quietly accepted. The browser contract also gains the two rows for the UI 0.12.87 helpers.

Closes: the held Medium from the 1.17.9 review (AD-20 parity was checked against manifests only), and the "Browser contract rows for the UI 0.12.87 helpers" entry in `reviews/requests/core.md`.

## What changed

- **A core module registers what it declares.** When a core module's manifest has a `capabilities` key, `register_capability` registers only those ids. Any other id under its prefix is refused. A core module with no `capabilities` key is unchanged, and so are Core's own ids (`tec-tac`, `core`). If Core cannot read module state, the registration goes through, because the enable and install checks already cover the manifest side.
- **A replacement registers at the declared version.** An honoured replacement that registers a replaced module's id must use the declared major version, with a minor.patch that is not lower. The check shares one rule with the parity check (`module_replacement.version_within_declared`), so the two cannot drift apart.
- **A refusal never stops start-up.** Following the 1.17.9-1 rule, Core logs one warning per module and id, registers nothing and returns normally. It never raises out of `AppConfig.ready()`. The name stays `capability-unavailable`.
- **The refusal is visible.** `replacement_status` gains `registered_mismatch`, a list of `{capability, declared, registered, reason}` with the existing codes `capability-major-mismatch` and `capability-version-lower`. `degraded` is true while the list is not empty. The list lives in the running process and clears on restart, or when a correct registration follows.
- **Browser contract rows.** New `ui.authenticated.tactical-operation` (`tacticalOperation`) and `ui.authenticated.tactical-permissions` (`hasTacticalPermission`). The first states exactly what Core checks (the operation is declared by the module id in the URL, the user holds the Tactical permission and role scope, and the route is owned) and that Core cannot tell which module's browser code made the call. It states the scoping rule as the contract: a module passes its own id, except for the AD-20 core module it replaces. It also says plainly that UI 0.12.87 does not enforce that rule yet. The `ui.authenticated.runtime-context` row gains the `tactical_permissions` rule (`can_*` keys, strict booleans, anything else dropped, a missing value becomes an empty map).
- **Docs.** `docs/module-replacement.md`, `docs/capabilities.md` and `docs/tactical-operations.md` (a "Browser helpers" pointer). One new rule in the contract catalog.

Not included: checking a core module's registered version against its own declared version. It needs a decision on what a lower or higher version should do for a core module, so it waits for a later release.

## Module-facing changes

- **New runtime rule.** A core module that declares `capabilities` in `tec_tac.json` must register exactly those ids. Anything else is logged and not registered. A core module without the key is unaffected. Correction (1.17.11): the original sentence here said no manifest declares the key. That was wrong. Endpoints (`modules/endpoints/package/extensions/endpoints/tec_tac.json`) declares `"capabilities": {}` on a core module, so under this rule no capability id can be registered by Endpoints. That is harmless today because Endpoints registers none. Windows Patching and Advanced Patch Management do not declare the key yet, so nothing else changes for an installed module until they add theirs.
- **New replacement rule.** A replacement must register a replaced capability at the declared major version with a minor.patch that is not lower. Anything else is logged and not registered.
- **New status field.** `replacement_status(...)` and the `replacement` object on `GET /api/tfd/modules/v2/` rows carry `registered_mismatch` (a list, empty when all is well). Additive.
- **Documentation only.** The two browser contract rows and the runtime-context rule describe the UI 0.12.87 contract. No HTTP contract, executor or permission changed.

## Tests

- New: `tests/module-replacement-registration-1.17.10.py`, `tests/browser-contract-ui-helpers-1.17.10.py`.
- Re-run and unchanged: the three 1.17.9 replacement tests, `tests/browser-contract-runtime-surface-1.17.2.py`, `tests/tactical-permission-context-1.17.7.py`.
- Not run here: Django and Tactical are not installed on this PC, so the dev-server behaviour is untested.

## Fixed after review (precheck)

- The replacement version check failed open. A replacement that registered a capability as "2", "2.0" or "2.0.0-1" while its manifest declared 1.2.0 raised inside the check, the error was swallowed, and the capability was accepted at the wrong major. `module_replacement._parse_version` now uses `module_state.Version.parse(...).core()`, the same parser capability registration uses. A registered version that cannot be read is refused and recorded in `registered_mismatch` as `capability-major-mismatch`.
- Test: `tests/module-replacement-registration-1.17.10.py` covers "2", "2.0", "2.0.0-1", an unparsable value, and a "1.2.0-1" rebuild suffix that stays accepted.
- Module-facing: no contract change. Only invalid or mismatched replacement registrations are now refused.
