# Tec-Tac Framework 1.16.0

## Audit trail for permissionless UI modules

Take Control and Remote Background have no permission groups, so Core refused every browser audit event they posted. This release gives them a safe way to keep an audit trail. It closes board questions Q31 and Q32.

A permissionless extension can now declare the browser events it posts in an optional `tec_tac.json` key:

```json
"audit_events": [{ "object_type": "agent", "actions": ["view", "run"] }]
```

### What changed

- **Manifest.** `audit_events` is a new supported key. Entries take only `object_type` (`client`, `site` or `agent`) and `actions` (standard actions or `custom:<slug>`). Core rejects unknown keys, a repeated `object_type`, empty or repeated actions, more than 20 entries or 20 actions, and a reportset that declares the key. `PluginSpec.audit_events` is added after `legacy`, so nothing positional changes.
- **Browser path.** `POST /api/tfd/audit/record/` keeps every existing step. When the permissioned check says no, the new `audit.declared_browser_event(...)` decides. It accepts only an enabled, installed, non-legacy module with no permission groups that declares that exact `object_type` and `action`. Everything else is HTTP 403 and writes nothing.
- **Scope.** On the declared path `object_id` is required. Core resolves the object through `core.resources` with the signed-in user's scope. Missing or out-of-scope gives 404 with one message, so existence is not leaked. A role without Tactical's `can_list_*` permission gives 403. The module's event is not recorded in either case.
- **Deny row.** For a 404 or 403 Core writes one Core-owned `deny` row: the signed-in user, the module id, the declared object type and id, a fixed Core message with none of the module's text, and `refused_action` and `reason` in `metadata`. It is non-strict, so a refusal never turns into a 500. (Assumption for board Q34.)
- **Record.** In scope, Core records the event with the actor, module id, version, source and correlation id under Core control. Every row carries `debug_info.operation_context.browser_provenance = "module-declared-event"`. The response is 201, or 202 if Tactical's AuditLog write failed.
- **Rate limit.** Unchanged: 60 a minute and 1 000 a day for each user and IP. Refused requests and deny rows count.
- **Public contract.** `/api/tfd/audit/record/` now has a full HTTP contract entry. The `ui.authenticated.audit` purpose and the rules list describe the new key. `rbac.permission_catalog` and the Module Manager rows carry `audit_events`, and the exported contract lists them under "Extension permissions".
- **Docs.** `docs/module-audit.md` has a new section and corrected security rules. `docs/developer-contracts.md` points to it.

### Audit size fix (backlog core-1.15.179)

`record()` measured module `metadata` and `operation_context` against the size limit one by one, so together they could exceed it and Tactical would replace the whole `debug_info`, wiping Core's provenance. `record()` now measures the whole `debug_info`. If it is too big, module `metadata` is replaced with the existing "value too large" marker first, then `operation_context`. The Core keys are never dropped and the `browser_provenance` marker is kept. Small input behaves as before.

### Audit hygiene (backlog core-1.15.127 and 1.15.127-1)

- The 403 message now describes what is allowed: a permissioned module, or a permissionless module that declares the event.
- The "no declared permissions" warning is logged once per module per process, not on every UI-context request. It is skipped for a module that declares `audit_events`. The text still says the module has no declared permissions and that browser audit POSTs get HTTP 403.
- `tests/audit-contract-foundation.py` no longer stubs the function under test. The real `can_record_from_browser` and `_resolve_module` run against a registry double.
- `tests/audit-browser-provenance-hardening.py` and the new test now run from `tests/review-hygiene-foundation.sh`. Before this they were only listed in the release manifest and ran nowhere.

## Module-facing changes

- Additive. A module that does not declare `audit_events` behaves exactly as before (403), including Endpoints. Permissioned modules take the untouched path.
- Core older than 1.16.0 rejects the unknown manifest key. A module that declares `audit_events` must set `requires.framework` to `>=1.16.0`.
- Sol's module validator reads `SUPPORTED_KEYS` from Core's `registry.py`, so it accepts the key once Core 1.16.0 is in `repos/core`.
- Next module work: Take Control 0.1.6 and Remote Background 0.2.0 each need an `audit_events` declaration and a rebuild.

## For Johan

- Q34 (deny row for refused attempts), Q35 (only client, site and agent objects) and Q36 (the browser cannot prove the module's code sent the event) are on the board with the assumptions used.
- After signing, please export a fresh public contract into `docs/contracts`.

No UI changes are required. UI 0.12.80 already posts `module_id` with each event and does not gate on permissions.

## Tests

- New: `tests/audit-declared-browser-events-1.16.0.py`.
- Updated: `tests/audit-browser-provenance-hardening.py`, `tests/audit-contract-foundation.py`, `tests/review-hygiene-foundation.sh`.
