# Tec-Tac Framework 1.17.95

Date: 30 October 2026. Audit rows for a person who reaches a module through another module. Core now writes the `run` and `deny` row with the real person as actor when a verified module calls a provider such as Endpoint Comms. Core modules can also write deny rows. Two held findings of the 1.17.94 review are closed.

Closes the requests "accept a verified-caller person as audit actor for a capability call" (endpoint-comms 0.5.1, AD-54 eighth amendment) and "audit.record deny rows for a core module" (nats-comms 0.1.2, endpoint-comms 0.2.0, AD-34 amendment of 29 October 2026) in `reviews/requests/core.md`.

## What changed and why

1. **Verified module caller (AD-54 eighth amendment, AD-31, AD-34).** A person using WAPM holds WAPM's permissions, not Endpoint Comms's. Until now Core refused the `run` row Endpoint Comms wrote for that person. Core now accepts it, and Core itself proves who called. `audit._verified_caller_actor_allowed` is tried after the declared-owner rule and the deny rule, and any doubt is a refusal. All must hold:
   * the actor is a signed-in person, not an installer user and not a service or device actor; the provider is an enabled, signed, non-legacy extension and not Core;
   * the action is exactly `run` or `deny`;
   * the provider opted in: a capability it registered sets `allowed_callers` and `audit_person_for_allowed_callers: true` (read by the new `capabilities.provider_audit_callers`, a registry read with no plugin scan);
   * Core walks the call stack with the new private `caller_identity.core_provider_second_caller`. It skips Core's audit frames, then the provider's own frames at any depth, and takes the next frame. That must be an installed, enabled, non-legacy module on the list. A Core, library, Django, Celery or generated frame, the provider itself, a disabled or legacy module and any read fault refuse;
   * the person is proved by a real Django request (or a DRF request around one) with a Tec-Tac session whose user is the actor; or, with no request, by the `VerifiedSchedulerRun` that `verify_run_context` returned (the new optional keyword `verified_run`), for a run of the calling module that is still running and whose owner is the actor.
   The row gets `debug_info.actor_authority = verified-module-caller` and `debug_info.actor_via_module_id = <calling module>`. A caller cannot supply either. The row keeps `actor_kind` human, the username, and the request's IP, session and correlation id.
2. **Registry of verified runs.** `scheduler_run_context` keeps a weak identity registry of the `VerifiedSchedulerRun` objects it returned, as it already does for issued contexts. A hand-built or copied run is refused. Two small reads: `is_core_verified_run` and `verified_run_still_running` (one fresh status read).
3. **Deny rows from a core module (AD-34 amendment, Johan, 29 October 2026).** `audit._server_module_deny_allowed` is now `_module_deny_allowed` (the old name stays as an alias) and accepts category `server` or `core`. Everything else of the AD-34 condition stays: signed-in person, not an installer user, action exactly `deny`, and Core verifies the caller of `audit.record` is that same module. Module `core`, premium, test and empty categories stay refused. The row keeps the marker `server-module-deny`, so exports stay valid.
4. **Endpoint transport owner, held Medium and Low of the 1.17.94 review.** Before any owner is registered in a process, `nats-comms` is now refused at `request`, `send_many` and `presence` while `endpoint-comms` is installed and enabled. The fact is read from a short cache (3 seconds). A failed read is kept 1 second and counts as "installed" (fail closed). `register_owner` still answers with its reason text. The except branch of `_verified_owner_id` now returns `None`, not `False`. Behaviour of `endpoint-comms` alone, `nats-comms` alone and a registered owner is unchanged.
5. **Text.** The `audit.record` contract entry (the export reads it), `docs/module-audit.md` (new section "Verified module caller (1.17.95)", the deny section widened), `docs/caller-identity.md` (the second-caller walk is private) and `docs/endpoint-transport.md`.

## Module-facing changes

* **New optional keyword `verified_run` on `audit.record`** (and so on the audit provider's `record`). Needs framework `>=1.17.95`. A module that does not pass it behaves as before.
* **New capability metadata keys** `allowed_callers` (a list of module ids; already used by Patch Management and WAPM) and `audit_person_for_allowed_callers: true`. Core reads `allowed_callers` for audit **only** when the flag is set on the same capability, so Patch Management (`allowed_callers: [maintenance]` and `[groups]`) is not widened. Endpoint Comms 0.5.1 publishes its list under the key `callers`, which Core does not read, so nothing changes for it until Endpoint Comms 0.5.2 adds the two keys.
* **Deny rows from a core-category module** now persist for a signed-in person who holds none of the module's permissions. Before, they raised `AuditContractError`, which the module's wrapper logged as `recorded=False`. No module needs a change. Affected core modules: endpoint-comms, nats-comms, agents, alerts, checks, endpoints, software, tasks, automation, groups, patching, maintenance, globalsettings.
* `endpoint-comms` can now drop its `endpoint-comms.run` and `endpoint-comms.view` check for WAPM and the other listed callers (request in `reviews/requests/core-modules.md`). WAPM keeps its own check (`wapm.view`, `wapm.manage`) before every call and passes the real request or the issued run context.
* Every existing `audit.record` and `AuditProvider.record` call keeps its signature and its behaviour. `core.endpoint_transport` stays 1.0.0.

Decisions taken (information, no answer needed): see `reviews/questions/core.md`, "Audit actor for verified module callers, Core 1.17.95".

## Tests

* New: `tests/audit-verified-caller-actor-1.17.95.py` (accepted and refused cases of the person and run-owner paths, markers, unchanged paths, docs and contract text), `tests/caller-identity-second-caller-1.17.95.py` (the real stack walk with temporary module folders, and `provider_audit_callers` on the real capabilities module), `tests/audit-core-module-deny-1.17.95.py`, `tests/endpoint-transport-owner-precheck-1.17.95.py`.
* Changed: `tests/audit-server-module-deny-1.17.30.py` asserted that category `core` is refused. It now asserts premium is refused and core is accepted. No other assertion changed.
* The 1.17.94 release note moved to `docs/releases/`.

## Not done here

* Endpoint Comms does not use the rule yet. Until 0.5.2 it keeps its permission check and writes what it writes today.
* The public contract for 1.17.94 and 1.17.95 needs exporting into `docs/contracts` on a running dev server after install. Claude cannot export it (request in `reviews/requests/core.md`).
* Django is not installed on the development PC. The tests use stubs and a fake `django.http.HttpRequest`; the real `HttpRequest` and DRF `Request` check is the same code `tactical_operations` already uses and is exercised on the dev server.
* Other held items stay open: queueing `wapm.*` frames in `send_many`, at-least-once hand-over of a large agent event, and the Low findings of 1.17.93.
