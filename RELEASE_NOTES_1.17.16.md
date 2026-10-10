# Tec-Tac Framework 1.17.16

This release gives modules the Core calls they have been waiting on, and fixes two held findings. Everything for modules is additive: a module that changes nothing keeps working. Modules can now ask Core to serve their URLs, share one correlation id across a request or a job, tell a user when a job finishes, and start a one-off Scheduler run for a user. Core now checks harder that `run_tactical_operation` gets a real signed-in request.

Closes, in `reviews/requests/core.md`: every "Module route mounting" entry; the correlation id entries of patching 0.3.0, 0.4.0 fix rounds 1, 7 and 8; both caller before-value entries; the notice entries; the one-off run entries (cyberhoot 0.8.0, patching round 3 and 8); the owned-schedule read (cyberhoot 0.8.0, scoutdns 0.2.0); and the `description` entry (patching round 7). The browser-carried correlation id from patching 0.3.0 is answered by design: a browser never supplies a correlation id, and patching 0.4.0 runs those calls from backend routes. Also closes the held Medium from the 1.17.7 review (the Python `run` trusted any object's `.user`) and the held Medium from the 1.17.15 review (a confirmed uninstall that left a replaced module off wrote no completion audit row).

Capability `core.tactical_operations` goes from 1.2.0 to 1.3.0. It is still major 1.

## Module-facing changes

Modules that use any of these need `requires.framework >=1.17.16`.

| What | Where | Needs a module change? |
|---|---|---|
| Manifest key `routes` `{prefix, urlconf}` and `tec_tac.route_mounting.mounted_routes()` | `docs/module-routes.md` | No. The old append keeps working. |
| Manifest key `description` | `docs/module-routes.md` | No. |
| `run_tactical_operation(..., correlation_id=, audit_before=)` | `docs/tactical-operations.md` | No. Both are optional keywords. |
| `run_tactical_operation` needs a real request with the Core session proof | `docs/tactical-operations.md` | Only for a module's own stub tests. |
| `audit.request_correlation_id(request)` and the Core-set `tec_tac_request_id` | `docs/module-audit.md` | No. |
| `tec_tac.notices.publish(...)` | `docs/module-interoperability.md` | No. |
| `scheduler.start_one_off_run`, `get_one_off_run`, `get_owned_schedule`, `SchedulerNotAllowed` | `docs/scheduler.md`, `docs/module-scheduling.md` | No. |
| Six new keys in the Scheduler handler context | `docs/scheduler.md` | No. Handlers that ignore them are unaffected. |

## What changed

### Core serves a module's URLs from its manifest (CQ47)

A module adds one key to `tec_tac.json`:

```json
"routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}
```

Core then serves the urlconf at `/api/tfd/windows-patching/`. The module no longer appends to `tacticalrmm.urls` or `tec_tac.urls` from its own `AppConfig.ready()`. The URL shape does not change.

- `prefix` is one lowercase slug and defaults to the module id. It may differ from the id.
- `urlconf` must sit inside one of the module's own `django_apps` packages. It can never point into `tacticalrmm`, `tec_tac` or another module. Extensions only: a reportset is refused. A bad key is refused when the package is inspected for install, not at the next start-up.
- Core mounts after every `AppConfig.ready()` has run, so a module's urls are never imported before its own `ready()`.
- Core mounts only modules that are loaded. A disabled module, and a replacement Core dropped because it was enabled next to the module it replaces (AD-20), are not mounted.
- Each module is mounted on its own. A urlconf that cannot be imported is logged and skipped. Nothing else is affected, and Tactical still starts.
- Core's own routes come first, so they always win. A module prefix may share a first segment with a Core route. The `audit` module's prefix and Core's `audit/record/` is the example.
- Two loaded modules asking for the same prefix: the first by sorted module id is mounted, the second is refused with a warning.
- Compatibility path, with no end date: a module that still appends to `tec_tac.urls` (licensing, serverhealth, tacticalupdater, scriptmanager, globalsettings, patching, sentinelone) or to `tacticalrmm.urls` (the others) is untouched. Core skips a prefix that is already appended. A module that adds `routes` and forgets to drop its append still works.
- `tec_tac.route_mounting.mounted_routes()` reports `{prefix, module, state, reason}` with `state` `mounted`, `compat` or `refused`. The contract export lists the key and the function. It does not list a mounted module's routes: they are the module's contract.
- No migration.

### `description` is an accepted manifest key

A plain string of 1 to 500 characters with no control characters. Extensions and reportsets may both declare it. No module has to. It shows as `description` on the module catalogue rows, the package inspect preview and the runtime module rows, and is `null` when absent. Module standard section 1 can now ask for it.

### One correlation id for a request or a job (CQ48)

- `run_tactical_operation(..., correlation_id="job-42")` writes that id on every Core row of the call: success, deny and outcome-unknown. It is 1 to 128 characters of letters, digits and `. _ : -`. A bad value gives HTTP 400, `invalid_correlation_id`.
- Core has no middleware entry of its own, and adding one would mean editing Tactical's tracked settings. So the first audit row of a request makes an id and keeps it on the request as `tec_tac_request_id`. Every later row of that request shares it.
- `audit.request_correlation_id(request)` returns that id, so a module backend can stamp its own parent row with it. A backend that works across requests passes its own id instead. An explicit id wins and never replaces the request id.
- Core sets it. A browser header is never read, and the audit endpoints still refuse a `correlation_id` field. The HTTP view for Tactical operations still accepts only `params`, `body` and `query`.
- Docs fix: `docs/module-audit.md` said the id came from `X-Request-ID` and `X-Correlation-ID` headers. It never did. The text now says so.

### A before value from the caller (CQ51)

Some routes have no `GET` to read the old value from. `run_tactical_operation(..., audit_before={...})` lets the caller assert it: a flat dict of at most 16 fields, each text (up to 256 characters), a whole number, true/false or null. A name that looks like a secret, a nested value, a float or an oversize value gives HTTP 400, `invalid_audit_before`.

Core uses it only when the operation declares no `audit.before` read. Tactical's own read wins when both exist. The row says `before_source: caller` or `before_source: tactical`, so a reviewer can tell an asserted value from a read one. It is on the success row only. It is Python only.

The audit object id from a `{pk}` path parameter (`audit.object_param`) and the before read (`audit.before`) shipped in 1.17.13 and 1.17.14. Report Manager 0.5.0 has not adopted `object_param` yet (the request is in `core-modules.md`). A new test locks the Report Manager shape.

### A real request for `run_tactical_operation` (held Medium, 1.17.7 review)

AD-19 condition 2 says Core never substitutes another user. The Python `run` took any object with a `.user`. It now accepts only a Django `HttpRequest`, or a DRF `Request` that wraps one, whose user is authenticated and which carries `tec_tac_session` (set by Core's `SessionAuthenticated` guard). Anything else gets HTTP 401, `authenticated_request_required`, and no audit row.

Real callers are unaffected: Patching and Script Execution call it from `SessionAuthenticated` views, and the Core HTTP route is the same. A module that has its own stub tests must pass an `HttpRequest` that carries `tec_tac_session`. The shared Core test stub shows how. Core's tests were updated the same way.

### Notices from a module backend (CQ49)

`tec_tac.notices.publish(user, client_id, level, message, action=None, *, module_id)` stores one notice for one user. It needs no request, so a backend route or a Scheduler handler can call it.

- The user must be active and interactive: not an installer user, no agent link, not blocked from the dashboard.
- `module_id` must be an installed, enabled extension, never `core` or `tec-tac`. It becomes the notice source. It is a claimed id: Core does not yet verify which module is calling, so until the verified caller identity request ships a module could name another enabled module. This is stated in the contract.
- The text goes through the existing checks (1000 characters, an internal route that starts with `/`, never a URL or `javascript:`).
- `client_id` is required. Core stores `<module_id>:<client_id>` as the key. A notice is stored once per user and key, and one the person has read is never reset.
- Not exposed over HTTP. No model change.

### Start a one-off run for a user, and read an owned schedule (CQ50, AD-13)

`scheduler.start_one_off_run(user=, owner_module=, action_id=, targets=, parameters=, name=)` starts one run of the module's own registered action for a user and returns the queued run. `scheduler.get_one_off_run(run_id, owner_module=)` reads its state.

- The user must be active and not an installer user, hold the action now, and hold the targets' scope. An action with no permission is startable only by scheduler managers, as in the browser. A user who may not gets `SchedulerNotAllowed`.
- Core makes one disabled `once` schedule owned by the module, with `owner_key` `one-off:<uuid>` and `created_by` the user. The ticker never dispatches it. The Scheduler page shows it as managed by the module. The existing once-retention cleanup removes it after 48 hours by default. The run history stays.
- Just before the handler runs, Core checks again that the user is still active and still holds the action and scope (AD-13 condition 2). If not, the run ends `skipped` with a plain reason and an audit row, and the handler never runs. A check that cannot be made counts as a refusal and never raises into Celery.
- Core writes one best-effort audit row when the run starts.
- The handler context gains `owner_type`, `owner_module`, `owner_key`, `owner_user_id`, `owner_username` and `one_off`. The user fields are set only for a one-off run and a user-owned schedule.
- This is the start-and-track call only. It is not the AD-13 system-action contract (registered Tactical actions running in-process as the owner), which is still open.

`scheduler.get_owned_schedule(owner_module, owner_key)` returns `{enabled, schedule_type, next_run_at, last_run_at, last_run_status, last_run_finished_at}`, or `None`. It does not expose the model.

No migration: all of this uses existing fields.

### Fixed: a confirmed uninstall that leaves a replaced module off now writes its audit row (held Medium, 1.17.15 review)

When an uninstall of an enabled replacement could not hand the replaced module back, and the person confirmed, the job left the module off but wrote no completion row. It now writes one: "Replacement X was uninstalled. The module it replaces, Y, stayed off because it cannot be enabled." The metadata keys are the same as for a disable. `docs/module-replacement.md` now describes the uninstall hand-back.

## Checks that ran here

- `bash tests/release-integrity.sh`, and every test named `*1.17.16*` that can run without Django.
- The earlier Tactical operation, audit, scheduler, notice, module and contract tests, run after the change.
- `python -m py_compile` on every changed file, and `ruff check` with the repo's configuration.

## What could not run here

Django, Celery and Tactical are not installed on the development PC. The stub tests run. These do not, and need the dev server (each script says how to run it):

- `tests/module-route-mount-runtime-1.17.16.py` (the real URL resolver and a real start-up).
- `tests/notices-publish-runtime-1.17.16.py` (real notice rows).
- `tests/scheduler-one-off-run-runtime-1.17.16.py` (real schedule and run rows, the real task body, the AD-13 re-check).

The earlier runtime scripts for Tactical operations (`tests/tactical-operations-runtime-1.17.7.py` and `-1.17.13.py`) were updated to carry the session proof and also need the dev server.

## Not in this release

- The AD-13 system-action contract, the conditional scope and per-call audit action (patching 0.3.0), a scope check on the agent of a loaded row (patching 0.4.0), secret storage, the role scope descriptor, `permissions_any`, the nested scope source, the streamed file answer, the larger body cap for template import, two audit actions on one route, `audit.count_fields`, naming the missing flag in the 403, a verified caller identity, API keys and SSO admin, and the production gate (AD-21 condition 6) all stay open in `reviews/requests/core.md`.
- Module adoption. Each module switches in its own release. The requests are in `core-modules.md` and `premium-modules.md`.
- The module validator under `pipeline/` may refuse the new manifest keys `routes` and `description` until it learns them. Core does not touch `pipeline/`.
