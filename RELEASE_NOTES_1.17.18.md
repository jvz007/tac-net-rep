# Tec-Tac Framework 1.17.18

This release fixes the package intake problem Johan reported, and gives core modules the Tactical operation rules they have been waiting on. Everything for modules is additive. A module that changes nothing keeps working.

**For people who install modules.** You can now upload several modules together with their signature files. Core pairs each package with its own signature and release file, so signed modules keep their trust state. Before this, Core refused with "Only one detached signature can accompany an uploaded package." Installing a module that is switched off now stops at the start with a plain reason, instead of failing half way.

Capabilities: `core.tactical_operations` goes from 1.3.0 to 1.4.0. It is still major 1.

## Closes

In `reviews/requests/core.md`:

- Retry settings on a one-off run (patching 0.6.0, certificatemanagement 0.3.0 fix round 1). This ends the AD-22 worker exception.
- The scope source for the row a path id loads (patching 0.4.0 fix round 1, tasks 0.2.0) and the scope entries that follow from it (automation 0.6.0, checks 0.12.0, agents 0.4.0).
- The unrestricted-scope rule (automation 0.6.0 run-task, agent-management 0.12.0 bulk recovery).
- List-valued and more `audit.before` fields (alerts 0.7.0, automation 0.6.0), the length-only count (software 0.1.0 fix round 7, before side only) and the list-GET read (agent-management 0.12.0, reportmanager 0.5.1).
- More than one operation on one route (agents 0.5.0, checks 0.12.0; alerts 0.7.0 gets the audit-verb part only through a body selector, see "Still open").
- Audit path parameters (take-control 0.2.0, remote-background 0.3.0 item c).
- The route owner rows for `agents/{id}/tasks/` and `agents/{id}/checks/` (tasks 0.2.0, checks 0.12.0).
- Refuse a disabled module up front (the patching 0.6.0 install on the dev server, Johan CQ59).
- The browser contract rows for UI 0.12.93 (`endpoint.grid-columns`, `tacticalScope()`). This also closes the held Low "New browser operations are ahead of Core's contract row".

It also closes the held Medium and the held Low from the 1.17.17 review (see "Held findings").

Johan's chat items of 11 October 2026: item 1 (several modules with their signature files) is fixed here. Item 2 (the alerts popup is covered by items on the page) is not Core work. It is written to `reviews/requests/ui.md`.

## Module-facing changes

Modules that use any of these need `requires.framework >=1.17.18`. Nothing existing changed. Every module under `modules/` that declares operations (agent-management, agents, alerts, automation, checks, globalsettings, licensing, patching, remote-background, reportmanager, scriptexecution, scriptmanager, software, take-control and tasks) was loaded as data and registers exactly as before: 96 declarations of 13 modules in `tests/tactical-operations-modules-compat-1.17.18.py`, and every Tactical route they declare is judged the same by the owner table in `tests/tactical-operation-route-owners-1.17.18.py`. Only patching calls `start_one_off_run`.

| What | Where | Needs a module change? |
|---|---|---|
| `start_one_off_run(..., retry_count=0, retry_delay_seconds=60)`: keyword-only, 0 to 10 and 1 to 86400. The worker retries on `SchedulerTransientError` and re-checks the owner on every attempt. | `docs/scheduler.md`, `docs/module-scheduling.md` | No. A call without them behaves as before. |
| `register_tactical_operation(caller_scope="unrestricted")`. A limited caller gets 403 `scope_unrestricted_required` and a deny row. | `docs/tactical-operations.md` | No. Automation and Agent Management declare it in their own releases. |
| Scope entries: `optional: true`, the type `agent_pk`, and `row_lookup`. New `tactical_operations.register_tactical_row_lookup(module_id, lookup_id, fn)`. A row with no agent is allowed to anyone who holds the Tactical flag (CQ57). | `docs/tactical-operations.md` | No. |
| `audit.before`: list values, `count_fields`, `select`, up to 32 fields. | `docs/tactical-operations.md` | No. |
| `body_selector`: several operations on one route inside the owning module when the bodies are provably exclusive. New refusal code `body_selector_mismatch` (400). | `docs/tactical-operations.md` | No. |
| `audit.params`: named path parameters copied into the row's after value. | `docs/tactical-operations.md` | No. |
| Route owner rows: `agents/{}/tasks/` is Tasks', `agents/{}/checks/` is Checks'. | `docs/tactical-operations.md` | No module declares them today. |
| `POST /api/tfd/modules/v2/packages/inspect/` also takes the repeated fields `signatures` and `metadata_files`. | `docs/trusted-publisher-verification.md` | The UI sends them in a later release. |
| The installer, the Module Manager and the job helpers refuse a disabled module with one plain sentence. | `docs/module-replacement.md` | No. |
| Three browser contract rows: `ui.authenticated.resource-views`, `ui.authenticated.runtime-context` and the new `ui.authenticated.tactical-scope`. | the exported contract | No. |

## What changed

### Several packages with their signature files (Johan, 11 October 2026)

Core refused every signature file when more than one package came in, and staged the packages with no signature at all. Now the inspect endpoint takes the repeated fields `signatures` and `metadata_files`, next to the old single `signature` and `metadata` fields, which still work for one package.

Core pairs from the release metadata and never by guessing. `filename` in the metadata must equal an uploaded package name, and `signature` must equal an uploaded signature name. These are the same two names Core already checks when it verifies a release. `stage_multiple_packages(uploads, signatures=None, metadata_files=None)` stages each package with its own signature and metadata. Bundles are paired the same way. The bootstrap command still calls it with one argument.

A package with neither file stays unsigned and follows the normal unsigned policy. Core refuses with a plain message that names the file when:

- a metadata file matches no uploaded package. A browser-renamed copy such as `name (1).zip` does not match. The message says to rename it back.
- a metadata file names a signature that was not uploaded;
- a signature belongs to no metadata file;
- two metadata files arrive for one package; or
- two uploaded packages or signatures share a name.

When any pairing fails, nothing is staged. Core still verifies trust for each package when it is staged and again when the batch install is queued.

The browser has its own check that blocks several signatures before Core is called. That is Core UI work, and it is in `reviews/requests/ui.md`.

### Retry settings on a one-off run

`start_one_off_run` takes `retry_count` (0 to 10, default 0) and `retry_delay_seconds` (1 to 86400, default 60). A handler can raise `SchedulerTransientError` to say "check again in a minute" without holding a worker. Core stores the settings on the one-off schedule and copies them onto the run. The worker already retries from the run's copy. Core re-checked how it does that: the owner check runs before the handler on every attempt (a permission lost between attempts ends the run `skipped`), and the countdown is the run's own delay. No change to `tasks.py` was needed. A bool, a text or a float, or a value out of range, raises `SchedulerError` before anything is created.

### Only for a caller with no client or site limits

An operation declared `caller_scope="unrestricted"` runs only for a caller whose Tactical role has no client or site limits (a superuser, a role superuser, or a role with both lists empty). Core asks `core.resources.scope_unrestricted`, the same answer the UI reads as `tactical_scope.unrestricted`. A limited caller, a caller with no role and a failed lookup are refused 403 `scope_unrestricted_required` with a deny row, and Tactical is never called. The check runs after the Tactical flag and the module permission, and before the body is cleaned. It never applies to a row that belongs to no agent. Johan's question about the refusal code is in `reviews/questions/core.md`. This release uses 403.

### New scope sources

- **Optional entries.** An entry with `optional: true` is resolved only when its body field is present and not null. An empty list is allowed and checks nothing. Client and site entries take lists of ids. One id out of scope refuses the call with 404.
- **Agent numbers.** The type `agent_pk` takes Tactical agent numbers. A new helper, `resources_adapter.agent_pks_in_role_scope`, checks them. `objects_in_role_scope` is unchanged. It still matches only the canonical agent id.
- **Row lookups (CQ56 a).** For a route whose path id loads a row, the owning core module registers a function that says which agent the row belongs to. Core calls it before dispatch. A missing lookup, a lookup that raises, `None` and a wrong answer shape all refuse with 404. A row with an agent is held to the caller's role scope. A row with no agent (a policy task, a policy check, a policy-level patch policy) is allowed to anyone who holds the Tactical flag, and Tactical decides the rest (CQ57). Core never reads Tactical's models (CQ56 b was refused). The lookup runs before dispatch, so a row can change between the lookup and Tactical's own load. That race is small and accepted. The audit row records the object id from the path and the metadata `scope_source: row_lookup` and `agentless`.

### Better before values in the audit row

- A declared before field that holds a list of whole numbers or short strings is recorded as a list, with `<field>_count`, and `<field>_truncated` when Core cut it (1000 entries, 64 KiB of text). A list of objects is never recorded. The field limit goes from 16 to 32.
- `count_fields` records only the length of a list, as `<field>_count`. Software's package list needs it. Only the before side ships. The after side needs a second Tactical read after every call, so it is a question for Johan.
- `select` is for a route with no single-row GET, such as `agents/deployments/`. Core reads the list GET in this process as the signed-in user and picks the row whose key equals the path parameter Core already cleaned. It never uses anything the browser sends. A paginated answer is read, the first 1000 rows are scanned, and a miss records `before: unavailable` without blocking the call.

### Several operations on one route

The owning module can declare more than one operation on one Tactical route when each carries a `body_selector` and every pair is provably exclusive (CQ60). For example, Checks can declare "add an endpoint check" (the body has `agent`) and "add a policy check" (the body has no `agent` and has `policy`) on `POST checks/`. A different module is still refused, so AD-6 stands for modules. At run time a body that does not fit the operation's own selector is refused 400 `body_selector_mismatch`, so a call can never run under the wrong operation's scope or audit verb. The wording of AD-6 condition 4 for this reading is for the main session to record from Johan's answer. This release does not edit `docs/review-accepted-decisions.md`.

### Path parameters in the audit row

`audit.params` names up to 8 path parameters. Core copies their cleaned values into the row's after value. Take Control can record the port of a Web VNC call, and Remote Background the pid of an end-process call.

### Route owner table

`agents/{id}/tasks/` belongs to Tasks and `agents/{id}/checks/` belongs to Checks. Neither module declares those routes, because Tactical's POST on them fails. This records the home.

### A disabled module is refused up front (CQ59)

`tec_tac.module_replacement.disabled_install_refusal(module_id)` reads the module state and the live model. For a module that is disabled because its replacement is honoured, it says:

> Windows Patching is disabled because Advanced Patch Management replaces it. Disable Advanced Patch Management and enable Windows Patching, then install again.

For any other reason it says "<Module> is disabled. Enable it, then install again." `scripts/install-extension.sh` calls it right after discovery and the already-installed check, before anything is copied or backed up, in a fresh install and in `--replace`. It prints `[TEC-TAC] ERROR: <message>` and exits. The Module Manager's install and batch install calls refuse with a plain 400 before any job is queued, and the two job helpers show the sentence as the job error. Enable, disable and hand-back are unchanged.

### Browser contract rows for UI 0.12.93

`ui.authenticated.resource-views` lists `gridColumns` and `loadGridColumns` and the placement `endpoint.grid-columns`. `ui.authenticated.runtime-context` lists the four `tactical_scope` fields. The new row `ui.authenticated.tactical-scope` documents `tacticalScope()`. The wording was checked against the UI source. The exported `docs/contracts` file is produced by the pipeline and was not edited.

## Held findings

- **Medium (1.17.17): module unregistration deleted an administrator's hand-registered server-maintenance actions.** `--unregister-module` and the stale-action sweep of `--register-module` now delete only registry files whose `registered_by` is `module-manifest`. A hand registration stays, even with `owner_module` set and even when protected. `tests/server-maintenance-module-actions-1.17.17.py` had an assertion that the old behaviour removed such a file. It now asserts the new rule.
- **Low (1.17.17): the hotfix text did not match the code.** The registered copy keeps running after a hotfix, because a hotfix writes only under the module folder and never re-registers. The code is right. The contract text, `docs/server-maintenance-capability.md` and the helper's docstring now say so. The 1.17.17 release notes are kept as they were.

## Still open

Not in this release, and still in `reviews/requests/core.md`: the software refresh count after the call, a per-call audit action and a conditional (per-call) scope for bulk operations (patching 0.3.0, agents 0.4.0, alerts 0.7.0; the selector and optional pieces help but do not answer them), a server-only flag, a GET operation with no audit row, a failed audit row for Tactical's 400, 404 and 409 answers, literal audit object ids, `object_field` for create rows, a bulk correlation id, the declared installer route, naming the missing flag in the 403, remote-background items a, b, d and e, the streamed file answer, the larger body cap, `permissions_any`, user invite and Core mail, API keys and SSO admin, the system-action contract, secret storage and the production gate.

## What could not run on this PC

Django and Tactical are not installed here. The new tests are stub-harness scripts like the existing ones. These parts need the dev server:

- the live install script (`install-extension.sh` as root), including the refusal and the `--replace` path;
- the in-process dispatch of a Tactical view, so the row lookup, the select read and the selector at run time are tested against stubs, not against Tactical;
- the Celery worker retry. The test drives `execute_schedule_run` with a stand-in for `self.retry`;
- the multipart upload through Django's request parser. The test hands Core stand-in upload objects.

## Tests

New, named after the version: `module-intake-multi-signature`, `scheduler-one-off-retry`, `tactical-operations-unrestricted`, `tactical-operations-scope-sources`, `tactical-operations-audit-before-lists`, `tactical-operations-body-selector`, `tactical-operations-audit-params`, `tactical-operation-route-owners`, `tactical-operations-modules-compat`, `installer-disabled-module`, `contract-export` and `server-maintenance-hand-registered`.

Six existing tests changed on purpose. Three assert the capability version, which is now 1.4.0 (`tactical-operations-1.17.7`, `tactical-operations-before-scope-1.17.14`, `audit-correlation-1.17.16`). One checks the version text in the contract export and the docs header (`contract-export-1.17.16`). One checked that 17 before fields are refused, and the limit is now 32 (`tactical-operations-audit-object-1.17.13`). One asserted the old unregister behaviour (`server-maintenance-module-actions-1.17.17`).
