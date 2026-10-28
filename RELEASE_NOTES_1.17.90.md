# Tec-Tac Framework 1.17.90

Date: 28 October 2026. Closes the Low of the 1.17.89 review, repairs a test that failed before 1.17.89 and adds the endpoint agent transport (capability `core.endpoint_transport` 1.0.0). One data migration (0042), no model change. The transport is additive: no existing contract, route or capability changed.

## What changed and why

1. **A schedule that is not monthly stores no monthly fields on create as well as edit (1.17.89 review, Low).** `_apply_schedule_fields` in `scheduler_views.py` now sets `day_of_month`, `month_week` and `month_weekday` to None whenever the schedule is not monthly. Both `POST` and `PATCH` use it. Before, only `PATCH` cleared them, so a weekly schedule created with `day_of_month=5` kept the 5.
2. **A stale monthly field is not an edit.** An old non-monthly row may still hold one. A second full-scope person who only renamed such a row looked like they had changed `day_of_month`, so the ownership moved to them and an `owner_changed` audit row was written. The edit comparison now reads the three monthly fields as None on a non-monthly schedule, on both sides. One helper (`_changed_edit_fields`) serves the confirmation check and the ownership check. A real timing edit by another person still takes the ownership.
3. **Migration `0042_clear_monthly_fields_non_monthly`.** Sets the three fields to None on every existing non-monthly schedule. Data only. It cannot widen anything: those values were never read for a non-monthly schedule.
4. **`tests/scheduler-legacy-target-regression.py` repaired (it failed before 1.17.89).** The code was right and the test was stale. Since 1.17.68 the manager bypass in `_require_target_scope` reads `if not strict and _native_scheduler_manager(user):`, and the test searched for the older text without `not strict`. Behind that, the test's list of helpers copied out of migration 0015 lacked `_reject_unknown_keys`, which `_legacy_normalize` calls. Both test lines are updated. The order check it makes (bypass before target normalisation) is unchanged and passes.

## Module-facing change

The schedule fix changes no contract, signature or route. The only visible difference: a schedule created or edited as daily, weekly, once or interval always returns `day_of_month`, `month_week` and `month_weekday` as null. The endpoint transport is module-facing and is described under its own heading below.

## Tests

New: `tests/scheduler-monthly-clear-1.17.90.py` (POST weekly with `day_of_month=5` stores None; a rename of a stale weekly row by a second full-scope person leaves `created_by` unchanged and writes no `owner_changed_from`; a real edit still moves the owner; migration 0042 read as source). Changed: `tests/scheduler-legacy-target-regression.py`, `tests/scheduler-compat-1.17.66.py` and `tests/scheduler-ownership-move-1.17.68.py` (they read the moved edit-field code as source).

## Requests

Closes `core: the endpoint transport (plan section 9A)` in `reviews/requests/core.md` once this release is signed and exported to `docs/contracts`. The release-manager closes the entry and names the version. Nothing else in the request file was built here.

## Not run here

Django is not installed on this PC. The runtime tests (`*-runtime-*`, `scheduler-claim-postgres`, `scheduler-unrestricted-scope`) need it and did not run. Migration 0042 was written by hand and not run on a database; `makemigrations --check` was not run (no model change). The view test runs the real `scheduler_views.py` on stubs.

## Fixed after review

The first build of 1.17.90 was rejected before signing (`CORE-FIX-NOTE.md`, ruff F821, 24 undefined names). `tests/scheduler-monthly-clear-1.17.90.py` ran the 1.17.89 harness with `exec()` into its own globals and then used names ruff cannot see. The test now binds every name it uses from the harness dict (`reset`, `post`, `patch`, `BASE`, `must`, `fields`, `Schedule`, `User`, `Granted`, `boss`, with `AUDITS` and `dt` as before). No suppression, no assertion removed. Nothing else in the schedule fix changed. No version was signed or pushed as 1.17.90 before this, so none is skipped.

## Endpoint transport

The endpoint agent is a native client that holds one websocket open to Core. Core owns the connection and its security. The module `nats-comms` owns what the messages mean. Full text: `docs/endpoint-transport.md`.

1. **Identity (`tec_tac.endpoint_transport.authenticate_endpoint_agent`).** The socket is `ws/tfd/endpoint-agent/`. The agent sends `Authorization: Token <Tactical agent token>` and `X-Agent-Id`. Core accepts only when the token is a Tactical agent token, its user is linked to an agent, that agent's id equals `X-Agent-Id` and the user is active. It reads Tactical's own tables only. The compare is constant time. There is no enrolment, no revoke call, no model and no migration: Tactical deleting the agent or issuing a new token is the revoke, caught at the next 10 minute re-check. Every refusal closes 4401 with a reason code in the audit row. Ten failed attempts a minute per address are allowed, the eleventh gets 4429. Only failures count.
2. **The consumer (`endpoint_transport_consumer.py`, loaded on first connection).** One live connection per agent, across processes (the new connection tells the group and the older one closes 4409). `ping` is answered with `pong`, Core pings every 60 seconds and closes after two unanswered pings. Presence is a cache key with a 150 second life. Frames are checked as in plan 7.2 (64 KB, 20 a second). Core never reads `func`. An event goes to the owner's Celery task with `(agent_id, frame)` from a worker thread, one audit row is written, then the `ack` is sent. A reply is routed only to the request delivered to the same connection. The route and the capability are each installed in their own guarded block in `apps.py`, so a fault is logged and Tactical still starts. A fault importing the consumer closes the socket 4503.
3. **The contract `core.endpoint_transport` 1.0.0.** Operations `register_owner`, `request`, `send_many` and `presence`, for `nats-comms` only.
4. **A test-only seed command** `tectac_endpoint_agent_loadseed`, inert unless the Django setting `TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST` is True. No route, no UI.

### Module-facing

* New capability `core.endpoint_transport` 1.0.0. A module that uses it must require framework >=1.17.90. Four new rows in the Core Python contract list (`tec_tac.endpoint_transport`).
* Only the module `nats-comms` may call it. Core verifies the caller from the call stack (`core.caller_identity`), not from the `module_id` argument, which must equal the verified id. Any other caller, Core itself and an unverifiable caller get `{"outcome": "denied"}` from every operation.
* `register_owner(module_id, event_task_path)` returns `{outcome: ok|denied|invalid}`. `event_task_path` is the dotted import path of a Celery task defined inside the `nats-comms` folder. An identical re-registration is accepted. A different path is refused.
* `request(module_id, agent_id, frame, timeout=10)` returns `{outcome: ok|timeout|offline|denied|invalid, reply}`. It is sync, returns within `timeout` + 1 second, and decides `offline` from presence without waiting. `frame.type` must be `request`.
* `send_many(module_id, agent_ids, frame)` returns `{outcome, queued, offline}`. At most 2000 agent ids. `frame.type` must be `event`.
* `presence(module_id, agent_ids)` returns `{outcome, presence: {agent_id: {connected, since}}}`. At most 2000 ids, cache only.
* Nothing existing changed. A grep of `modules/` found no user of `endpoint_transport`, `ws/tfd/endpoint-agent` or `nats-comms`.

### Assumptions (decide, build, record)

* An event Core cannot hand to the owner (nothing registered yet, or the Celery enqueue fails or times out) gets no ack. The agent keeps it and resends after it reconnects. Acking and dropping could lose a person's choice. Fail closed.
* Audit rows for connect, disconnect, refusals and events are non-strict. They record what happened on the channel and are not a gate. A failed audit write is logged and the event still goes to the owner. Payloads are never audited. Say so if you want strict rows for events: an audit database fault would then stop events being acked. The owner registration writes no row in this release (it is a memory-only call).
* The failure limit uses nginx's `X-Real-IP`, then the ASGI client address. The leftmost `X-Forwarded-For` is never used. A cache fault reads as not limited and is logged.
* The owner id `nats-comms` is a fixed constant in Core.
* A refusal is accepted and then closed with its code, so a native client can read 4401 or 4429. A plain-text connection is refused only where the proxy reports it (`X-Forwarded-Proto`). Otherwise TLS is left to nginx.
* The caller check uses the verified caller identity and not the `module_id` argument that the plan lists.
* `send_many` takes `event` frames only and `request` takes `request` frames only. A fire-and-forget request would have no waiting reply.
* `event_task_path` is a dotted import path of the Celery task object. Core stores the task's Celery name and calls it by name through `send_task`.

### Tests

New: `tests/endpoint-transport-identity-1.17.90.py`, `endpoint-transport-consumer-1.17.90.py`, `endpoint-transport-contract-1.17.90.py`, `endpoint-transport-loadseed-1.17.90.py` (shared stubs in `tests/endpoint_transport_harness.py`), and `endpoint-transport-runtime-1.17.90.py` (a dev-server probe in the style of `tactical-websocket-runtime-1.17.34.py`; written, not run).

### Not run here

Django models, channels, Redis, Celery and Tactical are not on this PC. The tests above run the real Core files against stubs of those boundaries and an in-memory channel layer. `tests/endpoint-transport-runtime-1.17.90.py` (real ASGI application, real cache, real token table) was written and not run. The Celery hand-over was tested against a stub `send_task`: whether a real broker call stays inside the 5 second timeout during a broker outage is for the dev-server run. `makemigrations --check` was not run (no model change). The export of `core.endpoint_transport` into `docs/contracts` is made from the signed code on the dev server and is not part of this package.

## Fixed after review (round 1, 1.17.90)

1. **Unauthenticated refusals no longer grow the audit table without limit (High).** `EndpointAgentConsumer.connect` now checks the failure limiter first. An address over the limit is closed 4429 with no audit row (`_refuse(..., audit=False)`). The plaintext refusal (`X-Forwarded-Proto: http`, which Tactical's nginx `/ws/` location does not strip) now counts as a failure through `note_failure`. At most 10 refusal rows per address per minute are written. Test: `tests/endpoint-transport-consumer-1.17.90.py` (50 plaintext then 50 unknown-token connections from one address: 10 closed 4403, 90 closed 4429, no more than 11 rows). The older rate-limit case now asserts the 11th refusal writes no row.
2. **Group membership is renewed (High).** channels_redis drops a group member after `group_expiry` (86400 s), after which requests, fan-out and takeover missed the connection. `_tick` now calls `group_add` on every ping (idempotent, once a minute). Test: the layer drops the member, the clock advances, one `_tick` renews it, a request reaches the consumer and a takeover still closes the older connection 4409.

No module-facing change. Not run here: Django is not installed; the tests use the stub harness.
