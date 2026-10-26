# Tec-Tac Framework 1.17.77

Date: 26 October 2026. Documentation and one regression test. No code change, no migration, no new route, no new setting. `core.system_actions` stays at 1.5.0.

A person can make the Communicator background sending schedule in the Scheduler today. Core already does the work. This release writes down how, and pins it with a test. Closes the request "how a person makes the Communicator background sending schedule" (from communicator 0.6.3, 23 October 2026).

## The answers

1. **Both registrations are accepted.** Remote Background registers the system action row `remote-background.command`. Communicator registers the Scheduler action of the same id for module `communicator`. They sit in two registries, so there is no clash. A person who holds `communicator.schedule` sees the action in the Scheduler.
2. **Choose a client or a site as the target.** The worker has no fixed endpoint list. Core re-reads the endpoints of a client or site at every run, so an endpoint added later is covered. The scope stored when the person saved the schedule still cuts every run. An endpoint outside the chosen targets is refused `outside_targets`; one outside the stored scope, `out_of_scope`. Nothing is sent in either case. An endpoint list works too, but it is fixed.
3. **The parameters have four keys.** `{allowed_templates, template_hashes, rights, max_timeout}`. The request named three. `rights` has been required since 1.17.76 (AD-50). `max_timeout` is optional. Communicator already returns all four.

Written in `docs/system-actions.md` ("The Communicator background sending schedule") and `docs/scheduler.md`.

## Module-facing change

None in Core. One thing Communicator must do, filed in `reviews/requests/premium-modules.md`: list `client` and `site` in `target_types` of its `remote-background.command` registration. Today it lists only `endpoint` and `endpoints`, so Core refuses a client target. I grepped `modules/` for `remote-background.command`, `target_types` of that registration and `system_action_parameters`: only Communicator (and its tests) use them. Nothing else changes.

## Tests

`tests/system-command-worker-schedule-1.17.77.py` (new, runs on the stub harness without Django): client and site targets create the schedule and a later endpoint is sent to; an endpoint of another client is `outside_targets`; an endpoint list refuses an unlisted endpoint; a client target is refused when the action lists only endpoint types; the parameters without `rights` are `bad_parameters`, and `max_timeout` is optional.

Not run here: Django, the real Scheduler page, the real dispatch. dev02 must test the checklist below.

## Test checklist (dev02, after Communicator lists `client` and `site`)

1. Open Scheduler, New schedule. Pick action "Communicator background sending". **Expected:** it is listed, and a client or site can be chosen as the target. **FAIL:** the action is missing, or only endpoints can be chosen. Send back: a screenshot and the Communicator version.
2. Pick one client you can see. Paste the parameters from `GET /api/tfd/communicator/background-worker/` (`system_action_parameters`). Save and confirm the Yes or No text. **Expected:** it saves, and the text names the template ids. **FAIL:** a refusal. Send back: the refusal text and the reason code in the audit log.
3. Open Audit, filter on your user. **Expected:** one row for the schedule you made, with your name. **FAIL:** no row, or another name. Send back: the audit export.
4. Queue a Messenger notice for one endpoint of that client, then use Run now. **Expected:** the run succeeds and the endpoint gets the notice. **FAIL:** `outside_targets`, `out_of_scope` or `function_unavailable`. Send back: the run history entry and its audit rows.
5. Queue a notice for an endpoint of a client you did not choose. **Expected:** that endpoint is refused `outside_targets` and nothing is sent to it. **FAIL:** it is sent. Send back: the run history and the endpoint's Tactical command history.
