# Tec-Tac Framework 1.17.84

Date: 27 October 2026. Fixes the scheduled Communicator send that failed on every run on dev02 (Core 1.17.81 and 1.17.82). No migration, no new route, no new setting.

## What changed and why

Core's route guard in `system_commands._send` refused every scheduled send with `function_unavailable` ("Tactical no longer serves the send-command view on this route"). The Celery log on dev02 showed it. Nothing reached Tactical, so the endpoint never got the message.

**Cause.** The guard checked `match.func.__name__ == "send_raw_cmd"`. In Tactical, `send_raw_cmd` is a DRF `@api_view`. Django 4 and later, and DRF, return a plain function called `view` (wrapped by `csrf_exempt`), so that name is `view`, not `send_raw_cmd`. The guard could never pass. It was not a worker-only problem: a person's send does not use this guard (it runs through Core's operation registry), so it kept working. The earlier tests used a fake function that carried the name, which is why they passed.

**Fix.** The guard now reads the name of the view class (`view_class` from Django, or `cls` from DRF; `api_view` names that class after the function) and also checks it belongs to Tactical's `agents` app. A route that lands on any other view, or in another app, is still refused. A route that cannot be resolved is refused too, with a log line. Fail closed is unchanged. Django's own `resolve` imports the URL configuration on its first call, so a worker that served no request needs no warm-up.

The view check now also runs in `run_one` before the per-run count and the claim, so a refusal burns no command_id and writes no audit row.

**A Core refusal now reaches the caller with its code.** If Core itself refuses after the claim (for example the view check), `run_one` closes the audit row as `refused` and raises the refusal. `run_system_command` then raises `SystemActionRefused` with the code (`function_unavailable`) and its plain reason, instead of a generic `failed` reply. The run still continues: it is one endpoint of a batch.

## Module-facing change

`run_system_command` can now raise `SystemActionRefused(reason=function_unavailable)` in a case where 1.17.81 and 1.17.82 returned `failed`. The codes already existed; Communicator already handles refusals. Replies `ran`, `unreachable` and `failed` (with `status`, `reason`, `error`, `tactical_detail`) are unchanged.

## Tests

`tests/system-command-failed-reason-1.17.84.py`: a view whose function is named `view` is read by its class (DRF `cls` and Django `view_class`); a fresh worker (nothing warmed, `resolve` imports the URLconf itself); another view, another app, a plain `view` with no class and a failed resolve are all refused; `run_one` refuses a wrong view before the claim and writes no row; a late Core refusal reaches the caller with its code and the closing row says `refused`. The 1.17.75 to 1.17.83 command tests still pass.

## Test checklist (dev02)

1. Install Core 1.17.84. Let the Communicator patch notice run from the background worker. **Expected:** the endpoint shows the popup; Scheduler shows 1 sent. **FAIL:** still failed. Send back: the lines of `/var/log/celery/w1-2.log` with `could not be sent` or `send-command route`.
2. Send the same line by hand through Run command. **Expected:** works as before.

## Not run here

Django is not installed on this PC. Tests run on the stub harness; the real DRF function name is taken from the Django 4+ and DRF source behaviour, not run here.
