# Tec-Tac Framework 1.17.82

Date: 27 October 2026. Closes the request "From communicator 0.6.11" (core: `run_system_command` outcome "failed" carries no reason). No migration, no new route, no new setting.

## What changed and why

When Tactical's send-command view refuses or raises, a scheduled command used to come back as `failed` with nothing to say why. Communicator could only show "the command could not be sent". Now the `failed` reply of `run_system_command` (and `system_commands.run_one`) also holds:

- `status`: the HTTP status of Tactical's view, or `None` when the view raised an error or Core refused the route before sending.
- `reason`: a short code. `tactical_permission_denied` (401, 403), `tactical_not_found` (404), `tactical_bad_request` (other 4xx), `tactical_error` (5xx), `tactical_view_raised` (the view raised), or a Core refusal code such as `function_unavailable`.

Core also logs one info line: `Scheduled command to endpoint <id> failed: status=<n> reason=<code> (run <id>)`. The command, the output, the payload and any token are never in the reply, the log or the audit rows.

## Module-facing change (additive)

`run_system_command` reply on `outcome: "failed"` gains `status` and `reason`. `outcome`, `output`, `truncated`, `message` and the `ran` and `unreachable` replies are unchanged. Callers that ignore the new keys keep working. Users in `modules/`: Communicator only. Capability version stays 1.5.0 (keys are additive).

## Why a scheduled system command could get `failed` (from the code)

Core sends the command by calling Tactical's `send_raw_cmd` view in-process as the service user `tectac-communicator`. Anything but a 2xx answer (other than the bare "Unable to contact the agent" 400, which is `unreachable`) ends `failed`, and so does any exception from the view. From Tactical 1.5.2's view and permissions, the candidates are:

1. **Permission (403):** `SendCMDPerms` needs the role's `can_send_cmd` and `_has_perm_on_agent`. Core re-checks the service role holds exactly `can_send_cmd` before every send, so a drifted role is a Core refusal (`function_unavailable`) rather than a 403. A 403 would mean Tactical itself refuses that user, for example the user's role cache is stale after the role was changed.
2. **Scope:** the service role has no client or site limits, so `_has_perm_on_agent` returns True. The person's own scope is checked by Core before the send, not by Tactical, so scope does not come from this view.
3. **Serializer or body (400/KeyError):** the view reads `timeout`, `shell`, `cmd` and `run_as_user` from the body. Core always sends all four, so this fails only if the template is rendered with a bad timeout.
4. **Raised error (status None):** the view calls `asyncio.run(agent.nats_cmd(...))`. In a worker that already runs an event loop, or when NATS is down, this raises instead of answering. A raise is not a 4xx and shows up as `tactical_view_raised`. It is the likeliest match for a background worker working where a web request works.
5. **Timeout:** the view waits `timeout + 2` seconds for the agent. A slow endpoint gives the bare "timeout", which is `unreachable`, not `failed`. A worker time limit shorter than that wait would kill the call with an exception, which also shows as `tactical_view_raised`.

The code cannot say which one dev02 hit. The new `status` and `reason` do. Nothing here is changed by this release.

## Tests

`tests/system-command-failed-reason-1.17.82.py`: status to reason mapping; `SendFailed` is still a `RuntimeError`; a 403 gives `status 403` and `tactical_permission_denied`; a raised view gives `None` and `tactical_view_raised`; a Core refusal gives its code but not its detail; outcome, output, truncated and message unchanged; info log written and never holds the command; `ran` and `unreachable` replies unchanged.

## Test checklist (dev02)

1. Install Core 1.17.82. Let the APM patch notice run from the Communicator background worker. **Expected:** if it still fails, the Communicator History row shows the Core status and reason. **FAIL:** a `failed` reply with no `status` and `reason`. Send back: the History row and Core log lines containing `Scheduled command to endpoint`.
2. Send the same Messenger line by hand through Run command. **Expected:** it works as before. **FAIL:** any change. Send back: the result.
3. Check the Core log. **Expected:** no command text or output in any line. **FAIL:** any command text.

## Not run here

Django is not installed on this PC. The new test and the 1.17.75 to 1.17.78 command tests run on the stub harness (the stub harness tracebacks printed are expected fail-closed logs).
