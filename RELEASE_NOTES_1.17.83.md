# Tec-Tac Framework 1.17.83

Date: 27 October 2026. Follow-up to 1.17.82 (request "From communicator 0.6.11"). No migration, no new route, no new setting.

## What changed and why

On dev02 every scheduled Communicator send still ends `failed` on Core 1.17.82, while a person's send to the same endpoint works. 1.17.82 added `status` and `reason`, but a raised error has no status. So the `failed` reply of `run_system_command` now also holds, additively:

- `error`: the class name of the exception (for example `RuntimeError`), never its message. Empty when Tactical answered.
- `tactical_detail`: Tactical's own error sentence (the `detail` field of its refusal, at most 160 characters). Empty otherwise. Never the command or the output.

The info log line is now: `Scheduled command to endpoint <id> failed: status=<n|None> reason=<code> error=<Class|-> detail=<text|-> (run <id>)`.

## Where to look on the server

- Logger name: `tec_tac.system_actions`. Level INFO for the line above.
- The full traceback is already written (since 1.17.76) at ERROR by the same logger with the text `The command could not be sent; Core never sends it again under this command_id.` It runs in the Celery worker that runs the Scheduler, so it lands in the Tactical Celery worker's log (service `celery.service`, journal: `journalctl -u celery -n 300 | grep -A25 "could not be sent"`), not in the web service log. Core's INFO line only shows if the Core logger is set to INFO.

## Root cause analysis (from the code)

Core runs `send_raw_cmd` in-process as `tectac-communicator`; a person's send runs the same view through `tactical_operations` as the person. Both build the request with the same builder. What differs is the user and the process (Celery worker, no web request). Reading Tactical 1.5.2 and Core, every step the view takes passes for this user on paper: `SendCMDPerms` needs `can_send_cmd` (the role has it, and Core refuses before any send if it does not), `_has_perm_on_agent` returns True for a role with no client or site limits, the body holds all four fields the view reads, and Core's route and service-user guards run before the send and would give a Core refusal, not `failed`. No static defect was found, and this release does not claim one. The remaining candidates are the view raising inside the Celery worker, or a 4xx or 5xx answer for the service user. The two new fields name which, with the first scheduled send after install. A Core refusal would show as its own code.

## Module-facing change (additive)

The `failed` reply gains `error` and `tactical_detail`. Everything else is unchanged.

## Tests

`tests/system-command-failed-reason-1.17.83.py`: the reply holds Tactical's detail sentence and the class name; a raised error gives the class name and never its message; the log line carries them and never the command. The 1.17.82 test still passes.

## Test checklist (dev02)

1. Install Core 1.17.83, let the patch notice run. **Expected:** it is sent, or History shows `status`, `reason`, `error`, `tactical_detail`. **FAIL:** a `failed` reply without those keys. Send back: the History row and the lines from the Celery journal that contain `could not be sent`.

## Not run here

Django is not installed on this PC. Tests run on the stub harness; the failure was not reproduced.
