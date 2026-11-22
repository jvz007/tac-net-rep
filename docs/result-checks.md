# Result checks (`core.result_checks` 1.0.0, Core 1.18.44)

A bulk run on 40 endpoints finishes minutes after the person closed the tab. A module can ask Core to follow the run. Core then tells the person once, in the bell, when the results are in. The page behind the notice shows one row per endpoint: state and exit code. **Core never stores output text.**

Johan, 22 November 2026. Plan: `reviews/plans-21-11-2026/B2-result-checks.md`, release 1.

## What a module does

1. In `AppConfig.ready()`, register a reader. It touches memory only. Wrap the call, log a refusal and go on.

```python
from tec_tac import result_checks

result_checks.register_reader(id="scriptexecution.bulk-script", module_id="scriptexecution", reader=read_bulk_script)
```

   `id` is `<module_id>.<name>`. The module must be an installed, enabled, non-legacy extension, and the reader's code must lie in the module's own folder. The identical definition twice is fine. A different one raises `ResultCheckRegistrationError` (a `ValueError`).

2. The reader answers for the endpoints it is given:

```python
def read_bulk_script(job_ref, endpoint_ids, user):
    return {"<endpoint id>": {"state": "done", "exit_code": 0, "hostname": "PC-01"}}
```

   `state` is `done`, `failed`, `offline` or `running`. `exit_code` is an int or `None`. `hostname` is text. The reader runs **as the person**, so it sees only what that person may see: no trusted global read. It must be **idempotent and read-only**, and it must never return output text.

3. When the run starts, from the module's own code:

```python
check_id = result_checks.start(user, reader_id="scriptexecution.bulk-script", label="Run script", endpoint_ids=ids,
                               job_ref={"script_id": 7, "started": "..."}, deadline_seconds=900)
```

   Only the module that owns the reader may call `start`. Core, an unverified caller and another module get `ResultCheckRefused` (a plain sentence that names no module). Limits: label 1 to 80 printable characters, 1 to 1000 unique endpoint ids (each at most 200 characters), `job_ref` a JSON object of at most 2 KiB, `deadline_seconds` 60 to 86400, at most 20 open checks per person. An argument outside a limit raises `ResultCheckInvalid` (a `ValueError`).

## What Core does

- The Scheduler tick queues at most 20 due checks as the Celery task `tec_tac.run_result_check`. The tick never runs a reader or any module code. Restart the Celery worker after an update so it knows the task.
- The task calls the reader **once**, for at most 500 running endpoints, as the person who started the check. The first check is due 60 seconds after `start`, then once a minute. With more than 500 endpoints the ones checked longest ago go first, so all of them rotate.
- A reader that raises, answers badly, or whose module is gone or disabled leaves the items running. The next minute tries again. A bad entry (unknown state, exit code that is not an int, hostname that is not text) leaves that item running. Unknown ids in the answer are ignored.
- The check closes when nothing is running, or at the deadline. Items still running then become `no_result`. `offline` is final: an endpoint that comes back later is not followed.
- On close: one notice to the person who started the check (`Run script: 38 done, 1 failed, 1 offline[, 2 no result]`, link `/results/<id>`, level success when everything is done, else warning) and one Core audit row `custom:result-check-closed` (counts, check id and reader id; never hostnames or endpoint ids). A refused `start` from a wrong caller writes at most one audit row `custom:result-check-refused` per module and reason every 5 minutes.
- A closed check is deleted 30 days later, its items with it. An open check always closes at its deadline (24 hours at most).
- If the person is inactive or blocked when a check runs, it closes without a notice.

## Reading a check

`GET /api/tfd/ui/result-checks/<id>/?page=1&page_size=50` (page size up to 100). The person who started the check only: a missing id, another person's check (a superuser included), a check past retention and an inactive person all get the same `404 {"detail": "Not found."}`. The answer holds `id`, `label`, `status`, `created_at`, `closed_at`, `deadline_at`, `summary`, `message`, `items` (`endpoint_id`, `hostname`, `state`, `exit_code`), `count`, `page`, `page_size` and `next_page`. It never holds output text, the job reference, the reader id or a module id.

## Not built

A per-person start rate limit, a superuser view of other people's checks, following client, site or all-target runs, and a retry of a notice that could not be stored.

Needs migration `0048_result_checks`.
