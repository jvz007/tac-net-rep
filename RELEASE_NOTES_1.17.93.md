# Tec-Tac Framework 1.17.93

Date: 30 October 2026. Endpoint transport 1.2. The 29 October 2026 load test showed the real cause of the failures that remained after 1.17.92: the uvicorn process had an open-file soft limit of 1024 (hard 524288). This release raises that limit in Core code and closes the three held Mediums of 1.17.92. The capability `core.endpoint_transport` stays at 1.0.0.

Workspace note: the pipeline signed 1.17.92 as `cc175c0`, but its final sync step failed and left this workspace one commit behind. The first commit of this release brings the tree onto the signed 1.17.92 files (no code differed). 1.17.93 is built on top.

## What changed and why

1. **The open-file soft limit is raised (AD-54 E2, Core code only).** At about 968 agents the process hit `[Errno 24]` (too many open files). Then psycopg could not resolve `localhost`, the identity check answered 1013 for 996 agents and nginx returned 36 HTTP 502. nginx was fine (`worker_connections` 4096, 0 "not enough" errors). `raise_open_file_limit()` in `endpoint_transport.py` sets the soft limit to the smaller of the hard limit and 65536, once per process. It never lowers a limit, never touches the hard limit and never raises: a fault is one warning line. It runs when Core starts in an ASGI server (uvicorn, daphne or hypercorn loaded, so Celery workers and `manage.py` are left alone) and again at the first endpoint socket. Verify with `cat /proc/$(pgrep -f uvicorn | head -1)/limits | grep -i 'open files'` (soft 65536) and the info line in the journal. No systemd or nginx change. If a server's hard limit is below about 4 096, that is a server change and goes to Johan. New docs section "Open files and the 2 000 agent target".
2. **The token re-check no longer fails open for ever (held Medium 1, security).** A fault at the 10 minute re-check kept the socket open without a time limit. Now Core records the last good identity check. When a re-check gets no identity answer and that check is older than 960 seconds (10 minutes, 60 seconds of jitter, 5 minutes of grace), Core closes 1013 with one throttled `custom:endpoint-refused` row (reason `identity_stale`). The agent reconnects through a fresh check or gets 1013 while the fault lasts. A real refusal still closes 4401 at once. The re-check has its own small pool (`recheck`, 2 threads, backlog 4096), so a connect flood cannot starve it.
3. **Audit pool hygiene (held Medium 2).** In 1.17.92 the audit rows stopped using `database_sync_to_async`'s cleanup, so a broken database connection held by one of the two audit threads was never dropped. `record_endpoint_event` now calls `close_old_connections()` before the write and in a `finally` after it (it does not close the connection itself, so a configured connection max age is respected). The function still never raises and writes the same fields.
4. **A full cache pool no longer switches the limiter off (held Medium 3).** A full cache pool read as "not limited". Now a full pool at the pre-check closes 1013 (`busy`, counts nothing), and a failed check whose failure cannot be counted closes 1013 `busy` instead of an uncounted 4401. A real cache backend error still reads as not limited, as AD-54 accepts. Other cache calls (presence, the plaintext count) are unchanged.
5. **The per-agent 4429 writes a row (Low 5 of 1.17.92-1).** An id over 10 failed checks a minute is closed 4429 with a `custom:endpoint-refused` row (reason `rate_limited_agent`). Only the per-address 4429, the signed pre-auth limit, stays without a row. Docs and metadata now say "every refusal except the per-address 4429 limit close".
6. **The `added_in` text states only what signed code does (Low 4).** The 600 per address and 600 row budget wording is gone from the metadata and docs. `REFUSAL_ROWS_PER_MINUTE` stays in code, off, and needs a signed amendment.

## Module-facing change

None. The contract version and operations are unchanged, so `nats-comms` needs no change. Behaviour on the socket: close code 1013 now also means a re-check with no identity answer for 16 minutes, or a full cache pool at connect. The agent already treats 1013 as retry later with back-off.

Decisions taken (information, no answer needed):
* The open-file limit is raised by Core (option a). A systemd `LimitNOFILE` change was not made: AD-54 E2 allows no server change.
* The re-check grace is 300 seconds (fail closed after 960 seconds). The reviewer's alternative was one more re-check period (about 21 minutes). A database outage over 16 minutes closes every endpoint socket 1013, and the agents reconnect when the database is back.
* A valid agent can get 1013 during a cache overload and retries with back-off. Nothing is granted.

## Not done here

* The 2 000 agent re-test on dev02. After install, check the open-file limit with the command above first.
* The wider limits proposal (600 per address, a row budget) stays unbuilt and unanswered in `reviews/questions/core.md`.
* Backlog Mediums and Lows of 1.17.90 and 1.17.92 that are not in these lines: concurrent `request()` calls on channels_redis, owner registration never re-checked, audit-table growth from many addresses, the uncached plugin scan, the load-seed token file mode. Next patches.
* The public contract needs exporting again into `docs/contracts` after install on dev02.

## Tests

New: `tests/endpoint-transport-openfiles-1.17.93.py`, `tests/endpoint-transport-recheck-1.17.93.py`, `tests/endpoint-transport-pools-1.17.93.py`, `tests/endpoint-transport-docs-1.17.93.py`. Changed: `tests/endpoint-transport-burst-1.17.92.py` (counts auth jobs apart from audit jobs), `tests/endpoint-transport-limiter-1.17.92.py` (the per-agent 4429 now has a row) and `tests/endpoint-transport-docs-1.17.92.py` (checks that the 1.17.92 notes are kept in `docs/releases/`).

What could not run on this PC: Django is not installed, so `tests/endpoint-transport-runtime-1.17.90.py` did not run. The Linux `resource` call is tested through a stub module. A real `setrlimit` could not run here. It needs the dev02 check above.


## Fixed after precheck

The 1.17.92 release notes (with the 1.17.92-1 rebuild history) are restored to `docs/releases/RELEASE_NOTES_1.17.92.md`, as the 1.17.91 notes were. Earlier notes are kept.
