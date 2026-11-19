# Tec-Tac Framework 1.18.21

Date: 19 November 2026. A module install run now has exactly one live tick chain. Stop only sets a flag. Raw helper and stage errors no longer reach the audit log or the progress body. Four tests that already failed are repaired or have a stale check retired.

## What changed and why

### 1. One live tick chain per run (Medium, review 1.18.20-1)

The 1.18.20 chain could still multiply or die. A busy tick ended the chain, and a progress poll could queue a tick of its own. Now every queued tick carries a token.

- The run file has an integer `seq`. `start_run` sets it to 0 and queues the first tick with it. `_advance` takes the run lock first. A tick whose `seq` is not the run's current `seq` is a duplicate. It ends at once and queues nothing.
- When a tick has more to do, it adds 1 to `seq`, stamps `heartbeat` and saves, all under the lock. `advance_and_requeue` then queues the next tick with the new `seq` after `TICK_DELAY_SECONDS` (3 s).
- A tick that finds the lock busy (a poll or a stop holds it for milliseconds) queues itself again with the same `seq` after `BUSY_DELAY_SECONDS` (5 s). The chain no longer dies, and a duplicate of that tick dies on the `seq` check.
- A progress request never starts a tick in normal running. It starts one only to recover a dead chain: the heartbeat is older than `STALE_TICK_SECONDS` (30 s) and the lock is free. The poll takes the lock without waiting, checks the heartbeat again under it, bumps `seq`, stamps the heartbeat, saves, and only then queues one tick. A second poll sees a fresh heartbeat and queues nothing. Any older tick still in the broker dies on the `seq` check.
- The heartbeat is also refreshed before the download (with the `downloading` save), after stage and queue return (with the `installing` save) and on every "again" return. A poll right after a long download, or in the 3 s gap, never sees a stale heartbeat.
- A tick queued by 1.18.20 has no `seq`. On a run file with no `seq` it is accepted once and adopts the current `seq`. A second one dies. `tec_tac.advance_module_install_run` takes an optional `seq=None`, so a message already in the broker with one argument still runs.
- `advance_run` keeps its meaning (True only when the run is final or gone) and skips the `seq` check, so direct callers and tests are unchanged.

Files: `framwork/tec_tac/module_install_run.py`, `framwork/tec_tac/tasks.py`. Both stay LF.

### 2. Stop only sets the flag (Low, review 1.18.20-1)

`request_stop` keeps its lock, its flag write, the `stopping` status and its audit row. It no longer queues a tick. The live chain reads `stop_requested` on its next tick (within 3 s) and ends the run. If the chain is dead, the recovery in item 1 picks the stop up after 30 s. A repeated Stop on a run that is already stopping answers 200 with the same body and saves, audits and queues nothing.

### 3. Core sentences for helper and stage errors (Low, review 1.18.20-1)

- A failed install job stores one Core sentence: `The install job failed at the stage "<stage>". The job history has the details.` The stage is the helper's short word, cut to 40 characters and limited to `a-z`, `0-9`, `_`, space and `-`. The raw job error goes only to the server log, with the run id and job id.
- A stage or queue refusal that Core raised itself (replacement, licence and the like) keeps its sentence only when it is at most 240 characters and holds no `/`, no `\`, no `://` and no drive letter. Otherwise the module gets `Core refused to install this module. The Core log has the reason.` and the raw text goes to the log.
- What is true now for the audit rows and the progress body: state words and Core sentences only. No token, URL or file path reaches them, even from a helper or stage error. Before this release a helper error was stored word for word.

### 4. Four tests that already failed

Core source is not changed for these.

- `licensing-availability-1.17.108`, `repository-retired-1.17.99` and `secret-store-1.17.100` extract functions from `module_repository.py` by AST. Since 1.17.109 and 1.18.11 the extracted code calls `is_development_server` and `_development_for`, which the test namespaces did not hold. The extractors now include `_development_for` (and, where the source grew, `_unavailable_licensed` and `MAX_UNAVAILABLE_ROWS`), and each namespace has an `is_development_server` stand-in that returns False (a production server). The 99 and 100 namespaces also get a minimal `_lcs` with the source kind.
- `licensing-availability-1.17.108` also asserted the old text `_unavailable_licensed(repos),`. The call now passes `cached`, so the assertion names that.
- `licensing-unclassified-test-1.17.109` read `RELEASE_NOTES_1.17.109.md` at the root and asserted `VERSION == 1.17.109`.
- `tests/online-install-run-1.18.20.py` is updated where the semantics changed: ticks are `(run_id, countdown, seq)`, the first tick has seq 0, a busy tick requeues itself with a delay (the "Review round 1" block is rewritten), and the next tick carries the next seq.

## Retired checks

- `tests/licensing-unclassified-test-1.17.109.py`, section 4: the release-notes heading loop and the `VERSION == 1.17.109` equality. Reason: the notes moved to `docs/releases/` and the version moves every release. Each release's `version-<n>` test guards the version. The docs, contract and line-ending checks stay.
- `tests/licensing-availability-1.17.108.py`, section 4: the same two checks, with the same reason (the plan named 1.17.109 only; 1.17.108 failed on the same missing notes file once the namespace was fixed).

## Findings closed

The three held findings of the 1.18.20-1 review (the Medium on the tick chain and two Lows: raw errors in audit rows, and Stop queuing a tick). They are not requests. Still held: the Low "Stop answers 503 busy for the whole length of a download". It needs the stop flag outside the tick lock, which is a separate change.

## Module-facing change

None. The three install routes, the contract and the response shapes are unchanged, and nothing in `modules/` uses the install-run code. One Core-internal Celery task, `tec_tac.advance_module_install_run`, gains an optional `seq` argument. A task already in the broker with one argument keeps working.

## Assumptions

- A progress poll may restart a dead chain, and only a dead one (heartbeat older than 30 s, lock free). The `seq` token makes this safe, because it cannot multiply chains. Without it, a lost broker message would leave a run stuck for 15 minutes with the browser closed. Johan may prefer the literal reading, where a poll never queues; then a dead run only closes as interrupted after 15 minutes. Recorded in `reviews/questions/core.md`.
- The stage word and the 240 character rule decide what text may reach an audit row. Recorded in `reviews/questions/core.md`.

## What could not be run

Django and `fcntl` are not on this PC. `FileStore` locking, the Celery task and the real stage and queue path (`stage_repository_package`, `queue_v2_install`, the helper job) run only on dev02. The new tests use injected collaborators and a fake broker.

## Johan dev02 checklist

a. Update dev02 to Core 1.18.21.
b. Open Welcome, tick two modules and start the install.
c. Poll progress every 2 seconds through the first download. PASS: the Celery log shows one tick about every 3 s. FAIL: two or more ticks in a 3 second window, or two overlapping `advance_module_install_run` lines for the same run id. Send the Celery log.
d. Press Stop twice while module one installs. PASS: `stop_requested` is true, the status goes `stopping` then `stopped`, module two is `skipped` with `stopped`, there are no extra ticks per click and one end audit row. FAIL: a second chain, a stuck `stopping`, or module two installing. Send the progress body and the audit rows.
e. Check the audit log. PASS: no file path in any install-run row. FAIL: a path appears. Send the row.
f. Let one run finish with no browser open. PASS: it ends `completed`. FAIL: it stays `running`. Send the Celery log.
