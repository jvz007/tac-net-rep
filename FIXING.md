# FIXING.md — Core 1.15.110

## Review scope

This release is intentionally scoped to **M12** from Claude's Core tracker.

### M12 — run-now must canonicalise Scheduler targets before execution

Problem being fixed:
- scheduled dispatch canonicalises saved targets before authorization and queueing;
- the manual `run now` path previously authorized and queued the raw saved target object, so legacy aliases or malformed target shapes could behave differently from scheduled execution.

Expected behavior in this release:
1. `SchedulerRunNowView.post()` canonicalises the saved target object before scope authorization or queueing.
2. A successful canonicalisation is persisted to the schedule before the manual run is created.
3. Already-canonical targets are not rewritten unnecessarily.
4. Invalid saved targets follow scheduled-dispatch quarantine semantics: the schedule is disabled, target state is marked invalid, HTTP 400 is returned, and no manual run is queued.
5. Scope authorization and the manual run snapshot both receive the canonical target object.

## Behavioral regression

`tests/scheduler-run-now-canonicalization.py` executes the production `SchedulerRunNowView.post()` method body and verifies:
- documented legacy dynamic scope aliases become canonical before authorization and queueing;
- canonical targets are left unchanged;
- invalid legacy/static aliases disable the schedule, return 400 and never authorize/queue a run.

## Explicitly out of scope

No other Medium or Low tracker item is intentionally changed in this release. In particular, M13+ remain open.
