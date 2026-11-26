# Tec-Tac Framework 1.18.55

Date: 26 November 2026. The audit log now tells you who enrolled an Engineer Console certificate, ending live tunnel sessions no longer holds up a web request, and the installer no longer fails a good install on a celery process id that systemd cannot name. It is a Core-only change. `main` stays held.

## Module-facing change

None. No contract, capability, endpoint or import changes, and `core.probe_transport` keeps its shape and its version (1.3.0). Two internal changes are named here so nobody is surprised by them:

- **The audit actor of the enrolment rows.** `custom:console-cert-issued`, any "replaced" `custom:console-cert-revoked` row and `custom:console-cert-enrol-refused` (after the code was matched) now sit under the engineer, not under `service:core.console-certificates`. The actor kind stays human. No module reads these rows.
- **Who ends live tunnel sessions after a revoke or CA replacement.** A Celery task does it, not the web request. The `core.probe_transport` answers and events are the same. `networkprobe` is not affected.

## Closes

- The request "core: Console certificate audit, the issue row names the engineer, not the service actor" in `reviews/requests/core.md`, from Johan's dev02 test of 26 November 2026.
- Held Low of the 1.18.53 review: connect-refusal rows shared the enrolment limiter.
- Held Low of the 1.18.53 review: the revoke and CA-replace hooks ended up to 50 sessions inside the web request.
- Held Medium of the 1.18.54 review: the post-install check guessed celery's `MainPID`.
- Held Low of the 1.18.54 review: the "check must not read the key" assertion could never fail.

## What changed and why

1. **The engineer is the audit actor of an enrolment.** The code comes only from the engineer's own signed-in My Account page and is bound to their enrolment, so the engineer is the right name on the row. `console_certificates.engineer_actor(user)` returns the person when they are a real signed-in account with a username, and the service actor otherwise (a blank username would make a strict audit row raise, so it falls back and never raises). `enrol()` passes it to `issue_certificate()`. The issue row and a "replaced" revoke row carry `via = enrolment_code` and the address. Every refusal after the code was matched (proof, key, host, certificate limit, inactive account and the rest) is written under the engineer with `via`, `engineer_id` and `username`. The service actor stays where no person is known: an unknown or burnt code, a bad header or body, tunnel connect refusals, and a CA made with no person. The administrator who allowed the enrolment is already named in the `custom:console-cert-issue-authorised` row, so no row loses a name. `docs/console-certificates.md` has an Actor column and a short section on finding every row of one certificate.
2. **One limiter key per refusal kind.** A refused enrolment and a refused tunnel connect from one address in the same minute now each write their one row. Two of the same kind in a minute still write one, and a cache fault still writes none. The enrolment key text is the one 1.18.54 used.
3. **Ending sessions leaves the web request.** `certificate_revoked()` and `ca_replaced()` write the backstop marker (one cache set, the only work left in the request), queue one Celery task (`tec_tac.end_console_certificate_sessions`) with a single bounded broker attempt (2 second timeouts, no retry, expires after 120 seconds), and return an empty list. The task runs the same two functions as before, now in a worker, with a soft time limit of 30 seconds and a hard limit of 45 seconds on top of the 10 second session budget. If the broker does not take the message, Core logs a warning and relies on the marker. Each Console socket reads the marker in its 5-second tick, so a session ends within 5 seconds even if the task never runs. There is no inline fallback.
4. **The post-install check finds celery's processes.** `service_group_check` in `install.sh` uses `MainPID` when it is a number above 1 with a readable status file, as before. Otherwise it reads the unit's control group (`systemctl show -p ControlGroup`, then `cgroup.procs`) and inspects the processes that run as the service user. A root helper in the same group is ignored. It passes when at least one process was inspected and every one carries the Tactical group, and it fails closed when none can be inspected. A process that exits while it is read is skipped. The diagnostics check `core.secret_store.service-access` does the same for an active unit whose `MainPID` is 0 or unreadable, and answers `ok`, `missing_group` or `unknown`. It never answers `not_running` for an active unit. No new state names. The key file is never opened.
5. **The key-guard test can fail now.** The old assertion used a basic regular expression where `|` is a literal, so it could never match. It uses `grep -Eq` and proves itself on a sample that contains `chmod 660 master.key`.
6. **Bookkeeping.** `tests/version-1.18.54.py` and `RELEASE_NOTES_1.18.54.md` moved to `tests/legacy` and `docs/releases`.

## Assumptions

Johan's decisions are in `reviews/questions/core.md` as information. None blocks this release.

- **The engineer is the actor of an enrolment.** Human actor, with `via = enrolment_code` and the address in the row. The service actor stays where no person is known.
- **The marker stays the guaranteed fast path.** The task is the immediate end and is best effort. If the broker or the worker is down, the end happens at the next 5-second tick, not at once. A worker that does not yet know the task (celery restarted after the web code) drops it, and the marker covers that window. Nothing about trust widens.
- **Control group fallback.** It reads `/sys/fs/cgroup<ControlGroup>/cgroup.procs` (the unified cgroup layout of Ubuntu 22.04 and later). On a server with another layout it finds nothing and fails closed with "Could not inspect", which is the safe side.

## New tests

- `tests/console-certificates-actor-1.18.55.py`: the issue row under the engineer with `via` and the address and nothing under the service actor; the "replaced" row; each refusal after a match under the engineer with the enrolment id; unknown code, burnt code and a bad header under the service actor; a blank username falls back and the enrolment still succeeds; the real audit provenance function takes the engineer; rows found by serial; no code, key, proof or header in any row or log; the limiter per kind (the enrolment key text equals the 1.18.54 key, a new minute writes again, a cache fault writes none).
- `tests/probe-tunnel-end-queue-1.18.55.py`: the hooks write the marker, queue one task with the 2 second broker options and return `[]`; no end in the calling thread; a broker fault, a missing task module and a cache fault; the task body ends the right sessions with the right detail and a second run ends nothing; the time budget on a fake clock; the 5-second tick ends a session from the marker alone; the task name and limits; `_after_commit` still calls only the two hook names.
- `tests/install-service-key-group-1.18.55.sh`: `service_group_check` against a fake `systemctl` and fake `/proc` and cgroup trees (good `MainPID`, `MainPID` 0 with three good processes, one process without the group, a root helper ignored, empty or missing cgroup, a vanished process, a wrong `MainPID`), `bash -n`, no CR bytes.
- `tests/diagnostics-secret-key-fallback-1.18.55.py`: `MainPID` 0 with good processes (`ok`), a missing group (`missing_group`), an unreadable cgroup (`unknown`), an inactive unit (`not_running`), a state that cannot be read (`unknown`), and the key file never opened.
- `tests/version-1.18.55.py`: version, notes, headings, checklist, line endings.
- Adjusted: `tests/console-certificates-enrol-1.18.52.py` (the actor and the refusal row metadata), `tests/probe-tunnel-certificates-1.18.53.py` (the ending now runs through the task body), `tests/install-service-key-group-1.18.54.sh` (the repaired key guard, and it reads the new function with the loop).

## What could not be run here

Django 6.1 and the Python tests ran on this PC. systemd, root, a real Celery broker and a real `/proc` and cgroup tree did not: `service_group_check` and the diagnostics readers are proved against fakes only, and the Celery task is proved against a stand-in for the task object. `tests/module-management-foundation.sh` needs `fcntl` and does not run on Windows. The dev02 checklist below carries the real proof.

## Johan dev02 checklist

**A. Enrol a Console certificate, then search the audit log.** Enrol one certificate through the normal flow. In the audit log, search by action `custom:console-cert-issued`. PASS: the row's user is the engineer's own username, with `via` = `enrolment_code` and the address in the details. FAIL: the user is `service:core.console-certificates`. Send back: that audit row.

**B. Replace the same PC.** Enrol again with the same PC label. PASS: the older certificate's `custom:console-cert-revoked` row (reason `replaced`) is also under the engineer, and a search by the older certificate's serial shows its issue and revoke rows. FAIL: it is under the service name. Send back: both rows.

**C. A refused enrolment.** Send an enrolment with a made-up code (the Console's enrol step with a wrong code is enough), then look at `custom:console-cert-enrol-refused`. PASS: the row sits under `service:core.console-certificates` with no engineer in it, because no person is known. A refusal after a real code matched (for example a clock or key fault in a test Console) sits under the engineer. FAIL: a made-up code names a person. Send back: the row.

**D. Revoke ends a live session.** Connect a Console, then revoke its certificate from the Core UI. PASS: the Console is closed within a few seconds, and the audit end row says `certificate_revoked`. Then stop `celery` (`sudo systemctl stop celery`), connect again, and revoke. PASS: the session still ends within about 5 seconds, because the marker does it. FAIL: a session stays up for more than 10 seconds. Send back: the end row and `journalctl -u celery` for that minute. Start `celery` again afterwards.

**E. Installer check with celery.** Run the installer or System Update on dev02 with celery running. PASS: four "Verified live ... runtime group" lines, including celery, and no "Could not inspect live celery process" failure. FAIL: either failure. Send back: the installer tail and `systemctl show celery -p MainPID -p ControlGroup`.

**F. Diagnostics.** Open the diagnostics report. PASS: `core.secret_store.service-access` shows pass and lists celery as `ok`. FAIL: celery shows `unknown` while it runs. Send back: the check's details.

## Not in this release

The `networkprobe` request to publish the end detail of a tunnel session, the access-changed event for declared modules, the tunnel check-in (on hold), the `softwarerepository` result-check rules and the Console sign-in work (planned for 1.18.56) are not in this release. The Core UI hint on how to find every row of one certificate is a request to the UI (`reviews/requests/ui.md`); Core only documents it here.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
