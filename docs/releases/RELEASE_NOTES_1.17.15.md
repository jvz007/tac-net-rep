# Tec-Tac Framework 1.17.15

Three things, decided or reported on 9 and 10 October 2026. A root helper that Windows had saved with line endings broke every module job on the dev server, so the installer now fixes that and says so plainly if it happens again. Uninstalling an enabled replacement now hands its replaced module back, as a disable already does (Johan, CQ43). A failed module job now also sends a Priority 1 email (Johan, CQ41). The email code is ready, but it stays off until Johan answers how outbound email is configured (CQ46).

Closes: in `reviews/requests/core.md`, the entry "root job helper with Windows line endings" (the source, the installer, the gate and the dispatch message), and the item "hand-back on uninstall (CQ43)" from the "Still open" list of 1.17.14. Not closed: the Priority 1 email is only half a feature until CQ46 is answered. The "Still open" items of 1.17.14 otherwise stand.

## What changed

### Root helpers keep Unix line endings, and the installer makes sure (root job helper, dev server)

`scripts/module-job-helper.py` was committed with Windows (CRLF) line endings. On Linux the first line then reads `#!/usr/bin/python3` with a stray carriage return, so the path does not exist and `sudo` fails with "unable to execute". Every module job on the dev server failed that way.

- The helper is LF only in the source. A new `.gitattributes` in the Core root keeps `scripts/*.py` and `scripts/*.sh` LF on every commit.
- `install.sh` copies each root helper through `install_root_script`, which strips a trailing carriage return. All the helpers `install.sh` puts in `/usr/local/sbin` and its library folders go through it.
- The release gate `tests/root-script-crlf-1.17.15.sh` fails with the name of any file under `scripts/` that holds a carriage return. It also checks the installer's strip is there. `tests/release-integrity.sh` runs it.
- When a module job cannot start because the helper has Windows line endings, the job error says so in plain words: "helper has Windows line endings - reinstall it from this version." Other dispatch errors keep their own text.

To repair a server that already has the bad helper, reinstall Core from this version. Johan's interim fix was `sudo sed -i 's/$//' /usr/local/sbin/tec-tac-module-job`, which also works.

### Uninstalling an enabled replacement hands its replaced module back (CQ43, AD-20)

A deliberate disable already switches the replaced module back on. An uninstall now does the same.

- `POST` to the module remove route checks the hand-back first. If the replaced module can come back, the job enables it after the uninstall, in the same job.
- If it cannot come back (a missing or disabled dependency, a version that does not fit, a runtime requirement, a module that cannot be managed from the UI), the request is refused with HTTP 400, `code: replacement_hand_back_confirmation_required`. The answer carries `detail`, `module`, `will_enable` and `hand_back_unavailable`, and nothing is queued. The person confirms by sending `confirm_without_hand_back: true`. Only exactly `true` confirms.
- A confirmed uninstall leaves the replaced module off and records it in `hand_back_skipped`.
- The root helper re-checks every rule before it removes anything: the replaced module is a core or server module, it is off, the module being removed is the one that replaces it, and no other enabled module replaces it. A failed check fails the job with nothing removed. After the removal it switches the module back on under the state lock, and records `enabled_modules`.
- The audit row says the replaced module was enabled again because its replacement was uninstalled. The queue-time row names what was asked.

### A failed module job keeps the fields Core queued (fix found while building CQ41)

The root helper wrote its final job record from the running request alone. That dropped `requested_by` and everything else Core had queued. For a v1 module job (install and remove) the person who started it was never named, so the 1.17.14 failure notice did not reach them. The helper now starts from what Core queued and puts its own fields on top (`run_job_record`).

### A Priority 1 email for a failed module job (CQ41, ships off)

A failed module job already raised a notice in Core (1.17.14). It now also sends an email to the same people: active superusers and the person who started the job. The subject names the module and the server. The body repeats the notice text, which holds no paths.

- One email per person and job. Core records that the try was made, so the next scheduler tick never sends it again. A send that fails is logged and not retried, so a dead mail server cannot flood anyone.
- The send follows Tactical's own method: implicit TLS on port 465, otherwise a plain connection upgraded with STARTTLS when the server needs a login, and a 20 second timeout.
- The email is built as a reusable function (`send_p1_email`), so server storage problems can call the same function when Core can detect them.
- Core does not read Tactical's `CoreSettings`, where the SMTP settings live today, because Tactical's models are not Core's to read. The settings source is `_mail_settings()`, which returns nothing until Johan answers CQ46. Until then no email is sent, and nothing fails.

## Module-facing change

- The module remove route (`POST` to remove a module) now accepts `confirm_without_hand_back` and can refuse with HTTP 400, `replacement_hand_back_confirmation_required`, when the replaced module cannot come back. An old caller that never sends the flag gets that refusal in that one case and nothing is queued. It is safe, but the UI should show the warning and send the flag (`reviews/requests/ui.md`). No module calls this route. The patchmanagement route `install-queue/remove` is its own.
- The job record gains `enable_modules` and `hand_back_skipped` for a remove job. Both are internal to the job and the audit row. The public job response already allows `enabled_modules` and `hand_back_skipped`.
- `module_manager.queue_remove` takes two new keyword arguments, `confirm_without_hand_back` and `actor`. Both are optional.

## Not in this release

- The outbound email settings source (CQ46). The Priority 1 email stays off until Johan answers.
- Server storage problems as a Priority 1 email type. Core has no detection path for them yet.
- The v2 root helper's dispatch error still shows the bare sudo text. The same line-ending fault would show there. Reinstalling Core fixes both.
- `docs/module-replacement.md` does not yet describe the uninstall hand-back. It will be updated with the next contract change.
- The UI does not yet show the uninstall warning (`reviews/requests/ui.md`).

## Checks

- `tests/root-script-crlf-1.17.15.sh` passes on this PC. A planted CRLF file in a copy of the tree is caught.
- `tests/module-failure-notices-email-1.17.15.py` passes. It covers the skip rules, the subject and body, one try per job and person, the SMTP sender against a fake server (STARTTLS, implicit TLS and an open relay), a failing send, and the sweep.
- `tests/module-replacement-uninstall-handback-1.17.15.py` passes. It runs the real hand-back rules over a fixture model and the real root helper's re-check and state write.
- `tests/module-job-dispatch-crlf-1.17.15.py` passes.
- The 1.17.14 notice and replacement tests that run without Django still pass.
- `ruff check` finds no new real errors (F, B, E9) in the changed files.
- The Django-dependent tests, the runtime tests and the Linux-only tests did not run on this PC. They run on the dev server.
