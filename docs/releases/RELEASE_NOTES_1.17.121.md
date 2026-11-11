# Tec-Tac Framework 1.17.121

Date: 11 November 2026. `core.sandbox` canary: one fix. The foreign-reader credential row could pass when the credential file did not exist. Now it passes only when the file was there and a second user was refused. **Nothing can run in the sandbox yet.** `SANDBOX_ENABLED` stays `False`; the sudo rule, the `install.sh` sandbox lines, the status keys and the public contract `core.sandbox` 1.0.0 are unchanged. The kill switch is not touched.

Request: the `core.sandbox` request in `reviews/requests/core.md` stays open. It ends only when the canary on dev02 finishes with `ALL CANARY STEPS PASSED` and a later patch flips the switch. This release closes the 1.17.120 held Medium ("foreign-reader row passes when the credential file does not exist"). **Release manager: mark that Medium closed in `reviews/core/BACKLOG-new-findings.md` when this signs.** No new question was written.

## What changed and why

The row "another dynamic user reads the credential file" expected `denied`. The probe program printed `DENIED` for every `OSError`. A missing file, or a unit that had already ended, raised an `OSError` too. So the row could show OK without proving anything. Changes in `scripts/sandbox-helper.py`:

1. **The probe program tells the cases apart.** It prints `DENIED` only for a `PermissionError` with errno `EACCES` or `EPERM`. It prints `MISSING` for a missing path (`FileNotFoundError`, `NotADirectoryError`). Any other `OSError` prints `ERROR`. It never prints the content or the path.
2. **`_foreign_credential_probe` returns only `READ`, `DENIED` or `MISSING`.** `ERROR`, an odd word, an empty answer or a non-zero exit all become an empty string.
3. **A root-side pre-check runs first.** The new `_credential_file_ready(unit)` needs the file `/run/credentials/<unit>.service/auth` to exist (checked as root) and `systemctl is-active` to say the unit is active. If either fails, the probe does not start and the row is `NOT RUN` with the text "credential file or unit was not there when the probe would have run". `_credential_rows` takes the check as a new optional argument `ready`, so existing callers keep working and tests need no real systemd.
4. **The check runs again after the probe.** If the file or unit is gone by then, a `DENIED` becomes `NOT RUN`: the probe cannot prove a denial without the file.
5. **Row mapping.** `DENIED` with file and unit present before and after is `OK`. `READ` is `ATTACK SUCCEEDED`. `MISSING`, an empty answer, an error and an exception are `NOT RUN`, each with a text that names the reason. `NOT RUN` already fails the canary through `canary_summary`. The row never prints the token or the credential path.
6. **New canary script `tests/sandbox-canary-1.17.121.sh`.** A copy of the 1.17.120 script (that one stays untouched) with the same steps 1 to 6 and the same checks. The installed-helper guard also needs the new pre-check in the helper. Step 4 gains check **4d**: the row "another dynamic user reads the credential file" must end with `OK` (not `NOT RUN`, not `ATTACK SUCCEEDED`).

Security direction: this fails closed. A row can be OK only after the file is proven present and the unit active, and only on a real permission refusal.

## Tests

* New: `tests/sandbox-credential-canary-1.17.121.py` (probe program with `READ`, `DENIED`, `MISSING`, `ERROR`; the probe function; the pre-check blocking the probe; `MISSING`, vanished file, `DENIED`, `READ`, exception; no token or path in any row; the default pre-check) and `tests/sandbox-canary-script-1.17.121.py` (static checks of the new `.sh`, bash syntax).
* Updated: `tests/sandbox-credential-mode-1.17.120.py` (injects the pre-check; a missing path now prints `MISSING`; the "did not start" text) and `tests/sandbox-canary-1.17.118.py` (stubs the pre-check).
* **Not run here:** real systemd, root, Linux and Django. `tests/sandbox-canary-1.17.121.sh` runs on dev02 only.

## dev02

Update dev02 to Core 1.17.121 and export the contract as usual. Then run `sudo bash tests/sandbox-canary-1.17.121.sh` as root and send back the whole output. The 1.17.120 DNS and credential results still decide the later patches.

## Module-facing changes

None. A search of `modules/` finds no user of `core.sandbox`, `sandbox_runners` or the helper's canary code, which is root-only and not part of any public contract. The new `ready` argument is optional.
