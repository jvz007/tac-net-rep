# Tec-Tac Framework 1.17.122

Date: 11 November 2026. `core.sandbox` canary: the credential check now accepts the file systemd really creates, and two held findings of 1.17.121 are closed. **Nothing can run in the sandbox yet.** `SANDBOX_ENABLED` stays `False`; the sudo rule, `install.sh`, the runtime, the registry, the status keys and the public contract `core.sandbox` 1.0.0 are unchanged. The kill switch is not touched.

Request: the `core.sandbox` canary request in `reviews/requests/core.md` ("core.sandbox canary 1.17.120 on dev02: credential check only") stays open. It ends only when the canary on dev02 finishes with `ALL CANARY STEPS PASSED`. This release closes the two 1.17.121 held findings: **Medium** "check 4d `OK$` can never match the padded canary table" and **Low** "credential run holds only 3 s". **Release manager: mark both closed in `reviews/core/BACKLOG-new-findings.md` when this signs.**

## What changed and why

All code changes are in `scripts/sandbox-helper.py` (the root-only helper). No Django file changed.

### 1. Credential check (dev02 diagnosis)

On dev02 the LoadCredential file is `root:root`, mode `440`, with a POSIX ACL entry `user:<unit uid>:r--`. The 1.17.120 rule wanted the unit's own group, so it refused a correct file.

* **The probe reports what it found.** The unit prints the file's owner, group and mode, the unit's own uid and gid, and the full ACL. It reads the ACL with a short `python3 -I -c` program that decodes the `system.posix_acl_access` attribute with the standard library, so the check does not depend on `getfacl`. The probe text holds no quote, `%` or `$`. The detail names owner, group, mode and every ACL entry on OK and on NO, for example `arrived, owner root, group root, mode 440, ACL user::r--, user:61908:r--, group::r--, mask::r--, other::---, source removed`. It never prints the token or the path.
* **New acceptance, fail closed.**
  * Mode exactly `0400` or `0440`, no "other" bit.
  * Owner is root or the unit's uid. Group is root or the unit's own gid.
  * The unit's own uid and gid are in the dynamic range (61184 or higher).
  * If an ACL exists: the owner, group and other entries are there; the only named entry is `user:<unit uid>` with read only; no named group; the mask and every entry except the owner entry grant no write; no entry grants execute; "other" grants nothing.
  * A missing, garbled or truncated ACL answer fails. A plain file with no ACL and the old `0400` owner shape stays accepted.
* **The 1.17.120 "any dynamic group" acceptance is removed.** A group that is neither root nor the unit's own gid is refused, even inside the dynamic range.
* **Canary rows.** The row "another dynamic user reads the credential file" keeps the 1.17.121 rule unchanged (OK only on `DENIED` with file and unit proven present before and after; `MISSING` is NOT RUN). The in-unit canary runner's "credential mode" row still accepts `0o400` and `0o440` (mode only; the ACL rule lives in the selftest).

Decision recorded as information (`reviews/questions/core.md`, Core 1.17.122, Question 1): Question 3 of 1.17.120 (credential mode) is tightened from "any dynamic gid" to "the unit's own gid or root, plus a one-user ACL". This narrows trust and widens no signed decision.

### 2. Check 4d (Medium)

`format_table` padded every cell, so the verdict "OK" ended in spaces when another verdict in the column was longer ("ATTACK SUCCEEDED"). The 1.17.121 check `grep 'OK$'` could never match. Two layers fix it:

* `format_table` now strips the trailing spaces of the header and of every row. The dashes line is unchanged. Every consumer of the table benefits.
* The new script `tests/sandbox-canary-1.17.122.sh` (a copy of 1.17.121; the old script stays untouched) uses padding-safe patterns. 4d picks the row by its exact attack text first (`grep -F`), then needs `OK[[:space:]]*$`. A `NOT RUN` or `ATTACK SUCCEEDED` row cannot match. The three awk counters end in `[[:space:]]*$`.

**Audit of every other `grep` and `awk` in the script**

| Place | Reads | Result |
|---|---|---|
| Helper source greps (guards) | the helper file | not a table; safe |
| `sudo -l` list greps (3a, 3b) | sudo output | not a padded table; safe |
| 4a `'^CANARY PASSED$'` | a `print()` line | no padding, no trailing space; safe |
| 4c `grep -q 'another dynamic user...'` | the table | substring match; safe |
| 4d | the table | **fixed** (above) |
| the three awk counters | the table | **fixed** (above) |
| 5c `grep` on `canary.json` | JSON file | not a table; safe |
| 5j `grep` on `audit.jsonl` | JSON lines | not a table; safe |
| Step 2 selftest table | printed by Python with `%-26s %-5s %s`; the detail is last | no trailing pad unless the detail is empty; no pattern reads it |

### 3. Credential hold (Low)

`_credential_rows` held the credential run for a literal 3 s. The helper waits 1.5 s, searches the host for the token, checks the file, runs the foreign-reader unit and checks again. On a slow server that did not fit. The hold is now the named constant `CANARY_CRED_HOLD_SECONDS = 10`, under `canary_row`'s 20 s `run_seconds`, so the run still ends on its own and the limit never fires first. The order of the steps is unchanged. The optional lower timeout for the three `_holders_search` commands was **not** built: those commands already have a 15 s limit each, and changing the call would break the tests that stub `_holders_search(token, unit)`. No effect on the selftest or on real runs.

### 4. New canary script

`tests/sandbox-canary-1.17.122.sh`: same steps as 1.17.121. The helper guard also needs the ACL decoder (`_PROBE_ACL`). Step 2 prints the credential row of the selftest on its own line. The patterns in step 4 are padding-safe.

## Tests

* New: `tests/sandbox-credential-acl-1.17.122.py` (accepted and refused shapes through the fake runner and the pure functions; the exact dev02 shape; a binary decode test of the in-unit program against hand-built bytes; the detail text on OK and NO), `tests/sandbox-canary-table-1.17.122.py` (runs the real 4d pipeline and awk counters taken out of the script on a `format_table` table with bash), `tests/sandbox-credential-hold-1.17.122.py` (virtual clock; the old 3 s hold turns the same stubs into NOT RUN, so the test can fail), `tests/sandbox-canary-script-1.17.122.py` (static checks of the new `.sh`).
* Updated: `tests/sandbox-fake-runner-1.17.120.py` (the fake credential answer now carries the ACL line and defaults to the dev02 shape), `tests/sandbox-credential-mode-1.17.120.py` (the "any dynamic gid" and "root group" cases follow the new rule; the detail text), `tests/sandbox-selftest-1.17.116.py` (its own fake sends the ACL line).
* **Not run here:** real systemd, root, Linux, Django and dev02. `tests/sandbox-canary-1.17.122.sh` runs on dev02 only.

## dev02

Update dev02 to Core 1.17.122 and export the public contract as usual. Then run `sudo bash tests/sandbox-canary-1.17.122.sh` as root and send back the whole output. It prints the credential row with owner, group, mode and ACL, which proves the diagnosis.

## Module-facing changes

None. A search of `modules/` finds `core.sandbox` used only by `modules/ai` (`providers.py`, `runner.py`) and `reportmanager` (`ai_schema`), through `tec_tac.sandbox`. None reads the selftest credential detail, the canary table or `hold_seconds`. The public contract surface (`sandbox.py`, `sandbox_views.py`, `contracts.py`) is unchanged.

## Correction (Core 1.17.123), 11 November 2026

Section 1 above, and Question 1 of Core 1.17.122 in `reviews/questions/core.md`, call the credential change a narrowing. That is not fully true. The 1.17.122 rule was **not a pure narrowing of 1.17.120**:

* it **newly accepted root as owner or group** of the credential file (1.17.120 accepted only the unit's own dynamic group), and
* it **added the uid floor of 61184** for the unit's own user and group ids,
* while it removed the "any dynamic gid" case.

So a file that 1.17.120 refused (root:root, mode 440) became acceptable, as long as its ACL passed. Core 1.17.123 narrows group root to the one case that works: the file's ACL exists and holds the named entry `user:<unit uid>` with read only. Mode 400 or 440 `root:root` with no ACL is now refused with a plain reason, because the unit could not read it anyway. The owner rule is unchanged. The dev02 shape (root:root, 440, ACL `user::r--`, `user:<uid>:r--`, `group::---`, `mask::r--`, `other::---`) stays accepted. This text only corrects the record; no 1.17.122 code is touched.
