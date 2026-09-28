# Tec-Tac Core 1.15.148

## Infrastructure and privileged-read closure

This release closes the remaining M18, L04, L07, L36 and L61 review gaps without changing unrelated runtime behavior.

### L36 — server maintenance no-follow job reads

`server-maintenance-helper.load_job()` now uses the existing descriptor-based `_read_json_nofollow()` path. Symlinked job files are rejected and FIFO/device substitutions are opened non-blocking then rejected as non-regular files.

### M18 — executable review/test hygiene

The historical 1.15.52 regression suites are executed by the new closure test against the current tree. Root-required claim/boundary tests are asserted to execute only through `tests/root-required-foundation.sh`, while normal foundations may still perform harmless presence checks.

### L04 — v1 staged metadata boundary

Behavioral coverage now exercises the real v1 `_read_json_nofollow()` staged-metadata reader and proves both symlink and FIFO substitution are rejected.

### L07 — trusted Bash resolution

Behavioral coverage now executes every privileged helper's `_trusted_bash()` resolver with controlled candidate metadata, proving fallback between `/bin/bash` and `/usr/bin/bash` and rejection of writable candidates.

### L61 — portable privileged-helper regressions

The three review-hygiene tests are asserted to be wired into the normal review runner and are executed under the unprivileged `nobody` account when the environment permits it.

## Regression coverage

- `tests/infrastructure-closure-1.15.148.py`
- `tests/review-hygiene-foundation.sh`
- `tests/server-maintenance-foundation.sh`
- existing Module Management and System Update foundations
