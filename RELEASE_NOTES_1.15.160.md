# Tec-Tac Core 1.15.160

## Tracker closure: M18, L04, L07, L61 and L76

- L04: the v1 lifecycle worker no longer calls `Path.is_file()` on staged metadata before the no-follow read. `claim_job()` now reaches staged metadata through `_read_json_nofollow()` first, so a symlink cannot be followed even during the existence pre-check. The regression invokes the real `claim_job()` path with symlinked staged metadata and proves no claimed request is created.
- L07: each privileged helper resolves and validates Bash exactly once when that helper process starts, stores the root-owned fixed-list result in `TRUSTED_BASH`, and uses that immutable path for runtime subprocesses. The behavioral regression instruments the actual filesystem boundary during module load and proves one resolution per helper process.
- M18/L61: portable privileged-boundary regressions now have their own explicit non-root runner wired into review hygiene. The genuinely root-only artifact-claim regressions remain isolated in `root-required-foundation.sh`, whose output states the root requirement.
- L76: recovery-key import now has direct behavioral coverage proving a symlinked or writable/untrusted recovery trust root is rejected before any trusted key is written. Existing isolated-Python, config-root, bounded import and export-path coverage remains in place.

No unrelated product behavior changed in this release.
