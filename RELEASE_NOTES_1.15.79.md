# Tec-Tac Framework 1.15.79

Security/correctness follow-up against the independent Core 1.15.42 review and the 1.15.67 status tracker, rebased onto 1.15.78-1.

## Scheduler
- Re-check the original user actor, action permission, account activity, and Tactical client/site/endpoint scope at run time. Revoked authority produces a skipped `AuthorizationRevoked` run instead of executing with stale authority.
- Contain failures per schedule so one malformed/deleted schedule or module action cannot abort the scheduler tick.
- Replace unbounded run prefetch in the schedule list with a scalar latest-status subquery; explicit detail responses remain bounded to the newest 50 runs.

## Audit, MFA and session security
- Browser audit writes now reject Core provenance and permissionless modules and use dedicated authenticated per-user/IP throttles.
- MFA backup-code generation now uses dedicated authenticated proof-attempt throttles rather than Tactical login throttles.
- Session-security policy changes require effective superuser authority; trusted proxy networks reject broad/public ranges and policy changes are force-audited.
- Revoked session/credential fingerprints are retained as security tombstones so cleanup cannot make revoked API-key or Django-session credentials trusted again.

## Module lifecycle and state
- Make `module-state.lock` root-owned `0600` so the Tactical service account cannot hold the privileged mutation lock.
- Serialize v1 module-state read/modify/write with `flock`, matching v2, and use unique fsynced temporary JSON files in both privileged module helpers.
- Harden rollback/module-recovery extraction with member validation and Python `tarfile` data filtering.

## Backup and housekeeping
- Enforce retention minimums of one day / one retained item and protect active staging/rollback categories from housekeeping deletion.
- Move privileged fixed-tree archives and SCP verification scratch data under the server-backup staging root instead of global `/tmp`.
- Remove verified remote backup staging copies after upload; clean known-invalid local bundle artifacts created before destination transfer while preserving complete bundles when a destination verification fails.

## Repository and installer hardening
- Redact repository/source URLs and raw repository errors from non-manager responses.
- Preserve requested-by/version/operation metadata in system-update install requests.
- Pin the Core release workflow `actions/checkout` action by commit SHA.
- Expand privileged publisher-import ownership checks to framework package parents and `tec_tac/__init__.py`.
- Use absolute privileged `python3`, `bash`, and `git` command paths.
- Publish `ui_url` in the TOTP enrollment OpenAPI contract.
- Keep Tec-Tac root config parsing data-only and reject CR/LF in generated config values to prevent line/key injection.

## Verification
- Adds `tests/review-followup-1.15.79.py` for the review-tail regressions.
- Existing root-Python, extraction, immutable-claim, superuser-guard, session-fingerprint, trust-policy, role-save, restore-rollback, scheduler-durability and backup-hardening regressions remain green.

## Deferred by design decision
- **N1 restore-bundle trust boundary is not changed in this release.** The supplied status tracker explicitly requires Johan's decision before implementation (server-signed restore bundles vs a fixed restore destination allow-list/root-owned installer-source design, or another approved approach).
