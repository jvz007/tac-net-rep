# Signed System Update Source Releases

Framework 1.15.46 hardens the Tec-Tac publisher tool schema-2 tree-signing path so the privileged worker independently establishes trust.

A signed repository root contains `tec-tac-release.json` (schema 2) and `tec-tac-release.json.sig`. The detached Ed25519 signature covers the exact manifest bytes. The manifest covers every release file by canonical relative path, byte size and SHA-256. Only root `.git` metadata and the two root signing outputs are excluded.

The web tier still verifies release metadata for operator visibility and staging, but its trust result is **not** authority for root execution. The Tactical-writable job contains only the requested component, staged upload id and downgrade request. On dispatch the root helper moves the staged archive into a root-only running area, extracts it, and independently verifies the complete tree against root-owned `/etc/tec-tac/trusted-publishers` and `/etc/tec-tac/policy/update-trust-policy.json`. Framework requires publisher permission `framework.update`; UI requires `ui.update`.

Only after root verification does the worker back up the installed source. The verified staged bytes are committed into a local `tec-tac/verified/...` Git branch; web-tier source type, branch and commit metadata do not control privileged deployment. The resulting execution checkout is then verified against the signed tree again before any installer runs.

All update sources share the same root trust requirement, including stable releases, selected branches and offline uploads. Production defaults to `signed_production`. Development defaults to `signed_development`; unsigned development updates require the explicit root-owned `TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_UPDATES=true` override and are logged as a security warning.

Downgrades require both a superuser request in the web tier and the root-owned `TEC_TAC_ALLOW_SYSTEM_DOWNGRADES=true` flag. This prevents a forged Tactical-writable job from authorizing a downgrade.

The root trust policy is stored under `/etc/tec-tac/policy/`. The Tactical sudo path may strengthen that floor but cannot lower it; lowering requires direct root-console use of the privileged trust helper.

Private signing keys never belong on a Tec-Tac server. Only public publisher policy and public verification keys are installed in the root-managed trust store.

## Remembered update source (1.17.2)

Core remembers a release or branch source for each component and uses it for the online check and as the default when staging. It changes nothing about trust: every staged package is still verified as root. The install job also records where the staged package came from (type, repository, ref, commit) as provenance in the history row. Root never uses it to decide anything. See `update-source.md`.

## Refused update (1.17.43)

An installer that refuses in its own pre-flight, before it changes anything, returns status 78 (`EX_CONFIG`). Core's `install.sh` does so
for the two checks that run before its first change: the installer payload layout and the system Python with its `cryptography` support.
The UI installer does the same from the UI release that ships it.

When the update helper sees status 78 it does not run the installer again, and it does not verify a rollback. The installed version never
changed, so it restores only the source checkout, so that `/opt/tec-tac-src` matches the installed version again. The job then ends with
stage `failed-pre-mutation`, status `failed`, and `rollback` set to `{performed: false, status: not-required, reason: installer-refused}`. Its
error names the installer's own reason and says the installed version is unchanged. `ROLLBACK FAILED` is not written for a refusal. If the
source restore itself fails, the log says `SOURCE RESTORE FAILED`, and the job ends `rollback-failed`.

Any other non-zero status keeps the full rollback as before: restore the previous component, run the installer again, and verify.

## Rollback and a failed verification check (1.17.96)

`install.sh` runs its verification checks through one function with one time limit, 120 seconds each (it was 45; the contract catalog check takes 46 s on the dev server). When a check fails or times out the log names the step, the elapsed seconds, the exit status (124 is the time limit) and the last 20 output lines with passwords, secrets, tokens and keys masked. A failed check ends the installer with status 79 (`INSTALL_VERIFY_FAILED_EXIT`) after the usual `[TEC-TAC] ERROR:` line and a `[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying <step>` line. The saved views repair step stays a warning. Since 1.17.97 a passing check prints its output through the same masking, and a failing check prints only the masked last 20 lines, so the full output never reaches the update log.

A rollback must not fail only because one of those checks TIMED OUT (since 1.17.97 the warning is for a timeout only). The files are already restored, so the helper treats this as a warning when the rollback installer stops with status 79, the `[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying <step>` marker AND its own `VERIFY STEP FAILED: <step> (timed out after N s ...` line for that same step, written during the rollback, and the restore, `verify_dynamic_plugins` and the layout check all passed. A check that failed for another reason (a model or RBAC assertion, a missing route, a registry assertion) means the restored Core may not load, so it is `rollback-failed`, and so is the previous version's installer (status 1), whose text cannot prove a timeout. All 12 checks run before the installer restarts the services, so the warning names what may not have run: `incomplete_stages` (`helper scripts`, `timers`, `service restart`), `restart` (`systemctl restart rmm daphne celery celerybeat`) and `advice`. The job keeps `status: failed` (the update failed) and its error, ends at stage `rolled-back`, and `rollback` is `{performed: true, status: warning, version, warning: <step>, installer_exit_status, incomplete_stages, restart, advice}`. The log says `restored <old>, verification warning: <step>` and no `ROLLBACK FAILED`. Any other failure stays `rollback.status: failed` with stage `rollback-failed`: a failing restore (it has no `installer_exit_status`), another installer status or error text, a check that failed without a timeout, or a failing check after the installer. The audit row for a warning reads `<old> was restored; the check after the restore reported a warning, check the server.` with `rollback_status: warning`.

The helper that runs the rollback is the one already installed on the server, so the new classification takes effect from the update after 1.17.96 is installed. The helper's own post-install verification limit is 120 s as well (it was 90).
