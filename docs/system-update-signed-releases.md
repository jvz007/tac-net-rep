# Signed System Update Source Releases

Framework 1.15.46 hardens the Tec-Tac publisher tool schema-2 tree-signing path so the privileged worker independently establishes trust.

A signed repository root contains `tec-tac-release.json` (schema 2) and `tec-tac-release.json.sig`. The detached Ed25519 signature covers the exact manifest bytes. The manifest covers every release file by canonical relative path, byte size and SHA-256. Only root `.git` metadata and the two root signing outputs are excluded.

The web tier still verifies release metadata for operator visibility and staging, but its trust result is **not** authority for root execution. The Tactical-writable job contains only the requested component, staged upload id and downgrade request. On dispatch the root helper moves the staged archive into a root-only running area, extracts it, and independently verifies the complete tree against root-owned `/etc/tec-tac/trusted-publishers` and `/etc/tec-tac/policy/update-trust-policy.json`. Framework requires publisher permission `framework.update`; UI requires `ui.update`.

Only after root verification does the worker back up the installed source. Since 1.17.98 it no longer writes release bytes into the source checkout: see "Source checkouts and the staging copy" below. Web-tier source type, branch and commit metadata never authorise privileged deployment; the bytes root runs are always checked against the signed tree first.

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

## GitHub requests and the rate limit (since 1.17.98)

The online update check is built to stay far below GitHub's API limit (60 an hour without a token, 5000 with one). All metadata calls go through one function. Saved answers are revalidated with ETags, so an unchanged answer costs a 304. A branch refresh sends one request (`GET /branches/<ref>`) and never refreshes the stable release; the release, the VERSION file at a commit and the signature preview are saved on their own and reused. Forced refreshes inside 20 seconds (branch) or 45 seconds (release) of the last check return the saved answer. Workers share one refresh through a lock file. The last rate-limit headers are saved as non-sensitive telemetry (`github_rate_limit`, never the token). When GitHub says the limit is exhausted Core keeps showing the saved answer with `github_rate_limit_error`, and sends nothing until the reset time.

The check and the stage are separate. The stage route accepts the commit the check showed (`commit`, 40 hex) and downloads exactly that commit with no metadata call; a different commit answers 409 `stale_candidate`. The downloaded archive is still verified in full, and the root helper verifies it again.

## Source checkouts and the staging copy (since 1.17.98)

`/opt/tec-tac-src/<component>` is a Git working copy that belongs to the Tactical account, whole (`.git` included), and stays that way. The update helper never changes it to root and never copies release bytes into it. Every Git call runs as the Tactical account, with hooks, the file-system monitor and attribute files switched off.

A Framework or UI update:

1. verifies the downloaded candidate as root (signed tree, publisher permission, root trust floor);
2. gives any path of the checkout that is not the Tactical account's back to it (a path owned by a third account is refused with the `chown` command; a root-owned file with a second hard link is refused, and the message names the top-level folder that holds it; from 1.17.105 the UI checkout's Git-ignored top-level `node_modules` and `dist` are not walked and keep their owner, because nothing runs from them and they are never copied);
3. writes any tracked changes to the update log and restores them to `HEAD`; removes untracked files only when they are generated (Python bytecode, an untracked UI `package-lock.json`); any other untracked file stops the update with the list, and ignored files (`node_modules`, `dist`) are left alone;
4. backs up the checkout (root-held archive);
5. moves the checkout to exactly the commit the candidate came from (`git checkout -B <ref> <sha>` for a branch, a detached `HEAD` for a release; a fetch only brings the objects in, nothing looks the branch up again). An offline package has no commit and leaves the checkout where it is;
6. copies the release into a root-only staging folder (`/var/lib/tec-tac/system-updates/install-stage`, `0700`): exactly the files the signed manifest lists, each compared with the manifest while it is copied, with explicit `root:root` ownership; the privileged verifier then checks the copy, and only then the component's own installer runs, from the copy. A changed `install.sh` (or any changed file) stops the update before any installer runs;
7. applies and checks the runtime ownership rule (Framework: `framework`, `scripts`, `templates` `root:root 0755`; `VERSION`, `tec_tac_package.json` `root:root 0644`; `extensions` and `reportsets` are not touched), the same rule `install.sh` applies through `tec-tac-system-update --runtime-ownership`;
8. records the provenance (repository, ref, exact 40-character commit) in the job and in `/var/lib/tec-tac/system-updates/provenance/<component>.json`;
9. checks that the checkout is owned by the Tactical account, is at that commit and that `git status --porcelain` is empty.

A rollback runs the previous installer from a staged copy of the root-held backup that must verify against the signed release that was installed, puts the runtime ownership rule back, moves the checkout back to its previous `HEAD` and branch as the Tactical account, and puts the previous provenance back. A server-backup restore runs `tec-tac-system-update --install-restored framework|ui`, which stages and verifies the restored checkout the same way (signed release required) before its installer runs.

`install.sh` run from a staging copy records the checkout it was given (`TEC_TAC_STAGED_SOURCE_CHECKOUT`) as `TEC_TAC_FRAMEWORK_SOURCE`. An older installer run by a rollback or a restore records its own folder; the helper sets that one config line back to the checkout afterwards.
