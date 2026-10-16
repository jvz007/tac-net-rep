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
