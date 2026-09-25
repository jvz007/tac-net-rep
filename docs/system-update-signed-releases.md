# Signed System Update Source Releases

Framework 1.15.46 hardens the Tec-Tac publisher tool schema-2 tree-signing path so the privileged worker independently establishes trust.

A signed repository root contains `tec-tac-release.json` (schema 2) and `tec-tac-release.json.sig`. The detached Ed25519 signature covers the exact manifest bytes. The manifest covers every release file by canonical relative path, byte size and SHA-256. Only root `.git` metadata and the two root signing outputs are excluded.

The web tier still verifies release metadata for operator visibility and staging, but its trust result is **not** authority for root execution. The Tactical-writable job contains only the requested component, staged upload id and downgrade request. On dispatch the root helper moves the staged archive into a root-only running area, extracts it, and independently verifies the complete tree against root-owned `/etc/tec-tac/trusted-publishers` and `/etc/tec-tac/policy/update-trust-policy.json`. Framework requires publisher permission `framework.update`; UI requires `ui.update`.

Only after root verification does the worker back up the installed source. The verified staged bytes are committed into a local `tec-tac/verified/...` Git branch; web-tier source type, branch and commit metadata do not control privileged deployment. The resulting execution checkout is then verified against the signed tree again before any installer runs.

All update sources share the same root trust requirement, including stable releases, selected branches and offline uploads. Production defaults to `signed_production`. Development defaults to `signed_development`; unsigned development updates require the explicit root-owned `TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_UPDATES=true` override and are logged as a security warning.

Downgrades require both a superuser request in the web tier and the root-owned `TEC_TAC_ALLOW_SYSTEM_DOWNGRADES=true` flag. This prevents a forged Tactical-writable job from authorizing a downgrade.

The root trust policy is stored under `/etc/tec-tac/policy/`. The Tactical sudo path may strengthen that floor but cannot lower it; lowering requires direct root-console use of the privileged trust helper.

Private signing keys never belong on a Tec-Tac server. Only public publisher policy and public verification keys are installed in the root-managed trust store.
