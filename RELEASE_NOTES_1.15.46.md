# Tec-Tac Framework 1.15.46

## Privilege-boundary hardening (P0 S1-S8)

- Root System Update and module lifecycle workers no longer trust Django/job-file `release_trust`, `publisher_trust`, package hashes, or source provenance as execution authority. Staged bytes and signing sidecars are claimed into root-only running storage and independently verified before privileged execution.
- Adds the root-owned `/usr/local/lib/tec-tac-security/privileged-trust.py` verifier. It reads only root-owned `/etc/tec-tac/trusted-publishers`, `/etc/tec-tac/policy/update-trust-policy.json`, and `/opt/tec-tac/etc/tec-tac.conf`; trust-path/environment process overrides are ignored.
- Production now defaults to `signed_production`; development defaults to `signed_development`. Legacy `unsigned` policy is raised during install. Unsigned execution is permitted only through explicit root-owned development overrides.
- The authoritative trust policy moves to `/etc/tec-tac/policy/` (`root:root`). The Tactical sudo path may strengthen the floor but cannot lower it; lowering requires direct root-console administration.
- Framework and UI source releases now require explicit publisher permissions `framework.update` and `ui.update`. Legacy publisher `system.update` permission is migrated to those two explicit permissions during install; publishers without prior update authority are not automatically granted it.
- All System Update sources, including releases, branches and offline packages, converge on the same root signature/trust verification. Verified staged bytes are committed into a local `tec-tac/verified/...` source branch; mutable web-tier branch/commit metadata no longer controls privileged deployment.
- System Update execution performs a second root verification of the actual checkout before running the installer. Pre-verification failures occur before backup/mutation and are reported as rollback not required.
- Module Manager v1/v2 workers independently verify detached package/bundle signatures and root trust before lifecycle execution. V2 additionally binds plan module IDs, versions and rename sources to facts extracted from the signed artifact manifests.
- Adds `core.privileged_operations` for module installation/removal, repositories, hotfix management, System Updates, Diagnostics/Housekeeping privileged surfaces, and Core server maintenance. Tactical `can_do_server_maint` no longer grants these code/root lifecycle operations.
- Only an effective Tactical/role superuser can grant or revoke `core.privileged_operations`; assignment changes are audited.
- Trust-policy lowering requests and system-downgrade requests are superuser-gated and audited. System downgrades also require root-owned `TEC_TAC_ALLOW_SYSTEM_DOWNGRADES=true` so a forged Tactical job cannot authorize one.
- Session fingerprints are derived from the authenticator DRF actually accepted. Knox credentials are bound to the authenticated token digest; Tactical API keys are bound to the resolved API-key record. Conflicting credential headers fail closed.
- TOTP QR remains protected by the Core `SessionAuthenticated` guard introduced in 1.15.45.

## Upgrade notes

- Effective superusers keep privileged lifecycle access automatically.
- Non-superuser roles that previously relied on Tactical `can_do_server_maint` must be explicitly granted `core.privileged_operations` by an effective superuser if they should retain Tec-Tac privileged lifecycle access.
- Trusted publishers that used legacy `system.update` are migrated automatically to `framework.update` and `ui.update`. Any publisher that did not already have update authority must be explicitly updated by a root administrator before it can sign Framework/UI releases.
- System Python must provide the `cryptography` package for root-side signature verification. The installer fails closed if it is unavailable.
- Root helpers for module hotfixes, housekeeping, backups and other privileged subsystems remain separate follow-up review items where the independent review explicitly marked them “not yet reviewed.”
