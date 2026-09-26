# Trusted Publisher Verification

Framework 1.15.36 introduces the Core-owned trusted publisher verification boundary for Tec-Tac module packages.

## Security model

The detached Ed25519 signature covers the exact package ZIP bytes. `release.json` is not signed and is therefore treated only as selector and consistency metadata. Core never trusts `publisher_id`, `key_id`, environment, or requested permissions from release metadata by themselves. They must resolve to a matching local policy under the root-managed trust store.

Default trust store:

```text
/etc/tec-tac/trusted-publishers/
  <publisher-id>/
    publisher.json
    public.key
```

The trust store is root-owned. The Tactical service account may read it but must not modify it.

## Accepted release set

A signed module release consists of:

```text
module-version.zip
module-version.zip.sig
module-version.release.json
```

The signature file format is:

```text
ed25519:<base64-signature>
```

Release metadata schema 1 requires:

```json
{
  "schema": 1,
  "publisher_id": "tech_flow_dynamics-dev",
  "key_id": "tech-key-dev-1025",
  "filename": "serverhealth-0.1.0.zip",
  "sha256": "<lowercase SHA-256>",
  "signature": "serverhealth-0.1.0.zip.sig",
  "algorithm": "Ed25519",
  "environment": "development"
}
```

`environment` may be omitted by older signing-tool output; in that case Core uses the locally installed publisher policy environment as the release environment. The publisher policy must still match the Core server environment.

## Publisher policy

Core supports a key list for rotation and revocation:

```json
{
  "schema": 1,
  "publisher_id": "tech_flow_dynamics-dev",
  "display_name": "Tech Flow Dynamics Development",
  "status": "trusted",
  "environment": "development",
  "permissions": [
    "module.install",
    "server_maintenance.register"
  ],
  "keys": [
    {
      "key_id": "tech-key-dev-1025",
      "status": "active",
      "algorithm": "Ed25519",
      "public_key_file": "public.key"
    }
  ]
}
```

A legacy single-key policy using top-level `key_id`, `key_status`, `algorithm`, and `public_key` is also accepted.

## Verification order

Before module installation Core:

1. reads only package manifests/metadata needed for inspection;
2. hashes the exact staged archive and compares it to release metadata;
3. resolves `publisher_id` and `key_id` against the local trust store;
4. requires publisher status `trusted` and key status `active`;
5. requires Ed25519;
6. checks canonical package/signature filenames;
7. checks server, publisher, and release environment consistency;
8. enforces required publisher permissions;
9. verifies the detached signature against the exact archive bytes;
10. re-runs web-tier trust verification immediately before install dispatch as defence in depth;
11. sends only an opaque staged upload id and requested operation into the privileged boundary;
12. the root-owned worker claims the package and signing sidecars into a root-only running area; and
13. the root-owned worker independently verifies the actual package bytes, active key, publisher environment, publisher permissions, and root-owned acceptance policy before executing lifecycle code.

A forged `publisher_trust`/`release_trust` claim in a Tactical-writable job file is not an execution authority. Changed, unsigned, or untrusted bytes fail in the root worker even if Django previously accepted them.

## Unsigned development override

Fresh installs are signed-by-default. Production defaults to `signed_production`; development defaults to `signed_development`. An unsigned module is executable only when the server is in development mode **and** the root-owned Tec-Tac configuration explicitly enables `TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_PACKAGES=true`. Unsigned production installs are rejected. An unsigned package is represented as:

```json
{
  "signed": false,
  "verified": false,
  "trusted": false,
  "state": "unsigned"
}
```

A package requesting a privileged publisher permission is fail-closed and requires a trusted signature.

## Manifest publisher permissions

An extension may declare the publisher permissions required for installation:

```json
{
  "publisher_permissions": [
    "server_maintenance.register"
  ]
}
```

Framework 1.15.36 supports:

- `module.install`
- `server_maintenance.register`

`module.install` is automatically required for every signed package. Declaring `server_maintenance.register` makes signing mandatory and the local publisher policy must explicitly grant it.

Reportsets may not declare publisher permissions.

This is intentionally a narrow signing/trust contract. Broader module capability/privilege declarations belong to the later Core privilege-manifest security layer.

## Server environment

Core reads the security environment from the root-owned `/opt/tec-tac/etc/tec-tac.conf`, defaulting to `production`. Privileged trust verification deliberately ignores process-environment overrides for the environment and trust-store path.

All privileged lifecycle helpers follow the same rule: caller-supplied `TEC_TAC_*` environment variables are stripped before privileged child processes are launched. Only narrowly scoped values constructed from root-owned Core state (for example the deployed UI root for a UI sync) are added back explicitly. System Update signed-release minimum-version policy is likewise read only from the root-owned configuration/defaults, never from process environment.

The installer writes the selected value into the managed Tec-Tac configuration. Development servers should explicitly set:

```text
TEC_TAC_ENVIRONMENT=development
```

A development publisher must not be installed as a production publisher merely to bypass environment checks.

## Offline Module Manager upload

The module inspect endpoints accept these multipart fields:

```text
package          required archive
signature        optional detached .sig
metadata         optional .release.json
```

`release_metadata` is accepted as an alias for `metadata`.

If either signing sidecar is supplied, both are required. Invalid signed packages are rejected rather than downgraded to unsigned.

## Repository releases

Repository index entries may optionally publish:

```json
{
  "signature": "serverhealth-0.1.0.zip.sig",
  "release_metadata": "serverhealth-0.1.0.release.json"
}
```

Core downloads both companions and applies the same verification path used for local uploads. Repository trust labels remain provenance only and never replace publisher verification.

## Public Core surface

```python
from tec_tac.trusted_publishers import (
    list_trusted_publishers,
    verify_release_files,
)
```

`verify_release_files` is Framework/internal infrastructure. Module code should not use it to create a private trust model. `list_trusted_publishers` is read-only metadata for diagnostics and administrative tooling.

## Diagnostics

Troubleshooting & Diagnostics exposes `core.security.publisher-trust`, including the configured trust-store path and safe publisher metadata. Private keys are never stored or returned.

## Invariants

- Private publisher keys never reside on Tec-Tac/Tactical servers.
- Repository origin is not publisher trust.
- Signed metadata identity is not proof of trust.
- A valid signature proves possession of an approved key, not unlimited privilege.
- Revoked or unknown keys fail closed.
- Invalid signed packages never fall back to unsigned handling.
- Unsigned privileged packages are rejected.
- Exact package bytes are verified before module code executes.

## Signed Framework source trees (publisher tool v0.2.0)

System Updates also understands the publisher tool's schema-2 source-tree format. A signed repository root contains `tec-tac-release.json` and `tec-tac-release.json.sig`. The web tier verifies it for inspection, but the root worker does not trust that result: it independently verifies the extracted staged tree against `/etc/tec-tac/trusted-publishers`, applies the root-owned trust floor, deploys only those verified bytes into the local source checkout, and verifies that execution checkout again before `install.sh`. Framework releases require publisher permission `framework.update`; UI releases require `ui.update`. See `docs/system-update-signed-releases.md`.

## Global acceptance policy

Tec-Tac maintains one global minimum acceptance level for System Updates and Module Management. The authoritative policy is `/etc/tec-tac/policy/update-trust-policy.json`, owned by `root:root` and not writable by the Tactical service account. Production defaults to `signed_production`; development defaults to `signed_development`. The web tier may request a stronger policy through the narrow root helper. Lowering the root trust floor requires direct root-console administration so compromise of the `tactical` account cannot disable signing.

Ordered levels:

1. `unsigned`
2. `signed_development`
3. `signed_production`
4. `secure_signed`

A package must meet the configured global floor **and** every component/module-specific rule. Lowering the global floor never disables existing requirements such as privileged module publisher permissions or component-specific signed-release enforcement.

Publisher environment isolation remains independent. A development signing identity is not accepted on a production server simply because the global floor is `signed_development`.

### Secure Signed

`secure_signed` is a high-assurance production signing tier. It requires:

- a valid trusted Ed25519 signature;
- publisher environment `production`; and
- `assurance: "secure"` on either the selected key record or the publisher policy in the local trusted-publisher store.

Key-level assurance takes precedence over publisher-level assurance. This flag is local trust policy; it is deliberately not asserted by untrusted package metadata.

Example key record:

```json
{
  "key_id": "tech-key-prod-2026",
  "status": "active",
  "algorithm": "Ed25519",
  "public_key": "public.key",
  "assurance": "secure",
  "permissions": ["module.install", "framework.update", "ui.update"]
}
```
