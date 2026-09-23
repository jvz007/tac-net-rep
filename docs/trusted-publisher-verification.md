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
10. re-runs trust verification immediately before install dispatch;
11. records package SHA-256 and the trust result in the durable lifecycle job;
12. has the root-owned lifecycle worker re-hash staged bytes before executing the installer.

A changed package therefore fails even if the staging metadata itself is modified after initial inspection.

## Transitional unsigned policy

Unsigned normal modules remain temporarily installable and are returned with:

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

Core reads the environment from:

1. `TEC_TAC_ENVIRONMENT` process environment;
2. `TEC_TAC_ENVIRONMENT` in `/opt/tec-tac/etc/tec-tac.conf`;
3. default `production`.

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

System Updates also understands the publisher tool's schema-2 source-tree format. A signed repository root contains `tec-tac-release.json` and `tec-tac-release.json.sig`. Core verifies the exact manifest bytes with the locally trusted active Ed25519 key, then requires the manifest to match the complete source tree by canonical relative path, byte size, and SHA-256. The execution worker pins the verified manifest/signature hashes into the update job and re-checks both the extracted staged tree and the Git checkout that will execute the installer. See `docs/system-update-signed-releases.md`.
