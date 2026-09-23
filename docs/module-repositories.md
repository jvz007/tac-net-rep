# Tec-Tac Module Repositories

Framework 1.7.0 adds multiple online module repositories to Module Management v2.

## Design contract

Repositories are metadata sources only. A repository index describes available module packages; Tec-Tac still downloads each package into the existing staging area, verifies its SHA-256 digest, re-inspects the package manifest, resolves dependencies, and uses the existing extension installer.

Installed modules may record repository provenance in `module-state.json`. When provenance exists, Tec-Tac keeps that module pinned to the recorded repository. Another repository may advertise the same module, but it cannot silently take over updates. Changing source requires an explicit source-change request.

## Repository index

A repository URL points to a schema 1 JSON document:

```json
{
  "schema": 1,
  "repository": {
    "id": "techflow-official",
    "name": "Tech Flow Official"
  },
  "modules": [
    {
      "id": "checks",
      "name": "Checks",
      "description": "Endpoint check management and reporting.",
      "version": "0.4.0",
      "download": "packages/checks-0.4.0.zip",
      "sha256": "<64 lowercase hexadecimal characters>",
      "dependencies": {},
      "optional_dependencies": {},
      "requires": {
        "framework": ">=1.7.0",
        "ui": ">=0.7.0"
      }
    }
  ]
}
```

`download` may be absolute or relative to the index URL. Every package entry requires a SHA-256 digest.

## Multiple repository resolution

Tec-Tac resolves sources in this order:

1. If an installed module has recorded source provenance, that repository remains authoritative.
2. Otherwise enabled repositories are considered by ascending priority number.
3. One repository wins before version comparison occurs.
4. Within that repository, the highest semantic version is selected.
5. Runtime and installed dependency compatibility are reported before a package can be staged.

Equal-priority repositories are ordered deterministically by repository id. Tec-Tac does not choose a lower-priority repository merely because it contains a newer version.

## Repository state

Configuration and cache are stored outside Tactical's source tree:

```text
/var/lib/tec-tac/module-manager/repositories/
├── repositories.json
└── cache/
    └── <repository-id>.json
```

Repository configuration includes local id, display name, index URL, enabled state, priority, trust label, and timestamps. Authentication secrets are not supported in schema 1 and must not be embedded in repository URLs.

## Trust labels

`official`, `internal`, and `custom` are provenance labels for operators. They do not replace package hash verification or package inspection.

## Online install flow

```text
Repository sync
      ↓
Online catalog
      ↓
Download + SHA-256 verification
      ↓
Existing Module Management v2 staging
      ↓
Package inspection + dependency plan
      ↓
Existing extension install lifecycle
      ↓
Source provenance committed after success
```

A failed download, digest mismatch, package inspection error, dependency failure, or install failure does not change the installed module's recorded source.

## Bundle artifacts in repositories (1.15.29)

A repository module entry may point to a normal single-module package or to a Tec-Tac bundle ZIP. Core classifies the downloaded artifact structurally after SHA-256 verification.

For a bundle-backed repository entry, the bundle must contain the module ID and exact version advertised by that repository entry. Staging returns the complete bundle preview and dependency plan, so installing an update may also install or update other modules declared by the same bundle.

A repository that wants each member of a suite to appear independently in the online catalog should publish one index entry per member/version. Those entries may reference the same bundle download and SHA-256. The bundle remains a distribution container; dependency, enable/disable, visibility and lifecycle state remain per module.
