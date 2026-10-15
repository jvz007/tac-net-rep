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

## Module ids in an index

A repository entry's `id` must use only letters, digits, `-` and `_` (`[A-Za-z0-9_-]+`). A dot is not allowed (1.17.39). A dot is the separator in capability ids and permission prefixes, so a dotted id would make the owner of a capability or permission unclear. The rule is the same one in `module-identifiers.md`. An entry with a dotted id is skipped and recorded with a reason that lists the allowed characters (see Skipped entries below).

## Skipped entries (1.17.39)

Core checks each entry of the index on its own. An entry that fails a check is **skipped**: Core records it and keeps the rest of the index. A skipped entry is never offered, staged or installed.

Each skipped entry appears in the sync answer, in the repository status and in the online catalog as a record of this shape:

```json
{"index": 2, "id": "checks", "version": "0.4.0", "reason": "Repository module checks 0.4.0 requires a valid SHA-256 digest."}
```

- `index` is the entry's position in the `modules` array (starting at 0).
- `id` and `version` are the entry's own text, cut to 100 characters with control characters removed. A value that is not text becomes `null`.
- `reason` is the plain-English reason, at most 300 characters. A caller who cannot manage modules sees a generic sentence instead of the reason. `index`, `id` and `version` still show.
- At most 100 records are listed. `sync.skipped_count` is the real total, so a count above 100 is possible.

Two rules go beyond one bad entry:

- **Duplicates.** When two entries have the same `id` and `version`, Core skips **both** copies with the reason `duplicate`. Neither can be trusted, so neither is used.
- **All entries invalid.** When the index has entries and none of them is valid, the sync fails (status `error`, error text "Every one of the N entries in the repository index was invalid"). The previous cache is kept, so a broken publish cannot empty a good catalog. An empty `modules` array is not a failure: it syncs with `module_count` 0.

The status stays `ok` when at least one entry is kept. Core adds no new status value.

Whole-index failures are still failures and keep the previous cache: an index that is not schema 1, a `modules` value that is not an array, a fetch failure, a size limit, and an address refused by the SSRF guard (for example a `download` that points to a private or local address without `trust=internal`). A download host that does not resolve counts as a skipped entry.

## Informational release fields (1.17.39)

Five optional fields on each entry are passed through to the catalog as information. Core shows them and **never acts on them**.

| Field | Type | Rule |
| --- | --- | --- |
| `channel` | string | Stripped, control characters removed, at most 64 characters. Null when absent, not text or empty. |
| `lifecycle` | string | The same rule as `channel`. |
| `downgrade_policy` | string | The same rule as `channel`. |
| `signing_environment` | string | The same rule as `channel`. |
| `recommended` | boolean | Strict `true` or `false`. Null when absent or not a boolean. |

A bad value never invalidates the entry: it becomes null. The values are not checked against a list. They are never used for selection, ordering, compatibility, staging or any refusal. A module release is chosen exactly as before, whatever these fields say. The online catalog copies them from the selected release onto each module item (null when nothing is selected, or when the cache was written before 1.17.39), and onto each release row.

Core does not refuse a downgrade, does not warn about a revoked module, and does not seed a default repository. Those decisions are not built.

## What the online catalog shows (1.17.41)

`GET /api/tfd/modules/catalog/online/` lists what the enabled repositories offer. It reads each repository's cache and never calls a repository: the manual Sync action is the only way a repository is read.

- `modules[]` holds only the modules that at least one enabled repository's cache offers. Each item still carries `installed`, `installed_version`, `update_available`, `compatible`, `available_sources` and `releases`. `count` is the length of `modules`.
- `installed_only[]` (`id`, `name`, `installed_version`, `installed_source`) holds the installed modules that no enabled repository offers. They are not presented as available. A module pinned to a repository that does not offer it is `source_conflict` only when another repository offers it. Otherwise it is in `installed_only`.
- `availability` says what the catalog can honestly say: `state` is `no_repository` (no enabled repository), `not_synced` (enabled, none synced yet), `sync_failed` (every enabled repository's last sync failed and none has a cache), `empty` (synced, no modules) or `ready`. It also carries `enabled_repositories`, `synced_repositories`, `installed_only_count` and a one-sentence `message` that is empty when the state is `ready`. For example: "No module repository is set up. Add one under Repositories, then sync it."
- A cache kept after a failed sync still counts as synced, so its modules stay offered.
- A person who cannot manage modules gets the same redaction as before and never sees a repository address.

Before 1.17.41 the list was built from the modules in the repositories and the modules installed, so with no repository the catalog showed only what was already installed.

## Entitlement

Repository sync, the online catalog listing and package download are **not gated on any entitlement or licence** (1.17.39). Core does not call the licensing capability on those paths, and a licence check, where a module needs one, stays in that module.

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

### Proxy-aware fetches

Repository fetches honor the service environment's `HTTP_PROXY` / `HTTPS_PROXY` and `NO_PROXY` settings. Core still resolves and validates every repository or redirect target against the SSRF policy before contacting the configured proxy. When a proxy is used, Core sends the proxy a connection to the already-approved pinned destination address rather than allowing the proxy to choose a different target address. Proxy URLs must use an `http://` proxy endpoint.
