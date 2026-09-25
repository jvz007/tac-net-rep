# Managed Module Hotfixes

Tec-Tac Framework 1.15.25 adds a Core-owned hotfix lifecycle for small, urgent module fixes that need to be deployed before the next normal module release.

A hotfix is a **temporary, declarative file overlay** on one exact installed module version. Core owns inspection, safety checks, backup, application, validation, reload/UI synchronization, audit state, and rollback. Module authors do not ship privileged apply/revert scripts.

## When to use a hotfix

Use a hotfix when all of the following are true:

- the defect is limited to an already-installed Tec-Tac module;
- only a small number of existing module files need replacement;
- no database migration is required;
- no module manifest or lifecycle hook needs to change;
- an urgent fix is required before the next normal module release.

Do **not** use a hotfix for normal feature delivery. The next full module release must include the fix and supersedes any applied hotfixes.

## Core ownership boundary

Core allows a hotfix to replace only existing regular files below the owning module's installed roots:

```text
/opt/tec-tac/extensions/<module-id>/
/opt/tec-tac/reportsets/<module-id>/
```

The following are deliberately blocked from hotfix replacement:

- `tec_tac.json`;
- `tec_tac_ui.json`;
- anything under a `migrations/` directory;
- anything under a `lifecycle/` directory;
- files outside the owning extension/reportset roots;
- symlink targets;
- new files that do not already exist in the installed module.

If one of those changes is required, publish a normal module release instead.

## Package layout

A managed hotfix is a ZIP containing exactly one `tec_tac_hotfix.json`. A single top-level wrapper directory is allowed and recommended. The ZIP follows the same detached Ed25519 release-signing model as module packages: upload the hotfix ZIP together with its `.sig` and `.release.json` sidecars. Production systems normally require a production-trusted signature through the root-owned trust policy; development systems follow their configured trust floor.

```text
cybercns-0.1.13-HF001/
├── tec_tac_hotfix.json
├── README.md                  # optional
└── payload/
    ├── extension/
    │   └── cybercns/
    │       └── secrets.py
    └── reportset/
        └── ...                # only when required
```

The path below `payload/extension/` is relative to the installed extension root. The path below `payload/reportset/` is relative to the installed reportset root.

## Manifest schema

```json
{
  "type": "tec-tac-hotfix",
  "schema": 1,
  "id": "HF001",
  "module_id": "cybercns",
  "base_version": "0.1.13",
  "description": "Allow legitimate ConnectSecure client secrets that resemble Tec-Tac encrypted values.",
  "reload": "django",
  "ui_sync": false,
  "validation": {
    "python_compile": true,
    "django_check": true
  },
  "targets": [
    {
      "component": "extension",
      "path": "cybercns/secrets.py",
      "sha256_before": "<64-char lowercase SHA-256 of the original 0.1.13 file>",
      "sha256_after": "<64-char lowercase SHA-256 of the replacement file>"
    }
  ]
}
```

### Required fields

`type`
: Must be `tec-tac-hotfix`.

`schema`
: Must be `1`.

`id`
: Stable hotfix identifier within the module, for example `HF001` or `CVE-2026-001-HF1`.

`module_id`
: Exact Tec-Tac module ID.

`base_version`
: Exact installed module version. Hotfixes deliberately do not use a broad semver range.

`targets`
: One or more existing files to replace. A hotfix may contain at most 64 targets.

### Target fields

`component`
: `extension` or `reportset`.

`path`
: Module-relative POSIX path. Absolute paths, `..`, hidden path components, migrations, lifecycle hooks, and module manifests are rejected.

`sha256_before`
: SHA-256 of the exact installed file the hotfix expects to replace.

`sha256_after`
: SHA-256 of the replacement file included in the hotfix payload.

Both hashes are mandatory. A matching module version alone is not sufficient proof that the installed file is safe to replace.

## Validation and reload behaviour

The manifest can request:

```json
{
  "reload": "none",
  "ui_sync": false,
  "validation": {
    "python_compile": false,
    "django_check": false
  }
}
```

Core strengthens these values automatically:

- any `.py` target forces Python compile validation, `manage.py check`, and a graceful Django/uWSGI reload;
- any file below `extension/ui/` forces Tec-Tac UI module synchronization;
- a package cannot turn off the safety checks Core requires for the file types it changes.

Hotfix packages cannot provide their own validation command, shell command, lifecycle script, sudo rule, or arbitrary reload command.

## Inspection lifecycle

Hotfix inspection is deliberately fail-closed.

Core verifies:

1. the upload is a bounded ZIP archive;
2. archive paths are safe and contain no symlinks;
3. exactly one `tec_tac_hotfix.json` exists;
4. the manifest schema and target list are valid;
5. the target module extension is installed, with an optional matching ReportSet;
6. extension and reportset versions match;
7. the installed version equals `base_version` exactly;
8. every target remains inside the owning module root;
9. every target already exists as a regular file;
10. every installed target matches `sha256_before`;
11. every payload member matches `sha256_after`;
12. the same hotfix ID is not already applied;
13. detached publisher signature, publisher environment, key status and `module.install` permission satisfy the current trust policy.

No installed files are changed during inspection.

## Apply lifecycle

Applying a staged hotfix queues a privileged Core lifecycle job. The Tactical web process never directly writes module code.

The worker does not trust Django's inspection result as an authorization decision. Root claims an immutable job copy into a root-only running directory, derives the staged package/sidecar paths from the upload UUID, and independently verifies the exact package bytes against the root-owned publisher store and trust policy before any file mutation.

The worker:

```text
claim root-private job + acquire global Tec-Tac lifecycle lock
    ↓
root reverify detached signature + publisher policy
    ↓
revalidate package + module version + before hashes
    ↓
back up every target
    ↓
atomically replace target files
    ↓
verify every after hash
    ↓
Python/Django validation where required
    ↓
UI sync where required
    ↓
graceful Django reload where required
    ↓
record applied-hotfix state
```

If application or validation fails after files have been changed, Core restores the backed-up originals and performs the required runtime refresh before marking the job failed.

## Rollback lifecycle

Applied hotfixes are rolled back in reverse application order.

Before rollback, Core verifies:

- the module still has the original `base_version`;
- the hotfix being rolled back is the latest applied hotfix for that module;
- every current target still matches the hotfix `sha256_after`;
- every backup still matches `sha256_before`.

Core then restores the originals, validates the module, synchronizes/reloads the runtime where required, moves the applied record into history, and removes it from the active hotfix list.

If a target was manually edited after the hotfix was applied, rollback fails closed rather than overwriting unknown code.

## Normal module upgrades supersede hotfixes

A successful normal module install, replacement, or removal retires all currently applied hotfix records for that module into hotfix history.

Example:

```text
cybercns 0.1.13 + HF001 + HF002
        ↓ normal package replacement
cybercns 0.1.14
hotfixes: none
```

Old hotfixes are never automatically replayed onto a new module version.

Module agents must therefore incorporate the hotfix into the next normal module release.

## API contract

All hotfix management endpoints require an authenticated Tactical session and effective Module Manager access (`can_do_server_maint` or effective superuser).

### Inspect/stage

```text
POST /api/tfd/modules/hotfixes/inspect/
Content-Type: multipart/form-data
field: hotfix=<zip>
field: signature=<detached .sig>
field: metadata=<release .json>
```

`package` is also accepted as the hotfix ZIP field and `release_metadata` as the metadata field for generic tooling. The stage response includes `publisher_trust`. Unsigned uploads are accepted only when the root-owned trust policy explicitly permits their trust level.

### Discard staged hotfix

```text
DELETE /api/tfd/modules/hotfixes/<upload-uuid>/
```

### Apply

```text
POST /api/tfd/modules/hotfixes/<upload-uuid>/apply/
```

Returns a lifecycle job with HTTP `202`.

### Job status

```text
GET /api/tfd/modules/hotfixes/jobs/<job-uuid>/
```

### List applied hotfixes

```text
GET /api/tfd/modules/v2/<module-id>/hotfixes/
```

### Roll back latest hotfix

```text
POST /api/tfd/modules/v2/<module-id>/hotfixes/<hotfix-id>/rollback/
```

A non-latest hotfix cannot be rolled back while later hotfixes are still applied.

## Module catalogue status

The Module Management v2 catalogue now includes a lightweight hotfix summary:

```json
{
  "hotfixes": {
    "count": 2,
    "ids": ["HF001", "HF002"],
    "latest": "HF002"
  }
}
```

This allows UI/support tooling to show that the installed module is running a hotfixed code state without inspecting files.

## Persistent state

Managed hotfix state is stored below:

```text
/var/lib/tec-tac/module-manager/hotfixes/
├── staged/
├── jobs/
├── running/
├── logs/
├── backups/
├── applied/
└── history/
```

The Tactical service user may stage packages and lifecycle jobs. Applied state, backups, history and execution are controlled by the root-owned hotfix helper.

The helper is installed as:

```text
/usr/local/sbin/tec-tac-module-hotfix
```

with a narrowly scoped sudo rule that permits only opaque hotfix-job dispatch from the Tactical service account.

## Converting an emergency script hotfix

Older/ad-hoc hotfixes may contain `apply_hotfix.py` and `revert_hotfix.py`. Do not package those scripts in the managed format.

Convert them by:

1. apply the intended source change in a clean copy of the target module version;
2. identify each changed existing file;
3. calculate SHA-256 for the original and corrected file;
4. place the corrected file under `payload/extension/...` or `payload/reportset/...`;
5. describe those exact replacements in `tec_tac_hotfix.json`;
6. let Core own backup, apply, validation and rollback.

For the CyberCNS 0.1.13 emergency hotfix used to design this contract, the existing script's *intent* is retained, while filesystem searching, source-line heuristics, privileged patching and separate revert code are removed from the module package.

## Hash generation

Linux:

```bash
sha256sum original-file.py corrected-file.py
```

PowerShell:

```powershell
Get-FileHash .\original-file.py -Algorithm SHA256
Get-FileHash .\corrected-file.py -Algorithm SHA256
```

Convert PowerShell output to lowercase when placing it in the manifest.

## Agent rules

When another Tec-Tac development agent creates a hotfix:

1. **Do not write an apply/revert installer.** Core owns the lifecycle.
2. **Do not search the server for a file to patch.** Identify the exact module-relative file.
3. **Do not patch Tactical or Core.** Module hotfixes may only target the owning module.
4. **Use the exact base module version.**
5. **Provide before and after SHA-256 for every target.**
6. **Ship complete corrected files, not line-diff instructions.**
7. **Do not include migrations, lifecycle hooks or manifest edits.** Publish a normal module release for those.
8. **Keep the hotfix small.** If the change becomes broad, publish a normal module release.
9. **Make the next normal module version include the fix.** Hotfixes are temporary overlays.
10. **Test both apply and rollback against the exact base version before distribution.**

## Security model

The managed format intentionally avoids arbitrary execution. A hotfix can supply data files that replace explicitly declared existing module files, but it cannot supply a privileged install script or command for Core to execute.

Security comes from several independent checks:

- exact module ownership boundary;
- exact base version;
- exact pre-change file hashes;
- exact payload hashes;
- no symlinks/path traversal;
- no migrations/lifecycle/manifests;
- root-owned execution helper;
- global lifecycle lock;
- pre-change backup;
- post-change validation;
- automatic failure rollback;
- persistent applied/history records.

The normal module release remains the authoritative long-term code state.
