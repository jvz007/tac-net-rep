# Remembered update source

Core remembers where each system component gets its updates. The System Updates page uses it, so a server that follows a branch keeps following it after a reload.

There are two components: `framework` (Core) and `ui`. Each has a source:

```json
{ "type": "release", "ref": null }
{ "type": "branch",  "ref": "dev" }
```

The default is `release` with `ref` null. It means "the latest stable GitHub release", which is how updates worked before 1.17.2.

## Read and change it

`GET /api/tfd/system/update-source/` is open to any signed-in user.

```json
{
  "update_sources": {
    "framework": { "type": "branch", "ref": "dev" },
    "ui": { "type": "release", "ref": null }
  },
  "updated_at": "2026-10-08T12:00:00+00:00",
  "updated_by": "alice"
}
```

`GET /api/tfd/system/updates/` also returns `update_sources`, so the System Updates page gets it in the call it already makes.

`PATCH /api/tfd/system/update-source/` changes one component:

```json
{ "component": "framework", "type": "branch", "ref": "dev" }
```

Who may change it: the same rule as runtime settings. An effective superuser, a role with `core.runtime_settings.manage`, or a role with `core.privileged_operations`. Anyone else gets 403.

Rules:

- `component` is `framework` or `ui`. `type` is `release` or `branch`.
- A branch name is at most 200 characters and uses only letters, digits and `. _ / -`. It has no `..` or `//`, does not start with `-` or `/`, and does not end with `/`, `.` or `.lock`.
- For `release`, `ref` is ignored and stored as null.
- Unknown fields get 400.
- Core does not check the branch against GitHub when you save. Saving works offline. A wrong name shows up as `branch_error` on the next check.
- A change writes one strict Core audit row (module `core`, object type `update_source`, object id the component, action `modify`) with the source before and after. It is written in the same transaction. If the audit write fails, the change is rolled back.
- Setting the value it already has changes nothing and writes no audit row.
- Writes share the runtime-settings limits: 10 a minute and 200 a day for each user and IP.

Changing the source does not stage or install anything. Staging and installing still need `core.privileged_operations`. Every signed-release and trust-policy check still applies to the package that is staged.

## Checking for updates

`GET /api/tfd/system/updates/online/?component=framework` uses the saved source.

For a `release` source the answer is the same as before 1.17.2.

For a `branch` source (1.17.3) Core does not call GitHub releases and does not read or write the release cache. The answer keeps every existing key, but `latest_release` is `null` and `release_error` is `null`. It adds three keys:

```json
{
  "source": { "type": "branch", "ref": "dev" },
  "branch": {
    "ref": "dev",
    "head_commit": "<40 hex>",
    "head_short": "a1b2c3d",
    "head_date": "2026-10-08T09:30:00Z",
    "installed_commit": "<40 hex or null>",
    "installed_short": "a1b2c3d",
    "installed_source": { "type": "branch", "ref": "dev" },
    "state": "same",
    "differs": false,
    "basis": "commit",
    "head_version": null,
    "installed_version": null
  },
  "branch_error": null
}
```

- `head_commit` and `head_date` come from GitHub's branch API. They are cached for 5 minutes in the release cache file. `force=1` skips the cache.
- `state` is `same`, `differs` or `unknown`. `differs` is `true`, `false` or `null` to match.
- A branch failure sets `branch_error`. Release data is not fetched for a branch source, so `latest_release` stays `null` either way.
- `basis` says how `state` was decided: `commit` (an install recorded the GitHub commit), `version` (the VERSION fallback below) or `null` (unknown). `head_version` and `installed_version` are set only when the VERSION fallback was tried. All three are new in 1.17.3.

### How "installed" is known

Core first compares the branch head with the GitHub commit recorded when the component was last installed. When that commit exists it decides (`basis` is `commit`). The install job now carries the source of the staged package (type, repository, ref and commit). The root helper copies a sanitised copy into the history row.

Core cannot use the `source_git` commit for this. The root helper commits the verified files to a local branch, so that SHA is local and never equals GitHub's.

The state is `unknown` when the most recent successful install of the component:

- was an offline upload,
- came from a different repository, or
- was made before 1.17.2, so it has no recorded commit.

Stage and install the branch once with 1.17.2 or later and the check becomes exact.

### The VERSION fallback (1.17.3)

When no install recorded a commit, Core reads the `VERSION` file at the branch head commit and compares it with the installed `VERSION`. Equal gives `same`. Not equal gives `differs`. `basis` is `version`.

This is weaker than a commit match. A branch can gain commits without a VERSION bump, so a version match can read `same` while the commits differ. Treat `basis: "version"` as "probably the same", not proof.

The state stays `unknown` (`basis` null) when the head VERSION cannot be read (not found, a GitHub error, bytes that are not text), when the installed VERSION is missing, or when either is not a plausible version string. A failed VERSION read never sets `branch_error`. The head VERSION is cached with the branch head for 5 minutes, keyed by the head commit. `force=1` bypasses it. A status check makes at most one extra GitHub call.

## Staging

`POST /api/tfd/system/updates/online/stage/` with no `source_type` uses the saved source (and its `ref`). An explicit `source_type` always wins. With no saved source, the default stays `release`.

## Python

`tec_tac.runtime_settings.get_update_source(component)` returns `{type, ref}`. It never raises. A missing or invalid stored value reads as the default.

Storage is the `update_sources` JSON column on `TecTacRuntimeConfig` (migration `0025_runtime_update_sources`).
