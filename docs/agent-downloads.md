# Agent downloads (Core 1.18.37, public installer in 1.18.39)

Core 1.18.37 lets a module hand one of its own files, such as an agent installer, to one device. The capability is `core.agent_downloads` 1.0.0. It needs framework >=1.18.37. It is additive: nothing existing changed.

Core 1.18.39 raises the capability to 1.1.0 and adds the public Endpoint Agent installer (AD-74): `publish_installer`, `unpublish_installer` and one fixed address that needs no sign-in. See The public installer below. The 1.0.0 calls, route and error codes are unchanged.

Core owns the check and the delivery. The module owns the file and what it means. Core never reads the file's meaning, keeps no copy and never chooses which file a device gets.

## What you get

* A module asks for a short link for one device and one file. It gets back a URL.
* The module sends that URL to the device through its own channel.
* The device fetches the file with its agent token. Nobody else can use the link.

## The two calls

Call them after `has_capability('core.agent_downloads')`. Both are sync: call them from a Celery task or a request thread. Both take keyword arguments after `module_id`.

### `grant_download(module_id, *, agent_id, path, sha256, ttl_seconds=600)`

Returns `{outcome, url, path, expires, expires_in, reason}`. `outcome` is `ok`, `denied`, `invalid` or `unavailable`.

| Argument | Rule |
|---|---|
| `module_id` | Must equal the module Core verifies from the call stack. |
| `agent_id` | A Tactical agent id (letters, digits, dot, dash, underscore, up to 80 characters). |
| `path` | Absolute, no `..`, its own real path. See Where the file may be. |
| `sha256` | 64 lowercase hex characters. Keep the hash of each file in your own version store. |
| `ttl_seconds` | A whole number (not a boolean). Clamped to 30..900 seconds (15 minutes). |

A second grant for the same device and file replaces the first.

`invalid` reasons: `bad_agent_id`, `bad_sha256`, `bad_ttl`, `bad_path`, `outside_module_folder`, `symlink_refused`, `not_a_file`, `too_large`, `hash_mismatch`.

`unavailable` reasons: `cache_unavailable`, `host_unavailable`, `audit_unavailable`, `file_unavailable`, `path_unavailable`. Nothing is stored. Try again later.

### `revoke_download(module_id, *, agent_id, path)`

Returns `{outcome, revoked}`. It withdraws only your own grant for that device and file. `revoked` is false when there was nothing to withdraw.

## Where the file may be

Your own installed module folder, or `/var/lib/tec-tac/<module id>/`. The path must be given as its real path. No part of it below that folder may be a symlink. The file must be a regular file of 1 to 100 000 000 bytes. Core opens it without following symlinks, hashes it and refuses unless the SHA-256 matches.

## Who may call

Any verified, enabled, non-legacy extension, for its own files only. Core reads the caller from the call stack, never from the argument. Core itself and an unverifiable caller get `denied`. No module id is named in Core.

## The download route

`GET https://<host>/api/tfd/agent-downloads/<token>/`

The host is the first Django `ALLOWED_HOSTS` entry, as Tactical builds the agent's API host. If it is empty or a wildcard, `grant_download` returns `unavailable`.

The device sends two headers, exactly once each:

| Header | Value |
|---|---|
| `Authorization` | `Token <Tactical agent token>` |
| `X-Agent-Id` | the Tactical agent id |

Core checks them with the same code as the endpoint websocket (AD-54 E5) and shares its failure counters. The link token in the path is the second key. A link granted to one device never serves another.

| Answer | Meaning |
|---|---|
| `200` | The raw file, with `Content-Length`. |
| `401` | Identity refused, or a missing, repeated or malformed header. |
| `403` | The proxy says the connection was plain text. |
| `404` | Unknown, expired or other device's link, or the file changed. |
| `405` | Not a GET. |
| `429` | More than 10 failed checks a minute from one address or for one agent id. `Retry-After: 60`. |
| `503` | All 8 download slots are busy, a server fault, or the audit row failed. `Retry-After: 30`. |

Every refusal has an empty body. Core never sends a redirect. The link works again until it expires, is revoked or is replaced, so a download that broke can be retried.

## Load and safety

* At most 8 downloads are served at once across Core. Over that, the answer is `503` with `Retry-After`.
* Core hashes the file at every serve and sends the same open file it hashed. If the bytes, the size or the file itself changed since the grant, the answer is `404` and the grant is withdrawn.
* Grants live in Django's cache (Redis on a Tactical server), keyed by the hash of the link token. A cache restart drops open links. The module grants again. Nothing is written to the database.
* The link token is in the URL, so the web server's access log must not record this path in full. Core never logs it. Django's own request logger writes the path of a 5xx answer (the 503 case), so Core puts a filter on the `django.request` logger (`log_redaction.py`, 1.18.38) that rewrites `/api/tfd/agent-downloads/<token>/` to `/api/tfd/agent-downloads/<redacted>/` before any handler sees the record. It never drops a record: the status stays logged.

## Audit

Strict Core rows (module `core`, object `agent`, provenance `agent-downloads`). No row means no link and no byte:

* `custom:agent-download-granted`: requested by module, file name, size, SHA-256, ttl, expiry, replaced.
* `custom:agent-download-served`: the download started (the device is the actor). It does not say it finished.

Non-strict rows: `custom:agent-download-revoked`, and `custom:agent-download-refused` for an identity refusal. Never the link token, the link or the full path.

## The public installer (Core 1.18.39, capability 1.1.0)

One Endpoint Agent installer can be public, so a technician can fetch it from a browser or a script with no sign-in. It needs framework >=1.18.39. It is additive.

### Who may publish

Only Endpoint Agent Management (`endpoint-agent-management`). Core keeps a short list of publisher ids in code (`INSTALLER_PUBLISHERS`) and verifies the caller from the call stack. The caller must equal `module_id` and be on that list. Core itself, an unverifiable caller, a mismatch and every other module get `denied`. A generic "any module may publish" call is not built: it would let any module make a file public at an address with no sign-in. Widening the list is a decision for Johan.

### `publish_installer(module_id, *, path, sha256, version)`

Returns `{outcome, reason}`. `outcome` is `ok`, `denied`, `invalid` or `unavailable`. Sync: call it from a Celery task or a request thread.

| Argument | Rule |
|---|---|
| `path` | As for `grant_download`: inside your own folder, no symlink, a regular file of 1 to 100 000 000 bytes. The file name must end in `.msi` (any case). |
| `sha256` | 64 lowercase hex characters. Core hashes the file and refuses unless it matches. |
| `version` | A plain version such as `0.1.2` or `0.1.2-rc1`, up to 40 characters. |

`invalid` reasons: `bad_sha256`, `bad_version`, `bad_path`, `not_msi`, `outside_module_folder`, `symlink_refused`, `not_a_file`, `too_large`, `hash_mismatch`.

`unavailable` reasons: `store_unavailable`, `audit_unavailable`, `file_unavailable`, `path_unavailable`. Nothing is published.

Only one installer exists. A new publish replaces the old one. It is kept in one database row (table `core_published_installer`, migration 0046), so it survives a restart and a cache flush. Core stores the path, not a copy of the file.

### `unpublish_installer(module_id)`

Returns `{outcome, unpublished}`. It removes the installer only when it is yours. Nothing to remove is `ok` with `unpublished` false and writes no row.

### The address

`GET https://<host>/api/tfd/endpoint-agent/installer.msi`

No sign-in, no code, no expiry. The MSI holds no secret: the agent it installs cannot connect without its own token. Core never redirects.

| Answer | Meaning |
|---|---|
| `200` | The raw file. Headers: `Content-Length`, `Content-Disposition: attachment` (the safe file name), `X-Content-SHA256` (the published hash), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Type: application/octet-stream`. |
| `403` | The proxy says the connection was plain text. |
| `404` | Nothing is published, or the file no longer matches: it changed, is a symlink now, is missing, or the publisher module is no longer installed. Empty body. |
| `405` | Not a GET. |
| `503` | All 8 installer slots are busy, or a server fault. `Retry-After: 30`. |

Core re-checks the path and recomputes the SHA-256 at every serve, through the same descriptor it then sends. That is one extra read pass of at most 100 MB per request. The route has its own counter of 8 downloads in flight, separate from the device route, so a flood of anonymous requests cannot block agent updates.

### What is audited, and what is not

Publish and unpublish write strict rows (module `core`, object type `agent-installer`, provenance `agent-downloads`): `custom:agent-installer-published` (publisher module, file name, size, SHA-256, version, replaced version) and `custom:agent-installer-unpublished`. The row is written in the same transaction as the store. If it fails, the change is rolled back. Never a full path.

An anonymous download writes no row. The per-address rate limit and buffering for this address belong to the web application firewall (securityWAF).

### Web server

nginx and uwsgi must pass `GET /api/tfd/endpoint-agent/installer.msi` to Django. A static-file rule for `.msi` must not catch it. Keep response buffering on.

## Agent column on Core's own rows (Core 1.18.39)

Core's rows for a download that is granted, revoked or started pass the device's agent id to the audit writer (`audit.record(..., agent_id=...)`, see `docs/module-audit.md`). The Audit page then shows Agent, Client and Site on them. Identity refusal rows carry it only when the id is well-formed. Publish and unpublish rows are not about a device and carry none.

## What Core does not do

Range requests, resumable downloads, a file store, a per-file allow-list inside a module and a page for any of this. The module checks the file's own signature on the device.
