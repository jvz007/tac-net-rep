# Troubleshooting & Diagnostics

Tec-Tac Core exposes a read-only troubleshooting report at `GET /api/tfd/system/diagnostics/` for authenticated users with server-maintenance authority.

The report is designed for operator diagnosis, not automated repair. It covers Framework/UI version discovery, Django system checks, Core and module migration drift, Tactical/Tec-Tac service state, Scheduler health, Core privileged helper presence, module dependency/runtime state, capability registration, Public Contracts generation, AuditLog compatibility and runtime storage health.

## Capability health

The normal report does **not** call module/provider health callbacks. This keeps diagnostics responsive even when an external provider is slow or offline.

An operator can explicitly request live provider health with:

```text
GET /api/tfd/system/diagnostics/?live_capabilities=1
```

Live capability health may take longer because providers are allowed to contact external systems.

## Migration drift

Migration detection is performed in memory with Django's migration loader/autodetector. It does not create migration files or alter the database.

- Core `tec_tac` drift is a failure because Core releases must carry their migrations.
- Installed `tec_tac_*` module drift is a warning because the owning module must ship the required migration in its next package.
- Operators should not use `makemigrations` on production as the permanent repair path.

## Module repository (1.17.99)

- **`repository_retired` on the Online catalogue.** The repository answered HTTP 401, 403, 404 or 410. Its old releases are not offered. Upload the signed `.zip`, `.zip.sig` and `.release.json` on Settings → Modules. See `docs/module-repositories.md`.
- **A custom `TEC_TAC_LICENSING_SERVER_URL` is ignored.** The value must be https, with a host, and no user info, query or fragment. The Core log says which rule failed (it never prints the value). Fix the key in `/opt/tec-tac/etc/tec-tac.conf` as root; restart is not needed.

- **`credentials_rejected` on the Online catalogue (1.17.100).** A repository that has credentials answered HTTP 401 or 403. It is not retired: it refused the credentials. Check them with the repository owner, then sync again. A repository with no credentials still reads as `repository_retired`. See `docs/module-repositories.md`.
- **The Licensing Server address returned to the default after a rollback or restore (1.17.100).** Core puts the line back after an installer older than 1.17.99 drops it. If the job log says "could not be put back", set `TEC_TAC_LICENSING_SERVER_URL` in `/opt/tec-tac/etc/tec-tac.conf` as root.

## Secret store (1.17.100, hardened in 1.17.101)

- **`master_key_unavailable` (503).** The secret store cannot use `/etc/tec-tac/secrets/master.key`. The Core log line names the reason: `missing`, `unreadable`, `not_a_file`, `wrong_owner`, `wrong_group`, `wrong_mode`, `wrong_size`, `folder_unsafe` or `placeholder`. `wrong_group` means the file is not in the group the installer recorded in `/etc/tec-tac/secrets/key-group` (normally `tactical`; since 1.17.102 Core reads that record instead of assuming a name), or that record is missing, not owned by root, group writable or not a valid group name. Re-running `install.sh` keeps the key and rewrites the record; `folder_unsafe` now also covers a link where the folder should be. Nothing was read or written, and Core never makes a key. Check as root with `sudo ls -ld /etc/tec-tac/secrets` and `sudo ls -l /etc/tec-tac/secrets/master.key`. The folder must be `root:<group in key-group> 0750` (normally `root:tactical`), the file `root:<that group> 0640` and exactly 32 bytes. Fix owner and mode with `sudo chown root:<that group>` and `sudo chmod 0640`. A missing key: restore your offline copy. Run `install.sh` only if no secret was ever stored, because it creates a new key.
- **`secret_unreadable` (503).** One secret cannot be decrypted with the current key: the key was replaced, or the row was changed. The module that owns it asks for the value again. Core wrote a `custom:decrypt-failed` audit row (at most one per secret every 5 minutes, so a repeating fault does not flood the log).
- **`caller_not_allowed` (403) from the secret store.** Only a signed, enabled module may call it, and only for its own secrets. Core wrote a `deny` audit row (at most one per name every 5 minutes).
- **`audit_failed` (503).** The secret was not changed because the audit row could not be written. Try again; check the Tactical audit log.
- **`invalid_name`, `invalid_value`, `secret_limit` (400).** A name is 1 to 64 characters of lower-case letters, digits, `.`, `_` and `-`. A value is text or bytes, 1 byte to 16 KiB. A module may keep 100 secrets.
- **`secret_conflict` (409) (1.17.101).** Two first writes of the same secret collided twice. Call again.
- **The installer stops with "The secret store master key has the wrong owner, mode or size" (1.17.101).** It checks the key after creating it. Run `sudo stat -c '%U:%G %a %s' /etc/tec-tac/secrets/master.key`. The answer must be `root:<group in /etc/tec-tac/secrets/key-group> 640 32` (normally `root:tactical 640 32`). Fix owner and mode as above, then run the installer again. If the size is wrong, restore your offline copy.
- See `docs/secret-store.md`.

## Security

Diagnostics require the same Core server-maintenance authority used by other system administration surfaces. Backend authorization remains authoritative. The report is read-only and does not expose secrets or raw authentication tokens.

- **`not_registered` (licensed catalogue, 1.17.103).** This server is not registered with the Licensing Server. Register it on the Licensing page first, then sync again. Register this server on the Licensing page, then sync again.
- **`licence_revoked` (licensed catalogue, 1.17.103).** The licence was revoked, so the licensed catalogue and new module installs are stopped. Check the Licensing page. Open the Licensing page and read the state. Fix the licence with Tech Flow Dynamics. New installs stay stopped until it is fixed.
- **`licence_expired` (licensed catalogue, 1.17.103).** The licence has expired, so the licensed catalogue and new module installs are stopped. Check the Licensing page. Renew the licence, then use Refresh now on the Licensing page.
- **`licence_grace_expired` (licensed catalogue, 1.17.103).** Licensing has no recent verified licence (the 7 day offline grace has ended, or none was checked yet). Use Refresh now on the Licensing page, then sync again. Use Refresh now on the Licensing page. Core needs one verified refresh to continue.
- **`licence_refused` (licensed catalogue, 1.17.103).** The Licensing Server refused this server's licence, so new module installs are stopped. Check the Licensing page. Open the Licensing page and read the state. Contact Tech Flow Dynamics if it does not clear.
- **`channel_not_permitted` (licensed catalogue, 1.17.103).** This licence does not allow the release channel set for this repository. Pick another channel, or leave it empty to use the licence's own. Core does not switch channels for you. Change the channel of the source (Settings → Modules → Repositories), or empty it to use the licence's own channel. Core never switches it for you.
- **`licensing_unavailable` (licensed catalogue, 1.17.103).** Core could not get an answer from the Licensing module or the Licensing Server. Check that the Licensing module is installed, enabled and healthy, then try again. Check that the Licensing module is installed, enabled and healthy on the Modules page. Then sync again. A network fault to the Licensing Server looks the same; it clears when the server answers.
- **`invalid_response` (licensed catalogue, 1.17.103).** The Licensing answer was not in the expected form, so Core did not use it. Try again later. Sync again later. If it repeats, send us the Core log line that starts with `licensing.catalogue`.
- **`bad_request` (licensed catalogue, 1.17.103).** The request was not valid. Check the channel name set for this repository. Fix the channel name of the source (lower case letters, digits, `-` or `_`).
- **`audit_unavailable` (licensed catalogue, 1.17.103).** Licensing could not write its audit record, so it did nothing. Try again. If it repeats, check the Core log: Licensing needs its audit record before it asks the server.
- **`release_not_found` (licensed catalogue, 1.17.103).** The Licensing Server does not have this release for your licence and channel. Sync the repository again. Sync the repository again. The release may have been withdrawn.
- **`grant_expired` (licensed catalogue, 1.17.103).** The download permission ran out before the files arrived, and a second one ran out too. Try again in a moment. Stage the module again. The download permission lasts about five minutes.
- **`download_refused` (licensed catalogue, 1.17.103).** The Licensing Server refused the download. The licence, the module or the publisher may have changed. Check the Licensing page, then sync again. Check the Licensing page. The licence, the module or the publisher key may have changed. Then sync again.
- **`download_failed` (licensed catalogue, 1.17.103).** The files could not be downloaded from the Licensing Server. Try again later. Try again later. Nothing was staged.
- **`verification_failed` (licensed catalogue, 1.17.103).** The downloaded files failed Core's own checks, so nothing was staged. Do not install it. The files did not pass Core's own signature check against the trusted publisher keys. Sync again; send us the Core log line if it repeats.
- **`release_mismatch` (licensed catalogue, 1.17.103).** The downloaded files do not match what the catalogue listed for this release, so nothing was staged. Do not install it. Sync again. The files differ from what the catalogue listed.
- **`not_in_licence` (licensed catalogue, 1.17.103).** This licence does not include this module, so it cannot be downloaded. The module is not part of the licence. Ask Tech Flow Dynamics.
- **`audit_not_saved` (licensed catalogue, 1.17.103).** The download did not start because its audit record could not be saved. Try again. Core does not start a download when it cannot write the audit record first.
- **`licence_policy_unreadable` (licensed catalogue, 1.17.108).** This Licensing version cannot read the licence's module policy. Update Licensing, then use Refresh now. Update the Licensing module, then use Refresh now on the Licensing page. Installed modules keep working.
- **`entitled_unavailable` (licensed release, 1.17.108).** Your licence includes this module, but the Licensing Server says this release is not available now. Sync again later.
- **`blocked_by_channel` (licensed release, 1.17.108).** This release is not offered on the release channel set for this repository. Pick another channel, or leave it empty to use the licence's own.
- **`missing_or_dependency` (licensed release, 1.17.108).** This release is missing on the Licensing Server, or a module it needs is not available. Sync again later, or install what it needs first.
- **`unclassified` (licensed release, 1.17.108; 1.17.109).** The Licensing Server lists this module with no category. Core treats it as test: offered only on a development server, in the development channel. On a development server in the development channel the release is offered with the warning "Unclassified on the Licensing Server: treated as test".

---
Tech Flow Dynamics · techxflow.co.za
