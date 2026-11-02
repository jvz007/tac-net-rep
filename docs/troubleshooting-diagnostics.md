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

## Secret store (1.17.100)

- **`master_key_unavailable` (503).** The secret store cannot use `/etc/tec-tac/secrets/master.key`. The Core log line names the reason: `missing`, `unreadable`, `not_a_file`, `wrong_owner`, `wrong_mode`, `wrong_size`, `folder_unsafe` or `placeholder`. Nothing was read or written, and Core never makes a key. Check as root with `sudo ls -ld /etc/tec-tac/secrets` and `sudo ls -l /etc/tec-tac/secrets/master.key`. The folder must be `root:tactical 0750`, the file `root:tactical 0640` and exactly 32 bytes. Fix owner and mode with `sudo chown root:tactical` and `sudo chmod 0640`. A missing key: restore your offline copy. Run `install.sh` only if no secret was ever stored, because it creates a new key.
- **`secret_unreadable` (503).** One secret cannot be decrypted with the current key: the key was replaced, or the row was changed. The module that owns it asks for the value again. Core wrote one `custom:decrypt-failed` audit row.
- **`caller_not_allowed` (403) from the secret store.** Only a signed, enabled module may call it, and only for its own secrets. Core wrote one `deny` audit row.
- **`audit_failed` (503).** The secret was not changed because the audit row could not be written. Try again; check the Tactical audit log.
- **`invalid_name`, `invalid_value`, `secret_limit` (400).** A name is 1 to 64 characters of lower-case letters, digits, `.`, `_` and `-`. A value is text or bytes, 1 byte to 16 KiB. A module may keep 100 secrets.
- See `docs/secret-store.md`.

## Security

Diagnostics require the same Core server-maintenance authority used by other system administration surfaces. Backend authorization remains authoritative. The report is read-only and does not expose secrets or raw authentication tokens.

---
Tech Flow Dynamics · techxflow.co.za
