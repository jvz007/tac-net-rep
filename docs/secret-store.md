# Core Secret Store

Core 1.17.100 (AD-57). Capability `core.secrets` 1.0.0. Python only: `tec_tac.secret_store`.

A module sometimes holds a value that must stay private, such as a token or a private key. Core keeps it encrypted in the database and gives it back only to the module that stored it. Nobody else can read it. No page, route or role can.

## What a module can do

Check `has_capability('core.secrets')` first, and require framework >=1.17.100.

| Call | What it does |
|---|---|
| `put(name, value)` | Stores or replaces one secret. Returns `created` or `replaced`. `value` is text or bytes, 1 byte to 16 KiB. |
| `get(name)` | Returns the value as stored (`str` or `bytes`), or `None` when there is none. |
| `delete(name)` | Removes one secret. Returns `True` when one was removed. |
| `configured(name)` | `True` or `False`. Never the value. Needs no master key. |
| `list_names()` | The names the module owns, sorted. No values. Needs no master key. |

A name is 1 to 64 characters: a lower-case letter or digit, then lower-case letters, digits, `.`, `_` or `-`. A module may keep 100 names.

## Who owns a secret

The module whose code makes the call. Core finds it from the call stack (AD-26). The module passes nothing in, so it cannot ask for another module's secrets. Core itself, a library, a disabled module and a legacy module are refused with 403 `caller_not_allowed`, and Core writes one `deny` audit row.

Read a secret only inside your module's server-side code, at the moment you need it. Never send it to the browser, never log it, never put it in an error, a job record, a setting or an audit row.

## How it is kept

- **Encryption.** AES-256-GCM through the `cryptography` package. Every write gets a new random nonce. The owner id and the name are bound in as authenticated data, so a row copied to another owner or name does not decrypt.
- **Master key.** `/etc/tec-tac/secrets/master.key`: 32 random bytes, `root:tactical`, mode 0640, in a `root:tactical` 0750 folder. Only `install.sh` creates it. It never overwrites an existing key. Core never creates, repairs or replaces it.
- **Key id.** Each row records which key made it, so a later key rotation can find the rows to re-encrypt. This release has one key and no rotation command.
- **Not in a backup.** The routine server backup leaves the secrets folder out, and a restore refuses a bundle that carries it. The key beside the encrypted rows would undo the protection. Keep one offline copy of `master.key`, for example in your password manager.

## What Core does when something is wrong

Core fails closed. It never guesses and never makes a new key.

| Code | HTTP | Meaning | What to do |
|---|---|---|---|
| `master_key_unavailable` | 503 | The master key is missing or unsafe. The Core log says why (`missing`, `unreadable`, `not_a_file`, `wrong_owner`, `wrong_mode`, `wrong_size`, `folder_unsafe`, `placeholder`). Nothing was read or written. | See Troubleshooting below. |
| `secret_unreadable` | 503 | One secret cannot be decrypted with the current key. | The module asks for the value again. |
| `caller_not_allowed` | 403 | The caller is not a signed, enabled module. | Call it from the owning module's own code. |
| `audit_failed` | 503 | The change was not made because its audit row could not be written. | Try again. |
| `invalid_name`, `invalid_value`, `secret_limit` | 400 | A rule above was broken. | Fix the call. |

Losing the master key makes every stored secret unreadable. No other data is lost. Each module asks for its values again.

## Audit

Each `put` (action `add` or `modify`) and `delete` writes one strict Core audit row **before** the change, in the same transaction. If the row cannot be written, nothing changes. The row holds the owner, the name, the size, the value type and the key id. It never holds the value. A refused caller writes a `deny` row. An unreadable secret writes a `custom:decrypt-failed` row.

A successful read writes no row, because a key read on every download would flood the log. The row keeps a read count and a last-read time instead.

## Troubleshooting

Check the key as root:

```
sudo ls -ld /etc/tec-tac/secrets
sudo ls -l /etc/tec-tac/secrets/master.key
sudo stat -c '%U:%G %a %s' /etc/tec-tac/secrets/master.key
```

Expected: the folder `root:tactical` mode `750`; the file `root:tactical 640 32`.

| What you see | What to do |
|---|---|
| Log reason `missing` | Restore your offline copy as `root:tactical` 0640. If no secret was ever stored, run the installer: it creates a key. |
| `wrong_owner` or `wrong_mode` | `sudo chown root:tactical /etc/tec-tac/secrets/master.key` and `sudo chmod 0640 /etc/tec-tac/secrets/master.key` |
| `folder_unsafe` | `sudo chown root:tactical /etc/tec-tac/secrets` and `sudo chmod 0750 /etc/tec-tac/secrets` |
| `wrong_size`, `not_a_file`, `placeholder` | The file is damaged. Restore your offline copy. The installer refuses to replace a file of the wrong size, on purpose. |
| `secret_unreadable` for every secret | The key was replaced. Restore the key that made the secrets, or have each module store its values again. |

---
Tech Flow Dynamics · techxflow.co.za
