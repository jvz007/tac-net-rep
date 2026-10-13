# API keys (Tactical's API key admin, Core's half)

Tactical lets an administrator create API keys for its users, so scripts and tools can call its API. Tec-Tac replaces Tactical's UI, so a technician must be able to do the same here. The screens are Core UI work. This page covers what Core does on the server (Core 1.17.26, parity under AD-25).

## What Tactical does (v1.5.2, `accounts/views.py`)

| Route | Method | Tactical flag | What it does |
|---|---|---|---|
| `/accounts/apikeys/` | GET | `can_list_api_keys` | Lists every key: id, name, key value, expiration, owner id, owner username |
| `/accounts/apikeys/` | POST | `can_manage_api_keys` | Creates a key. Tactical makes the 32-character value itself |
| `/accounts/apikeys/<id>/` | PUT | `can_manage_api_keys` | Edits the name, owner and expiration. A `key` in the body is dropped |
| `/accounts/apikeys/<id>/` | DELETE | `can_manage_api_keys` | Deletes the key |

Core does not change what Tactical returns or accepts. Tactical's list shows the key values to anyone who holds List API keys, and Tec-Tac keeps that. The one exception is below.

## What Core adds

Core wraps these handlers at start-up (`tactical_account_guard`).

**Account protection (earlier releases).** With account protection on (docs/account-security-policy.md), a caller who is not an effective superuser cannot create, edit or delete a key that belongs to, or is moving to, a protected superuser account. The answer is 403 and one Core `deny` row (`object_type` `superuser_account_protection`, `operation` `create_api_key`, `update_api_key` or `delete_api_key`). The list shows `[REDACTED]` instead of a protected owner's key for such a caller.

**One Core audit row per successful write (1.17.26).** Create, edit and delete each write one strict row in the same transaction. A failed audit write rolls the change back.

| Field | Value |
|---|---|
| `module_id` | `core` |
| `object_type` | `api_key` |
| `action` | `add`, `modify` or `delete` |
| `object_id` | the key's id |
| `metadata` | `name`, `owner` (username), `owner_id`. An edit also has `changed`: the field names that differ, from `name`, `owner` and `expiration` |
| `before` and `after` | an edit has both, each `{name, owner, expiration}`. A create has `after`. A delete has `before` |

**The key value is never in a row.** Core never reads the key field for the audit. The key is not in `before`, `after` or `metadata`.

A create row finds the new key by its name and owner after Tactical saves it. Key names are unique in Tactical. If Core cannot find the key, the row still goes out, with no `object_id` and `matched` 0 in `metadata`. A created key is never left without a row.

A call that is refused writes the deny row and no success row. A call Tactical itself refuses (a name already in use, a bad body, an unknown id) writes no success row either.

## What the browser may call

The browser calls Tactical's routes above through Core's transport, as before. The permission flags are Tactical's: `can_list_api_keys` for the list, `can_manage_api_keys` for the rest. Tactical decides. The UI hides a control the person cannot use (AD-12: denied means hidden and refused). The UI half of this entry is in `reviews/requests/ui.md`.

## Not in this release

Tactical's SSO provider and settings admin (`/accounts/ssoproviders/`) is left out. It needs a decision from Johan on how to avoid locking every superuser out (CQ84).

Tests: `tests/api-key-audit-1.17.26.py`. The real-database check is `tests/api-key-audit-runtime-1.17.26.py`, written for the dev server and not run here.
