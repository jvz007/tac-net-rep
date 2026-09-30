# Saved views (Core 1.17.0)

Saved views let a person keep a named set of filters and layout and come back to it later. Core keeps them in one table for every module, so modules no longer need browser storage, cookies or a table of their own.

**Framework baseline:** 1.17.0. A module that uses the service must set `requires.framework` to `>=1.17.0`.

## What a saved view is

| Field | Meaning |
|---|---|
| `id` | UUID, set by Core |
| `module_id` | The module that owns the view. `core` or an installed, enabled module |
| `view_key` | Which screen or list the view belongs to. A lowercase slug (`a-z`, `0-9`, `-`, `_`), up to 64 characters |
| `name` | 1 to 160 characters. Unique for one owner, module and `view_key` |
| `payload` | A JSON object, up to 64 KiB |
| `owner` | The user who created it. Set by Core, never taken from the request |
| `readers` | A list of user ids (up to 100). Shown to the owner only |

## Who can see a view

- `readers` empty: shared with everyone who can use the module.
- `readers` not empty: private. The owner and the listed users can read it.
- Only me: send `readers: [<your own user id>]`. An empty list means everyone, so a view only the owner can read lists the owner's own id.
- Only the owner changes or deletes a view. There is no administrator override.
- Someone who cannot read a private view gets "not found", so its existence stays private. Someone who can read it but is not the owner gets "permission denied" when they try to change or delete it.
- Other users see a `shared` flag. They never see the `readers` list.

Who may use a module's views follows the module. A module with permission groups needs one of its grants. A permissionless module needs a signed-in user. Tec-Tac adds no permission of its own, and Tactical's permissions still decide what a person can do in the module.

## What a payload may hold

Filters and layout only: a search text, selected columns, sort order, a pane size, a tab name. A payload must never hold data from Tactical, secrets, passwords, tokens or anything a person has not chosen to keep. Keep it small. Core rejects a payload over 64 KiB, and a person can have at most 100 views for one module and `view_key`.

## HTTP contract

Call these through the module runtime's `api()` transport. Do not use browser storage, cookies or your own headers.

```text
GET    /api/tfd/saved-views/?module=<module_id>[&view_key=<view_key>]
POST   /api/tfd/saved-views/
GET    /api/tfd/saved-views/<uuid>/
PUT    /api/tfd/saved-views/<uuid>/
DELETE /api/tfd/saved-views/<uuid>/
```

`module` is required on the list call. `POST` takes `module_id`, `view_key`, `name`, `payload` and optional `readers`. `PUT` takes any of `name`, `payload` and `readers`; what you leave out stays as it was. `module_id` and `view_key` never change.

| Status | Meaning |
|---|---|
| 201, 200, 204 | Created, read or changed, deleted |
| 400 | Invalid field, unknown module, payload too large, a reader that does not exist, quota reached |
| 403 | You cannot use the module, or you can read the view but are not the owner |
| 404 | No such view, or a private view you cannot read |
| 409 | You already have a view with this name for this module and `view_key` |
| 429 | Write rate limit: 60 a minute and 2 000 a day for each user and IP. Reads are not counted |
| 500 | The audit row could not be written. Nothing was saved |

## Python contract

```python
from tec_tac.saved_views import (
    list_views, get_view, create_view, update_view, delete_view,
    SavedViewError, SavedViewValidationError, SavedViewNotFound,
    SavedViewPermissionDenied, SavedViewConflict, SavedViewAuditError,
)
```

The functions take the signed-in user first and follow the same rules as the HTTP contract: `list_views(user, module_id, view_key=None)`, `get_view(user, view_id)`, `create_view(user, module_id, view_key, name, payload, readers=None)`, `update_view(user, view_id, *, name=..., payload=..., readers=...)` and `delete_view(user, view_id)`. Each failure is a `SavedViewError` subclass with a `status_code`.

## Audit

Create, change and delete each write a Core audit row: module `core`, object type `saved_view`, object id = the view id, action `add`, `modify` or `delete`. The row holds the module, `view_key`, name, a shared flag and a readers count. It never holds the payload. The audit write is part of the same transaction. If it fails, the change is rolled back.

## Users and modules going away

- Deleting a user deletes that user's saved views, shared ones included. Core's normal user-delete audit applies.
- Removing a module leaves its views in place, like user preferences. The owner can still read and delete them. Nobody can list them until the module is installed again.

## Moving off browser storage

1. Replace reads and writes of `localStorage` or `sessionStorage` for saved views with the calls above.
2. Choose a stable `view_key` for each screen (for example `endpoints` or `audit-log`).
3. Offer "Only me" and "Shared" in the save dialog. Send `readers: [<your user id>]` for only me and omit `readers` for shared. Offer a picker for specific people only if the module needs it.
4. Views saved only in a person's browser cannot be moved by Core. Say so in the release notes, and let people save them again.
5. Raise `requires.framework` to `>=1.17.0`.
6. Until this release is installed, keep the view list in memory, as Audit and Endpoints do today.
