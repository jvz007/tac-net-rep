# Tec-Tac Audit Write Contract

**Status:** Public Core developer contract  
**Backend:** `tec_tac.audit.record(...)`  
**Browser runtime:** `audit.record(event)`  
**Persistence:** Tactical `logs.models.AuditLog` through Core only

## Architectural boundary

```text
Tec-Tac module
    ↓
Core public audit contract
    ↓
Core audit service
    ↓
Tactical AuditLog
    ↓
Audit module / Tactical audit APIs / retention / export
```

Modules MUST NOT import, instantiate, or write `logs.models.AuditLog` directly. Core is the only supported Tec-Tac writer. Tactical's own audit records are not changed or rewritten.

## Backend contract

Server-side modules should record the audit event immediately after the authoritative business action succeeds:

```python
from tec_tac.audit import record

result = record(
    actor=request.user,
    module_id="advancedpatch",
    action="modify",
    object_type="patch_profile",
    object_id=str(profile.pk),
    message="Updated patch profile Monthly Servers",
    before=before_data,
    after=after_data,
    metadata={"request_id": request_id},
    request=request,
)
```

`actor` must be the authenticated Tactical user. There is deliberately no `username` argument. Core derives `username` from the actor and rejects actor/provenance fields on the browser API.

Backend authorization remains authoritative. Audit recording does not grant permission to perform the business action. Modules must authorize the action first, perform it, then record the event.

## Browser runtime

Authenticated UI modules receive a module-scoped `audit` service from `register(context)`:

```js
export async function register({ audit }) {
  const result = await audit.record({
    action: 'modify',
    object_type: 'example',
    object_id: '123',
    message: 'Updated example',
    before: oldValue,
    after: newValue,
  })
}
```

The browser runtime injects the owning module ID. A module does not supply `username`, module version, source, or correlation provenance.

For server-mutating operations, prefer recording from the authorized backend endpoint rather than relying on a second browser request. The browser helper is appropriate for Core/UI actions whose authoritative operation is itself browser-side or where the backend API cannot yet own the event.

## Event fields

| Field | Required | Notes |
| --- | --- | --- |
| `action` | yes | Standard action or controlled `custom:<slug>` fallback. |
| `object_type` | yes | Lowercase slug, maximum 100 characters. |
| `object_id` | no | Stored in Core provenance inside `debug_info`. |
| `message` | no | Tactical applies its existing 255-character safe truncation. |
| `before` | no | Written to Tactical `before_value`. |
| `after` | no | Written to Tactical `after_value`. |
| `metadata` | no | Stored beneath Core provenance in `debug_info.metadata`. |

## Standard action vocabulary

Use these values wherever they fit:

```text
add
modify
delete
run
approve
deny
enable
disable
install
uninstall
view
export
import
sync
test
acknowledge
resolve
```

When no standard action accurately describes the event, use a controlled fallback:

```text
custom:<slug>
```

Example: `custom:recalculate`.

Do not invent ad-hoc action spellings when a standard action exists.

## Provenance added by Core

Core writes these values into Tactical `debug_info`:

```json
{
  "source": "tec-tac",
  "module_id": "advancedpatch",
  "module_version": "1.2.3",
  "object_id": "123",
  "correlation_id": "...when available...",
  "metadata": {}
}
```

Module version is resolved from the installed registry. Browser callers cannot override it. Correlation/request IDs are taken from the Core request context or standard `X-Request-ID` / `X-Correlation-ID` headers when available.

## Tactical compatibility and payload limits

Core writes through Tactical's existing `AuditLog.objects.create()` and uses Tactical field names:

- `username`
- `action`
- `object_type`
- `before_value`
- `after_value`
- `message`
- `debug_info`

Tactical's existing `AUDIT_MAX_VALUE_BYTES` handling therefore remains authoritative for `before_value`, `after_value`, and final `debug_info` persistence. Core also pre-checks module `metadata` and replaces oversized metadata with a safe error marker while preserving Core provenance where practical.

Tec-Tac object types and controlled action values may extend Tactical's display choices. Tactical stores these fields as normal character columns and its audit serializer/filter path returns their raw values.

## Failure behavior

Audit persistence is **non-strict by default**. A database/audit writer failure:

1. is logged by Core at error level;
2. returns `recorded: false`;
3. does not normally undo an already-successful business action.

Core-owned workflows may explicitly pass `strict=True` to the backend `record()` function when compliance requirements make audit persistence transaction-critical. Modules should not choose strict mode casually.

Contract validation failures (invalid module ID, unauthenticated actor, invalid action/object type) are programming/authorization errors and are raised/rejected rather than silently ignored.

## HTTP endpoint

The module-scoped browser helper uses:

```text
POST /api/tfd/audit/record/
```

The endpoint requires the normal authenticated Tec-Tac session guard. It derives the actor from `request.user` and rejects client-supplied identity/provenance keys.

## Security rules

- Never accept `username` from a module event.
- Never let a module override `source`, `module_version`, or request/correlation provenance.
- The requested module must exist and be enabled.
- Users without access to a permission-bearing module cannot use its browser audit writer.
- Audit records describe an action; they do not authorize that action.
- Never place secrets, passwords, API tokens, private keys, or full credential payloads in `before`, `after`, or `metadata`.
