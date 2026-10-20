# Module licensing requirement

**Framework baseline:** 1.14.1+ (the mode, the status read and the override: 1.17.58)

Tec-Tac modules may declare that installation requires a live entitlement from a versioned backend capability. Licensing is enforced by Core; modules and the browser do not decide whether installation is allowed.

## Manifest contract

Declare `licensing` in the extension `tec_tac.json`:

```json
{
  "id": "reportmanager",
  "type": "extension",
  "version": "1.0.0",
  "licensing": {
    "required": true,
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "capability_version": ">=1.0.0,<2.0.0"
  }
}
```

Fields:

- `required` - boolean. When false/omitted no licensing gate is applied.
- `product` - stable licensing product identifier.
- `capability` - namespaced Tec-Tac backend capability ID.
- `capability_version` - required public capability contract version range.

When `required=true`, all other fields are mandatory.

## Enforcement points

Core checks entitlement during package inspection and **again** during the install request. The installation check resolves the live capability/provider again and does not trust a prior inspection result.

For bundles and multi-package batches every contained module is checked independently. At install time Core re-reads each staged package manifest before evaluating entitlement.

## Licensing provider contract

The declared capability must resolve through `tec_tac.capabilities` and pass normal capability checks (installed/enabled provider, contract version, provider health).

The provider object must expose:

```python
check_entitlement(
    *,
    product: str,
    module_id: str,
    module_version: str,
)
```

Accepted return values:

```python
True
False
{"licensed": True}
{"licensed": False, "reason": "subscription expired"}
{"entitled": True, "edition": "professional"}
{"allowed": False, "reason": "product not assigned"}
```

Provider-specific JSON-safe fields are retained as diagnostic details.

## Failure contract

In **enforce** mode (see "Enforcement mode" below; the default since 1.17.58 is log-only), inspection or installation fails closed when the provider is missing, disabled, unhealthy, capability-incompatible/unregistered, has an invalid contract, raises during the check, or denies entitlement.

HTTP responses use status `403`:

```json
{
  "detail": "Product 'reportmanager' is not licensed.",
  "code": "licensing_requirement_failed",
  "licensing": {
    "required": true,
    "module": "reportmanager",
    "module_version": "1.0.0",
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "required_capability_version": ">=1.0.0,<2.0.0",
    "state": "unlicensed",
    "licensed": false,
    "reason": "subscription expired"
  }
}
```

Capability availability failures retain the registry state such as `missing`, `disabled`, `unhealthy`, `version-incompatible`, or `capability-unavailable`.

## Security boundary

- The package manifest declares the requirement; it does not grant entitlement.
- The browser cannot bypass the check by editing inspection state.
- The install request resolves entitlement again from the live capability provider.
- Modules must not implement a client-side licensing decision as a substitute for Core enforcement.

## Enforcement mode (since 1.17.58)

Johan's decision (19 October 2026): nothing is enforced yet. The licence gate has three modes, set with the runtime setting `licensing_enforcement_mode`
(`GET` and `PATCH /api/tfd/system/runtime-settings/`, see `docs/runtime-settings.md`):

| Mode | What the gate does |
|---|---|
| `log-only` (the default) | Runs the check. A module that would be refused is staged or installed anyway. Core writes one audit row, `custom:licence-would-block`, and the candidate's `licensing_status` carries `would_block: true`. Nothing is refused. |
| `off` | Does not run the check. No row. A module that needs a licence gets `licensing_status {state: "not-checked", licensed: null}`. |
| `enforce` | Refuses as before 1.17.58: 403 `licensing_requirement_failed`. The payload's `licensing` object gains `enforcement_mode: "enforce"`. |

A module with no `licensing.required` is unchanged in every mode, and so is a licensed module.

**What licensing never blocks, in any mode.** Sign-in, Tactical operations, module rollback and security updates. The gate (`_enforce_candidate_licensing`) is called only
from module stage and install code (the v2 inspect, install and batch routes, the repository stage, bundle intake and the two v1 module package routes). A test
reads the source and pins that it is not referenced from sign-in, the UI context, the Tactical operations executor, module rollback or the system-update helper.

**A revoked licence.** When enforcement is on, a revoked licence will disable new installs only. That is not built: nothing can detect revocation yet (it needs
the 24-hour refresh of the licensed catalogue). Nothing is enforced now.

**Defaults and failure.** The stored value is blank until someone chooses a mode. Blank means "use Core's default", `DEFAULT_LICENSING_MODE` in `module_licensing.py`.
Moving the default to `enforce` before public beta is a one-constant change with no data migration; a mode someone chose explicitly stays. The getter never raises:
a read error, a blank or an invalid stored value reads as `log-only`, because licensing must never block by accident.

**What goes into the row and the status.** Core's own words only. The audit row (action `custom:licence-would-block`, actor the service `core/licensing/gate`, object the
module, metadata `module`, `version`, `state`, `reason`, `mode`) and the `licensing_status` in log-only carry the manifest's own names, Core's state code and a fixed
sentence per state. A provider's reason text, its `details` dict, its health dict and an exception message are never copied, because they can hold anything a
provider chooses to say. A key, token or fingerprint therefore never reaches a row, a status or a log line from the gate. (The enforce-mode 403 payload is unchanged
and still carries the provider's own result, as it did before.) A batch install gates one candidate twice in one request and writes one row. There is no dedupe
across requests: each stage and install is a person's request.

## The licence status read (since 1.17.58)

`GET /api/tfd/system/licensing/`, for an effective superuser and for a holder of `core.runtime_settings.manage`. Anyone else gets 403. It writes no audit row and makes no
network call. It is built from allow-listed scalars only:

```json
{
  "mode": {"value": "log-only", "source": "default", "choices": ["off", "log-only", "enforce"], "default": "log-only"},
  "enforcing": false,
  "licence": {"state": "licensing_unavailable", "module_licensing": "provisional", "reason": "Module licensing is provisional: ..."},
  "would_block": {"count": 1, "modules": [{"module_id": "reportmanager", "version": "0.6.2", "state": "unlicensed", "reason": "Product 'reportmanager' is not licensed."}], "limit": 50},
  "grace": {"window_days": 7, "days_left": null, "reason": "..."},
  "never_blocked": ["sign-in", "Tactical operations", "rollback", "security updates"],
  "revoked_effect": "A revoked licence will disable new module installs only when enforcement is on. That is not active: ..."
}
```

- `licence.state`: Core reads the public capability status of `licensing.entitlements` and takes only the health keys `license_state` and `module_licensing` (and the
  registered metadata `module_licensing`). A missing, disabled, unhealthy or provisional provider reports `licensing_unavailable` (nothing is shown as licensed while
  module licensing is provisional). Otherwise the state is the Licensing module's, when it is one of `licensed`, `unlicensed`, `expired`, `revoked`, `unavailable`,
  `invalid`, `provisional`; any other value reads as `unknown`.
- `would_block`: every installed extension whose manifest has `licensing.required`, run through the same check the gate uses, with the mode ignored (so it shows what
  `enforce` would do). At most 50 rows are listed. `count` is the true number. A module whose check fails in an unexpected way is counted with the state `check-error`.
- `grace`: the 7-day window and its calculation need a Licensing-Server-signed refresh time that does not exist yet, so `days_left` is `null` with a plain reason.
- The UI context answer (`GET /api/tfd/ui/context/`) is not changed.

## Audited override of a licence refusal (since 1.17.58)

For an emergency, an effective superuser may let one refused module through a stage or install. It is a bypass of a licensing gate, so it is narrow and recorded.

- The field is `licence_override_reason`: a form field on the multipart `POST /api/tfd/modules/v2/packages/inspect/`, and a JSON string on
  `POST /api/tfd/modules/v2/packages/<upload_id>/install/` and `POST /api/tfd/modules/catalog/online/stage/`. The v1 module package routes take none.
- Only an effective superuser may send it. Anyone else gets 403 `licence_override_superuser_required` and one best-effort Core deny row (object `licence_override`, no
  reason text), before any package work, in every mode. A superuser's field that is present but empty, longer than 500 characters, with a control or invisible
  character, or not text is a 400 `invalid_licence_override_reason`. It is never silently ignored.
- It matters only when the mode is `enforce` and the check refused. Then Core writes one **strict** audit row first (`custom:licence-override`, actor the superuser,
  metadata `module`, `version`, `state`, `mode`, `override_reason`) and the stage or install continues with `licensing_status {..., overridden: true}`. If the strict
  row cannot be written, the original refusal stands (fail closed). In `log-only` and `off` nothing blocks, so no override row is written.
- It skips the licence refusal and nothing else. Signature, trust, compatibility, dependency, replacement and category checks run exactly as before. The override is
  used inside the one gate function, and a test pins that.
- It does not carry from the stage to the install: the install runs the gate again and needs its own reason. The reason text is the only free text in the row.
- The override is flagged for human review (commercial): see the questions file and the release notes.

Tests: `tests/licensing-enforcement-mode-1.17.58.py`, `tests/licensing-status-1.17.58.py`, `tests/licensing-override-1.17.58.py`. Dev server: `tests/licensing-mode-runtime-1.17.58.py`.
