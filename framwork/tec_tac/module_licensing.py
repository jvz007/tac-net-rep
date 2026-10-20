"""Licensing enforcement mode, licence status read and audited override for the module install gate (Core 1.17.58).

Johan's rules (19 October 2026), kept here in one place:

* The default is **log-only**: nothing is enforced. A licensed module that would be refused is installed, and Core writes one audit row
  (``custom:licence-would-block``) so the owner can see what enforcement would do. ``off`` skips the check. ``enforce`` refuses, as Core
  did before 1.17.58.
* Licensing never blocks sign-in, Tactical operations, module rollback or security updates. The gate
  (``module_manager_v2._enforce_candidate_licensing``) is called only from module stage and install code, and a test pins it.
* A revoked licence will disable NEW installs only when enforcement is on. Nothing can detect revocation yet, so that is not built.
* Fail open: a licensing read that fails never blocks. The mode getter never raises and answers the default.

This file has no Django import at module level, so the pure parts run in a plain-Python test. The model is read inside the getter.
The HTTP view of the status read is in ``module_licensing_views``.
"""
from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("tec_tac.module_licensing")

SETTING_LICENSING_MODE = "licensing_enforcement_mode"
MODE_OFF = "off"
MODE_LOG_ONLY = "log-only"
MODE_ENFORCE = "enforce"
LICENSING_MODES = (MODE_OFF, MODE_LOG_ONLY, MODE_ENFORCE)
# Flip this one constant to ship a stricter default. A stored value (an explicit choice) always wins; a blank stored value follows it.
DEFAULT_LICENSING_MODE = MODE_LOG_ONLY

ACTION_WOULD_BLOCK = "custom:licence-would-block"
ACTION_OVERRIDE = "custom:licence-override"
OVERRIDE_FIELD = "licence_override_reason"
OVERRIDE_MIN_LENGTH = 1
OVERRIDE_MAX_LENGTH = 500
OVERRIDE_DENIED_MESSAGE = "Only a Tec-Tac superuser may override a licence refusal."
OVERRIDE_DENIED_OBJECT = "licence_override"

REASON_CAP = 200
FIELD_CAP = 120
STATUS_MODULE_CAP = 50
GRACE_WINDOW_DAYS = 7
LICENSING_CAPABILITY = "licensing.entitlements"
# Core's own copy of the Licensing module's state names (licensing.entitlements metadata.states). A name outside it reads as 'unknown'.
LICENCE_STATES = frozenset({"licensed", "unlicensed", "expired", "revoked", "unavailable", "invalid", "provisional"})
MODULE_LICENSING_STATES = frozenset({"provisional", "enforced"})
STATE_LICENSING_UNAVAILABLE = "licensing_unavailable"

NEVER_BLOCKED = ("sign-in", "Tactical operations", "rollback", "security updates")
REVOKED_EFFECT = (
    "A revoked licence will disable new module installs only when enforcement is on. That is not active: nothing can detect a revoked "
    "licence yet, and the mode is not enforce."
)
GRACE_REASON = (
    "The 7-day window runs from the last signed refresh of the licensed catalogue, which does not exist yet. "
    "Core shows no days left rather than guess."
)

# What the licence check reports, in Core's own words. Provider text (an entitlement reason, an exception message, a health reason)
# never goes into an audit row, a status answer or a log line from here: it can carry anything a provider chooses to say.
_SAFE_REASONS = {
    "unlicensed": "The module's product is not licensed.",
    "expired": "The module's licence has expired.",
    "revoked": "The module's licence was revoked.",
    "invalid": "The module's licence is not valid.",
    "unavailable": "The licence could not be checked.",
    "capability-unavailable": "The licensing capability is not available.",
    "disabled": "The licensing provider module is disabled.",
    "unhealthy": "The licensing provider reports that it is not healthy.",
    "health-reentrant": "The licensing provider's health check could not complete.",
    "version-incompatible": "The licensing capability version does not match what the module needs.",
    "provider-contract-invalid": "The licensing provider does not offer an entitlement check.",
    "provider-error": "The licensing entitlement check failed.",
    "check-error": "The licence check could not be completed.",
}
_UNKNOWN_REASON = "The licence check did not pass."


# ------------------------------------------------------------------------------------------------------------------------ the mode

def _clean_mode(value: Any) -> str | None:
    return value if isinstance(value, str) and value in LICENSING_MODES else None


def read_mode() -> tuple[str, str]:
    """(effective mode, source). Source is ``set`` when a valid value is stored, else ``default``. Never raises: any read failure,
    a blank value or a value outside the choices gives the default. Licensing must never block, so it fails open."""
    try:
        from .models import TecTacRuntimeConfig

        stored = _clean_mode(getattr(TecTacRuntimeConfig.current(), SETTING_LICENSING_MODE, ""))
        if stored is not None:
            return stored, "set"
    except Exception:
        logger.debug("Could not read the licensing enforcement mode; using the default.", exc_info=True)
    return DEFAULT_LICENSING_MODE, "default"


def get_licensing_enforcement_mode() -> str:
    """The effective licensing mode: ``off``, ``log-only`` or ``enforce``. Never raises."""
    try:
        return read_mode()[0]
    except Exception:
        return DEFAULT_LICENSING_MODE


def serialize_mode(stored: Any) -> dict:
    """The runtime-settings object for the mode, from the stored value (blank means the default)."""
    clean = _clean_mode(stored)
    return {"value": clean or DEFAULT_LICENSING_MODE, "source": "set" if clean else "default", "choices": list(LICENSING_MODES), "default": DEFAULT_LICENSING_MODE}


# ------------------------------------------------------------------------------------------------------------------- safe summaries

def _text(value: Any, cap: int = FIELD_CAP) -> str | None:
    if value is None:
        return None
    text = "".join(ch for ch in str(value) if ord(ch) >= 32 and ord(ch) != 127)
    return text[:cap]


def safe_state(result: Any) -> str:
    state = result.get("state") if isinstance(result, dict) else None
    return state if isinstance(state, str) and state in _SAFE_REASONS else "unknown"


def safe_reason(result: Any) -> str:
    """Core's own sentence for a refusal state. For an unlicensed product it names the product (manifest text, capped)."""
    state = safe_state(result)
    if state == "unlicensed" and isinstance(result, dict) and result.get("product"):
        return f"Product {_text(result.get('product'), 80)!r} is not licensed."[:REASON_CAP]
    return _SAFE_REASONS.get(state, _UNKNOWN_REASON)


def refusal_summary(result: Any, mode: str) -> dict:
    """The allow-listed scalars of a refusal result, for the candidate's licensing_status and the audit row.

    No provider reason, no ``details`` dict, no ``capability_status`` dict, no error text: only Core's own state names and fixed
    sentences and the manifest's own product and capability names."""
    source = result if isinstance(result, dict) else {}
    return {
        "required": True,
        "module": _text(source.get("module")),
        "module_version": _text(source.get("module_version")),
        "product": _text(source.get("product")),
        "capability": _text(source.get("capability")),
        "required_capability_version": _text(source.get("required_capability_version")),
        "capability_version": _text(source.get("capability_version")),
        "provider_module": _text(source.get("provider_module")),
        "state": safe_state(source),
        "licensed": False,
        "reason": safe_reason(source),
        "enforcement_mode": mode,
        "would_block": True,
    }


def not_checked_status(candidate: dict) -> dict:
    """``off``: nothing is checked and no row is written."""
    licensing = candidate.get("licensing") if isinstance(candidate.get("licensing"), dict) else {}
    return {
        "required": bool(licensing.get("required")),
        "module": _text(candidate.get("id") or candidate.get("plugin_id")),
        "module_version": _text(candidate.get("extension_version") or candidate.get("version")),
        "state": "not-checked",
        "licensed": None,
        "reason": "Licensing enforcement is off, so the licence was not checked.",
        "enforcement_mode": MODE_OFF,
    }


def already_recorded(candidate: dict, key: str) -> bool:
    """True when this same candidate already carries a status that recorded ``key`` (``audited`` or ``overridden``) for the same module
    and version. A batch install gates one candidate twice in one request; the row is written once."""
    previous = candidate.get("licensing_status")
    if not isinstance(previous, dict) or previous.get(key) is not True:
        return False
    return previous.get("module") == _text(candidate.get("id") or candidate.get("plugin_id"))


def audit_would_block(summary: dict) -> bool:
    """One best-effort audit row for a refusal that log-only let through. Returns True when a row was written. Never raises."""
    try:
        from . import audit

        actor = audit.service_audit_actor(module_id="core", service="licensing", identity="gate")
        result = audit.record(
            actor=actor, module_id="core", action=ACTION_WOULD_BLOCK, object_type="module", object_id=summary.get("module"),
            message="Licensing is in log-only mode. This module would have been refused.",
            metadata={
                "module": summary.get("module"), "version": summary.get("module_version"), "state": summary.get("state"),
                "reason": _text(summary.get("reason"), REASON_CAP), "mode": MODE_LOG_ONLY,
            },
            strict=False,
        )
        return bool(result.get("recorded", True)) if isinstance(result, dict) else True
    except Exception:
        logger.warning("Could not write the licence would-block audit row for %s.", summary.get("module"), exc_info=True)
        return False


# ----------------------------------------------------------------------------------------------------------------------- the override

class OverrideDenied(PermissionError):
    """The caller is not an effective superuser (HTTP 403)."""


class OverrideInvalid(ValueError):
    """The reason is present but empty or invalid (HTTP 400)."""


_override_local = threading.local()


def clean_override_reason(value: Any) -> str:
    """The reason text: plain text of 1 to 500 characters after trimming, no control or invisible characters. Anything else is refused."""
    if not isinstance(value, str):
        raise OverrideInvalid(f"{OVERRIDE_FIELD} must be text.")
    reason = value.strip()
    if len(reason) < OVERRIDE_MIN_LENGTH:
        raise OverrideInvalid(f"{OVERRIDE_FIELD} must not be empty.")
    if len(reason) > OVERRIDE_MAX_LENGTH:
        raise OverrideInvalid(f"{OVERRIDE_FIELD} must be at most {OVERRIDE_MAX_LENGTH} characters.")
    import unicodedata

    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in reason):
        raise OverrideInvalid(f"{OVERRIDE_FIELD} must not contain control or invisible characters.")
    return reason


def read_override(request, data=None) -> str | None:
    """The override reason of a request, or None when the field is absent.

    Checked before any package work, in every mode. A field that is present from a caller who is not an effective superuser is a
    403 (one best-effort Core deny row, object ``licence_override``, no reason text), whatever it holds. From a superuser, an empty,
    over-long or non-text value is a 400. It is never silently ignored. ``data`` defaults to ``request.data``."""
    payload = request.data if data is None else data
    try:
        present = OVERRIDE_FIELD in payload
    except TypeError:
        present = False
    if not present:
        return None
    from .rbac import is_effective_superuser

    if not is_effective_superuser(request.user):
        _audit_override_denied(request)
        raise OverrideDenied(OVERRIDE_DENIED_MESSAGE)
    return clean_override_reason(payload[OVERRIDE_FIELD])


def _audit_override_denied(request) -> None:
    try:
        from .audit import record

        record(
            actor=request.user, module_id="core", action="deny", object_type="module", object_id=OVERRIDE_DENIED_OBJECT,
            message="Blocked a licence override that needs a superuser.", metadata={"reason": "superuser_required"}, request=request, strict=False,
        )
    except Exception:
        logger.exception("Unable to persist the licence override denial audit")


@contextmanager
def override_scope(user, reason: str | None):
    """The override of this thread for the duration of one stage or install request. Always cleared, on success and on an exception.

    ``reason`` None is no override (nothing is set)."""
    if reason is None:
        yield
        return
    previous = getattr(_override_local, "active", None)
    _override_local.active = (user, reason)
    try:
        yield
    finally:
        _override_local.active = previous


def active_override() -> tuple[Any, str] | None:
    return getattr(_override_local, "active", None)


def audit_override(user, reason: str, summary: dict) -> None:
    """The STRICT audit row of an applied override. Raises when the row cannot be written: the caller then keeps the refusal."""
    from .audit import record

    record(
        actor=user, module_id="core", action=ACTION_OVERRIDE, object_type="module", object_id=summary.get("module"),
        message="A superuser overrode a licence refusal for this module.",
        metadata={
            "module": summary.get("module"), "version": summary.get("module_version"), "state": summary.get("state"),
            "mode": MODE_ENFORCE, "override_reason": reason,
        },
        strict=True,
    )


# ------------------------------------------------------------------------------------------------------------------- the status read

def _licensing_provider_view() -> dict:
    """{state, module_licensing, reason}: only scalars from the public capability status of ``licensing.entitlements``."""
    try:
        from .capabilities import capability_status

        status = capability_status(LICENSING_CAPABILITY)
    except Exception:
        status = {}
    if not isinstance(status, dict) or not status.get("available"):
        return {
            "state": STATE_LICENSING_UNAVAILABLE, "module_licensing": "unknown",
            "reason": "The Licensing module is not installed, is disabled or is not healthy, so no licence state is shown.",
        }
    health = status.get("health") if isinstance(status.get("health"), dict) else {}
    metadata = status.get("metadata") if isinstance(status.get("metadata"), dict) else {}
    module_licensing = health.get("module_licensing", metadata.get("module_licensing"))
    module_licensing = module_licensing if isinstance(module_licensing, str) and module_licensing in MODULE_LICENSING_STATES else "unknown"
    raw_state = health.get("license_state")
    state = raw_state if isinstance(raw_state, str) and raw_state in LICENCE_STATES else "unknown"
    if module_licensing != "enforced" or state == "provisional":
        return {
            "state": STATE_LICENSING_UNAVAILABLE, "module_licensing": module_licensing,
            "reason": "Module licensing is provisional: nothing is treated as licensed yet, and nothing is shown as licensed.",
        }
    return {"state": state, "module_licensing": module_licensing, "reason": None}


def _installed_licensed_candidates() -> list[dict]:
    """The installed extensions whose manifest says ``licensing.required``, as candidates for the gate's own check."""
    from . import module_manager_v2 as v2
    from . import registry

    candidates = []
    for plugin in registry.get_plugins():
        if plugin.plugin_type != "extension":
            continue
        try:
            payload = json.loads((plugin.root / registry.MANIFEST_NAME).read_text(encoding="utf-8"))
            licensing = v2._licensing_metadata(payload)
        except Exception:
            continue
        if licensing.get("required"):
            candidates.append({"id": plugin.plugin_id, "extension_version": plugin.version, "licensing": licensing})
    return candidates


def _would_block_row(candidate: dict) -> dict | None:
    """None when the module passes; else {module_id, version, state, reason}. The mode is ignored: this is what enforce would do."""
    from . import module_manager_v2 as v2

    try:
        v2.check_licensing_requirement(candidate)
        return None
    except v2.LicensingRequirementError as exc:
        result = exc.result
    except Exception:
        result = {"state": "check-error"}
    return {
        "module_id": _text(candidate.get("id")), "version": _text(candidate.get("extension_version")),
        "state": safe_state(result), "reason": safe_reason({**result, "product": (candidate.get("licensing") or {}).get("product")}),
    }


def build_licensing_status() -> dict:
    """The licence status read: the mode, the licence state, what would be blocked, days of grace. Allow-listed scalars only.

    No key, token, fingerprint or provider text, and no network call from Core. Never writes a row."""
    mode, source = read_mode()
    stored = mode if source == "set" else ""
    blocked = []
    count = 0
    try:
        for candidate in _installed_licensed_candidates():
            row = _would_block_row(candidate)
            if row is not None:
                count += 1
                if len(blocked) < STATUS_MODULE_CAP:
                    blocked.append(row)
    except Exception:
        logger.exception("Could not list the installed modules that need a licence.")
    return {
        "mode": serialize_mode(stored),
        "enforcing": mode == MODE_ENFORCE,
        "licence": _licensing_provider_view(),
        "would_block": {"count": count, "modules": blocked, "limit": STATUS_MODULE_CAP},
        "grace": {"window_days": GRACE_WINDOW_DAYS, "days_left": None, "reason": GRACE_REASON},
        "never_blocked": list(NEVER_BLOCKED),
        "revoked_effect": REVOKED_EFFECT,
    }
