"""Signed module categories (AD-21, Core 1.17.13): one set of rules for every place that needs the category.

A module's manifest says what kind of module it is: ``core`` (wraps one Tactical API group), ``server`` (manages the
Tec-Tac or Tactical server), ``premium`` (functionality Tactical does not have) or ``test`` (a development module).
A manifest with no category is treated as ``test``. Core refuses to INSTALL a test module on a server that is not a
development server. Since 1.17.14 (Johan CQ38) the refusal is install-only: a module that is already installed keeps
loading and can be enabled, and the status still carries the warning (an upgrade is an install, so it is checked again).

The development flag is read from the root-owned ``TEC_TAC_ENVIRONMENT`` setting through ``trust_policy``, the same
setting that picks the default update trust level. Nothing a module or a browser sends can change it.

Nothing here raises: when the setting cannot be read, the server counts as not a development server (fail closed).
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("tec_tac.module_category")

CATEGORIES = ("core", "server", "premium", "test")
DEFAULT_CATEGORY = "test"
# A manifest that writes one of these needs Core 1.17.13 or later: older Core rejects the value.
NEW_CATEGORIES = ("premium", "test")
FRAMEWORK_FOR_NEW_CATEGORIES = "1.17.13"

WARNING_MISSING_DEV = (
    "This module does not state its category. Core treats it as Test. It still runs on this development server, "
    "and the next release of the module needs to carry a category."
)
WARNING_MISSING = (
    "This module does not state its category. Core treats it as Test. On a server that is not a development server "
    "Core refuses to install it, so the next release of the module needs to carry a category."
)
WARNING_TEST = (
    "This is a Test module. Core installs Test modules on a development server only."
)
REFUSED_MESSAGE = (
    "Core refuses to install a Test module on a server that is not a development server. "
    "The module's next release needs to carry a category (core, server or premium)."
)


def normalize(value: Any) -> str:
    """The declared category as written, lower-cased, or an empty string."""
    return str(value or "").strip().lower()


def effective_category(declared: Any) -> str:
    """The category Core acts on: the declared one, or ``test`` when the manifest names none."""
    return normalize(declared) or DEFAULT_CATEGORY


def is_development_server() -> bool:
    """True only when the root-owned config says this is a development server. Fails closed."""
    try:
        from . import trust_policy

        return trust_policy._server_environment() == "development"
    except Exception:
        logger.debug("Could not read the server environment; treating this as not a development server.", exc_info=True)
        return False


def refused(declared: Any, *, development: bool | None = None) -> bool:
    """True when an install of this module must be refused: effective category test, not a development server.
    Only installs ask (1.17.14, CQ38): enabling a module that is already installed is never refused for its category."""
    development = is_development_server() if development is None else bool(development)
    return effective_category(declared) == DEFAULT_CATEGORY and not development


def replacement_category_ok(declared: Any, *, development: bool | None = None) -> bool:
    """AD-20 with AD-21: a replacement is ``premium``, or has no category on a development server. A module that writes
    ``test`` may not replace anything, and a core or server module never does."""
    value = normalize(declared)
    if value == "premium":
        return True
    development = is_development_server() if development is None else bool(development)
    return value == "" and development


def describe(declared: Any, *, development: bool | None = None) -> dict[str, Any]:
    """The status fields every module row carries (additive)."""
    development = is_development_server() if development is None else bool(development)
    value = normalize(declared)
    effective = effective_category(value)
    missing = value == ""
    blocked = refused(value, development=development)
    warning = None
    if missing:
        warning = WARNING_MISSING_DEV if development else WARNING_MISSING
    elif value == "test" and not development:
        warning = WARNING_TEST
    return {
        "category": value or None,
        "effective_category": effective,
        "category_missing": missing,
        "category_refused": blocked,
        "category_warning": warning,
    }


def refusal_problem(module_id: str, declared: Any, *, development: bool | None = None) -> dict[str, Any] | None:
    """A lifecycle problem dict for an install that must be refused, else None. Install plans only (1.17.14, CQ38)."""
    if not refused(declared, development=development):
        return None
    return {
        "type": "category_refused",
        "module": module_id,
        "category": normalize(declared) or None,
        "effective_category": DEFAULT_CATEGORY,
        "message": REFUSED_MESSAGE,
    }


# Core 1.18.11 (Johan, 18 November 2026): a core module always stays installed and on.
LOCK_REASON = "core_module_locked"
_LOOKUP = object()


def core_lifecycle_lock(module_id: str, manifest_category: Any, state_category: Any = None, *, name: Any = None,
                        development: bool | None = None, replaced_by_honoured: Any = _LOOKUP) -> dict[str, str] | None:
    """None when ``module_id`` may be disabled or uninstalled, else ``{"reason": code, "message": plain sentence}``.

    A module is locked when its manifest category OR the category recorded in module state is ``core`` (a mismatch fails
    closed). It is not locked on a development server, or while a premium replacement of it is honoured
    (``replaced_by_honoured`` is that module's id or a true value; left out, Core looks it up). Never raises: a doubt locks."""
    try:
        if "core" not in (normalize(manifest_category), normalize(state_category)):
            return None
        development = is_development_server() if development is None else bool(development)
        if development:
            return None
        if replaced_by_honoured is _LOOKUP:
            from . import module_replacement

            replaced_by_honoured = module_replacement.replaced_by(module_id)
        if replaced_by_honoured:
            return None
    except Exception:
        logger.exception("Could not work out the core lifecycle lock for %s; treating it as locked.", module_id)
    shown = " ".join(str(name or module_id).split()) or str(module_id)
    return {
        "reason": LOCK_REASON,
        "message": (f"{shown} is a core module and always stays installed and on. "
                    "A premium module that replaces it can take over, and a development server can switch it off."),
    }
