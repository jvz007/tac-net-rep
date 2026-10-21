"""The scope a schedule keeps from the person who made it (Core 1.17.68, Johan 21 October 2026, Q-APM12 option b).

Johan's words: "If an engineer was responsible to configure APM and leaves the business his account will be disabled, but the work that he has
done shouldn't be undone. When a profile is then edited by another engineer the ownership will move to him."

What this module does. When a person creates or edits a schedule, Core stores a small snapshot on the schedule row (``creation_scope``):

    {"v": 1, "captured_for": "<user name>", "captured_at": "<ISO time>",
     "scope": {"unrestricted": bool, "whole_client_ids": [...], "site_ids": [...]},
     "flags": ["can_manage_winupdates", ...]}      # the Tactical role flags the person held, true ones only, sorted

An unattended run of that schedule reads this snapshot through ``VerifiedSchedulerRun`` (``held_at_creation``, ``resolved_endpoints``). It never
reads the owner's live row, so a disabled or demoted owner changes nothing, and it can never reach further than the person could when they
saved it. Nothing here widens anything: the endpoints a run may touch are the schedule's targets AND this snapshot.

What it does not do. It does not remove a module's own live checks: a module that still calls ``has_tactical_permission`` or ``resource_context``
for an unattended run keeps the old behaviour. A row made before migration 0037 has no snapshot, and Core never invents one: the new reads raise
``CreationScopeUnavailable`` (edit and save the schedule once). The snapshot is data about a person's rights at one moment. It grants nothing by
itself: a schedule still needs a Core-checked person to create or change it.

Every read of Core is one small function so a test can replace it without Django.
"""
from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

logger = logging.getLogger("tec_tac.scheduler")

SCOPE_VERSION = 1
_FLAG_RE = re.compile(r"^can_[a-z0-9_]{1,80}$")


def _descriptor(user) -> dict:
    from . import resources_adapter

    return resources_adapter.role_scope_descriptor(user)


def _flags(user) -> dict:
    from .rbac import tactical_permission_catalog

    return tactical_permission_catalog(user)


def _now() -> datetime:
    return datetime.now(UTC)


def _ids(values) -> list[int]:
    out = set()
    for value in values or ():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("a scope id must be a positive whole number")
        out.add(value)
    return sorted(out)


def capture(user) -> dict:
    """The creation-time snapshot of ``user`` (a Tactical user row). Never raises: when the scope or the flags cannot be read, the snapshot is
    the empty one (no client, no site, no flag), which is the safe side: a run built on it reaches nothing."""
    name = str(getattr(user, "username", "") or "")[:150]
    try:
        scope = _descriptor(user)
        scope_part = {
            "unrestricted": bool(scope.get("unrestricted")) is True,
            "whole_client_ids": _ids(scope.get("whole_client_ids")),
            "site_ids": _ids(scope.get("site_ids")),
        }
        flags = sorted(flag for flag, held in dict(_flags(user)).items() if held is True and isinstance(flag, str) and _FLAG_RE.fullmatch(flag))
    except Exception:
        logger.warning("The scope of a person could not be read for a schedule; the stored scope is empty.", exc_info=True)
        scope_part, flags = {"unrestricted": False, "whole_client_ids": [], "site_ids": []}, []
    return {"v": SCOPE_VERSION, "captured_for": name, "captured_at": _now().isoformat(), "scope": scope_part, "flags": flags}


def normalize(value) -> dict | None:
    """The snapshot in canonical form, or None when ``value`` is empty or not a snapshot Core wrote (a wrong shape is never repaired)."""
    try:
        if not isinstance(value, dict) or value.get("v") != SCOPE_VERSION:
            return None
        scope = value.get("scope")
        flags = value.get("flags")
        if not isinstance(scope, dict) or not isinstance(flags, list) or not isinstance(scope.get("unrestricted"), bool):
            return None
        if not all(isinstance(flag, str) and _FLAG_RE.fullmatch(flag) for flag in flags):
            return None
        return {
            "v": SCOPE_VERSION,
            "captured_for": str(value.get("captured_for") or "")[:150],
            "captured_at": str(value.get("captured_at") or "")[:40],
            "scope": {"unrestricted": scope["unrestricted"], "whole_client_ids": _ids(scope.get("whole_client_ids")), "site_ids": _ids(scope.get("site_ids"))},
            "flags": sorted(set(flags)),
        }
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        return None


def snapshot_of(holder) -> dict | None:
    """The stored snapshot of a schedule (or a delegation grant), or None."""
    return normalize(getattr(holder, "creation_scope", None))


def holds(snapshot: dict, flag: str) -> bool:
    return flag in snapshot["flags"]


def covers(snapshot: dict, *, client_id, site_id) -> bool:
    """Is an endpoint at this client and site inside the snapshot? Tactical's own rule for agents: the site's client is a granted client, or the
    site is a granted site. An unrestricted snapshot covers everything; an empty one covers nothing."""
    scope = snapshot["scope"]
    if scope["unrestricted"]:
        return True
    return client_id in scope["whole_client_ids"] or site_id in scope["site_ids"]
