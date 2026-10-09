"""Honoured module replacement (AD-20, Core 1.17.9).

A module that is neither a core nor a server module may declare ``replaces = "<module id>"`` in its manifest, naming
one core or server module (1.17.11: server modules can be replaced too). Core honours that only while all of these
hold, worked out from manifests and module state alone (never from the runtime registry, so start-up order cannot
change the answer):

1. the replacement is enabled;
2. the replaced module is installed, is a core or server module, and is DISABLED;
3. no other enabled module claims the same target;
4. the replaced module declares ``capabilities`` (an empty ``{}`` is allowed, an absent key is not);
5. the replacement declares every one of those capability ids at the same major version, and a minor.patch that is
   not lower. Extra capabilities are additive.

Honouring is computed on every call. Disabling the replacement drops its rights at once, and the replaced module can be
enabled again. Never raises at start-up: a replacement that is not honoured is simply not honoured, with a reason code
in the status.

1.17.11 (AD-20 amendments, Johan 9 October 2026):

* Enabling or installing a replacement names the module it will disable (``disable_plan``, ``install_disables``) and
  disables it in the same job, once the operator has confirmed that exact list.
* If state shows both enabled, Core does not honour the replacement, drops it from what it loads, and queues a job
  that disables the replacement and keeps the replaced module (``conflicted_replacements``, ``reconcile_conflicts``).
* An honoured replacement satisfies a hard dependency on the replaced module id (``satisfies_dependency``).
"""
from __future__ import annotations

import dataclasses
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import module_state as _module_state
from . import registry as _registry

logger = logging.getLogger("tec_tac.module_replacement")

REASON_REPLACEMENT_DISABLED = "replacement-disabled"
REASON_TARGET_MISSING = "target-missing"
REASON_TARGET_NOT_CORE = "target-not-core"
REASON_TARGET_ENABLED = "target-enabled"
REASON_COMPETING = "competing-replacement"
REASON_CAPS_UNDECLARED = "capabilities-undeclared"
REASON_CAP_MISSING = "capability-missing"
REASON_CAP_MAJOR = "capability-major-mismatch"
REASON_CAP_LOWER = "capability-version-lower"

# The categories a replacement may take the place of (1.17.11). A manifest without a category is neither.
REPLACEABLE_CATEGORIES = frozenset({"core", "server"})

# One reconcile job per replacement and pair per hour, so a failing dispatch cannot loop every minute.
RECONCILE_INTERVAL_SECONDS = 3600

# Reasons that mean "the two modules would be enabled together", reported as replacement_conflict.
CONFLICT_REASONS = frozenset({REASON_TARGET_ENABLED, REASON_COMPETING})

MESSAGES = {
    REASON_REPLACEMENT_DISABLED: "The replacement module is disabled, so the core module keeps its routes and contracts.",
    REASON_TARGET_MISSING: "The core module this module replaces is not installed.",
    REASON_TARGET_NOT_CORE: "The module this module replaces is not a core or server module.",
    REASON_TARGET_ENABLED: "Both modules are enabled. Core does not run the replacement; it disables the replacement and keeps the module it replaces.",
    REASON_COMPETING: "Another enabled module also replaces the same module. Only one replacement can be enabled.",
    REASON_CAPS_UNDECLARED: "The module it replaces does not declare its capabilities, so Core cannot check that the replacement covers them.",
    REASON_CAP_MISSING: "The replacement does not publish every capability of the module it replaces.",
    REASON_CAP_MAJOR: "The replacement publishes a capability at a different major version from the replaced module's.",
    REASON_CAP_LOWER: "The replacement publishes a capability at a lower version than the replaced module's.",
}


@dataclass(frozen=True)
class Node:
    """What the check needs to know about one installed module."""

    id: str
    category: str = ""
    enabled: bool = True
    replaces: str = ""
    capabilities: Mapping[str, str] | None = None  # None: the manifest has no ``capabilities`` key


def _parse_version(value: str) -> tuple[int, int, int]:
    # One parser for every version rule: "2", "2.0" and "2.0.0-1" read as 2.0.0 (suffix ignored), garbage raises.
    return _module_state.Version.parse(value).core()


def version_within_declared(declared: str, registered: str) -> str | None:
    """None when a registered capability version is acceptable for the version declared in the manifest, else the reason
    code: the same major, and a minor.patch that is not lower. ``parity()`` and run-time registration share this rule."""
    try:
        have = _parse_version(registered)
    except _module_state.ModuleStateError:
        return REASON_CAP_MAJOR  # fail closed: an unreadable registered version is never accepted
    want = _parse_version(declared)
    if have[0] != want[0]:
        return REASON_CAP_MAJOR
    if have[1:] < want[1:]:
        return REASON_CAP_LOWER
    return None


# Process-local record of registrations refused for a version outside the declared one: (module, capability) -> row.
_MISMATCHES: dict[tuple[str, str], dict[str, str]] = {}


def record_registered_mismatch(module_id: str, capability_id: str, declared: str, registered: str, reason: str) -> None:
    _MISMATCHES[(module_id, capability_id)] = {"capability": capability_id, "declared": declared, "registered": registered, "reason": reason}


def clear_registered_mismatch(module_id: str, capability_id: str) -> None:
    _MISMATCHES.pop((module_id, capability_id), None)


def registered_mismatches(module_id: str) -> list[dict[str, str]]:
    return [dict(row) for (owner, _), row in sorted(_MISMATCHES.items()) if owner == module_id]


def live_model(plugins=None, state=None) -> dict[str, Node]:
    """The installed extensions and their enabled state, read from the registry and the module state file."""
    plugins = _registry.get_plugins() if plugins is None else plugins
    state = _module_state.load_state() if state is None else state
    model: dict[str, Node] = {}
    for plugin in plugins:
        if getattr(plugin, "plugin_type", "extension") != "extension" or getattr(plugin, "legacy", False):
            continue
        declared = bool(getattr(plugin, "capabilities_declared", False))
        caps = dict(getattr(plugin, "capabilities", ()) or ())
        model[plugin.plugin_id] = Node(
            id=plugin.plugin_id,
            category=str(getattr(plugin, "category", "") or ""),
            enabled=_module_state.is_enabled(plugin.plugin_id, state),
            replaces=str(getattr(plugin, "replaces", "") or ""),
            capabilities=caps if (declared or caps) else None,
        )
    return model


def parity(replaced: Node, replacement: Node) -> tuple[str | None, list[dict]]:
    """Compare capability lists. Returns (first reason code or None, one row per capability that fails)."""
    expected = dict(replaced.capabilities or {})
    offered = dict(replacement.capabilities or {})
    failures = []
    reason = None
    for cap_id in sorted(expected):
        want = expected[cap_id]
        have = offered.get(cap_id)
        code = None
        if have is None:
            code = REASON_CAP_MISSING
        else:
            code = version_within_declared(want, have)
        if code:
            failures.append({"capability": cap_id, "required": want, "declared": have, "reason": code})
            reason = reason or code
    return reason, failures


def check(model: Mapping[str, Node], replacement_id: str, *, assume_enabled: bool = False) -> tuple[str | None, list[dict]]:
    """None when ``replacement_id`` is honoured, else the first refusal code (plus failing capabilities).

    ``assume_enabled`` asks "would it be honoured if it were enabled?", which the enable check uses.
    """
    node = model.get(replacement_id)
    if node is None or not node.replaces:
        return REASON_TARGET_MISSING, []
    if not node.enabled and not assume_enabled:
        return REASON_REPLACEMENT_DISABLED, []
    target = model.get(node.replaces)
    if target is None:
        return REASON_TARGET_MISSING, []
    if target.category not in REPLACEABLE_CATEGORIES:
        return REASON_TARGET_NOT_CORE, []
    if target.enabled:
        return REASON_TARGET_ENABLED, []
    if any(other.id != replacement_id and other.enabled and other.replaces == node.replaces for other in model.values()):
        return REASON_COMPETING, []
    if target.capabilities is None:
        return REASON_CAPS_UNDECLARED, []
    return parity(target, node)


_WARNED: set[tuple[str, str]] = set()


def _warn_both_enabled(model: Mapping[str, Node], replacement_id: str) -> None:
    node = model[replacement_id]
    key = (replacement_id, node.replaces)
    if key not in _WARNED:
        _WARNED.add(key)
        logger.warning(
            "Module %s replaces %s but both are enabled. Core does not honour the replacement, does not load it, and "
            "queues a job that disables %s and keeps %s.", replacement_id, node.replaces, replacement_id, node.replaces,
        )


def _with_enabled(model: Mapping[str, Node], changes: Mapping[str, bool]) -> dict[str, Node]:
    out = dict(model)
    for module_id, enabled in changes.items():
        node = out.get(module_id)
        if node is not None and node.enabled != enabled:
            out[module_id] = dataclasses.replace(node, enabled=enabled)
    return out


def _hypothetical(model: Mapping[str, Node], node: Node, *, will_enable: bool, blocked=()) -> tuple[Mapping[str, Node], list[str]]:
    """The model as it would be once ``node`` is enabled and the module it replaces is disabled, and that module's id.

    The replaced module is named only when it is installed, replaceable, enabled and not part of the same job (a module
    that is itself being installed or upgraded in that job is never disabled by it).
    """
    target = model.get(node.replaces)
    if (not will_enable or target is None or target.category not in REPLACEABLE_CATEGORIES or not target.enabled
            or target.id in blocked):
        return model, []
    return _with_enabled(model, {target.id: False}), [target.id]


def disable_plan(model: Mapping[str, Node], module_id: str) -> list[str]:
    """The module ids that enabling ``module_id`` would disable (AD-20 amendment 1a, 1.17.11). Empty when it replaces
    nothing, is enabled already, has nothing enabled to replace, or would be refused for any other reason."""
    node = model.get(module_id)
    if node is None or not node.replaces or node.enabled:
        return []
    hypothetical, disables = _hypothetical(model, node, will_enable=True)
    if not disables:
        return []
    reason, _ = check(hypothetical, module_id, assume_enabled=True)
    return [] if reason else disables


def install_disables(model: Mapping[str, Node], candidate_ids, installed_ids=()) -> dict[str, list[str]]:
    """{candidate id: [module ids its fresh install would disable]} (1.17.11). ``model`` already holds the candidates.
    Only a fresh install of a module with ``replaces`` names anything; an upgrade of an installed replacement does not."""
    wanted, installed = set(candidate_ids), set(installed_ids)
    result: dict[str, list[str]] = {}
    for module_id in sorted(wanted - installed):
        node = model.get(module_id)
        if node is None or not node.replaces:
            continue
        hypothetical, disables = _hypothetical(model, node, will_enable=True, blocked=wanted)
        if disables and check(hypothetical, module_id, assume_enabled=True)[0] is None:
            result[module_id] = disables
    return result


def satisfies_dependency(model: Mapping[str, Node], dep_id: str) -> str | None:
    """The honoured replacement of ``dep_id``, which satisfies a hard dependency on it (1.17.11), else None.

    Only the enabled test is substituted. A version constraint still applies to the installed replaced module's own
    version (it stays installed and disabled). Pass a future model to ask "would it be honoured". Never raises."""
    try:
        for node in sorted(model.values(), key=lambda n: n.id):
            if node.replaces == dep_id and node.enabled and check(model, node.id)[0] is None:
                return node.id
    except Exception:
        logger.exception("Could not work out whether %s is replaced; treating the dependency as not satisfied by a replacement.", dep_id)
    return None


def conflicted_replacements(model: Mapping[str, Node]) -> list[tuple[str, str]]:
    """[(replacement id, replaced id)] for every enabled replacement whose replaced module is also enabled (1.17.11)."""
    pairs = []
    for node in sorted(model.values(), key=lambda n: n.id):
        if not (node.replaces and node.enabled):
            continue
        target = model.get(node.replaces)
        if target is not None and target.enabled and target.category in REPLACEABLE_CATEGORIES:
            pairs.append((node.id, target.id))
    return pairs


def _audit_replacement(actor, *, action: str, object_id: str, message: str, metadata: dict) -> None:
    """One Core audit row, never fatal (non-strict)."""
    try:
        from . import audit

        if actor is None:
            actor = audit.service_audit_actor(module_id="core", service="module-replacement", identity="system")
        audit.record(actor=actor, module_id="core", action=action, object_type="module", object_id=object_id,
                     message=message, metadata=metadata, strict=False)
    except Exception:
        logger.exception("Could not write the %s audit row for %s.", action, object_id)


def audit_replaced_disabled(actor, replacement_id: str, disabled: list[str], job_id: Any) -> None:
    """Audit row for a job that disables a replaced module as part of enabling or installing its replacement."""
    for replaced in disabled:
        _audit_replacement(
            actor, action="custom:module-replacement-disabled", object_id=replaced,
            message=f"Module {replaced} is disabled because its replacement {replacement_id} was enabled.",
            metadata={"replacement": replacement_id, "replaced": replaced, "job_id": str(job_id or "")},
        )


def reconcile_conflicts(*, model: Mapping[str, Node] | None = None, now: datetime | None = None) -> list[dict]:
    """Queue one ``disable`` job per enabled replacement that sits next to its enabled replaced module (1.17.11).

    module-state.json is root-owned, so the Tactical process cannot fix the pair itself; it asks the root job helper,
    the way a user job does. A pair with a queued, dispatched or running disable job is skipped, and a replacement gets
    at most one job an hour, whatever happened to the last one. Never raises. Returns one row per pair it acted on."""
    rows: list[dict] = []
    try:
        from . import module_manager_v2 as v2

        model = live_model() if model is None else model
        pairs = conflicted_replacements(model)
        if not pairs:
            return rows
        now = now or datetime.now(timezone.utc)
        unresolved = set(conflicted_replacements(v2._model_with_pending_jobs(dict(model))))
        recent = v2._recent_reconcile_jobs()
        for replacement_id, replaced_id in pairs:
            if (replacement_id, replaced_id) not in unresolved:
                continue
            last = recent.get(replacement_id)
            if last is not None and (now - last).total_seconds() < RECONCILE_INTERVAL_SECONDS:
                continue
            row = {"replacement": replacement_id, "replaced": replaced_id, "queued": False, "job_id": None, "error": None}
            try:
                job = v2.queue_replacement_conflict_disable(replacement_id, replaced_id)
                row.update(queued=True, job_id=job.get("id"))
                logger.warning("Module %s replaces %s and both were enabled. Queued job %s to disable %s; %s stays.",
                               replacement_id, replaced_id, job.get("id"), replacement_id, replaced_id)
                _audit_replacement(
                    None, action="custom:module-replacement-conflict-resolved", object_id=replacement_id,
                    message=f"Both {replacement_id} and the module it replaces, {replaced_id}, were enabled. Core queued a job that disables {replacement_id} and keeps {replaced_id}.",
                    metadata={"replacement": replacement_id, "replaced": replaced_id, "job_id": str(job.get("id") or "")},
                )
            except Exception as exc:
                row["error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Could not queue the job that disables %s next to %s: %s", replacement_id, replaced_id, row["error"])
            rows.append(row)
    except Exception:
        logger.exception("Replacement conflict check failed; Tactical is not affected.")
    return rows


def honoured_replacement(module_id: str, *, model: Mapping[str, Node] | None = None) -> str | None:
    """The core module ``module_id`` replaces while that is honoured, else None. Never raises."""
    try:
        model = live_model() if model is None else model
        node = model.get(str(module_id))
        if node is None or not node.replaces:
            return None
        reason, _ = check(model, node.id)
        if reason == REASON_TARGET_ENABLED and node.enabled:
            _warn_both_enabled(model, node.id)
        return node.replaces if reason is None else None
    except Exception:
        logger.exception("Could not work out whether %s replaces a core module; treating it as not honoured.", module_id)
        return None


def replaced_by(core_id: str, *, model: Mapping[str, Node] | None = None) -> str | None:
    """The module that honourably replaces ``core_id`` right now, else None."""
    try:
        model = live_model() if model is None else model
        for node in model.values():
            if node.replaces == core_id and honoured_replacement(node.id, model=model) == core_id:
                return node.id
    except Exception:
        logger.exception("Could not work out what replaces %s.", core_id)
    return None


def declared_capabilities(module_id: str, *, model: Mapping[str, Node] | None = None) -> dict[str, str]:
    model = live_model() if model is None else model
    node = model.get(str(module_id))
    return dict(node.capabilities or {}) if node else {}


def _registered(capability_id: str) -> bool:
    from .capabilities import _registration

    return _registration(capability_id) is not None


def _status_for(model: Mapping[str, Node], node: Node, *, check_registered: bool) -> dict[str, Any]:
    reason, failures = check(model, node.id)
    honoured = reason is None
    target = model.get(node.replaces)
    expected = dict(target.capabilities or {}) if target else {}
    status: dict[str, Any] = {
        "module_id": node.id,
        "replaces": node.replaces,
        "enabled": node.enabled,
        "honoured": honoured,
        "reason": reason,
        "message": "This module is the active replacement and owns the core module's routes and contracts." if honoured else MESSAGES[reason],
        "capabilities": {"expected": sorted(expected), "declared": sorted(node.capabilities or {}), "failed": failures},
        "conflict": bool(node.enabled and target is not None and target.enabled and target.category in REPLACEABLE_CATEGORIES),
        "degraded": False,
        "unregistered": [],
        "registered_mismatch": [],
    }
    if honoured and check_registered:
        try:
            missing = sorted(cap for cap in expected if not _registered(cap))
        except Exception:
            missing = []
        # Informational only. It is never a refusal: registration happens at start-up, after this check.
        mismatch = registered_mismatches(node.id)
        status["degraded"] = bool(missing or mismatch)
        status["unregistered"] = missing
        # 1.17.10: a capability the replacement tried to register outside its declared major, or below its declared
        # minor.patch. Core refused the registration at start-up, so the name stays unavailable.
        status["registered_mismatch"] = mismatch
    return status


def replacement_status(module_id: str | None = None, *, model: Mapping[str, Node] | None = None, check_registered: bool = True):
    """Status of one module's replacement (dict, or None when it declares none), or a list for every declaring module."""
    model = live_model() if model is None else model
    if module_id is not None:
        node = model.get(str(module_id))
        if node is None or not node.replaces:
            return None
        return _status_for(model, node, check_registered=check_registered)
    return [_status_for(model, node, check_registered=check_registered) for node in sorted(model.values(), key=lambda n: n.id) if node.replaces]


def enable_problems(model: Mapping[str, Node], module_id: str) -> list[dict]:
    """Problems that stop ``module_id`` being enabled (AD-20 conditions 1 and 3), as lifecycle problem dicts.

    1.17.11: the replaced module being enabled is not a refusal for the replacement itself. Enabling it names that
    module (``disable_plan``) and disables it in the same job, so every other rule is checked as if it already were."""
    problems: list[dict] = []
    node = model.get(module_id)
    if node is None:
        return problems
    if node.replaces:
        hypothetical, _ = _hypothetical(model, node, will_enable=not node.enabled)
        reason, failures = check(hypothetical, module_id, assume_enabled=True)
        if reason:
            kind = "replacement_conflict" if reason in CONFLICT_REASONS else "replacement_incomplete"
            problems.append({"type": kind, "module": module_id, "replaces": node.replaces, "reason": reason,
                             "message": MESSAGES[reason], "capabilities": failures})
    if node.category in REPLACEABLE_CATEGORIES:
        for other in sorted(model.values(), key=lambda n: n.id):
            if other.enabled and other.replaces == module_id:
                problems.append({"type": "replacement_conflict", "module": module_id, "replaced_by": other.id,
                                 "reason": REASON_TARGET_ENABLED,
                                 "message": f"Module {other.id!r} is enabled and replaces this module. Disable {other.id!r} first."})
    return problems


def install_problems(model: Mapping[str, Node], candidate_ids, installed_ids=()) -> list[dict]:
    """Problems with installing the candidates (already merged into ``model``).

    A replacement may be installed only while its target is installed, and only if parity holds. A fresh install of a
    replacement disables an enabled target in the same job (1.17.11), so the rules are checked as if it already were,
    unless the target is itself part of the install. A core or server module that an enabled replacement points at
    must keep the capabilities that replacement covers when it is upgraded, and may not be installed fresh (it would
    start enabled next to the replacement).
    """
    problems: list[dict] = []
    wanted = set(candidate_ids)
    installed = set(installed_ids)
    for node in sorted(model.values(), key=lambda n: n.id):
        if not node.replaces:
            continue
        if node.id in wanted:
            if node.id in installed:
                reason, failures = check(model, node.id, assume_enabled=True)
            else:
                hypothetical, _ = _hypothetical(model, node, will_enable=True, blocked=wanted)
                reason, failures = check(hypothetical, node.id, assume_enabled=True)
        elif node.replaces in wanted and node.enabled:
            reason, failures = check(model, node.id)
            if reason in CONFLICT_REASONS and node.replaces in installed:
                continue  # an upgrade of a module that was already enabled next to it does not make that worse
        else:
            continue
        if reason:
            kind = "replacement_conflict" if reason in CONFLICT_REASONS else "replacement_incomplete"
            problems.append({"type": kind, "module": node.id, "replaces": node.replaces, "reason": reason,
                             "message": MESSAGES[reason], "capabilities": failures})
    return problems
