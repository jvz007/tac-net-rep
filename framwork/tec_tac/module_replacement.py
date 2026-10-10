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

1.17.13 (AD-21): the replacement must be a ``premium`` module, or have no category on a development server. A module
that writes ``test`` cannot declare ``replaces`` (the registry refuses it). Reason code ``replacement-category``.

1.17.12 (AD-20 hand-back, Johan CQ32 and CQ33, 9 October 2026):

* Enabling the replaced module while its replacement is enabled is no longer refused. It names the replacement
  (``disable_plan``), needs two confirmations, and switches the replacement off in the same job (``replacements_of``,
  ``switches_replacement``).
* Disabling a replacement switches the replaced module back on in the same job when it can (``hand_back_plan``).
* Audit follows what happened: a "queued" row when the job is queued (``audit_switch_queued``) and one outcome row per
  module the job changed, written by the scheduler tick once the job has finished (``audit_finished_jobs``).
"""
from __future__ import annotations

import dataclasses
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import module_category as _module_category
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
REASON_REPLACEMENT_CATEGORY = "replacement-category"

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
    REASON_REPLACEMENT_CATEGORY: "A replacement must be a Premium module. A module with no category counts as Test, and Core honours that on a development server only.",
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
    if not _module_category.replacement_category_ok(node.category):  # AD-21: premium, or no category on a development server
        return REASON_REPLACEMENT_CATEGORY, []
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


def replacements_of(model: Mapping[str, Node], module_id: str) -> list[str]:
    """The enabled modules that replace ``module_id`` (1.17.12). Empty unless ``module_id`` is an installed core or server
    module. Used by the enable direction of the hand-back and by the root helper's twin of the rule."""
    target = model.get(module_id)
    if target is None or target.category not in REPLACEABLE_CATEGORIES:
        return []
    return sorted(other.id for other in model.values() if other.enabled and other.replaces == module_id and other.id != module_id)


def switches_replacement(model: Mapping[str, Node], module_id: str) -> bool:
    """True when enabling ``module_id`` (a disabled core or server module) would switch off an enabled replacement of it.
    That is the direction that needs the second confirmation (1.17.12)."""
    node = model.get(module_id)
    return bool(node is not None and not node.enabled and replacements_of(model, module_id))


def hand_back_plan(model: Mapping[str, Node], replacement_id: str) -> list[str]:
    """[replaced module id] when disabling ``replacement_id`` should switch the module it replaces back on (CQ33, 1.17.12).

    Only when the module declares ``replaces`` and is enabled, the target is installed, is a core or server module and is
    disabled, and no other enabled module replaces the same target. When both are enabled (the reconcile case) or the
    target is enabled already, it is [] (the replaced module is on, so there is nothing to hand back)."""
    node = model.get(replacement_id)
    if node is None or not node.replaces or not node.enabled:
        return []
    target = model.get(node.replaces)
    if target is None or target.category not in REPLACEABLE_CATEGORIES or target.enabled:
        return []
    if any(other.id != replacement_id and other.enabled and other.replaces == node.replaces for other in model.values()):
        return []
    return [target.id]


def disable_plan(model: Mapping[str, Node], module_id: str) -> list[str]:
    """The module ids that enabling ``module_id`` would disable (AD-20 amendment 1a, 1.17.11). Empty when it replaces
    nothing, is enabled already, has nothing enabled to replace, or would be refused for any other reason.

    1.17.12: for a disabled core or server module it is the enabled replacements of that module (the hand-back, CQ32)."""
    node = model.get(module_id)
    if node is None or node.enabled:
        return []
    if not node.replaces:
        return replacements_of(model, module_id)
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


def correlation_id_for(action: str, job_id: Any) -> str:
    """The correlation id of an audit row this module writes for a job: ``module-replacement:<action>:<job id>`` (1.17.13).

    ``<action>`` is the audit action without its ``custom:module-replacement-`` prefix (disabled, enabled, conflict-resolved,
    switch-failed, switch-queued). The audit writer keeps the correlation id when it has to replace oversized metadata,
    so the sweep can always find the row it wrote."""
    short = str(action).replace("custom:module-replacement-", "", 1)
    return f"module-replacement:{short}:{job_id or ''}"[:255]


def _audit_replacement(actor, *, action: str, object_id: str, message: str, metadata: dict, correlation_id: str | None = None) -> None:
    """One Core audit row, never fatal (non-strict)."""
    try:
        from . import audit

        if actor is None:
            actor = audit.service_audit_actor(module_id="core", service="module-replacement", identity="system")
        extra = {"correlation_id": correlation_id} if correlation_id else {}
        audit.record(actor=actor, module_id="core", action=action, object_type="module", object_id=object_id,
                     message=message, metadata=metadata, strict=False, **extra)
    except Exception:
        logger.exception("Could not write the %s audit row for %s.", action, object_id)


ACTION_SWITCH_QUEUED = "custom:module-replacement-switch-queued"
ACTION_DISABLED = "custom:module-replacement-disabled"
ACTION_ENABLED = "custom:module-replacement-enabled"
ACTION_CONFLICT_RESOLVED = "custom:module-replacement-conflict-resolved"
ACTION_SWITCH_FAILED = "custom:module-replacement-switch-failed"

# The outcome sweep looks back this far and at this many job files per scheduler tick (1.17.12).
AUDIT_WINDOW_DAYS = 7
AUDIT_MAX_JOBS_PER_TICK = 200


def _join_ids(ids) -> str:
    return ", ".join(sorted({str(value) for value in ids}))


def audit_switch_queued(actor, subject_id: str, job_id: Any, disabled=(), enabled=(), skipped=()) -> None:
    """Audit row for a job that asks Core to switch modules (1.17.12). It records the request, written when the job is
    queued, and claims no change: the outcome rows come from ``audit_finished_jobs`` once the job has run.

    1.17.14: ``skipped`` names the replaced modules the request confirmed to leave off because they cannot be enabled."""
    disabled, enabled, skipped = sorted(set(disabled or ())), sorted(set(enabled or ())), sorted(set(skipped or ()))
    if not (disabled or enabled or skipped):
        return
    parts = []
    if disabled:
        parts.append(f"disable {_join_ids(disabled)}")
    if enabled:
        parts.append(f"enable {_join_ids(enabled)}")
    message = f"Module {subject_id} was asked to switch: job {job_id or ''} will {' and '.join(parts) if parts else 'change nothing else'}."
    metadata = {"job_id": str(job_id or ""), "disable": disabled, "enable": enabled}
    if skipped:
        message += f" It was confirmed that {_join_ids(skipped)} stays off because it cannot be enabled."
        metadata["hand_back_skipped"] = skipped
    _audit_replacement(
        actor, action=ACTION_SWITCH_QUEUED, object_id=subject_id, message=message, metadata=metadata,
        correlation_id=correlation_id_for(ACTION_SWITCH_QUEUED, job_id),
    )


def _audit_already_written(action: str, object_id: str, job_id: str) -> bool:
    """True when Tactical's AuditLog holds a row with this action and object for this job. Raises when the lookup cannot
    run; the caller then writes nothing, so a broken lookup can never duplicate a row every tick.

    1.17.13: the row is found by its correlation id (``correlation_id_for``), which the audit writer never drops, and still
    by ``metadata.job_id``, which a row written by 1.17.12 carries and a row whose metadata was replaced by the size marker
    does not."""
    from django.db.models import Q

    from . import audit

    return audit._auditlog_model().objects.filter(
        Q(debug_info__correlation_id=correlation_id_for(action, job_id)) | Q(debug_info__metadata__job_id=job_id),
        action=action, debug_info__object_id=object_id,
    ).exists()


def _parse_when(value) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _id_list(value) -> list[str]:
    return [str(item) for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _replacement_for(job: Mapping[str, Any], replaced_id: str) -> str:
    """The module whose enable or install led to ``replaced_id`` being disabled, from the job's own plan."""
    for action in (job.get("plan") or {}).get("actions") or []:
        if isinstance(action, Mapping) and replaced_id in _id_list(action.get("will_disable")):
            return str(action.get("id") or "")
    return str(job.get("plugin_id") or "")


# The switch-failed row keeps its text short, so it fits the audit size limit and is never replaced by the size marker (1.17.13).
FAILED_ERROR_MAX = 300
FAILED_PLANNED_MAX = 10


def _plain(value: Any, limit: int) -> str:
    """Printable ASCII only, cut to ``limit`` characters."""
    return "".join(ch for ch in str(value or "") if 32 <= ord(ch) < 127)[:limit]


def _failed_outcome(job: Mapping[str, Any], stage: str) -> tuple[str, bool | None]:
    """The sentence for a failed switch and the ``rolled_back`` value, from what the root helper recorded (1.17.13).

    The helper sets ``rolled_back`` only after it has put the flags back and ``rollback_error`` when that raised, so the
    stage name alone is never taken as proof. A job file written by 1.17.12 has neither field."""
    if job.get("rollback_error"):
        return "Core could not put the flags back. Check the Modules page to see which modules are enabled.", False
    if job.get("rolled_back") is True:
        return "The flags were put back as they were.", True
    if stage in {"runtime-sync", "rollback"}:
        return (f"The outcome is not confirmed: the job stopped at stage {stage}. Check the module state on the Modules page.", None)
    return "Nothing was changed.", False


def _outcome_rows(job: Mapping[str, Any], replaces_of) -> list[dict]:
    """The audit rows one finished job owes: [{action, object_id, message, metadata}]. Pure; no I/O."""
    job_id = str(job.get("id") or "")
    subject = str(job.get("plugin_id") or "")
    base = {"job_id": job_id, "requested_by": str(job.get("requested_by") or "")}
    rows: list[dict] = []
    if job.get("status") == "succeeded":
        for target in _id_list(job.get("disabled_modules")):
            if job.get("action") == "enable" and job.get("replacement_confirmed") is True:
                # The replaced module was enabled again and switched its replacement off (CQ32).
                message = f"Replacement {target} was disabled because the module it replaces, {subject}, was enabled again."
                replacement, replaced = target, subject
            else:
                replacement, replaced = _replacement_for(job, target), target
                message = f"Module {target} was disabled because replacement {replacement} was enabled."
            rows.append({"action": ACTION_DISABLED, "object_id": target, "message": message,
                         "metadata": {**base, "replacement": replacement, "replaced": replaced}})
        # 1.17.15 (CQ43): an uninstall of the replacement hands back the same way; the row says what happened to it.
        gone = "uninstalled" if job.get("action") == "remove" else "disabled"
        for target in _id_list(job.get("enabled_modules")):
            rows.append({"action": ACTION_ENABLED, "object_id": target,
                         "message": f"Module {target} was enabled again because its replacement {subject} was {gone}.",
                         "metadata": {**base, "replacement": subject, "replaced": target}})
        skipped = _id_list(job.get("hand_back_skipped"))
        if skipped and job.get("action") == "disable":
            # 1.17.14 (CQ34): the replacement was disabled on a confirmation to leave the replaced module off.
            rows.append({"action": ACTION_DISABLED, "object_id": subject,
                         "message": f"Replacement {subject} was disabled. The module it replaces, {_join_ids(skipped)}, stayed off because it cannot be enabled.",
                         "metadata": {**base, "replacement": subject, "replaced": ", ".join(sorted(skipped)), "hand_back_skipped": sorted(skipped)}})
        if job.get("reason") != "replacement_conflict":
            for target in _id_list(job.get("reconciled_modules")):
                rows.append({"action": ACTION_CONFLICT_RESOLVED, "object_id": target,
                             "message": f"Replacement {target} was found enabled next to the module it replaces and was disabled.",
                             "metadata": {**base, "replacement": target, "replaced": replaces_of(target)}})
    elif job.get("status") == "failed" and (_id_list(job.get("disable_modules")) or _id_list(job.get("enable_modules"))):
        planned = (_id_list(job.get("disable_modules")) + _id_list(job.get("enable_modules")))
        planned = sorted(set(planned))[:FAILED_PLANNED_MAX]
        stage = _plain(job.get("stage"), 40)
        outcome, rolled_back = _failed_outcome(job, stage)
        error = _plain(job.get("error"), FAILED_ERROR_MAX) or "no error was recorded"
        rows.append({"action": ACTION_SWITCH_FAILED, "object_id": subject,
                     "message": f"The switch for module {subject} did not finish (stage {stage or 'unknown'}, planned: {_join_ids(planned)}). {outcome} Error: {error}",
                     "metadata": {**base, "stage": stage, "error": error, "planned": planned, "rolled_back": rolled_back,
                                  "replacement": subject, "replaced": ""}})
    return rows


def _write_outcome_row(row: dict) -> bool:
    job_id = row["metadata"]["job_id"]
    try:
        if _audit_already_written(row["action"], row["object_id"], job_id):
            return False
    except Exception:
        logger.exception("Could not look up the %s audit row of job %s for %s; not writing it.", row["action"], job_id, row["object_id"])
        return False
    try:
        from . import audit

        actor = audit.service_audit_actor(module_id="core", service="module-replacement", identity="system")
        result = audit.record(actor=actor, module_id="core", action=row["action"], object_type="module",
                              object_id=row["object_id"], message=row["message"], metadata=row["metadata"], strict=False,
                              correlation_id=correlation_id_for(row["action"], job_id))
    except Exception:
        logger.exception("Could not write the %s audit row for %s.", row["action"], row["object_id"])
        return False
    return bool(result.get("recorded", True)) if isinstance(result, dict) else True


def audit_finished_jobs(*, now: datetime | None = None, jobs=None, model: Mapping[str, Node] | None = None) -> int:
    """Write the outcome audit rows of module jobs that have finished (1.17.12). Returns the number of rows written.

    Audit follows what happened, so the rows are written after the root helper has finished, from the job file it left:
    ``disabled_modules``, ``enabled_modules`` and ``reconciled_modules`` of a succeeded job, and a switch-failed row for
    a failed job that had a planned list. It looks only at jobs finished in the last ``AUDIT_WINDOW_DAYS`` days and at
    most ``AUDIT_MAX_JOBS_PER_TICK`` of them, newest first. A row already in the audit log (same action, object and job
    id) is never written again. Non-strict: it never raises, and logs once per failing job."""
    written = 0
    try:
        if jobs is None:
            from . import module_manager_v2 as v2

            jobs = v2._iter_jobs()
        now = now or datetime.now(timezone.utc)
        horizon = now.timestamp() - AUDIT_WINDOW_DAYS * 86400
        candidates = []
        for job in jobs:
            if not isinstance(job, Mapping) or job.get("status") not in ("succeeded", "failed"):
                continue
            when = _parse_when(job.get("finished_at"))
            if when is not None and when.timestamp() >= horizon:
                candidates.append((when, job))
        candidates.sort(key=lambda item: item[0], reverse=True)
        known = dict(model) if model is not None else None

        def replaces_of(module_id: str) -> str:
            nonlocal known
            try:
                if known is None:
                    known = dict(live_model())
                node = known.get(module_id)
                return node.replaces if node is not None else ""
            except Exception:
                return ""

        for _, job in candidates[:AUDIT_MAX_JOBS_PER_TICK]:
            try:
                for row in _outcome_rows(job, replaces_of):
                    if _write_outcome_row(row):
                        written += 1
            except Exception:
                logger.exception("Could not write the outcome audit rows for module job %s.", job.get("id"))
    except Exception:
        logger.exception("Replacement audit sweep failed; Tactical is not affected.")
    return written


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
                    None, action=ACTION_CONFLICT_RESOLVED, object_id=replacement_id,
                    message=f"Both {replacement_id} and the module it replaces, {replaced_id}, were enabled. Core queued a job that disables {replacement_id} and keeps {replaced_id}.",
                    metadata={"replacement": replacement_id, "replaced": replaced_id, "job_id": str(job.get("id") or "")},
                    correlation_id=correlation_id_for(ACTION_CONFLICT_RESOLVED, job.get("id")),
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
    module (``disable_plan``) and disables it in the same job, so every other rule is checked as if it already were.
    1.17.12: the other direction is not a refusal either. Enabling a core or server module whose replacement is enabled
    names the replacement in ``disable_plan`` and switches it off in the same job, after two confirmations."""
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
