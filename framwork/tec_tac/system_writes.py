"""System writes: the second kind of Tactical work Core does for an honoured premium replacement (core.system_actions 1.3.0, Core 1.17.70, CQ203, AD-45).

The first kind (``system_actions.py``) starts a Tactical Celery task with ``.delay``. Some Tactical work has no task: a person's decision on one
Windows update is a plain PUT that saves one column. Core does not call that route and does not let a module touch Tactical's tables. It holds ONE
fixed write, ``winupdate.set_action``, in this file, and runs it only for the module that is the honoured replacement of Windows Patching.

What this file does, for ``run_system_write`` (the checks of the run itself are in ``system_actions._run``, in the same order as for a task)
    1. ``resolve_changes``: strict shape (exactly ``update_id`` and ``action`` per item, whole numbers, each update once, at most 40 000, every action
       one of the ``allowed_actions`` the person confirmed), then Core reads each update's endpoint itself. One unknown update refuses the whole call.
       The endpoint set then goes through the same scope and target checks as ``agent_ids``. Nothing names an id in a message.
    2. ``plan_group``: for one group (at most 2000 updates) read the current decision of every update (the "before").
    3. ``write_audit_rows``: one STRICT audit row per chunk of at most 500 changes, BEFORE the write, carrying ``[update_id, before, after]`` and the run,
       schedule, creator, confirmer, action and group digest. If one row cannot be written, nothing is written for the group.
    4. ``apply_group``: inside one transaction, with row locks, through Tactical's own ``WinUpdateSerializer(partial=True)`` with ``{"action": value}``,
       the same serializer Tactical's PUT uses. A row whose decision is no longer the one Core read (a person changed it meanwhile) is NOT overwritten:
       a person's later decision wins. A change that equals the current decision is counted, not written.
    5. ``record_closing``: one closing audit row per group with the counts and the decisions actually saved.

Honest limit: Tactical's own audit log does not show this write, because Core writes the column in its own process and not through Tactical's route.
Core's strict rows are the record. A failed write is outcome-unknown, as for a task: the group is never written again.
"""
from __future__ import annotations

import logging

from . import system_actions as _sa

logger = logging.getLogger("tec_tac.system_actions")

AUDIT_CHUNK = 500  # changes per strict audit row
READ_BLOCK = 5000  # ids per database lookup
MAX_LISTED = 500  # ids listed in the closing row for the rare cases (changed meanwhile, vanished)
CLOSING_ACTION = "custom:write-closed"


class WriteRefused(Exception):
    """The ``changes`` of a call are refused. ``reason`` is a code of ``system_actions.REASONS``; ``detail`` is plain text that names no id."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------------------------------------------ the few places this file reads or writes Tactical
def _models():
    from winupdate.models import WinUpdate

    return WinUpdate


def _blocks(ids):
    ids = list(ids)
    for start in range(0, len(ids), READ_BLOCK):
        yield ids[start:start + READ_BLOCK]


def _read_update_agents(update_ids) -> dict:
    """``{update number: endpoint number}`` for the updates that exist (one fixed read of Tactical's WinUpdate id and agent)."""
    WinUpdate = _models()
    found = {}
    for block in _blocks(update_ids):
        for update_id, agent_pk in WinUpdate.objects.filter(pk__in=block).values_list("pk", "agent__pk"):
            found[int(update_id)] = int(agent_pk)
    return found


def _read_actions(update_ids) -> dict:
    """``{update number: its current decision}`` for the updates that exist."""
    WinUpdate = _models()
    found = {}
    for block in _blocks(update_ids):
        for update_id, action in WinUpdate.objects.filter(pk__in=block).values_list("pk", "action"):
            found[int(update_id)] = str(action)
    return found


def _write_locked(planned) -> dict:
    """Write ``planned`` (a list of ``(update number, before, after)``) in ONE transaction with row locks. A row whose decision is no longer ``before``
    is left alone. Saves through Tactical's own serializer with the one key ``action``; any other column is out of reach. Returns
    ``{"saved": [[number, after]], "changed": [number], "vanished": [number]}``. Raises on any failure (the transaction rolls back)."""
    from datetime import timezone as dt_timezone

    from django.db import transaction
    from winupdate.serializers import WinUpdateSerializer

    WinUpdate = _models()
    saved, changed, vanished = [], [], []
    wanted = {number: (before, after) for number, before, after in planned}
    with transaction.atomic():
        rows = {}
        for block in _blocks(sorted(wanted)):
            for row in WinUpdate.objects.select_for_update().filter(pk__in=block).order_by("pk"):
                rows[int(row.pk)] = row
        for number in sorted(wanted):
            before, after = wanted[number]
            row = rows.get(number)
            if row is None:
                vanished.append(number)
            elif str(row.action) != before:
                changed.append(number)  # a person decided in between: their decision wins
            else:
                serializer = WinUpdateSerializer(instance=row, data={"action": after}, partial=True, context={"default_tz": dt_timezone.utc})
                serializer.is_valid(raise_exception=True)
                serializer.save()
                saved.append([number, after])
    return {"saved": saved, "changed": changed, "vanished": vanished}


def available() -> bool:
    """Can Core reach Tactical's WinUpdate model and serializer? A Tactical upgrade can never make Core write something else: the row is fixed."""
    try:
        from winupdate.serializers import WinUpdateSerializer  # noqa: F401

        _models()
        return True
    except Exception:
        logger.warning("Tactical's WinUpdate model or serializer is not available.", exc_info=True)
        return False


# ------------------------------------------------------------------------------------------------ 1. the changes of a call
def resolve_changes(changes, cleaned) -> tuple[dict, list]:
    """``(decisions, endpoint numbers)`` for a call, or ``WriteRefused``. ``decisions`` maps each update number to its decision.

    The shape is judged for every item first, then the decisions against what the person confirmed, then Core reads each update's endpoint."""
    if isinstance(changes, (str, bytes, dict)) or not isinstance(changes, (list, tuple)):
        raise WriteRefused("bad_changes")
    if not 1 <= len(changes) <= _sa.MAX_WRITE_ITEMS:
        raise WriteRefused("bad_changes", f" At most {_sa.MAX_WRITE_ITEMS} changes in one call, and at least one.")
    decisions = {}
    for item in changes:
        if not isinstance(item, dict) or set(item) != {"update_id", "action"}:
            raise WriteRefused("bad_changes")
        number, action = item["update_id"], item["action"]
        if isinstance(number, bool) or not isinstance(number, int) or not 0 < number < 2**63 or not isinstance(action, str) or number in decisions:
            raise WriteRefused("bad_changes")
        decisions[number] = action
    allowed = set(cleaned.get("allowed_actions") or ())
    if any(action not in allowed for action in decisions.values()):  # includes 'inherit' and anything unknown
        raise WriteRefused("action_not_allowed")
    try:
        agents = _read_update_agents(sorted(decisions))
    except Exception:
        logger.warning("The updates of a write could not be read; the call is refused.", exc_info=True)
        raise WriteRefused("function_unavailable") from None
    if set(agents) != set(decisions):
        raise WriteRefused("unknown_update")
    return decisions, sorted(set(agents.values()))


# ------------------------------------------------------------------------------------------------ 2 to 5. one group
def plan_group(group, decisions) -> dict:
    """Read the current decision of every update of the group. ``write`` holds ``(number, before, after)`` for the ones that change."""
    before = _read_actions(group)
    write, same, vanished = [], [], []
    for number in group:
        if number not in before:
            vanished.append(number)
        elif before[number] == decisions[number]:
            same.append(number)
        else:
            write.append((number, before[number], decisions[number]))
    return {"write": write, "same": same, "vanished": vanished}


def _meta(definition, run, schedule_id, provenance, extra, digest, index, groups_total, total) -> dict:
    return {
        "requested_by": "scheduler", "run_id": str(run.id), "schedule_id": str(schedule_id), "owner_module": definition.module_id,
        "action_id": definition.id, "function": definition.function, "kind": "write", "group": index, "groups": groups_total,
        "total_changes": total, "targets_digest": digest, **provenance, **extra,
    }


def write_audit_rows(*, actor, definition, run, schedule_id, provenance, extra, planned, digest, index, groups_total, total) -> None:
    """One strict row per chunk of at most 500 changes, BEFORE the write. Raises when one cannot be written (the caller then writes nothing)."""
    write = planned["write"]
    chunks = [write[start:start + AUDIT_CHUNK] for start in range(0, len(write), AUDIT_CHUNK)]
    for part, chunk in enumerate(chunks, start=1):
        metadata = _meta(definition, run, schedule_id, provenance, extra, digest, index, groups_total, total)
        metadata.update(phase="before_write", part=part, parts=len(chunks), change_count=len(chunk), changes=[[n, b, a] for n, b, a in chunk])
        _sa._audit().record(
            actor=actor, module_id="core", action="run", object_type="system_action", object_id=definition.id,
            message=(f"A scheduled write of {len(chunk)} Windows update decision(s) is being made in Tactical (group {index} of {groups_total}, "
                     f"part {part} of {len(chunks)}). Each line holds the update, the decision before and the decision after."),
            metadata=metadata, strict=True,
        )


def apply_group(planned) -> dict:
    """Write the group. Returns the counts and the decisions actually saved. Raises on a failed write (the caller treats that as outcome-unknown)."""
    write = planned["write"]
    result = _write_locked(write) if write else {"saved": [], "changed": [], "vanished": []}
    return {
        "written": len(result["saved"]), "unchanged": len(planned["same"]), "changed_meanwhile": len(result["changed"]),
        "vanished": len(planned["vanished"]) + len(result["vanished"]), "saved": result["saved"], "changed_ids": list(result["changed"]),
        "vanished_ids": list(planned["vanished"]) + list(result["vanished"]),
    }


def record_closing(*, actor, definition, run, schedule_id, provenance, extra, outcome, digest, index, groups_total, total) -> None:
    """The closing row of a group, after the write. The write is already made, so a row that cannot be written is logged and the run goes on."""
    metadata = _meta(definition, run, schedule_id, provenance, extra, digest, index, groups_total, total)
    metadata.update(
        phase="closed", written=outcome["written"], unchanged=outcome["unchanged"], changed_meanwhile=outcome["changed_meanwhile"],
        vanished=outcome["vanished"], saved=outcome["saved"], changed_meanwhile_ids=outcome["changed_ids"][:MAX_LISTED],
        vanished_ids=outcome["vanished_ids"][:MAX_LISTED],
    )
    try:
        _sa._audit().record(
            actor=actor, module_id="core", action=CLOSING_ACTION, object_type="system_action", object_id=definition.id,
            message=(f"A scheduled write of Windows update decisions was made in Tactical (group {index} of {groups_total}): {outcome['written']} written, "
                     f"{outcome['unchanged']} already as decided, {outcome['changed_meanwhile']} left alone because a person changed them meanwhile."),
            metadata=metadata, strict=True,
        )
    except Exception:
        logger.exception("The closing audit row of a write group could not be written; the write was made and the 'before' rows hold the record.")
