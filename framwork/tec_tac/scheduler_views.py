from __future__ import annotations

import logging
from datetime import datetime, time, timedelta
from uuid import UUID

from django.db import connection, transaction
from django.db.models import OuterRef, Q, Subquery
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime, parse_time
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated
from rest_framework.exceptions import NotFound, PermissionDenied

from .models import TecTacSchedule, TecTacScheduleRun, TecTacSchedulerConfig
from .rbac import has_extension_permission, has_tactical_permission
from . import resources_adapter
from .scheduler import (
    CORE_REASONS,
    CORE_OWN_MODULE_IDS,
    ORPHAN_LABEL,
    ScheduleVisibility,
    TACTICAL_PERMISSION_PREFIX,
    SchedulerError,
    check_monthly_shape,
    get_scheduled_action,
    is_one_off_schedule,
    is_tactical_permission_entry,
    queue_manual_run,
    remember_removed_schedule,
    manual_person_action,
    sync_module_schedule_state,
    schedule_creator_names,
    scheduled_actions,
    switch_monthly_mode,
    TAKEOVER_REFUSED,
    TakeoverRefused,
    _record_takeover_refusal,
    _resolver_scope_check,
    serialize_action,
    serialize_run,
    serialize_schedule,
    scheduler_health,
    validate_schedule_payload,
)
from .views import _role_for_user
from .system_action_confirmation import SystemActionCreationRefused, describe_confirmation, require_creation, audit_extra as _system_audit_extra
from . import scheduler_creation_scope

logger = logging.getLogger("tec_tac.scheduler")


def _native_scheduler_manager(user) -> bool:
    role = _role_for_user(user)
    return bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False) or bool(getattr(role, "can_do_server_maint", False) if role else False)


def _can_use_action(user, action) -> bool:
    if _native_scheduler_manager(user):
        return True
    # 1.17.17: any-of. A Tec-Tac code or a Tactical role flag (tactical:can_...). An entry that cannot be checked counts as
    # not held and never stops the next entry; no entry at all means managers only.
    for entry in action.permission_entries:
        try:
            if is_tactical_permission_entry(entry):
                if has_tactical_permission(user, entry[len(TACTICAL_PERMISSION_PREFIX):]):
                    return True
            elif has_extension_permission(user, entry):
                return True
        except ValueError:
            logger.warning("Scheduled action %s names a permission that does not exist: %s", action.id, entry)
        except Exception:
            logger.exception("Scheduled action %s: permission %s could not be checked", action.id, entry)
    return False


def _require_action(user, action_id, *, allow_unregistered_manager=False):
    try:
        action = get_scheduled_action(action_id)
    except SchedulerError as exc:
        # Managers must be able to remove an orphaned schedule after its owning
        # module/action has disappeared. Non-managers still fail closed because
        # there is no action permission left to authorize against.
        if allow_unregistered_manager and _native_scheduler_manager(user):
            return None
        raise NotFound(str(exc)) from exc
    if not _can_use_action(user, action):
        raise PermissionDenied("You do not have permission to schedule this action.")
    return action


from .scheduler_targets import (
    SchedulerTargetShapeError,
    normalize_scheduler_targets,
    tactical_scope_ref,
)


def _normalize_targets(targets):
    try:
        return normalize_scheduler_targets(targets)
    except SchedulerTargetShapeError as exc:
        raise SchedulerError(str(exc)) from exc






def _canonicalize_endpoint_targets_globally(targets):
    """Repair legacy endpoint aliases without making an authorization decision."""
    canonical = dict(targets or {})
    target_type = str(canonical.get("type") or "none").strip().lower()
    try:
        if target_type in {"endpoint", "endpoints", "agent", "agents"}:
            values = list(canonical.get("ids") or [])
            resolved = resources_adapter.canonical_agent_target_ids(identifiers=values)
            if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
                raise SchedulerError("One or more persisted scheduler endpoints no longer resolve to a Tactical agent.")
            canonical["ids"] = resolved
        elif target_type == "dynamic":
            scope = dict(canonical.get("scope") or {})
            if str(scope.get("type") or "").strip().lower() in {"endpoint", "agent"}:
                values = list(scope.get("ids") or [])
                resolved = resources_adapter.canonical_agent_target_ids(identifiers=values)
                if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
                    raise SchedulerError("One or more persisted scheduler endpoints no longer resolve to a Tactical agent.")
                scope["type"] = "endpoint"
                scope["ids"] = resolved
                canonical["scope"] = scope
    except resources_adapter.TacticalResourceAdapterError as exc:
        raise SchedulerError(str(exc)) from exc
    return canonical
def _canonicalize_endpoint_targets_for_user(user, targets):
    canonical = dict(targets or {})
    target_type = str(canonical.get("type") or "none").strip().lower()
    if target_type in {"endpoint", "endpoints", "agent", "agents"}:
        values = list(canonical.get("ids") or [])
        resolved = resources_adapter.canonical_agent_target_ids_in_scope(user=user, identifiers=values)
        if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
            raise PermissionDenied("One or more scheduler endpoints are outside your Tactical access scope.")
        canonical["ids"] = resolved
    elif target_type == "dynamic":
        scope = dict(canonical.get("scope") or {})
        if str(scope.get("type") or "").strip().lower() in {"endpoint", "agent"}:
            values = list(scope.get("ids") or [])
            resolved = resources_adapter.canonical_agent_target_ids_in_scope(user=user, identifiers=values)
            if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
                raise PermissionDenied("One or more scheduler endpoints are outside your Tactical access scope.")
            scope["type"] = "endpoint"
            scope["ids"] = resolved
            canonical["scope"] = scope
    return canonical

def _scope_target_refs(targets):
    try:
        return [tactical_scope_ref(targets)]
    except SchedulerTargetShapeError as exc:
        raise SchedulerError(str(exc)) from exc


def _require_target_scope(user, targets, *, payload=False, module_id=None, strict=False):
    # Managers must be able to inspect and repair legacy/module schedules even
    # when their saved target object predates the canonical target contract.
    # 1.17.68: ``strict`` has no manager bypass (used before ownership moves to a person). ``module_id`` names the module that owns the
    # schedule's action: a module-owned target type that module registered a resolver for is judged by the endpoints it names.
    if not strict and _native_scheduler_manager(user):
        return
    try:
        refs = _scope_target_refs(targets)
    except SchedulerError as exc:
        if payload:
            raise
        raise PermissionDenied("The saved scheduler target definition is not in the supported canonical format.") from exc
    if payload:
        for ref in refs:
            if ref["kind"] in {"client", "site", "endpoint"} and not ref["values"]:
                raise SchedulerError(f"{ref['kind'].capitalize()} scheduler targets require at least one target identifier.")
    for ref in refs:
        kind, values = ref["kind"], ref["values"]
        if kind in {"none", "module"}:
            if kind == "module" and module_id:
                decided = _resolver_scope_check(user, module_id, targets, strict=strict)
                if decided is True:
                    continue
                if decided is False:
                    raise PermissionDenied("One or more scheduler targets are outside your Tactical client/site access scope.")
            if resources_adapter.tactical_scope_unrestricted(user=user):
                continue
            raise PermissionDenied(
                "Non-Tactical scheduler targets require unrestricted Tactical client/site scope."
            )
        if kind == "dynamic_unscoped":
            if resources_adapter.tactical_scope_unrestricted(user=user):
                continue
            raise PermissionDenied("Dynamic scheduler targets require unrestricted Tactical client/site scope or an explicit client, site, or endpoint scope.")
        if not values:
            raise PermissionDenied("The saved schedule target scope is not available to this account.")

        try:
            if kind == "client":
                allowed = resources_adapter.explicit_client_target_ids_in_scope(user=user, client_ids=values)
                requested = set(values)
            elif kind == "site":
                allowed = resources_adapter.site_target_ids_in_scope(user=user, site_ids=values)
                requested = set(values)
            else:
                requested = {str(v) for v in values}
                allowed = resources_adapter.agent_target_identifiers_in_scope(user=user, identifiers=values)
        except SchedulerError:
            raise
        except Exception as exc:
            # Authorization must fail closed if Tactical scope resolution is unavailable.
            raise PermissionDenied("Unable to verify the scheduler target scope for this account.") from exc

        if not requested.issubset(allowed):
            raise PermissionDenied("One or more scheduler targets are outside your Tactical client/site access scope.")


def _can_access_target_scope(user, targets, *, module_id=None, strict=False) -> bool:
    if not strict and _native_scheduler_manager(user):
        return True
    try:
        _require_target_scope(user, targets, payload=False, module_id=module_id, strict=strict)
        return True
    except (PermissionDenied, SchedulerError):
        return False


def _owner_type_filter(request):
    value = str(request.query_params.get("owner_type") or "").strip().lower()
    if not value:
        return None
    if value not in {TecTacSchedule.OwnerType.USER, TecTacSchedule.OwnerType.MODULE}:
        raise SchedulerError("owner_type must be user or module.")
    return value


MAX_NAME_FILTER = 150  # the longest user name Core stores


def _name_filter(request, key):
    """``created_by`` or ``confirmed_by`` query value (1.17.63): trimmed text, or None when absent. A name that is not stored matches nothing."""
    value = str(request.query_params.get(key) or "").strip()
    return value or None


def _name_filters_match(schedule, created_by, confirmed_by) -> bool:
    """Does ``schedule`` pass the creator and confirmer filters (1.17.63, CQ179 b)? Exact, case-insensitive. The creator is the stored name or,
    for a row made before migration 0036, the creator row's user name. No filter means every schedule passes. It adds no right: it is only
    asked about a schedule the caller may already list."""
    if created_by:
        creator, _confirmed = schedule_creator_names(schedule)
        if not creator or creator.casefold() != created_by.casefold():
            return False
    if confirmed_by:
        _creator, confirmed = schedule_creator_names(schedule)
        if not confirmed or confirmed.casefold() != confirmed_by.casefold():
            return False
    return True


def _person_name(user) -> str:
    """The user name stored on a schedule (1.17.63), at most 150 characters; empty when there is no user."""
    return str(getattr(user, "username", "") or "")[:MAX_NAME_FILTER]


_TIMING_FIELDS = ("schedule_type", "run_at", "run_time", "weekdays", "day_of_month", "month_week", "month_weekday", "interval_seconds", "timezone")
_EDIT_FIELDS = ("action_id", "target_mode", "targets", "parameters", "schedule_type", "timezone", "run_at", "run_time", "weekdays", "day_of_month", "month_week", "month_weekday", "interval_seconds")


_MONTHLY_FIELDS = ("day_of_month", "month_week", "month_weekday")


def _edit_value(name, schedule_type, value):
    """1.17.90: the three monthly fields only mean something on a monthly schedule, so a non-monthly schedule compares them as None. A row
    made before this release may still hold a stale one, and a stale value must not look like an edit (it would move the ownership)."""
    from .scheduler import _comparable

    if name in _MONTHLY_FIELDS and schedule_type != TecTacSchedule.ScheduleType.MONTHLY:
        return None
    return _comparable(name, value)


def _changed_edit_fields(schedule, data):
    """The edit fields ``data`` changes on ``schedule`` (1.17.90: one place for both the confirmation check and the ownership check)."""
    new_type, old_type = data.get("schedule_type", schedule.schedule_type), schedule.schedule_type
    return [name for name in _EDIT_FIELDS if name in data and _edit_value(name, new_type, data.get(name)) != _edit_value(name, old_type, getattr(schedule, name))]


def _system_action_creation(user, action, data, confirmation_id, *, schedule=None):
    """1.17.66 (AD-13 as amended): the creation-time controls and the one Yes or No for a declared system action. None for any other action, for
    a schedule that stays switched off and, on an edit, for a change that touches neither the action, targets, parameters nor timing and does not
    switch it on. Raises ``SystemActionCreationRefused``."""
    if not data.get("enabled", True):
        return None
    if schedule is not None and schedule.enabled and not _changed_edit_fields(schedule, data):
        return None
    when = {name: data.get(name) for name in _TIMING_FIELDS}
    return require_creation(user, action, data.get("targets"), data.get("parameters"), when, confirmation_id)


def _audit_system_schedule(user, schedule, verb, info, extra=None):
    """One strict audit row for a created or edited schedule of a system action: creator, confirmer, schedule, total, groups and timing. A row that
    cannot be written stops the change (the caller's transaction rolls back). ``extra`` (1.17.68) carries the ownership move, when there was one."""
    from .scheduler import _audit_schedule_row

    _audit_schedule_row(
        user, schedule, verb, f"A person {'created' if verb == 'add' else 'changed'} a schedule for a system action.", strict=True,
        extra={"requested_by": "person", **_system_audit_extra(info), **(extra or {})},
    )


def _require_user_managed(schedule):
    if schedule.owner_type == TecTacSchedule.OwnerType.MODULE:
        raise PermissionDenied(
            f"Schedule is managed by module {schedule.owner_module!r}. Change it from the owning module instead."
        )


def _require_schedule_owner_or_manager(user, schedule):
    if schedule.owner_type == TecTacSchedule.OwnerType.MODULE:
        return
    if _native_scheduler_manager(user):
        return
    if schedule.created_by_id != getattr(user, "id", None):
        raise PermissionDenied("Only the schedule owner or a scheduler manager may change this user schedule.")

def _parse_fields(payload: dict) -> dict:
    data = dict(payload)
    if "run_at" in data:
        if data["run_at"] in (None, ""):
            data["run_at"] = None
        elif isinstance(data["run_at"], str):
            value = parse_datetime(data["run_at"])
            if not value:
                raise SchedulerError("run_at must be an ISO-8601 datetime.")
            data["run_at"] = value
    if "interval_anchor_at" in data:
        if data["interval_anchor_at"] in (None, ""):
            data["interval_anchor_at"] = None
        elif isinstance(data["interval_anchor_at"], str):
            value = parse_datetime(data["interval_anchor_at"])
            if not value:
                raise SchedulerError("interval_anchor_at must be an ISO-8601 datetime.")
            data["interval_anchor_at"] = value
    if "run_time" in data:
        if data["run_time"] in (None, ""):
            data["run_time"] = None
        elif isinstance(data["run_time"], str):
            value = parse_time(data["run_time"])
            if not value:
                raise SchedulerError("run_time must be an HH:MM time.")
            data["run_time"] = value
    return data


def _apply_schedule_fields(schedule, data):
    allowed = {
        "name", "module_id", "action_id", "target_mode", "targets", "parameters",
        "schedule_type", "timezone", "run_at", "run_time", "weekdays", "day_of_month",
        "month_week", "month_weekday", "interval_seconds", "interval_anchor_at", "enabled", "missed_policy", "missed_grace_minutes", "concurrency_policy",
        "retry_count", "retry_delay_seconds",
    }
    for key in allowed:
        if key in data:
            setattr(schedule, key, data[key])
    if schedule.schedule_type != TecTacSchedule.ScheduleType.INTERVAL:
        schedule.interval_seconds = None
        schedule.interval_anchor_at = None
    if schedule.schedule_type != TecTacSchedule.ScheduleType.MONTHLY:
        # 1.17.90: one place for POST and PATCH. A schedule that is not monthly stores none of the three monthly fields.
        schedule.day_of_month = schedule.month_week = schedule.month_weekday = None


def _validate_shape(data):
    schedule_type = data.get("schedule_type")
    if schedule_type == TecTacSchedule.ScheduleType.ONCE and not data.get("run_at"):
        raise SchedulerError("A one-time schedule requires run_at.")
    if schedule_type in {TecTacSchedule.ScheduleType.DAILY, TecTacSchedule.ScheduleType.WEEKLY, TecTacSchedule.ScheduleType.MONTHLY} and not data.get("run_time"):
        raise SchedulerError("Recurring calendar schedules require run_time.")
    if schedule_type == TecTacSchedule.ScheduleType.INTERVAL:
        if not data.get("interval_seconds"):
            raise SchedulerError("Interval schedules require interval_seconds.")
        if not data.get("interval_anchor_at"):
            raise SchedulerError("Interval schedules require interval_anchor_at.")
    if schedule_type == TecTacSchedule.ScheduleType.WEEKLY and not data.get("weekdays"):
        raise SchedulerError("Weekly schedules require at least one weekday.")
    check_monthly_shape(data)
    action = get_scheduled_action(data["action_id"])
    targets = data.get("targets") or {}
    target_type = str(targets.get("type") or "none")
    if target_type not in action.target_types:
        raise SchedulerError(f"Action {action.id} does not support target type {target_type!r}.")


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Scheduler"], summary="List schedulable actions"))
class SchedulerActionListView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        items = [serialize_action(a) for a in scheduled_actions() if _can_use_action(request.user, a)]
        return Response({"actions": items, "count": len(items), "manage": _native_scheduler_manager(request.user)})


def _sync_module_state_safely(visibility) -> None:
    """1.17.97: bring paused_reason and its audit row up to date before a list (the tick does the same). A fault here never stops the answer."""
    try:
        sync_module_schedule_state(visibility=visibility)
    except Exception:
        logger.exception("Pausing the schedules of disabled or removed modules failed; the list is answered from the live module state.")


def _hide_if_module_disabled(schedule, visibility=None):
    """1.17.97: a schedule of a disabled module (or one whose module state cannot be read) does not exist for the API: 404, like an unknown id."""
    if (visibility or ScheduleVisibility()).hidden(schedule):
        raise NotFound("No schedule with that id was found.")


def _orphaned_filter(request):
    value = str(request.query_params.get("orphaned") or "").strip().lower()
    if not value:
        return None
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no"}:
        return False
    raise SchedulerError("orphaned must be true or false.")


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Scheduler"], summary="List schedules"),
    post=extend_schema(tags=["Tec-Tac Scheduler"], summary="Create schedule"),
)
class SchedulerListView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        try:
            owner_type = _owner_type_filter(request)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)
        # 1.17.63 (CQ179 b): an administrator can ask who made or confirmed a schedule. This only narrows the list: the scope and
        # permission filtering below is unchanged, so nobody sees a schedule they could not see before, and no right is added.
        created_by = _name_filter(request, "created_by")
        confirmed_by = _name_filter(request, "confirmed_by")
        try:
            orphaned = _orphaned_filter(request)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)
        visibility = ScheduleVisibility()  # 1.17.97: read live at request time, so the answer never lags the helper that wrote the module state
        _sync_module_state_safely(visibility)
        latest_status = TecTacScheduleRun.objects.filter(schedule_id=OuterRef("pk")).order_by("-created_at").values("status")[:1]
        qs = TecTacSchedule.objects.select_related("created_by", "updated_by").annotate(
            latest_status=Subquery(latest_status)
        )
        if owner_type:
            qs = qs.filter(owner_type=owner_type)
        rows = []
        for schedule in qs:
            if visibility.hidden(schedule):
                continue  # a disabled module's schedules are left out (1.17.97); an unreadable module state hides every module-bound one
            if orphaned is not None and bool(visibility.orphan_module(schedule)) != orphaned:
                continue
            if not _name_filters_match(schedule, created_by, confirmed_by):
                continue  # only ever removes a row: the permission and scope test below is exactly what it was
            try:
                action = get_scheduled_action(schedule.action_id)
            except SchedulerError:
                action = None
            if (_native_scheduler_manager(request.user) or (action and _can_use_action(request.user, action))) and _can_access_target_scope(request.user, schedule.targets, module_id=schedule.module_id):
                rows.append(serialize_schedule(schedule, visibility=visibility))
        return Response({
            "schedules": rows, "count": len(rows), "manage": _native_scheduler_manager(request.user),
            "owner_type": owner_type,
            "module_state_unreadable": visibility.unreadable,  # 1.17.97, additive: true means module-bound schedules are hidden (fail closed)
        })

    def post(self, request):
        try:
            incoming = _parse_fields(dict(request.data))
            confirmation_id = incoming.pop("confirmation_id", None)
            data = validate_schedule_payload(incoming)
            action = _require_action(request.user, data["action_id"])
            data.setdefault("targets", {"type": action.target_types[0]})
            data.setdefault("parameters", {})
            data.setdefault("target_mode", TecTacSchedule.TargetMode.SNAPSHOT)
            data.setdefault("enabled", True)
            data.setdefault("missed_policy", TecTacSchedule.MissedPolicy.SKIP)
            data.setdefault("missed_grace_minutes", 60)
            data.setdefault("concurrency_policy", TecTacSchedule.ConcurrencyPolicy.SKIP)
            data.setdefault("retry_count", 0)
            data.setdefault("retry_delay_seconds", 60)
            if data.get("schedule_type") == TecTacSchedule.ScheduleType.INTERVAL and not data.get("interval_anchor_at"):
                data["interval_anchor_at"] = timezone.now().replace(second=0, microsecond=0)
            data["targets"] = _normalize_targets(data.get("targets"))
            system_info = _system_action_creation(request.user, action, data, confirmation_id)
            data["targets"] = _canonicalize_endpoint_targets_for_user(request.user, data["targets"])
            _validate_shape(data)
            _require_target_scope(request.user, data.get("targets"), payload=True, module_id=action.module_id)
            schedule = TecTacSchedule(
                owner_type=TecTacSchedule.OwnerType.USER, created_by=request.user, updated_by=request.user,
                created_by_username=_person_name(request.user), confirmed_by_username=_person_name(request.user),
                creation_scope=scheduler_creation_scope.capture(request.user),  # 1.17.68: what this person could reach when they saved it
            )
            _apply_schedule_fields(schedule, data)
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            if system_info is None:
                schedule.save()
            else:
                with transaction.atomic():
                    schedule.save()
                    _audit_system_schedule(request.user, schedule, "add", system_info)
            return Response(serialize_schedule(schedule, include_runs=True), status=201)
        except SystemActionCreationRefused as exc:
            return Response({"detail": str(exc), "reason": exc.reason}, status=403)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)


class SchedulerDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    def get_object(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule.objects.select_related("created_by", "updated_by"), pk=schedule_id)
        _hide_if_module_disabled(schedule)
        action = _require_action(request.user, schedule.action_id)
        _require_target_scope(request.user, schedule.targets, payload=False, module_id=schedule.module_id)
        return schedule, action

    def get(self, request, schedule_id):
        schedule, _ = self.get_object(request, schedule_id)
        return Response(serialize_schedule(schedule, include_runs=True))

    def patch(self, request, schedule_id):
        schedule, _ = self.get_object(request, schedule_id)
        _require_user_managed(schedule)
        _require_schedule_owner_or_manager(request.user, schedule)
        try:
            merged = {
                "name": schedule.name, "action_id": schedule.action_id, "module_id": schedule.module_id,
                "target_mode": schedule.target_mode, "targets": schedule.targets, "parameters": schedule.parameters,
                "schedule_type": schedule.schedule_type, "timezone": schedule.timezone,
                "run_at": schedule.run_at, "run_time": schedule.run_time, "weekdays": schedule.weekdays,
                "day_of_month": schedule.day_of_month, "month_week": schedule.month_week,
                "month_weekday": schedule.month_weekday, "interval_seconds": schedule.interval_seconds,
                "interval_anchor_at": schedule.interval_anchor_at, "enabled": schedule.enabled,
                "missed_policy": schedule.missed_policy, "missed_grace_minutes": schedule.missed_grace_minutes,
                "concurrency_policy": schedule.concurrency_policy, "retry_count": schedule.retry_count,
                "retry_delay_seconds": schedule.retry_delay_seconds,
            }
            incoming = _parse_fields(dict(request.data))
            confirmation_id = incoming.pop("confirmation_id", None)
            merged.update(incoming)
            switch_monthly_mode(merged, incoming)
            data = validate_schedule_payload(merged)
            action = _require_action(request.user, data["action_id"])
            data["targets"] = _normalize_targets(data.get("targets"))
            system_info = _system_action_creation(request.user, action, data, confirmation_id, schedule=schedule)
            data["targets"] = _canonicalize_endpoint_targets_for_user(request.user, data["targets"])
            _validate_shape(data)
            _require_target_scope(request.user, data.get("targets"), payload=True, module_id=action.module_id)
            # 1.17.68 (Johan, 21 October 2026): a person other than the owner who edits the schedule (an edit field, or switching it on) takes the
            # ownership, and the scope is stored again for the new owner. Never widens: their own scope must cover every target, with no manager
            # bypass, or the edit is refused and nothing changes. Switching a schedule off, or a rename alone, moves nothing.
            edit_fields = _changed_edit_fields(schedule, data)
            turned_on = bool(data.get("enabled", schedule.enabled)) and not schedule.enabled
            edited = bool(edit_fields) or turned_on
            other_person = schedule.created_by_id != request.user.id
            takeover = bool(edited and other_person and bool(data.get("enabled", schedule.enabled)))
            if takeover and not _can_access_target_scope(request.user, data.get("targets"), module_id=action.module_id, strict=True):
                refusal = TakeoverRefused(TAKEOVER_REFUSED)
                refusal.takeover_row = (request.user, schedule.pk, action.id, action.module_id)
                raise refusal
            previous_names = schedule_creator_names(schedule)
            _apply_schedule_fields(schedule, data)
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.updated_by = request.user
            # 1.17.63 (CQ179 b): the editor confirms the schedule, after the permission and scope checks above (unchanged). A row
            # made before migration 0036 keeps its creator: the name is filled in from created_by the first time it is edited.
            if not schedule.created_by_username:
                schedule.created_by_username = _person_name(schedule.created_by)
            owner_move = None
            if takeover:
                owner_move = {"owner_changed_from": previous_names[0], "owner_changed_to": _person_name(request.user), "previous_confirmed_by": previous_names[1]}
                schedule.created_by = request.user
                schedule.created_by_username = _person_name(request.user)
            if takeover or (edited and not other_person):
                schedule.creation_scope = scheduler_creation_scope.capture(request.user)
            schedule.confirmed_by_username = _person_name(request.user)
            schedule.last_due_key = ""
            if system_info is None:
                schedule.save()
                if owner_move:
                    from .scheduler import _audit_schedule_row

                    _audit_schedule_row(request.user, schedule, "modify", "The ownership of a schedule moved to the person who edited it.",
                                        extra={"requested_by": "person", **owner_move})
            else:
                with transaction.atomic():
                    schedule.save()
                    _audit_system_schedule(request.user, schedule, "modify", system_info, owner_move)
            return Response(serialize_schedule(schedule, include_runs=True))
        except TakeoverRefused as exc:
            _record_takeover_refusal(exc)
            return Response({"detail": str(exc), "reason": exc.reason}, status=403)
        except SystemActionCreationRefused as exc:
            return Response({"detail": str(exc), "reason": exc.reason}, status=403)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)

    def delete(self, request, schedule_id):
        force = str(request.query_params.get("force") or "").strip().lower() in {"1", "true", "yes", "on"}
        with transaction.atomic():
            schedule = get_object_or_404(
                TecTacSchedule.objects.select_for_update(of=("self",)).select_related("created_by", "updated_by"), pk=schedule_id
            )
            _hide_if_module_disabled(schedule)
            _require_user_managed(schedule)
            _require_action(request.user, schedule.action_id, allow_unregistered_manager=True)
            _require_schedule_owner_or_manager(request.user, schedule)
            _require_target_scope(request.user, schedule.targets, payload=False)
            active = list(schedule.runs.select_for_update().filter(
                status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]
            ))
            if active and not force:
                return Response({
                    "detail": "Schedule has active runs. Use force=true to fail those runs and delete the schedule.",
                    "code": "active_runs",
                    "active_runs": len(active),
                }, status=409)
            if active:
                finished = timezone.now()
                for run in active:
                    run.status = TecTacScheduleRun.Status.FAILED
                    run.error_type = "ForceDeleted"
                    run.error = "Schedule was force-deleted while this run was active."
                    run.finished_at = finished
                    run.save(update_fields=["status", "error_type", "error", "finished_at"])
            if force:
                from .audit import record as audit_record
                audit_record(
                    actor=request.user,
                    module_id="core",
                    action="delete",
                    object_type="scheduler_schedule",
                    object_id=str(schedule.pk),
                    message="Scheduler schedule force-deleted.",
                    before=serialize_schedule(schedule, include_runs=False),
                    metadata={"force": True, "active_runs_failed": len(active)},
                    strict=True,
                )
            schedule.delete()
        return Response(status=204)


def _audit_run_now_refusal(user, schedule, reason: str) -> None:
    """One deny row for a Run now that Core refused for a declared person action (1.17.85). Best effort: a failed row is logged."""
    try:
        from . import audit

        audit.record(
            actor=user, module_id="core", action="deny", object_type="scheduler_schedule", object_id=str(schedule.pk),
            message=f"Run now of {schedule.action_id} was refused: the person who pressed it {'lacks the permission' if reason == 'no_permission' else 'is outside the targets scope'}.",
            metadata={"action_id": schedule.action_id, "owner_module": schedule.owner_module, "reason": reason, "manual": True},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a refused Run now could not be written")


class SchedulerRunNowView(APIView):
    permission_classes = [SessionAuthenticated]
    def post(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule, pk=schedule_id)
        visibility = ScheduleVisibility()
        _hide_if_module_disabled(schedule, visibility)
        if visibility.orphan_module(schedule) or getattr(schedule, "paused_reason", "") in CORE_REASONS:
            return Response({"detail": "This schedule is paused because the module that owns it is not installed.", "code": "schedule_paused"}, status=409)
        if is_one_off_schedule(schedule):
            # 1.17.17: a one-off run belongs to the user who started it and happens once. Refused before any other check, so a
            # second user cannot queue a run under the first user's identity and nobody can repeat it from the browser.
            raise PermissionDenied(f"This one-off run is managed by module {schedule.owner_module!r} and cannot be run again.")
        person_run = manual_person_action(schedule)
        try:
            _require_action(request.user, schedule.action_id)
        except PermissionDenied:
            if person_run:
                _audit_run_now_refusal(request.user, schedule, "no_permission")
                raise PermissionDenied("You do not have permission to run this action, so Run now was refused. Ask an administrator for the right.") from None
            raise
        _require_schedule_owner_or_manager(request.user, schedule)
        try:
            canonical_targets = _normalize_targets(schedule.targets or {})
            canonical_targets = _canonicalize_endpoint_targets_globally(canonical_targets)
        except SchedulerError as exc:
            schedule.enabled = False
            schedule.target_state = "invalid"
            schedule.target_state_detail = str(exc)[:500]
            schedule.save(update_fields=["enabled", "target_state", "target_state_detail", "updated_at"])
            return Response({"detail": str(exc)}, status=400)
        try:
            _require_target_scope(request.user, canonical_targets, payload=False, module_id=schedule.module_id, strict=person_run)  # 1.17.86: no manager bypass for a declared person action
        except PermissionDenied:
            if person_run:
                _audit_run_now_refusal(request.user, schedule, "outside_scope")
                raise PermissionDenied("These targets are outside your Tactical scope, so Run now was refused.") from None
            raise
        if canonical_targets != (schedule.targets or {}):
            schedule.targets = canonical_targets
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.save(update_fields=["targets", "target_state", "target_state_detail", "updated_at"])
        # 1.17.85: Core records the person who pressed the button; a declared person action then runs as them (re-checked live at run time)
        try:
            run = queue_manual_run(schedule, started_by=request.user if person_run else None)
        except SchedulerError as exc:
            return Response({"detail": str(exc), "code": "schedule_paused"}, status=409)
        return Response(serialize_run(run), status=202)


class SchedulerRunListView(APIView):
    permission_classes = [SessionAuthenticated]
    # Tactical production uses PostgreSQL and therefore the set-based JSONB
    # scope prefilter above. Keep alternate/test database backends safe too:
    # never allow a scoped history request to walk unbounded retained history
    # in Python. One extra candidate lets us detect truncation without a full
    # queryset count/scan.
    FALLBACK_SCOPE_SCAN_LIMIT = 5000

    @staticmethod
    def _positive_int(raw, *, default, maximum):
        if raw in (None, ""):
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise SchedulerError("page and page_size must be integers.") from exc
        if value < 1:
            raise SchedulerError("page and page_size must be positive integers.")
        return min(value, maximum)

    def _base_queryset(self, request, owner_type):
        qs = TecTacScheduleRun.objects.select_related("schedule")
        schedule_id = str(request.query_params.get("schedule_id") or "").strip()
        if schedule_id:
            try:
                schedule_uuid = UUID(schedule_id)
            except (TypeError, ValueError) as exc:
                raise SchedulerError("schedule_id must be a UUID.") from exc
            qs = qs.filter(schedule_snapshot_id=schedule_uuid)
        if owner_type:
            qs = qs.filter(owner_type=owner_type)
        # 1.17.97: the runs of a disabled module's schedules are left out with the schedules. An unreadable module state keeps only Core's own runs.
        hidden_ids, keep_core_only = ScheduleVisibility().hidden_run_filter()
        if keep_core_only:
            keep = [*CORE_OWN_MODULE_IDS, ""]
            qs = qs.filter(module_id__in=keep, owner_module__in=keep)
        elif hidden_ids:
            qs = qs.exclude(Q(module_id__in=hidden_ids) | Q(owner_module__in=hidden_ids))

        status_value = str(request.query_params.get("status") or "").strip().lower()
        if status_value:
            valid = {value for value, _label in TecTacScheduleRun.Status.choices}
            if status_value not in valid:
                raise SchedulerError("status is not a supported scheduler run state.")
            qs = qs.filter(status=status_value)

        search = str(request.query_params.get("search") or "").strip()
        if search:
            query = (
                Q(schedule_name__icontains=search)
                | Q(action_id__icontains=search)
                | Q(status__icontains=search)
                | Q(owner_module__icontains=search)
                | Q(owner_key__icontains=search)
                | Q(error_type__icontains=search)
                | Q(error__icontains=search)
                | Q(celery_task_id__icontains=search)
            )
            try:
                query |= Q(id=UUID(search))
            except (TypeError, ValueError):
                pass
            qs = qs.filter(query)
        return qs

    @staticmethod
    def _permitted_action_ids(user):
        return {action.id for action in scheduled_actions() if _can_use_action(user, action)}

    @staticmethod
    def _scope_snapshot_allows(targets, scope_snapshot):
        if scope_snapshot.get("unrestricted"):
            return True
        try:
            ref = tactical_scope_ref(targets)
        except SchedulerTargetShapeError:
            return False
        kind, values = ref["kind"], ref["values"]
        if kind in {"none", "module"}:
            return True
        if kind == "dynamic_unscoped" or not values:
            return False
        if kind == "client":
            return set(int(v) for v in values).issubset(scope_snapshot["client_ids"])
        if kind == "site":
            return set(int(v) for v in values).issubset(scope_snapshot["site_ids"])
        return {str(v) for v in values}.issubset(scope_snapshot["endpoint_ids"])

    @staticmethod
    def _sql_scope_prefilter(qs, scope_snapshot):
        """Apply exact PostgreSQL JSONB scope filtering before count/paging."""
        if scope_snapshot.get("unrestricted") or connection.vendor != "postgresql":
            return qs

        clients = [str(v) for v in scope_snapshot["client_ids"]]
        sites = [str(v) for v in scope_snapshot["site_ids"]]
        endpoints = [str(v) for v in scope_snapshot["endpoint_ids"]]
        table = TecTacScheduleRun._meta.db_table
        target = f'{table}."targets_snapshot"'
        sql = f"""
        (
          COALESCE({target}->>'type', 'none') = 'none'
          OR COALESCE({target}->>'type', 'none') NOT IN ('client','clients','site','sites','endpoint','endpoints','agent','agents','dynamic')
          OR (
            COALESCE({target}->>'type', '') IN ('client','clients')
            AND jsonb_typeof({target}->'ids') = 'array'
            AND jsonb_array_length({target}->'ids') > 0
            AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements_text({target}->'ids') AS e(v)
              WHERE NOT (e.v = ANY(%s::text[]))
            )
          )
          OR (
            COALESCE({target}->>'type', '') IN ('site','sites')
            AND jsonb_typeof({target}->'ids') = 'array'
            AND jsonb_array_length({target}->'ids') > 0
            AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements_text({target}->'ids') AS e(v)
              WHERE NOT (e.v = ANY(%s::text[]))
            )
          )
          OR (
            COALESCE({target}->>'type', '') IN ('endpoint','endpoints','agent','agents')
            AND jsonb_typeof({target}->'ids') = 'array'
            AND jsonb_array_length({target}->'ids') > 0
            AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements_text({target}->'ids') AS e(v)
              WHERE NOT (e.v = ANY(%s::text[]))
            )
          )
          OR (
            COALESCE({target}->>'type', '') = 'dynamic'
            AND jsonb_typeof({target}->'scope') = 'object'
            AND (
              (
                ({target}->'scope'->>'type') IN ('client','clients')
                AND jsonb_typeof({target}->'scope'->'ids') = 'array'
                AND jsonb_array_length({target}->'scope'->'ids') > 0
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text({target}->'scope'->'ids') AS e(v) WHERE NOT (e.v = ANY(%s::text[])))
              )
              OR (
                ({target}->'scope'->>'type') IN ('site','sites')
                AND jsonb_typeof({target}->'scope'->'ids') = 'array'
                AND jsonb_array_length({target}->'scope'->'ids') > 0
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text({target}->'scope'->'ids') AS e(v) WHERE NOT (e.v = ANY(%s::text[])))
              )
              OR (
                ({target}->'scope'->>'type') IN ('endpoint','endpoints','agent','agents')
                AND jsonb_typeof({target}->'scope'->'ids') = 'array'
                AND jsonb_array_length({target}->'scope'->'ids') > 0
                AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text({target}->'scope'->'ids') AS e(v) WHERE NOT (e.v = ANY(%s::text[])))
              )
            )
          )
        )
        """
        return qs.extra(where=[sql], params=[clients, sites, endpoints, clients, sites, endpoints])

    def _row_visible(self, request, run, *, manager, permitted_actions=None, scope_snapshot=None):
        if manager:
            return True
        action_id = run.action_id or (run.schedule.action_id if run.schedule else "")
        if action_id not in (permitted_actions or set()):
            return False
        run_targets = run.targets_snapshot or (run.schedule.targets if run.schedule else {})
        return self._scope_snapshot_allows(run_targets, scope_snapshot or {})

    def _paged_response(self, request, qs, owner_type):
        page = self._positive_int(request.query_params.get("page"), default=1, maximum=1_000_000)
        page_size = self._positive_int(request.query_params.get("page_size"), default=50, maximum=100)
        manager = _native_scheduler_manager(request.user)

        # Scheduler managers can see the complete filtered queryset, so let the
        # database perform count/offset/limit directly. Scoped operators require
        # per-run target authorization; scan with an iterator so retained history
        # is never materialized as one large Python list.
        if manager:
            total = qs.count()
            offset = (page - 1) * page_size
            visible = list(qs[offset:offset + page_size])
        else:
            permitted_actions = self._permitted_action_ids(request.user)
            scope_snapshot = resources_adapter.scheduler_scope_snapshot(user=request.user)
            qs = qs.filter(Q(action_id__in=permitted_actions) | Q(action_id="", schedule__action_id__in=permitted_actions))
            qs = self._sql_scope_prefilter(qs, scope_snapshot)
            if connection.vendor == "postgresql":
                total = qs.count()
                offset = (page - 1) * page_size
                visible = list(qs[offset:offset + page_size])
            else:
                rows = []
                candidate_count = 0
                candidate_qs = qs[: self.FALLBACK_SCOPE_SCAN_LIMIT + 1]
                candidate_iter = (
                    candidate_qs.iterator(chunk_size=200)
                    if hasattr(candidate_qs, "iterator")
                    else iter(candidate_qs)
                )
                for run in candidate_iter:
                    candidate_count += 1
                    if candidate_count > self.FALLBACK_SCOPE_SCAN_LIMIT:
                        raise SchedulerError(
                            "Scoped run history exceeds the bounded fallback scan limit; "
                            "use PostgreSQL for complete scoped history queries."
                        )
                    if self._row_visible(
                        request,
                        run,
                        manager=False,
                        permitted_actions=permitted_actions,
                        scope_snapshot=scope_snapshot,
                    ):
                        rows.append(run)
                total = len(rows)
                offset = (page - 1) * page_size
                visible = rows[offset:offset + page_size]

        pages = (total + page_size - 1) // page_size if total else 0
        return Response({
            "runs": [serialize_run(run) for run in visible],
            "count": total,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "next_page": page + 1 if page < pages else None,
            "previous_page": page - 1 if page > 1 and pages else None,
            "owner_type": owner_type,
        })

    def get(self, request):
        try:
            owner_type = _owner_type_filter(request)
            qs = self._base_queryset(request, owner_type)
        except (SchedulerError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)

        paged = any(key in request.query_params for key in ("page", "page_size", "search", "status"))
        if paged:
            try:
                return self._paged_response(request, qs, owner_type)
            except SchedulerError as exc:
                return Response({"detail": str(exc)}, status=400)

        # Compatibility path for older Core/UI consumers. Preserve the original
        # bounded response shape and 200-candidate behavior exactly.
        rows = []
        manager = _native_scheduler_manager(request.user)
        permitted_actions = None if manager else self._permitted_action_ids(request.user)
        scope_snapshot = None if manager else resources_adapter.scheduler_scope_snapshot(user=request.user)
        for run in qs[:200]:
            if self._row_visible(request, run, manager=manager, permitted_actions=permitted_actions, scope_snapshot=scope_snapshot):
                rows.append(serialize_run(run))
        return Response({"runs": rows, "count": len(rows), "owner_type": owner_type})


class SchedulerConfigView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not _native_scheduler_manager(request.user):
            raise PermissionDenied("Scheduler configuration requires server-maintenance authority.")
        config = TecTacSchedulerConfig.current()
        return Response({
            "once_retention_hours": config.once_retention_hours,
            "run_retention_days": config.run_retention_days,
            "queued_stale_minutes": config.queued_stale_minutes,
            "minimum_once_retention_hours": 1,
            "maximum_once_retention_hours": 720,
            "minimum_run_retention_days": 1,
            "maximum_run_retention_days": 3650,
            "minimum_queued_stale_minutes": 1,
            "maximum_queued_stale_minutes": 1440,
            "updated_at": config.updated_at.isoformat(),
            "updated_by": config.updated_by.username if config.updated_by else None,
        })

    def patch(self, request):
        if not _native_scheduler_manager(request.user):
            raise PermissionDenied("Scheduler configuration requires server-maintenance authority.")
        config = TecTacSchedulerConfig.current()
        updates = []
        rules = {
            "once_retention_hours": (1, 720),
            "run_retention_days": (1, 3650),
            "queued_stale_minutes": (1, 1440),
        }
        for field, (minimum, maximum) in rules.items():
            if field not in request.data:
                continue
            try:
                value = int(request.data.get(field))
            except (TypeError, ValueError):
                return Response({"detail": f"{field} must be an integer."}, status=400)
            if value < minimum or value > maximum:
                return Response({"detail": f"{field} must be between {minimum} and {maximum}."}, status=400)
            setattr(config, field, value)
            updates.append(field)
        if not updates:
            return Response({"detail": "At least one scheduler configuration field is required."}, status=400)
        config.updated_by = request.user
        config.save(update_fields=[*updates, "updated_by", "updated_at"])
        return self.get(request)


class SchedulerHealthView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        if not _native_scheduler_manager(request.user):
            raise PermissionDenied("Scheduler diagnostics require server-maintenance authority.")
        return Response(scheduler_health())


class SchedulerEventJobsView(APIView):
    """GET /api/tfd/scheduler/event-jobs/ (core.event_jobs 1.0.0, Core 1.17.45): the event jobs modules registered, with counts, backlog,
    the oldest pending age and the last error. The same authority as scheduler/health/. It never returns a payload, a key or a row id."""

    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not _native_scheduler_manager(request.user):
            raise PermissionDenied("Event job diagnostics require server-maintenance authority.")
        from .event_jobs import list_event_jobs

        return Response(list_event_jobs())


class SchedulerSelfTestView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        if not _native_scheduler_manager(request.user):
            raise PermissionDenied("Scheduler self-tests require server-maintenance authority.")
        mode = str(request.data.get("mode") or "immediate")
        if mode not in {"immediate", "scheduled", "failure", "retry"}:
            return Response({"detail": "mode must be immediate, scheduled, failure, or retry."}, status=400)
        action_id = {
            "immediate": "tec-tac.scheduler-test",
            "scheduled": "tec-tac.scheduler-test",
            "failure": "tec-tac.scheduler-test-failure",
            "retry": "tec-tac.scheduler-test-retry",
        }[mode]
        run_at = timezone.now() + timedelta(minutes=2)
        schedule = TecTacSchedule.objects.create(
            name=f"Scheduler self-test · {mode}", module_id="tec-tac", action_id=action_id, owner_type=TecTacSchedule.OwnerType.USER,
            targets={"type": "none"}, parameters={"message": f"Scheduler {mode} self-test"},
            schedule_type=TecTacSchedule.ScheduleType.ONCE, timezone="UTC", run_at=run_at,
            enabled=(mode == "scheduled"), retry_count=(1 if mode == "retry" else 0), retry_delay_seconds=5,
            created_by=request.user, updated_by=request.user,
        )
        if mode == "scheduled":
            return Response({"mode": mode, "schedule": serialize_schedule(schedule)}, status=201)
        run = queue_manual_run(schedule)
        return Response({"mode": mode, "schedule": serialize_schedule(schedule), "run": serialize_run(run)}, status=202)


@extend_schema_view(
    post=extend_schema(tags=["Tec-Tac Scheduler"], summary="Confirmation text and id for a system action schedule"),
)
class SchedulerSystemActionConfirmationView(APIView):
    """The plain Yes or No for a schedule of a system action (1.17.66). Body: ``action_id``, ``targets``, ``parameters`` (with the confirmed
    values under ``system_action_parameters``) and ``when`` (the timing fields; ``{"schedule_type": "once", "run_at": "now"}`` for a one-off run).
    Answers ``{required, text, confirmation_id, total, groups, expires_in}``. Every creation-time check runs first, so a person who may not
    create the schedule gets a refusal and a deny row, never a text. For an action that is not a system action it answers ``required: false``."""
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        body = request.data if isinstance(request.data, dict) else {}
        try:
            result = describe_confirmation(request.user, body.get("action_id"), body.get("targets"), body.get("parameters"), body.get("when"))
        except SystemActionCreationRefused as exc:
            return Response({"detail": str(exc), "reason": exc.reason}, status=403)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(result)


# ---- 1.17.97: schedules whose owner module is not installed ('Owner module not installed'): list, Disable and Remove -----------------------------

class _OrphanAuditFailed(Exception):
    """A strict audit row could not be written; nothing was changed."""


def _require_scheduler_manager(user):
    if not _native_scheduler_manager(user):
        raise PermissionDenied("Only a Scheduler manager can manage the schedules of a module that is not installed.")


def _orphan_audit(user, action, message, *, object_type, object_id, metadata, before=None):
    from . import audit

    try:
        audit.record(actor=user, module_id="core", action=action, object_type=object_type, object_id=str(object_id), message=message,
                     before=before, metadata={"orphaned": True, **metadata}, strict=True)
    except Exception as exc:
        logger.exception("Tec-Tac audit row for an orphaned schedule could not be written")
        raise _OrphanAuditFailed() from exc


_AUDIT_FAILED = {"detail": "The audit row could not be written, so nothing was changed.", "code": "audit_unavailable"}


def _orphan_in_scope(user, schedule) -> bool:
    """The target scope check the list and DELETE make (``_can_access_target_scope``). A row that fails it is skipped and counted."""
    return _can_access_target_scope(user, schedule.targets, module_id=schedule.module_id)


def _active_run_count(schedule) -> int:
    return schedule.runs.filter(status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]).count()


def _orphan_apply(schedule, request, mode: str) -> None:
    """Disable or remove one orphaned schedule inside the caller's transaction (the audit row is written first, strictly)."""
    if mode == "disable":
        schedule.enabled = False
        schedule.save(update_fields=["enabled", "updated_at"])
    else:
        remember_removed_schedule(schedule, getattr(request.user, "username", ""))  # a module can then answer 'removed by an administrator'
        schedule.delete()


class _OrphanSingleView(APIView):
    permission_classes = [SessionAuthenticated]
    mode = "disable"

    def _run(self, request, schedule_id):
        _require_scheduler_manager(request.user)
        visibility = ScheduleVisibility(read_state=False)
        try:
            with transaction.atomic():
                schedule = get_object_or_404(TecTacSchedule.objects.select_for_update(of=("self",)).select_related("created_by", "updated_by"), pk=schedule_id)
                module_id = visibility.orphan_module(schedule)
                if not module_id:
                    return Response({"detail": "The module that owns this schedule is installed, or Core cannot tell. Change the schedule from the module.",
                                     "code": "owner_module_installed"}, status=409)
                if not _orphan_in_scope(request.user, schedule):
                    raise PermissionDenied("The targets of this schedule are outside your Tactical scope.")
                active = _active_run_count(schedule)
                if active:
                    return Response({"detail": "This schedule has a queued or running run. Wait for it to end.", "code": "active_runs", "active_runs": active}, status=409)
                removing = self.mode == "remove"
                _orphan_audit(
                    request.user, "delete" if removing else "disable",
                    f"Schedule of module {module_id} {'removed' if removing else 'switched off'} because the module is not installed.",
                    object_type="scheduler_schedule", object_id=schedule.pk,
                    before=serialize_schedule(schedule, visibility=visibility) if removing else None,
                    metadata={"owner_module": schedule.owner_module or None, "owner_key": schedule.owner_key or None, "module_id": module_id, "count": 1},
                )
                _orphan_apply(schedule, request, self.mode)
                return Response({"module_id": module_id, "count": 1, "schedule_id": str(schedule_id), "mode": self.mode, "skipped_out_of_scope": 0})
        except _OrphanAuditFailed:
            return Response(_AUDIT_FAILED, status=503)


class _OrphanModuleView(APIView):
    permission_classes = [SessionAuthenticated]
    mode = "disable"

    def _run(self, request, module_id):
        _require_scheduler_manager(request.user)
        body = request.data if isinstance(request.data, dict) else {}
        if body.get("confirm") is not True:
            return Response({"detail": "Send confirm: true. The person has to say Yes first.", "code": "confirmation_required"}, status=400)
        visibility = ScheduleVisibility(read_state=False)
        if visibility.installed is None or module_id in visibility.installed or module_id in CORE_OWN_MODULE_IDS:
            return Response({"detail": "That module is installed, or Core cannot tell. Change its schedules from the module.", "code": "owner_module_installed"}, status=409)
        try:
            with transaction.atomic():
                candidates = TecTacSchedule.objects.select_for_update(of=("self",)).filter(
                    Q(owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module_id) | Q(owner_type=TecTacSchedule.OwnerType.USER, module_id=module_id)
                )
                rows = [s for s in candidates if visibility.orphan_module(s) == module_id]
                if not rows:
                    return Response({"detail": "No schedule of that module was found.", "code": "not_found"}, status=404)
                in_scope = [s for s in rows if _orphan_in_scope(request.user, s)]
                skipped = len(rows) - len(in_scope)
                busy = sum(1 for s in in_scope if _active_run_count(s) > 0)
                if busy:
                    return Response({"detail": "Some of these schedules have a queued or running run. Wait for them to end.", "code": "active_runs", "active_runs": busy}, status=409)
                removing = self.mode == "remove"
                targets = [s for s in in_scope if removing or s.enabled]
                if targets:
                    _orphan_audit(
                        request.user, "delete" if removing else "disable",
                        f"{len(targets)} schedule(s) of module {module_id} {'removed' if removing else 'switched off'} because the module is not installed.",
                        object_type="scheduler_module", object_id=module_id,
                        metadata={"module_id": module_id, "count": len(targets), "skipped_out_of_scope": skipped, "schedule_ids": [str(s.pk) for s in targets][:200]},
                    )
                    for schedule in targets:
                        _orphan_apply(schedule, request, self.mode)
                return Response({"module_id": module_id, "count": len(targets), "mode": self.mode, "skipped_out_of_scope": skipped})
        except _OrphanAuditFailed:
            return Response(_AUDIT_FAILED, status=503)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Scheduler"], summary="Schedules whose owner module is not installed, by module"))
class SchedulerOrphanedListView(APIView):
    """Scheduler managers only. The modules that are not installed but still own schedules, with their counts. A row outside the manager's target
    scope is left out and counted in ``out_of_scope``. When the module registry cannot be read nothing is listed and ``registry_unreadable`` is true."""
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_scheduler_manager(request.user)
        visibility = ScheduleVisibility(read_state=False)
        modules: dict = {}
        out_of_scope = 0
        for schedule in TecTacSchedule.objects.select_related("created_by", "updated_by"):
            module_id = visibility.orphan_module(schedule)
            if not module_id:
                continue
            if not _orphan_in_scope(request.user, schedule):
                out_of_scope += 1
                continue
            entry = modules.setdefault(module_id, {"module_id": module_id, "label": ORPHAN_LABEL, "count": 0, "enabled_count": 0, "schedules": []})
            entry["count"] += 1
            entry["enabled_count"] += 1 if schedule.enabled else 0
            entry["schedules"].append({"id": str(schedule.pk), "name": schedule.name, "action_id": schedule.action_id, "owner_key": schedule.owner_key or None,
                                       "owner_type": schedule.owner_type, "enabled": bool(schedule.enabled)})
        return Response({"modules": sorted(modules.values(), key=lambda m: m["module_id"]), "count": len(modules), "out_of_scope": out_of_scope,
                         "registry_unreadable": visibility.installed is None})


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Scheduler"], summary="Switch off one schedule whose owner module is not installed"))
class SchedulerOrphanedDisableView(_OrphanSingleView):
    mode = "disable"

    def post(self, request, schedule_id):
        return self._run(request, schedule_id)


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac Scheduler"], summary="Remove one schedule whose owner module is not installed"))
class SchedulerOrphanedRemoveView(_OrphanSingleView):
    mode = "remove"

    def delete(self, request, schedule_id):
        return self._run(request, schedule_id)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Scheduler"], summary="Switch off every schedule of a module that is not installed"))
class SchedulerOrphanedModuleDisableView(_OrphanModuleView):
    mode = "disable"

    def post(self, request, module_id):
        return self._run(request, module_id)


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac Scheduler"], summary="Remove every schedule of a module that is not installed"))
class SchedulerOrphanedModuleRemoveView(_OrphanModuleView):
    mode = "remove"

    def delete(self, request, module_id):
        return self._run(request, module_id)
