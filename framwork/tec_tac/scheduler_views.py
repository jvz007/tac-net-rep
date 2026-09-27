from __future__ import annotations

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
from .rbac import has_extension_permission
from . import resources_adapter
from .scheduler import (
    SchedulerError,
    get_scheduled_action,
    queue_manual_run,
    scheduled_actions,
    serialize_action,
    serialize_run,
    serialize_schedule,
    scheduler_health,
    validate_schedule_payload,
)
from .views import _role_for_user


def _native_scheduler_manager(user) -> bool:
    role = _role_for_user(user)
    return bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False) or bool(getattr(role, "can_do_server_maint", False) if role else False)


def _can_use_action(user, action) -> bool:
    if _native_scheduler_manager(user):
        return True
    if not action.permission:
        return False
    try:
        return has_extension_permission(user, action.permission)
    except ValueError:
        return False


def _require_action(user, action_id):
    try:
        action = get_scheduled_action(action_id)
    except SchedulerError as exc:
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


def _require_target_scope(user, targets, *, payload=False):
    # Managers must be able to inspect and repair legacy/module schedules even
    # when their saved target object predates the canonical target contract.
    if _native_scheduler_manager(user):
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


def _can_access_target_scope(user, targets) -> bool:
    if _native_scheduler_manager(user):
        return True
    try:
        _require_target_scope(user, targets, payload=False)
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
        "interval_seconds", "interval_anchor_at", "enabled", "missed_policy", "missed_grace_minutes", "concurrency_policy",
        "retry_count", "retry_delay_seconds",
    }
    for key in allowed:
        if key in data:
            setattr(schedule, key, data[key])
    if schedule.schedule_type != TecTacSchedule.ScheduleType.INTERVAL:
        schedule.interval_seconds = None
        schedule.interval_anchor_at = None


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
    if schedule_type == TecTacSchedule.ScheduleType.MONTHLY and not data.get("day_of_month"):
        raise SchedulerError("Monthly schedules require day_of_month.")
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
        latest_status = TecTacScheduleRun.objects.filter(schedule_id=OuterRef("pk")).order_by("-created_at").values("status")[:1]
        qs = TecTacSchedule.objects.select_related("created_by", "updated_by").annotate(
            latest_status=Subquery(latest_status)
        )
        if owner_type:
            qs = qs.filter(owner_type=owner_type)
        rows = []
        for schedule in qs:
            try:
                action = get_scheduled_action(schedule.action_id)
            except SchedulerError:
                action = None
            if (_native_scheduler_manager(request.user) or (action and _can_use_action(request.user, action))) and _can_access_target_scope(request.user, schedule.targets):
                rows.append(serialize_schedule(schedule))
        return Response({
            "schedules": rows, "count": len(rows), "manage": _native_scheduler_manager(request.user),
            "owner_type": owner_type,
        })

    def post(self, request):
        try:
            data = validate_schedule_payload(_parse_fields(dict(request.data)))
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
            data["targets"] = _canonicalize_endpoint_targets_for_user(request.user, data["targets"])
            _validate_shape(data)
            _require_target_scope(request.user, data.get("targets"), payload=True)
            schedule = TecTacSchedule(owner_type=TecTacSchedule.OwnerType.USER, created_by=request.user, updated_by=request.user)
            _apply_schedule_fields(schedule, data)
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.save()
            return Response(serialize_schedule(schedule, include_runs=True), status=201)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)


class SchedulerDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    def get_object(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule.objects.select_related("created_by", "updated_by"), pk=schedule_id)
        action = _require_action(request.user, schedule.action_id)
        _require_target_scope(request.user, schedule.targets, payload=False)
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
                "day_of_month": schedule.day_of_month, "interval_seconds": schedule.interval_seconds,
                "interval_anchor_at": schedule.interval_anchor_at, "enabled": schedule.enabled,
                "missed_policy": schedule.missed_policy, "missed_grace_minutes": schedule.missed_grace_minutes,
                "concurrency_policy": schedule.concurrency_policy, "retry_count": schedule.retry_count,
                "retry_delay_seconds": schedule.retry_delay_seconds,
            }
            merged.update(_parse_fields(dict(request.data)))
            data = validate_schedule_payload(merged)
            _require_action(request.user, data["action_id"])
            data["targets"] = _normalize_targets(data.get("targets"))
            data["targets"] = _canonicalize_endpoint_targets_for_user(request.user, data["targets"])
            _validate_shape(data)
            _require_target_scope(request.user, data.get("targets"), payload=True)
            _apply_schedule_fields(schedule, data)
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.updated_by = request.user
            schedule.last_due_key = ""
            schedule.save()
            return Response(serialize_schedule(schedule, include_runs=True))
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)

    def delete(self, request, schedule_id):
        force = str(request.query_params.get("force") or "").strip().lower() in {"1", "true", "yes", "on"}
        with transaction.atomic():
            schedule = get_object_or_404(
                TecTacSchedule.objects.select_for_update().select_related("created_by", "updated_by"), pk=schedule_id
            )
            _require_user_managed(schedule)
            _require_action(request.user, schedule.action_id)
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


class SchedulerRunNowView(APIView):
    permission_classes = [SessionAuthenticated]
    def post(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule, pk=schedule_id)
        _require_action(request.user, schedule.action_id)
        _require_schedule_owner_or_manager(request.user, schedule)
        try:
            canonical_targets = _normalize_targets(schedule.targets or {})
        except SchedulerError as exc:
            schedule.enabled = False
            schedule.target_state = "invalid"
            schedule.target_state_detail = str(exc)[:500]
            schedule.save(update_fields=["enabled", "target_state", "target_state_detail", "updated_at"])
            return Response({"detail": str(exc)}, status=400)
        if canonical_targets != (schedule.targets or {}):
            schedule.targets = canonical_targets
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.save(update_fields=["targets", "target_state", "target_state_detail", "updated_at"])
        _require_target_scope(request.user, canonical_targets, payload=False)
        run = queue_manual_run(schedule)
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
