from __future__ import annotations

from datetime import datetime, time

from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime, parse_time
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import NotFound, PermissionDenied

from .models import TecTacSchedule, TecTacScheduleRun
from .rbac import has_extension_permission
from .scheduler import (
    SchedulerError,
    get_scheduled_action,
    queue_manual_run,
    scheduled_actions,
    serialize_action,
    serialize_run,
    serialize_schedule,
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
        "enabled", "missed_policy", "missed_grace_minutes", "concurrency_policy",
        "retry_count", "retry_delay_seconds",
    }
    for key in allowed:
        if key in data:
            setattr(schedule, key, data[key])


def _validate_shape(data):
    schedule_type = data.get("schedule_type")
    if schedule_type == TecTacSchedule.ScheduleType.ONCE and not data.get("run_at"):
        raise SchedulerError("A one-time schedule requires run_at.")
    if schedule_type in {TecTacSchedule.ScheduleType.DAILY, TecTacSchedule.ScheduleType.WEEKLY, TecTacSchedule.ScheduleType.MONTHLY} and not data.get("run_time"):
        raise SchedulerError("Recurring schedules require run_time.")
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
    permission_classes = [IsAuthenticated]
    def get(self, request):
        items = [serialize_action(a) for a in scheduled_actions() if _can_use_action(request.user, a)]
        return Response({"actions": items, "count": len(items), "manage": _native_scheduler_manager(request.user)})


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Scheduler"], summary="List schedules"),
    post=extend_schema(tags=["Tec-Tac Scheduler"], summary="Create schedule"),
)
class SchedulerListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        rows = []
        for schedule in TecTacSchedule.objects.select_related("created_by", "updated_by").prefetch_related("runs"):
            try:
                action = get_scheduled_action(schedule.action_id)
            except SchedulerError:
                action = None
            if _native_scheduler_manager(request.user) or (action and _can_use_action(request.user, action)):
                rows.append(serialize_schedule(schedule))
        return Response({"schedules": rows, "count": len(rows), "manage": _native_scheduler_manager(request.user)})

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
            _validate_shape(data)
            schedule = TecTacSchedule(created_by=request.user, updated_by=request.user)
            _apply_schedule_fields(schedule, data)
            schedule.save()
            return Response(serialize_schedule(schedule, include_runs=True), status=201)
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)


class SchedulerDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get_object(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule.objects.select_related("created_by", "updated_by"), pk=schedule_id)
        action = _require_action(request.user, schedule.action_id)
        return schedule, action

    def get(self, request, schedule_id):
        schedule, _ = self.get_object(request, schedule_id)
        return Response(serialize_schedule(schedule, include_runs=True))

    def patch(self, request, schedule_id):
        schedule, _ = self.get_object(request, schedule_id)
        try:
            merged = {
                "name": schedule.name, "action_id": schedule.action_id, "module_id": schedule.module_id,
                "target_mode": schedule.target_mode, "targets": schedule.targets, "parameters": schedule.parameters,
                "schedule_type": schedule.schedule_type, "timezone": schedule.timezone,
                "run_at": schedule.run_at, "run_time": schedule.run_time, "weekdays": schedule.weekdays,
                "day_of_month": schedule.day_of_month, "enabled": schedule.enabled,
                "missed_policy": schedule.missed_policy, "missed_grace_minutes": schedule.missed_grace_minutes,
                "concurrency_policy": schedule.concurrency_policy, "retry_count": schedule.retry_count,
                "retry_delay_seconds": schedule.retry_delay_seconds,
            }
            merged.update(_parse_fields(dict(request.data)))
            data = validate_schedule_payload(merged)
            _require_action(request.user, data["action_id"])
            _validate_shape(data)
            _apply_schedule_fields(schedule, data)
            schedule.updated_by = request.user
            schedule.last_due_key = ""
            schedule.save()
            return Response(serialize_schedule(schedule, include_runs=True))
        except SchedulerError as exc:
            return Response({"detail": str(exc)}, status=400)

    def delete(self, request, schedule_id):
        schedule, _ = self.get_object(request, schedule_id)
        schedule.delete()
        return Response(status=204)


class SchedulerRunNowView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, schedule_id):
        schedule = get_object_or_404(TecTacSchedule, pk=schedule_id)
        _require_action(request.user, schedule.action_id)
        run = queue_manual_run(schedule)
        return Response(serialize_run(run), status=202)


class SchedulerRunListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        qs = TecTacScheduleRun.objects.select_related("schedule")
        schedule_id = request.query_params.get("schedule_id")
        if schedule_id:
            qs = qs.filter(schedule_id=schedule_id)
        rows = []
        for run in qs[:200]:
            try:
                action = get_scheduled_action(run.schedule.action_id)
            except SchedulerError:
                action = None
            if _native_scheduler_manager(request.user) or (action and _can_use_action(request.user, action)):
                item = serialize_run(run)
                item["schedule_name"] = run.schedule.name
                item["action_id"] = run.schedule.action_id
                rows.append(item)
        return Response({"runs": rows, "count": len(rows)})
