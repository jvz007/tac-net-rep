from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

import logging
from datetime import UTC, datetime

from .capabilities import build_operation_context
from . import module_job_logs
from .server_maintenance import (
    ServerMaintenanceError,
    ServerMaintenanceNotFound,
    read_job_log,
    ServerMaintenancePermissionDenied,
    get_server_maintenance_provider,
    holds_action_permission,
)
from .session_security import SessionAuthenticated
from .rbac import can_manage_privileged_operations

logger = logging.getLogger(__name__)


def _require_server_maintenance(user):
    if not can_manage_privileged_operations(user):
        raise PermissionDenied("Tec-Tac core.privileged_operations permission is required for Core server maintenance.")


def _context(request, source_action: str) -> dict:
    return build_operation_context(
        source_module="core",
        source_action=source_action,
        requested_by=str(request.user.username),
        request_path=str(request.path),
    )


def _denied(exc: ServerMaintenancePermissionDenied):
    """403 that names the permission to ask for (1.17.17)."""
    return Response({"detail": str(exc), "classification": exc.classification, "permission": exc.permission, "job_id": exc.job_id}, status=403)


def _permission_map(provider, request) -> dict:
    """action id -> the permission the registry declares now, for jobs written before 1.17.17."""
    rows = provider.list_actions(context=_context(request, "core.server_maintenance.list_actions"))
    return {str(row.get("id")): row.get("permission") for row in rows}


def _job_visible(user, job: dict, permissions: dict) -> bool:
    """AD-12: a job of an action that needs a permission is hidden from a caller who does not hold it."""
    return holds_action_permission(user, job.get("permission") or permissions.get(str(job.get("action") or "")))


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="List registered privileged maintenance actions"))
class ServerMaintenanceActionListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_server_maintenance(request.user)
        provider = get_server_maintenance_provider()
        rows = provider.list_actions(context=_context(request, "core.server_maintenance.list_actions"))
        # 1.17.17 (AD-12): an action that needs a Tec-Tac permission is hidden from a caller who does not hold it
        rows = [row for row in rows if holds_action_permission(request.user, row.get("permission"))]
        return Response({"actions": rows, "count": len(rows)})


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="List durable server-maintenance jobs"),
    post=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Start a registered privileged server-maintenance job"),
)
class ServerMaintenanceJobListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_server_maintenance(request.user)
        provider = get_server_maintenance_provider()
        try:
            limit = int(request.query_params.get("limit", 100))
        except (TypeError, ValueError):
            return Response({"detail": "limit must be an integer."}, status=400)
        # the permission filter runs after the limit is applied to the newest jobs, so a hidden job can shorten the page
        rows = provider.list_jobs(
            status=request.query_params.get("status") or None,
            action=request.query_params.get("action") or None,
            limit=limit,
            include_output=False,
            context=_context(request, "core.server_maintenance.list_jobs"),
        )
        permissions = _permission_map(provider, request)
        rows = [row for row in rows if _job_visible(request.user, row, permissions)]
        return Response({"jobs": rows, "count": len(rows)})

    def post(self, request):
        _require_server_maintenance(request.user)
        action = str(request.data.get("action") or "").strip()
        parameters = request.data.get("parameters", {})
        try:
            job = get_server_maintenance_provider().start(
                action=action,
                parameters=parameters,
                context=_context(request, "core.server_maintenance.start"),
                user=request.user,
            )
            return Response(job, status=202)
        except ServerMaintenancePermissionDenied as exc:
            return _denied(exc)
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Get durable server-maintenance job state and output"))
class ServerMaintenanceJobDetailView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_server_maintenance(request.user)
        try:
            provider = get_server_maintenance_provider()
            job = provider.get_job(job_id=str(job_id), context=_context(request, "core.server_maintenance.get_job"))
            if not _job_visible(request.user, job, _permission_map(provider, request)):
                # denied means hidden: the same answer as a job that does not exist
                return Response({"detail": f"Server-maintenance job {job_id} was not found.", "classification": "not_found", "job_id": None}, status=404)
            return Response(job)
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Log, stdout and stderr of one server-maintenance job (1.17.67): scrubbed, capped at 5 MB, audited"))
class ServerMaintenanceJobLogView(APIView):
    """The job's log as plain text. Inline by default; ``?download=1`` sends a file; ``?part=all|log|stdout|stderr`` (default all, three headed
    sections). Every read writes one strict audit row; if it cannot be written nothing is sent."""
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_server_maintenance(request.user)
        download = request.query_params.get("download") == "1"
        part = str(request.query_params.get("part") or "all").strip().lower()
        try:
            log = read_job_log(str(job_id), request.user, part)
        except ServerMaintenanceNotFound:
            return Response({"detail": f"Server-maintenance job {job_id} was not found.", "code": "job_not_found"}, status=404)
        except module_job_logs.JobLogError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status)
        except OSError:
            logger.exception("Tec-Tac server-maintenance job log could not be read")
            return Response({"detail": "The log could not be read. Check Tec-Tac diagnostics/logs."}, status=503)
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        filename = f"server-maintenance-{module_job_logs.safe_label(log.action)}-{day}.log" if download else None
        return module_job_logs.serve_log(
            request, log, object_type="server_maintenance_job_log",
            metadata={"job_id": log.job_id, "action": log.action, "part": part, "bytes": log.size, "truncated": log.truncated, "download": download},
            filename=filename, label="server-maintenance job log")


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Cancel a durable server-maintenance job"))
class ServerMaintenanceJobCancelView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, job_id):
        _require_server_maintenance(request.user)
        try:
            return Response(get_server_maintenance_provider().cancel(
                job_id=str(job_id),
                context=_context(request, "core.server_maintenance.cancel"),
                user=request.user,
            ), status=202)
        except ServerMaintenancePermissionDenied as exc:
            return _denied(exc)
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=400)
