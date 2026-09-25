from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .capabilities import build_operation_context
from .server_maintenance import ServerMaintenanceError, get_server_maintenance_provider
from .session_security import SessionAuthenticated
from .rbac import can_manage_privileged_operations


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


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="List registered privileged maintenance actions"))
class ServerMaintenanceActionListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_server_maintenance(request.user)
        provider = get_server_maintenance_provider()
        rows = provider.list_actions(context=_context(request, "core.server_maintenance.list_actions"))
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
        rows = provider.list_jobs(
            status=request.query_params.get("status") or None,
            action=request.query_params.get("action") or None,
            limit=limit,
            include_output=False,
            context=_context(request, "core.server_maintenance.list_jobs"),
        )
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
            )
            return Response(job, status=202)
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Get durable server-maintenance job state and output"))
class ServerMaintenanceJobDetailView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_server_maintenance(request.user)
        try:
            return Response(get_server_maintenance_provider().get_job(
                job_id=str(job_id),
                context=_context(request, "core.server_maintenance.get_job"),
            ))
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=404)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Server Maintenance"], summary="Cancel a durable server-maintenance job"))
class ServerMaintenanceJobCancelView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, job_id):
        _require_server_maintenance(request.user)
        try:
            return Response(get_server_maintenance_provider().cancel(
                job_id=str(job_id),
                context=_context(request, "core.server_maintenance.cancel"),
            ), status=202)
        except ServerMaintenanceError as exc:
            return Response({"detail": str(exc), "classification": exc.classification, "job_id": exc.job_id}, status=400)
