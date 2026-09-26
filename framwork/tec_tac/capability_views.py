from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated

from .capabilities import capability_status, list_capabilities
from .rbac import can_manage_privileged_operations


def _live_health_requested(request) -> bool:
    raw = str(request.query_params.get("live") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _allow_live_health(request) -> bool:
    if not _live_health_requested(request):
        return False
    if not can_manage_privileged_operations(request.user):
        raise PermissionDenied("Tec-Tac core.privileged_operations permission is required for live capability health checks.")
    return True


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Capabilities"], summary="List module capabilities"))
class CapabilityListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        live = _allow_live_health(request)
        rows = list_capabilities(check_health=live)
        return Response({"capabilities": rows, "count": len(rows), "live": live})


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Capabilities"], summary="Inspect module capability"))
class CapabilityDetailView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, capability_id):
        required_version = request.query_params.get("version") or None
        live = _allow_live_health(request)
        row = capability_status(capability_id, version=required_version, check_health=live)
        # An absent provider/capability is still useful diagnostic state. Return
        # 200 for known runtime state so callers can distinguish missing,
        # disabled, incompatible and unhealthy without exception mapping.
        if row["state"] == "missing" and "." not in capability_id:
            raise NotFound("Capability IDs are namespaced, for example communicator.messaging.")
        return Response(row)
