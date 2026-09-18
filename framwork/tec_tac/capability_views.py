from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .capabilities import capability_status, list_capabilities


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Capabilities"], summary="List module capabilities"))
class CapabilityListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        rows = list_capabilities()
        return Response({"capabilities": rows, "count": len(rows)})


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Capabilities"], summary="Inspect module capability"))
class CapabilityDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, capability_id):
        required_version = request.query_params.get("version") or None
        row = capability_status(capability_id, version=required_version)
        # An absent provider/capability is still useful diagnostic state. Return
        # 200 for known runtime state so callers can distinguish missing,
        # disabled, incompatible and unhealthy without exception mapping.
        if row["state"] == "missing" and "." not in capability_id:
            raise NotFound("Capability IDs are namespaced, for example communicator.messaging.")
        return Response(row)
