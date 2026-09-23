from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from .diagnostics import diagnostic_report
from .session_security import SessionAuthenticated
from .views import _require_module_manager


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Run Core troubleshooting diagnostics"))
class SystemDiagnosticsView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        live = str(request.query_params.get("live_capabilities") or "").strip().lower() in {"1", "true", "yes", "on"}
        return Response(diagnostic_report(live_capabilities=live))
