"""Read routes for available module updates (Core 1.17.104, phase 1 of module automatic updates: notify and highlight only).

Both routes need the module-manage permission (core.privileged_operations), the same check as every module lifecycle route. They read
the cached Online catalog only: no network call, no write.
"""
import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_updates import list_updates, update_count
from .session_security import SessionAuthenticated
from .views import _require_module_manager

logger = logging.getLogger("tec_tac.module_updates")

_UNAVAILABLE = "Module updates could not be read. Check the module repositories, then try again."


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List available module updates"))
class ModuleUpdateListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        try:
            return Response(list_updates())
        except Exception:
            logger.warning("The module update list could not be built.", exc_info=True)
            return Response({"detail": _UNAVAILABLE}, status=503)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Count available module updates"))
class ModuleUpdateCountView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        try:
            return Response(update_count())
        except Exception:
            logger.warning("The module update count could not be built.", exc_info=True)
            return Response({"detail": _UNAVAILABLE}, status=503)
