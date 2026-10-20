"""``GET /api/tfd/system/licensing/``: the licence status read (Core 1.17.58, R-11).

Allowed for an effective superuser and for a holder of ``core.runtime_settings.manage`` (the people who can set the licensing mode).
Everyone else gets 403. A read writes no audit row. The answer is built from allow-listed scalars only (see
``module_licensing.build_licensing_status``): no key, token, fingerprint or provider text, and Core makes no network call.
"""
from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_licensing import build_licensing_status
from .rbac import can_manage_runtime_settings, is_effective_superuser
from .session_security import SessionAuthenticated

LICENSING_STATUS_DENIED = "A Tec-Tac superuser or a holder of core.runtime_settings.manage may read the licensing status."


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Licensing"], summary="Read the licensing mode, licence state and what would be blocked"))
class LicensingStatusView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not (is_effective_superuser(request.user) or can_manage_runtime_settings(request.user)):
            raise PermissionDenied(LICENSING_STATUS_DENIED)
        return Response(build_licensing_status())
