"""Core sandbox routes (Core 1.17.118): the status answer and the cancel route. See docs/sandbox-capability.md."""
from __future__ import annotations

import re

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from . import sandbox
from .rbac import can_manage_sandbox, can_view_sandbox
from .session_security import SessionAuthenticated

_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_STATUS_FOR_CODE = {
    "sandbox_disabled": 409, "sandbox_unavailable": 503, "runner_unknown": 404, "invalid_input": 400, "not_owner": 403, "start_failed": 502,
}


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Sandbox"], summary="Sandbox status: readiness, slots, canary and registered runners"))
class SandboxStatusView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_view_sandbox(request.user):
            raise PermissionDenied("Tec-Tac core.sandbox.view permission is required to read the sandbox status.")
        return Response(sandbox.status(live=True))


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Sandbox"], summary="Cancel a sandbox run by id"))
class SandboxRunCancelView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, run_id):
        if not can_manage_sandbox(request.user):
            raise PermissionDenied("Tec-Tac core.sandbox.manage permission is required to cancel a sandbox run.")
        if not _RUN_ID_RE.fullmatch(str(run_id)):
            return Response({"detail": "The run id must be 32 lowercase hexadecimal characters.", "code": "invalid_input"}, status=400)
        try:
            sandbox.cancel_by_person(str(run_id), user=request.user)
        except sandbox.SandboxError as exc:
            return Response({"detail": exc.message, "code": exc.code}, status=_STATUS_FOR_CODE.get(exc.code, 400))
        return Response({"run_id": str(run_id), "cancelled": True}, status=202)
