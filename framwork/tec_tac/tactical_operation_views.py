"""POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ (Core 1.17.7).

The browser names a declared operation and sends {params, body}. Core runs it server-side for the signed-in user and
writes the audit row where the call happens. See tec_tac.tactical_operations and docs/tactical-operations.md.
"""
from __future__ import annotations

from django.http import HttpResponse
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated
from .tactical_operations import (
    AUDIT_HEADER,
    AUDIT_NOT_RECORDED,
    AUDIT_RECORDED,
    TacticalOperationError,
    run_tactical_operation,
)
from .throttles import TacticalOperationDayThrottle, TacticalOperationMinThrottle

_ALLOWED_FIELDS = {"params", "body"}


def _audit_headers(audit) -> dict:
    """X-Tec-Tac-Audit is present only when a Core audit row was due for this call."""
    if not isinstance(audit, dict) or "recorded" not in audit:
        return {}
    return {AUDIT_HEADER: AUDIT_RECORDED if audit.get("recorded") else AUDIT_NOT_RECORDED}


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Run a declared Tactical operation and audit it"))
class TacticalOperationView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [TacticalOperationMinThrottle, TacticalOperationDayThrottle]

    def post(self, request, module_id, operation_id):
        payload = request.data
        if not isinstance(payload, dict):
            return Response({"detail": "The request must be a JSON object.", "code": "invalid_operation_request"}, status=400)
        unknown = sorted(set(payload) - _ALLOWED_FIELDS)
        if unknown:
            return Response({"detail": "Unknown field(s): " + ", ".join(str(name)[:40] for name in unknown), "code": "invalid_operation_request"}, status=400)
        try:
            result = run_tactical_operation(request, module_id, operation_id, payload.get("params"), payload.get("body"))
        except TacticalOperationError as exc:
            return Response({"detail": exc.message, "code": exc.code}, status=exc.status, headers=_audit_headers(exc.audit))
        # Tactical's status and body are relayed unchanged.
        response = HttpResponse(result.content, status=result.status, content_type=result.content_type or None)
        for name, value in result.headers.items():
            response[name] = value
        for name, value in _audit_headers(result.audit).items():
            response[name] = value
        return response
