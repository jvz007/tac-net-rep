from __future__ import annotations

import logging

from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .audit import AuditContractError, record
from .session_security import SessionAuthenticated

logger = logging.getLogger("tec_tac.audit")

_ALLOWED_FIELDS = {"module_id", "action", "object_type", "object_id", "message", "before", "after", "metadata"}
_FORBIDDEN_IDENTITY_FIELDS = {"username", "actor", "user", "module_version", "source", "correlation_id", "request_id"}


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Record a Tec-Tac module audit event"))
class AuditRecordView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        payload = request.data
        if not isinstance(payload, dict):
            return Response({"detail": "Audit event must be a JSON object."}, status=400)
        forbidden = sorted(set(payload) & _FORBIDDEN_IDENTITY_FIELDS)
        if forbidden:
            return Response({"detail": "Actor/provenance fields are Core-owned and may not be supplied: " + ", ".join(forbidden)}, status=400)
        unknown = sorted(set(payload) - _ALLOWED_FIELDS)
        if unknown:
            return Response({"detail": "Unknown audit event field(s): " + ", ".join(unknown)}, status=400)
        if str(payload.get("module_id") or "").strip() == "core":
            return Response({"detail": "Browser audit events may not claim Core provenance."}, status=403)
        try:
            result = record(
                actor=request.user,
                module_id=payload.get("module_id"),
                action=payload.get("action"),
                object_type=payload.get("object_type"),
                object_id=payload.get("object_id"),
                message=payload.get("message"),
                before=payload.get("before"),
                after=payload.get("after"),
                metadata=payload.get("metadata"),
                request=request,
                strict=False,
            )
        except AuditContractError as exc:
            detail = str(exc)
            status = 403 if "not permitted" in detail else 400
            return Response({"detail": detail}, status=status)
        return Response(result, status=201 if result.get("recorded") else 202)
