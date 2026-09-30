from __future__ import annotations

import logging

from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .audit import (
    BROWSER_PROVENANCE_MARKER,
    AuditContractError,
    can_record_from_browser,
    declared_browser_event,
    record,
)
from .session_security import SessionAuthenticated
from .throttles import AuditWriteDayThrottle, AuditWriteMinThrottle

logger = logging.getLogger("tec_tac.audit")

_ALLOWED_FIELDS = {"module_id", "action", "object_type", "object_id", "message", "before", "after", "metadata"}
_FORBIDDEN_IDENTITY_FIELDS = {"username", "actor", "user", "module_version", "source", "correlation_id", "request_id"}

_NOT_PERMITTED = (
    "Browser audit events are not permitted for this module or event. The module must be explicitly permissioned, "
    "or be a permissionless module that declares this exact event in audit_events."
)
_DENY_MESSAGE = "Core refused a module-declared browser audit event: the object is outside the signed-in user's scope."


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Record a Tec-Tac module audit event"))
class AuditRecordView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [AuditWriteMinThrottle, AuditWriteDayThrottle]

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
        module_id = str(payload.get("module_id") or "").strip()
        if module_id == "core":
            return Response({"detail": "Browser audit events may not claim Core provenance."}, status=403)
        if not can_record_from_browser(request.user, module_id):
            if not declared_browser_event(request.user, module_id, payload.get("action"), payload.get("object_type")):
                return Response({"detail": _NOT_PERMITTED}, status=403)
            return self._record_declared(request, payload)
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

    def _record_declared(self, request, payload):
        """Record an event a permissionless module declared, after Core checks the object scope."""
        from .resources import (
            ResourceNotFound,
            ResourcePermissionDenied,
            ResourceValidationError,
            resolve_resource,
            user_context,
        )

        module_id = str(payload.get("module_id") or "").strip()
        action = str(payload.get("action") or "").strip().lower()
        object_type = str(payload.get("object_type") or "").strip().lower()
        object_id = payload.get("object_id")
        if object_id is None or isinstance(object_id, (dict, list, bool)) or not str(object_id).strip():
            return Response({"detail": "object_id is required for module-declared browser audit events."}, status=400)
        try:
            resolve_resource(object_type, object_id, context=user_context(request.user))
        except ResourceValidationError as exc:
            return Response({"detail": str(exc), "recorded": False}, status=400)
        except (ResourceNotFound, ResourcePermissionDenied) as exc:
            missing = isinstance(exc, ResourceNotFound)
            self._record_deny(request, module_id, action, object_type, object_id, "not_found" if missing else "permission_denied")
            return Response({"detail": str(exc), "recorded": False}, status=404 if missing else 403)
        try:
            result = record(
                actor=request.user,
                module_id=module_id,
                action=payload.get("action"),
                object_type=payload.get("object_type"),
                object_id=object_id,
                message=payload.get("message"),
                before=payload.get("before"),
                after=payload.get("after"),
                metadata=payload.get("metadata"),
                request=request,
                strict=False,
                operation_context={"browser_provenance": BROWSER_PROVENANCE_MARKER},
            )
        except AuditContractError as exc:
            detail = str(exc)
            return Response({"detail": detail}, status=403 if "not permitted" in detail else 400)
        return Response(result, status=201 if result.get("recorded") else 202)

    @staticmethod
    def _record_deny(request, module_id, action, object_type, object_id, reason):
        """Keep refused attempts in the log with a Core-owned row that carries none of the module's text."""
        try:
            record(
                actor=request.user,
                module_id=module_id,
                action="deny",
                object_type=object_type,
                object_id=str(object_id)[:255],
                message=_DENY_MESSAGE,
                metadata={"refused_action": action, "reason": reason},
                request=request,
                strict=False,
                operation_context={"browser_provenance": BROWSER_PROVENANCE_MARKER},
            )
        except Exception:
            logger.exception("Unable to write the Core deny row for module=%s object_type=%s", module_id, object_type)
