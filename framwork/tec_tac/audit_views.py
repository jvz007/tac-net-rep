from __future__ import annotations

import logging
import threading

from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .audit import (
    SCOPE_CHECKED_OBJECT_TYPES,
    AuditContractError,
    can_record_from_browser,
    declared_browser_event,
    record,
    record_browser_declared,
    record_core_refusal,
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
# One fixed Core message per refusal reason. Neither carries any text from the module.
_DENY_MESSAGES = {
    "not_found": "Core refused a module-declared browser audit event: the object is missing or outside the signed-in user's scope.",
    "permission_denied": "Core refused a module-declared browser audit event: the signed-in user's role lacks Tactical's permission to list this object type.",
}
_DENY_MESSAGE = _DENY_MESSAGES["not_found"]  # 1.16.0 name, kept for importers
_OBJECT_ID_MAX = 255

# 1.17.7: the browser-declared path is deprecated. Core still serves it exactly as before, adds the Deprecation
# header to its responses and logs one warning per module per process. The end date is not set (CQ18).
DEPRECATION_HEADERS = {"Deprecation": "true"}
_DEPRECATION_WARNED: set[str] = set()
_DEPRECATION_LOCK = threading.Lock()


def _warn_declared_path_deprecated(module_id: str) -> None:
    with _DEPRECATION_LOCK:
        if module_id in _DEPRECATION_WARNED:
            return
        _DEPRECATION_WARNED.add(module_id)
    logger.warning(
        "Module %s posted a browser-declared audit event to /api/tfd/audit/record/. This path is deprecated since "
        "Core 1.17.7: a Tactical call should use a registered Tactical operation, and a module's own backend action "
        "should call tec_tac.audit.record from its backend route. See docs/module-audit.md.",
        module_id,
    )


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
        _warn_declared_path_deprecated(module_id)
        action = str(payload.get("action") or "").strip().lower()
        object_type = str(payload.get("object_type") or "").strip().lower()
        object_id = payload.get("object_id")
        if object_type in SCOPE_CHECKED_OBJECT_TYPES:
            if object_id is None or isinstance(object_id, (dict, list, bool)) or not str(object_id).strip():
                return Response({"detail": "object_id is required for module-declared browser audit events."}, status=400, headers=DEPRECATION_HEADERS)
            try:
                resolve_resource(object_type, object_id, context=user_context(request.user))
            except ResourceValidationError as exc:
                return Response({"detail": str(exc), "recorded": False}, status=400, headers=DEPRECATION_HEADERS)
            except (ResourceNotFound, ResourcePermissionDenied) as exc:
                missing = isinstance(exc, ResourceNotFound)
                self._record_deny(
                    request, module_id, action, object_type, object_id,
                    "not_found" if missing else "permission_denied", 404 if missing else 403,
                )
                return Response({"detail": str(exc), "recorded": False}, status=404 if missing else 403, headers=DEPRECATION_HEADERS)
        elif object_id is not None:
            # Any other declared object type has no scope check and no deny row. object_id is optional.
            if isinstance(object_id, (dict, list, bool)) or not str(object_id).strip():
                return Response({"detail": "object_id must be a string or number when provided."}, status=400, headers=DEPRECATION_HEADERS)
            if len(str(object_id)) > _OBJECT_ID_MAX:
                return Response({"detail": f"object_id may not exceed {_OBJECT_ID_MAX} characters."}, status=400, headers=DEPRECATION_HEADERS)
        try:
            result = record_browser_declared(
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
            )
        except AuditContractError as exc:
            detail = str(exc)
            return Response({"detail": detail}, status=403 if "not permitted" in detail else 400, headers=DEPRECATION_HEADERS)
        return Response(result, status=201 if result.get("recorded") else 202, headers=DEPRECATION_HEADERS)

    @staticmethod
    def _record_deny(request, module_id, action, object_type, object_id, reason, status):
        """Keep refused attempts in the log with a Core-owned row that carries none of the module's text."""
        try:
            record_core_refusal(
                actor=request.user,
                module_id=module_id,
                object_type=object_type,
                object_id=str(object_id)[:255],
                message=_DENY_MESSAGES[reason],
                metadata={"refused_action": action, "reason": reason, "status": status},
                request=request,
            )
        except Exception:
            logger.exception("Unable to write the Core deny row for module=%s object_type=%s", module_id, object_type)
