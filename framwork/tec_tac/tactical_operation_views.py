"""POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ (Core 1.17.7).

The browser names a declared operation and sends {params, body}. Core runs it server-side for the signed-in user and
writes the audit row where the call happens. See tec_tac.tactical_operations and docs/tactical-operations.md.

1.17.13: the JSON form also takes ``query`` (a GET operation's whitelisted query string). A multipart/form-data form
carries the text parts ``params``, ``body`` and ``query`` (each a JSON object) and one file part named as the operation
declares it. The file's size is checked before it is read.

1.17.14: the size limit is the system setting ``tactical_operation_upload_max_mib`` (default 10 MiB, at most 25), and an
operation's own lower cap still wins. The declared request length is checked against the same setting.
"""
from __future__ import annotations

import json

from django.http import HttpResponse
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated
from .tactical_operations import (
    AUDIT_HEADER,
    AUDIT_NOT_RECORDED,
    AUDIT_RECORDED,
    TacticalOperationError,
    get_operation,
    run_tactical_operation,
    upload_ceiling_bytes,
)
from .throttles import TacticalOperationDayThrottle, TacticalOperationMinThrottle

_ALLOWED_FIELDS = {"params", "body", "query"}
_MULTIPART_ENVELOPE_BYTES = 256 * 1024  # text parts and part headers around the file


def _audit_headers(audit) -> dict:
    """X-Tec-Tac-Audit is present only when a Core audit row was due for this call."""
    if not isinstance(audit, dict) or "recorded" not in audit:
        return {}
    return {AUDIT_HEADER: AUDIT_RECORDED if audit.get("recorded") else AUDIT_NOT_RECORDED}


def _bad(detail: str, code: str = "invalid_operation_request", status: int = 400):
    return Response({"detail": detail, "code": code}, status=status)


def _is_multipart(request) -> bool:
    return str(getattr(request, "content_type", "") or "").split(";")[0].strip().lower() == "multipart/form-data"


def _json_part(data, name: str):
    """A text part of a multipart request, parsed as a JSON object. Returns (value, error response)."""
    raw = data.get(name)
    if raw in (None, ""):
        return None, None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None, _bad(f"The {name} part must be a JSON object.")
    if not isinstance(value, dict):
        return None, _bad(f"The {name} part must be a JSON object.")
    return value, None


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Run a declared Tactical operation and audit it"))
class TacticalOperationView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [TacticalOperationMinThrottle, TacticalOperationDayThrottle]
    parser_classes = (JSONParser, MultiPartParser)

    def post(self, request, module_id, operation_id):
        upload = None
        if _is_multipart(request):
            # Refuse a huge request before DRF parses it: the declared length is checked first.
            try:
                length = int(request.META.get("CONTENT_LENGTH") or 0)
            except (TypeError, ValueError):
                length = 0
            ceiling = upload_ceiling_bytes()  # the system setting, read now (1.17.14, CQ40)
            if length > ceiling + _MULTIPART_ENVELOPE_BYTES:
                return _bad("The request is larger than Core accepts for an upload.", "upload_too_large", 413)
            data = request.data
            files = request.FILES
            # DRF puts the file parts into request.data as well, so the file keys are not unknown text fields.
            unknown = sorted(set(data.keys()) - set(files.keys()) - _ALLOWED_FIELDS)
            if unknown:
                return _bad("Unknown field(s): " + ", ".join(str(name)[:40] for name in unknown))
            payload = {}
            for name in ("params", "body", "query"):
                value, error = _json_part(data, name)
                if error is not None:
                    return error
                payload[name] = value
            if len(files) != 1 or len(files.getlist(next(iter(files.keys())))) != 1:
                return _bad("Send exactly one file part.", "invalid_upload")
            part_name = next(iter(files.keys()))
            uploaded = files[part_name]
            declared = get_operation(module_id, operation_id)
            cap = ceiling
            if declared and declared.get("upload"):
                cap = min(cap, int(declared["upload"]["max_bytes"]))
            size = getattr(uploaded, "size", None)
            if size is None or size > cap:  # the size is known before the content is read
                return _bad(f"The file is larger than {cap} bytes.", "upload_too_large", 413)
            # For an operation whose part is named after the file (FILE_NAME_FIELD) the part key is the browser's choice and
            # the file name is the filename attribute, falling back to the part key.
            upload = {"field": part_name, "name": getattr(uploaded, "name", "") or part_name, "content_type": getattr(uploaded, "content_type", ""), "content": uploaded.read()}
        else:
            payload = request.data
            if not isinstance(payload, dict):
                return _bad("The request must be a JSON object.")
            unknown = sorted(set(payload) - _ALLOWED_FIELDS)
            if unknown:
                return _bad("Unknown field(s): " + ", ".join(str(name)[:40] for name in unknown))
        try:
            result = run_tactical_operation(
                request, module_id, operation_id, payload.get("params"), payload.get("body"), query=payload.get("query"), upload=upload,
            )
        except TacticalOperationError as exc:
            return Response({"detail": exc.message, "code": exc.code}, status=exc.status, headers=_audit_headers(exc.audit))
        # Tactical's status and body are relayed unchanged.
        response = HttpResponse(result.content, status=result.status, content_type=result.content_type or None)
        for name, value in result.headers.items():
            response[name] = value
        for name, value in _audit_headers(result.audit).items():
            response[name] = value
        return response
