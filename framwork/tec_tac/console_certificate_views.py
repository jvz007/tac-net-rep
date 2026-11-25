"""Engineer Console certificate routes (Core 1.18.52, C3). All under /api/tfd/console-certificates/. See docs/console-certificates.md.

Every route needs a signed-in session except ``enrol/``, which has no sign-in: the one-time code in its header is the credential, and the
Console proves it holds the private key. The logic is in ``console_certificates`` (imported when a route is first used, so a fault there never
stops Tactical from loading this file's URLs). Denied is hidden and refused (AD-12): every permission refusal writes one non-strict Core deny
row, then answers 403.
"""
from __future__ import annotations

import logging
import re

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .rbac import (
    can_manage_console_certificates,
    can_view_console_certificates,
    is_effective_superuser,
)
from .session_security import SessionAuthenticated
from .throttles import (
    ConsoleCertificateWriteDayThrottle,
    ConsoleCertificateWriteMinThrottle,
    ConsoleEnrolmentCodeDayThrottle,
    ConsoleEnrolmentCodeMinThrottle,
)

logger = logging.getLogger("tec_tac.console_certificates")

TAG = "Tec-Tac Console Certificates"
_SERIAL = re.compile(r"^[0-9a-f]{32}$")
_STATES = ("active", "expired", "revoked")


def _cc():
    from . import console_certificates

    return console_certificates


def _answer(payload, status: int = 200, retry_after: int | None = None):
    response = Response(payload, status=status)
    response["Cache-Control"] = "no-store"
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response


def _error(code: str, detail: str, status: int, retry_after: int | None = None):
    return _answer({"detail": detail, "code": code}, status, retry_after)


def _guarded(call):
    """Run one route body and map the refusals every route can raise: ours, the secret store's and a failed strict audit row."""
    from .audit import AuditWriteError
    from .secret_store import SecretStoreError

    cc = _cc()
    try:
        return call(cc)
    except cc.ConsoleCertError as exc:
        return _error(exc.code, exc.message, exc.status_code, exc.retry_after)
    except SecretStoreError as exc:
        return _error(exc.code, str(exc), exc.status_code)
    except AuditWriteError:
        return _error("audit_failed", "The change could not be recorded, so it was not made.", 503)


def _checked_body(request, allowed: tuple[str, ...]):
    """The JSON object, or a 400 Response. An empty body is an empty object; any key outside ``allowed`` is refused."""
    data = request.data
    if data is None or (hasattr(data, "__len__") and len(data) == 0):
        return {}
    if not isinstance(data, dict):
        return _error("invalid_request", "The body must be a JSON object.", 400)
    unknown = sorted(str(key) for key in data if key not in allowed)
    if unknown:
        return _error("unknown_field", "Unknown field(s): " + ", ".join(unknown), 400)
    return dict(data)


def _refuse_permission(request, object_type: str, message: str, object_id=None):
    _cc().deny(request.user, object_type, object_id)
    raise PermissionDenied(message)


@extend_schema_view(get=extend_schema(tags=[TAG], summary="My Console certificates, my open enrolment and the server's host and id"))
class ConsoleCertificateMineView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        return _guarded(lambda cc: _answer(cc.overview_for(request.user, cc.own_host(request))))


@extend_schema_view(post=extend_schema(tags=[TAG], summary="A one-time code to enrol one Console PC (own open enrolment only)"))
class ConsoleCertificateEnrolmentCodeView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleEnrolmentCodeMinThrottle, ConsoleEnrolmentCodeDayThrottle]

    def post(self, request):
        body = _checked_body(request, ())
        if isinstance(body, Response):
            return body

        def run(cc):
            result = cc.create_enrolment_code(request.user, cc.own_host(request), cc.client_address(request))
            result["code_expires_at"] = result["code_expires_at"].isoformat()
            return _answer(result)

        return _guarded(run)


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Enrol a Console: the code in the header, a proof of the key in the body (no sign-in)"))
class ConsoleCertificateEnrolView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = []
    parser_classes = [JSONParser]
    http_method_names = ["post"]

    def post(self, request):
        cc = _cc()
        if cc.forwarded_plaintext(request):
            return _error("tls_required", "Use https.", 403)
        ip = cc.client_address(request)
        if cc.rate_limited(ip):
            return _error("rate_limited", "Too many attempts. Wait a minute and try again.", 429, 60)
        declared = request.META.get("CONTENT_LENGTH")
        try:
            if declared not in (None, "") and int(declared) > cc.MAX_BODY_BYTES:
                cc.refuse_early(ip, cc.ConsoleCertError("body_too_large", "The request is too large.", 413))
                return _error("body_too_large", "The request is too large.", 413)
        except (TypeError, ValueError):
            cc.refuse_early(ip, cc.ConsoleCertError("invalid_request", "The request is not valid.", 400))
            return _error("invalid_request", "The request is not valid.", 400)
        django_request = getattr(request, "_request", request)
        try:
            cached = getattr(django_request, "_body", None)
            raw = cached[: cc.MAX_BODY_BYTES + 1] if isinstance(cached, (bytes, bytearray)) else django_request.read(cc.MAX_BODY_BYTES + 1)
        except Exception:
            logger.debug("The enrolment body could not be read.", exc_info=True)
            cc.note_failure(ip)
            return _error("invalid_request", "The request is not valid.", 400)

        def run(cc):
            try:
                code, fields = cc.parse_enrol_request(request.META.get("HTTP_AUTHORIZATION"), bytes(raw), declared)
            except cc.ConsoleCertError as exc:
                raise cc.refuse_early(ip, exc) from None
            bundle = cc.enrol(code=code, host=cc.own_host(request), fields=fields, ip=ip)
            return _answer(bundle, 201)

        return _guarded(run)


def _int_param(request, name: str, default=None, *, minimum: int = 1):
    value = request.query_params.get(name)
    if value in (None, ""):
        return default
    if not re.fullmatch(r"[0-9]{1,9}", str(value)) or int(value) < minimum:
        return False
    return int(value)


@extend_schema_view(get=extend_schema(tags=[TAG], summary="Console certificates (own rows; every row with view or manage), with the open enrolments"))
class ConsoleCertificateListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        engineer = _int_param(request, "engineer", minimum=0)
        page = _int_param(request, "page", 1)
        page_size = _int_param(request, "page_size", 50)
        state = request.query_params.get("state") or None
        if engineer is False or page is False or page_size is False or (state is not None and state not in _STATES):
            return _error("invalid_request", "engineer, page and page_size must be whole numbers and state one of active, expired or revoked.", 400)
        can_view = can_view_console_certificates(request.user)
        return _guarded(lambda cc: _answer(cc.list_for(request.user, can_view=can_view, engineer=engineer, state=state, page=page, page_size=page_size)))


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Allow one engineer to enrol a Console PC (manage)"))
class ConsoleCertificateIssueView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleCertificateWriteMinThrottle, ConsoleCertificateWriteDayThrottle]

    def post(self, request):
        if not can_manage_console_certificates(request.user):
            _refuse_permission(request, "console_certificate", "Tec-Tac core.console_certificates.manage permission is required to allow a Console enrolment.")
        body = _checked_body(request, ("user_id",))
        if isinstance(body, Response):
            return body
        user_id = body.get("user_id")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            return _error("invalid_request", "user_id must be a whole number.", 400)

        def run(cc):
            row = cc.authorise(request.user, user_id, cc.client_address(request))
            row["authorised_at"] = row["authorised_at"].isoformat()
            row["expires_at"] = row["expires_at"].isoformat()
            return _answer(row, 201)

        return _guarded(run)


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Cancel an open Console enrolment (manage)"))
class ConsoleCertificateEnrolmentCancelView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleCertificateWriteMinThrottle, ConsoleCertificateWriteDayThrottle]

    def post(self, request, enrolment_id):
        if not can_manage_console_certificates(request.user):
            _refuse_permission(request, "console_certificate", "Tec-Tac core.console_certificates.manage permission is required to cancel an enrolment.", str(enrolment_id))
        body = _checked_body(request, ())
        if isinstance(body, Response):
            return body
        return _guarded(lambda cc: _answer(cc.cancel_enrolment(request.user, enrolment_id)))


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Revoke a Console certificate (manage on any, or the owner on their own)"))
class ConsoleCertificateRevokeView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleCertificateWriteMinThrottle, ConsoleCertificateWriteDayThrottle]

    def post(self, request, serial):
        if not _SERIAL.fullmatch(str(serial)):
            return _error("invalid_request", "The serial must be 32 lower-case hexadecimal characters.", 400)
        body = _checked_body(request, ("reason",))
        if isinstance(body, Response):
            return body
        reason = body.get("reason")
        if not isinstance(reason, str) or reason not in _cc().REVOKE_REASONS:
            return _error("invalid_request", "reason must be one of: " + ", ".join(_cc().REVOKE_REASONS) + ".", 400)
        can_manage = can_manage_console_certificates(request.user)

        def run(cc):
            try:
                return _answer(cc.revoke(request.user, str(serial), reason, can_manage=can_manage))
            except cc.ConsoleCertError as exc:
                if exc.code == "permission_required":  # the deny row is already written
                    raise PermissionDenied(exc.message) from None
                raise

        return _guarded(run)


@extend_schema_view(get=extend_schema(tags=[TAG], summary="The Console certificate authority: when it ends and whether its key can be used (view)"))
class ConsoleCertificateCaView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_view_console_certificates(request.user):
            _refuse_permission(request, "console_ca", "Tec-Tac core.console_certificates.view permission is required to see the certificate authority.")
        return _guarded(lambda cc: _answer(cc.ca_status()))


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Replace the Console certificate authority (superuser only)"))
class ConsoleCertificateCaReplaceView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleCertificateWriteMinThrottle, ConsoleCertificateWriteDayThrottle]

    def post(self, request):
        if not is_effective_superuser(request.user):
            _refuse_permission(request, "console_ca", "Only a Tec-Tac superuser may replace the Console certificate authority.")
        body = _checked_body(request, ("confirm",))
        if isinstance(body, Response):
            return body
        if body.get("confirm") is not True:
            return _error("confirmation_required", "Send {\"confirm\": true}. Replacing the authority revokes every Console certificate and cancels every open enrolment.", 400)

        def run(cc):
            result = cc.replace_ca(request.user)
            result["not_after"] = result["not_after"].isoformat()
            return _answer(result)

        return _guarded(run)
