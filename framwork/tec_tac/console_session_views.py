"""Engineer Console session routes (Core 1.18.56, C1). All under /api/tfd/console-sessions/. See docs/console-sessions.md.

``authorise/`` is the browser's (a signed-in person asks for a one-time sign-in code). ``token/`` has no sign-in: the one-time code, the PKCE
verifier, the certificate and a proof signed with the certificate's key are the credential. ``current/``, ``activity/`` and ``sign-out/`` are the
Console's own, and they accept only ConsoleSessionAuthentication (the Console token plus a proof of every request); no other Core route lists that
class, so the Console token is refused everywhere else. The logic is in ``console_sessions`` (imported when a route is first used, so a fault there
never stops Tactical from loading this file's URLs). Every answer carries Cache-Control: no-store.
"""
from __future__ import annotations

import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .console_sessions import ConsoleSessionAuthenticated, ConsoleSessionAuthentication
from .session_security import SessionAuthenticated
from .throttles import ConsoleActivityMinThrottle, ConsoleSigninDayThrottle, ConsoleSigninMinThrottle

logger = logging.getLogger("tec_tac.console_sessions")

TAG = "Tec-Tac Console Sessions"


def _cc():
    from . import console_certificates

    return console_certificates


def _cs():
    from . import console_sessions

    return console_sessions


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


class _NoStoreView(APIView):
    """Every answer of a Console route, refusals included, is no-store."""

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response


@extend_schema_view(post=extend_schema(tags=[TAG], summary="A one-time sign-in code for the Engineer Console (own certificate, signed in with a person)"))
class ConsoleSessionAuthoriseView(_NoStoreView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ConsoleSigninMinThrottle, ConsoleSigninDayThrottle]
    http_method_names = ["post", "options"]

    def post(self, request):
        cc, cs = _cc(), _cs()
        if not cc.interactive_session(request):  # an API key or a plain Django session cannot start a Console sign-in
            cs.deny(request.user)
            return _error("interactive_session_required", "This needs a person signed in to Tec-Tac. An API key cannot do it.", 403)

        def run(cc):
            cc._store()._load_master_key()  # 503 master_key_unavailable before anything else
            body = cs.parse_authorise_body(request.data)
            return _answer(cs.authorise(request.user, body, cc.own_host(request)))

        return _guarded(run)


def _count_early(ip: str, code: str, status: int) -> None:
    """A refusal before the body was looked at: counted against the address with the same at-most-one-row-a-minute rule."""
    _cs()._refuse_signin(ip, _cc().ConsoleCertError(code, code, status), {"serial": None, "user": None})


@extend_schema_view(post=extend_schema(tags=[TAG], summary="Exchange a sign-in code for a Console session (no sign-in: the code, the verifier, the certificate and its proof)"))
class ConsoleSessionTokenView(_NoStoreView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = []
    parser_classes = [JSONParser]
    http_method_names = ["post"]

    def post(self, request):
        cc, cs = _cc(), _cs()
        if cc.forwarded_plaintext(request):
            return _error("tls_required", "Use https.", 403)
        ip = cc.client_address(request)
        if cc.rate_limited(ip, cc.SIGNIN_FAILURE_PREFIX):
            return _error("rate_limited", "Too many attempts. Wait a minute and try again.", 429, 60)
        declared = request.META.get("CONTENT_LENGTH")
        django_request = getattr(request, "_request", request)
        try:
            if declared not in (None, "") and int(declared) > cc.MAX_BODY_BYTES:
                _count_early(ip, "body_too_large", 413)
                return _error("body_too_large", "The request is too large.", 413)
        except (TypeError, ValueError):
            _count_early(ip, "invalid_request", 400)
            return _error("invalid_request", "The request is not valid.", 400)
        try:
            cached = getattr(django_request, "_body", None)
            raw = cached[: cc.MAX_BODY_BYTES + 1] if isinstance(cached, (bytes, bytearray)) else django_request.read(cc.MAX_BODY_BYTES + 1)
        except Exception:
            logger.debug("The sign-in body could not be read.", exc_info=True)
            _count_early(ip, "invalid_request", 400)
            return _error("invalid_request", "The request is not valid.", 400)

        def run(cc):
            bundle = cs.redeem(
                django_request, raw=bytes(raw), declared=declared, cert_header=request.META.get("HTTP_X_TECTAC_CONSOLE_CERT"),
                proof_header=request.META.get("HTTP_X_TECTAC_CONSOLE_PROOF"), host=cc.own_host(request), ip=ip)
            return _answer(bundle, 201)

        return _guarded(run)


class _ConsoleOnlyView(_NoStoreView):
    """A route only the Console may call: ConsoleSessionAuthentication and nothing else."""

    authentication_classes = [ConsoleSessionAuthentication]
    permission_classes = [ConsoleSessionAuthenticated]


@extend_schema_view(get=extend_schema(tags=[TAG], summary="The Console's own session: engineer, PC, times, minimum version and heartbeat"))
class ConsoleSessionCurrentView(_ConsoleOnlyView):
    http_method_names = ["get", "options"]

    def get(self, request):
        from . import session_security

        trust = request.tec_tac_session
        policy = session_security.get_effective_policy(request.user, request)
        auth = request.auth
        return _answer({
            "engineer": {"id": request.user.pk, "username": request.user.get_username()},
            "serial": auth.serial, "short_serial": auth.short_serial, "pc_label": auth.pc_label,
            "created_at": trust.created_at.isoformat() if trust.created_at else None,
            "last_activity_at": trust.last_activity_at.isoformat() if trust.last_activity_at else None,
            "idle_expires_at": trust.idle_expires_at.isoformat() if trust.idle_expires_at else None,
            "absolute_expires_at": trust.absolute_expires_at.isoformat() if trust.absolute_expires_at else None,
            "console_min_version": _cs().CONSOLE_MIN_VERSION,
            "heartbeat_seconds": int(policy.get("activity_heartbeat_seconds") or 60),
        })


@extend_schema_view(post=extend_schema(tags=[TAG], summary="The Console's activity heartbeat: extends the idle limit"))
class ConsoleSessionActivityView(_ConsoleOnlyView):
    throttle_classes = [ConsoleActivityMinThrottle]
    http_method_names = ["post", "options"]

    def post(self, request):
        from . import session_security

        session = session_security.record_activity(request)
        return _answer({"last_activity_at": session["last_activity_at"], "idle_expires_at": session["idle_expires_at"],
                        "absolute_expires_at": session["absolute_expires_at"]})


@extend_schema_view(post=extend_schema(tags=[TAG], summary="End this Console session (the Tec-Tac session and its Knox token end with it)"))
class ConsoleSessionSignOutView(_ConsoleOnlyView):
    http_method_names = ["post", "options"]

    def post(self, request):
        _cs().sign_out(request.auth)
        return _answer({"revoked": True})
