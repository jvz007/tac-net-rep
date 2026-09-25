from __future__ import annotations

from django.contrib.auth import login
from knox.views import LoginView as KnoxLoginView
from python_ipware import IpWare
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from logs.models import AuditLog
from tacticalrmm.helpers import notify_error
from tacticalrmm.throttles import LoginDayThrottle, LoginMinThrottle
from tacticalrmm.utils import get_core_settings

from .mfa_backup import (
    MfaBackupProofError,
    audit_generation_proof_failure,
    backup_code_status,
    burn_backup_code_hash_cost,
    consume_backup_code,
    generate_backup_codes,
    verify_generation_proof,
)
from .session_security import SessionAuthenticated, SessionSecurityError


class MfaBackupCodesView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [LoginMinThrottle, LoginDayThrottle]

    def get_throttles(self):
        if getattr(self.request, "method", "GET").upper() == "POST":
            return super().get_throttles()
        return []

    def get(self, request):
        response = Response({"status": backup_code_status(request.user)})
        response["Cache-Control"] = "no-store, max-age=0"
        return response

    def post(self, request):
        try:
            verify_generation_proof(
                request.user,
                password=str(request.data.get("password") or ""),
                totp_code=str(request.data.get("totp") or ""),
            )
            payload = generate_backup_codes(request.user, requested_by=request.user.username)
        except MfaBackupProofError as exc:
            audit_generation_proof_failure(
                request.user,
                requested_by=request.user.username,
                client_ip=str(getattr(request, "_client_ip", "") or ""),
            )
            return Response({"detail": str(exc)}, status=400)
        except SessionSecurityError as exc:
            return Response({"detail": str(exc)}, status=400)
        response = Response(payload, status=201)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        return response


class BackupCodeLoginView(KnoxLoginView):
    """Issue a normal Tactical Knox token after password + one-time backup code.

    This endpoint intentionally mirrors Tactical's local login guardrails and
    throttles. It exists only because upstream Tactical currently accepts TOTP
    as the second factor and has no recovery-code storage/login contract.
    """

    permission_classes = (AllowAny,)
    throttle_classes = [LoginMinThrottle, LoginDayThrottle]

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        if not serializer.is_valid():
            burn_backup_code_hash_cost()
            AuditLog.audit_user_failed_login(
                str(request.data.get("username") or ""),
                debug_info={"ip": getattr(request, "_client_ip", "")},
            )
            return notify_error("Bad credentials")

        user = serializer.validated_data["user"]
        if user.block_dashboard_login or user.is_sso_user:
            burn_backup_code_hash_cost()
            return notify_error("Bad credentials")

        core_settings = get_core_settings()
        if not user.is_superuser and core_settings.block_local_user_logon:
            burn_backup_code_hash_cost()
            return notify_error("Bad credentials")

        if not getattr(user, "totp_key", None):
            burn_backup_code_hash_cost()
            return notify_error("Bad credentials")

        code = str(request.data.get("backup_code") or "")
        if not consume_backup_code(user, code, requested_by=user.username):
            AuditLog.audit_user_failed_twofactor(
                str(request.data.get("username") or ""),
                debug_info={"ip": getattr(request, "_client_ip", "")},
            )
            return notify_error("Bad credentials")

        login(request, user)
        ipw = IpWare()
        client_ip, _ = ipw.get_client_ip(request.META)
        if client_ip:
            user.last_login_ip = str(client_ip)
            user.save(update_fields=["last_login_ip"])

        AuditLog.audit_user_login_successful(
            user.username,
            debug_info={"ip": getattr(request, "_client_ip", ""), "mfa": "backup_code"},
        )
        response = super().post(request, format=None)
        response.data["username"] = user.username
        response.data["name"] = None
        response.data["mfa"] = "backup_code"
        return Response(response.data)
