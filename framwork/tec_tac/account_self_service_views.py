from __future__ import annotations

from rest_framework.response import Response
from rest_framework.views import APIView

from .account_self_service import (
    AccountSelfServiceError,
    account_summary,
    change_own_password,
    reset_own_totp,
    tactical_ui_preferences,
    update_tactical_ui_preferences,
)
from .mfa_backup import backup_code_status
from .session_security import SessionAuthenticated
from .throttles import TotpEnrollmentDayThrottle, TotpEnrollmentMinThrottle


class MyAccountView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        return Response({
            "account": account_summary(request.user),
            "mfa": backup_code_status(request.user),
            "tactical_ui": tactical_ui_preferences(request.user),
        })


class MyAccountPasswordView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [TotpEnrollmentMinThrottle, TotpEnrollmentDayThrottle]

    def put(self, request):
        try:
            result = change_own_password(
                request.user,
                current_password=str(request.data.get("current_password") or ""),
                new_password=str(request.data.get("new_password") or ""),
                current_session_id=getattr(getattr(request, "tec_tac_session", None), "id", None),
                request=request,
            )
        except AccountSelfServiceError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(result)


class MyAccountTotpResetView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [TotpEnrollmentMinThrottle, TotpEnrollmentDayThrottle]

    def post(self, request):
        try:
            result = reset_own_totp(
                request.user,
                current_password=str(request.data.get("current_password") or ""),
                current_totp=str(request.data.get("current_totp") or ""),
                request=request,
            )
        except AccountSelfServiceError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(result)


class MyAccountTacticalUiView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        return Response({"preferences": tactical_ui_preferences(request.user)})

    def put(self, request):
        try:
            preferences = update_tactical_ui_preferences(request.user, request.data, request=request)
        except AccountSelfServiceError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response({"preferences": preferences})
