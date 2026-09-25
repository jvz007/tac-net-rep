from __future__ import annotations

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TecTacSessionTrust
from .session_security import (
    SessionAuthenticated,
    SessionSecurityError,
    can_manage_session_security,
    can_manage_login_sessions,
    diagnostics,
    get_current_session,
    get_effective_policy,
    list_audit_events,
    list_active_login_sessions,
    list_sessions,
    record_activity,
    revoke_active_login_session,
    revoke_session,
    revoke_user_login_sessions,
    revoke_user_sessions,
    update_global_policy,
)


def _forbidden():
    return Response({"detail": "Session security administration permission denied."}, status=403)


def _browser_policy(policy):
    return {
        "idle_timeout_minutes": policy["idle_timeout_minutes"],
        "absolute_lifetime_minutes": policy["absolute_lifetime_minutes"],
        "ip_change_policy": policy["ip_change_policy"],
        "activity_heartbeat_seconds": policy["activity_heartbeat_seconds"],
    }


class CurrentSessionView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        return Response({"session": get_current_session(request), "policy": _browser_policy(get_effective_policy(request.user, request))})


class SessionActivityView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        return Response({"session": record_activity(request)})


class SessionListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        current_id = str(request.tec_tac_session.id)
        username = str(request.query_params.get("username") or "").strip()
        if username and username != request.user.username and not can_manage_session_security(request.user):
            return _forbidden()
        rows = list_sessions(username=username or None, user=None if username else request.user)
        for row in rows:
            row["current"] = row["id"] == current_id
        return Response({"sessions": rows, "count": len(rows)})


class SessionRevokeView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, session_id):
        target = get_object_or_404(TecTacSessionTrust, pk=session_id)
        if target.user_id != request.user.pk and not can_manage_session_security(request.user):
            return _forbidden()
        reason = str(request.data.get("reason") or "user-request")[:255]
        row = revoke_session(target.id, reason=reason, requested_by=request.user.username)
        return Response({"session": row})


class RevokeOtherSessionsView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        result = revoke_user_sessions(
            request.user.username,
            except_session_id=request.tec_tac_session.id,
            reason=str(request.data.get("reason") or "user-revoke-others")[:255],
            requested_by=request.user.username,
        )
        return Response(result)


class SessionPolicyView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_manage_session_security(request.user):
            return _forbidden()
        return Response({"policy": get_effective_policy(request.user, request)})

    def put(self, request):
        if not can_manage_session_security(request.user):
            return _forbidden()
        payload = request.data.get("policy", request.data)
        try:
            policy = update_global_policy(payload, requested_by=request.user.username)
        except (SessionSecurityError, TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response({"policy": policy})


class SessionAuditView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_manage_session_security(request.user):
            return _forbidden()
        username = str(request.query_params.get("username") or "").strip() or None
        event_type = str(request.query_params.get("event_type") or "").strip() or None
        try:
            limit = int(request.query_params.get("limit") or 200)
        except (TypeError, ValueError):
            return Response({"detail": "limit must be an integer."}, status=400)
        rows = list_audit_events(username=username, event_type=event_type, limit=limit)
        return Response({"events": rows, "count": len(rows)})


class SessionDiagnosticsView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_manage_session_security(request.user):
            return _forbidden()
        return Response(diagnostics())

def _login_sessions_forbidden():
    return Response({"detail": "Login session administration requires Tactical account-management permission."}, status=403)


class AdminLoginSessionListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_manage_login_sessions(request.user):
            return _login_sessions_forbidden()
        rows = list_active_login_sessions(current_request=request)
        return Response({"sessions": rows, "count": len(rows)})


class AdminLoginSessionRevokeView(APIView):
    permission_classes = [SessionAuthenticated]

    def delete(self, request, session_ref):
        if not can_manage_login_sessions(request.user):
            return _login_sessions_forbidden()
        try:
            result = revoke_active_login_session(
                session_ref,
                reason=str(request.data.get("reason") or "administrator-request")[:255],
                requested_by=request.user.username,
            )
        except SessionSecurityError as exc:
            return Response({"detail": str(exc)}, status=404)
        return Response(result)


class AdminUserLoginSessionsRevokeView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, user_id):
        if not can_manage_login_sessions(request.user):
            return _login_sessions_forbidden()
        result = revoke_user_login_sessions(
            int(user_id),
            reason=str(request.data.get("reason") or "administrator-request")[:255],
            requested_by=request.user.username,
        )
        return Response(result)

