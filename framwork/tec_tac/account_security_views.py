from __future__ import annotations

import logging

from rest_framework.response import Response
from rest_framework.views import APIView

from .account_security_policy import AccountSecurityPolicyError, get_policy, set_policy
from .audit import AuditWriteError, record
from .rbac import is_effective_superuser
from .session_security import SessionAuthenticated, can_manage_account_security

logger = logging.getLogger("tec_tac.account_security")


class AccountSecurityPolicyView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not can_manage_account_security(request.user):
            return Response({"detail": "Account security administration permission denied."}, status=403)
        try:
            policy = get_policy()
        except AccountSecurityPolicyError as exc:
            logger.exception("Unable to read root-owned account security policy")
            return Response({"detail": "Unable to read account security policy.", "error_type": exc.__class__.__name__}, status=500)
        return Response({"policy": policy, "can_change": is_effective_superuser(request.user)})

    def put(self, request):
        if not is_effective_superuser(request.user):
            return Response({"detail": "Only an effective superuser may change account security policy."}, status=403)
        if "protect_superuser_accounts" not in request.data:
            return Response({"detail": "protect_superuser_accounts is required."}, status=400)
        try:
            current = get_policy()
            requested = request.data.get("protect_superuser_accounts")
            if not isinstance(requested, bool):
                return Response({"detail": "protect_superuser_accounts must be a boolean."}, status=400)
            updated = set_policy(requested, updated_by=str(request.user.username))
            try:
                record(
                    actor=request.user,
                    module_id="core",
                    action="modify",
                    object_type="account_security_policy",
                    object_id="global",
                    before={"protect_superuser_accounts": current["protect_superuser_accounts"]},
                    after={"protect_superuser_accounts": updated["protect_superuser_accounts"]},
                    metadata={"root_owned": True},
                    request=request,
                    strict=True,
                )
            except AuditWriteError:
                # The owner decision requires every policy change to be audited.
                # Best-effort rollback restores the previous root-owned value when
                # Tactical audit persistence is unavailable.
                try:
                    set_policy(current["protect_superuser_accounts"], updated_by=str(request.user.username))
                except Exception:
                    logger.exception("Account security policy audit failed and rollback also failed")
                return Response({"detail": "Policy change was not retained because the audit record could not be written."}, status=500)
            return Response({"policy": updated, "can_change": True})
        except (AccountSecurityPolicyError, TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)
