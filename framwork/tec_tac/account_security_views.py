from __future__ import annotations

import logging

from rest_framework.response import Response
from rest_framework.views import APIView

from .account_security_policy import AccountSecurityPolicyError, get_policy, set_policy
from .audit import AuditContractError, AuditWriteError, record
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
            requested = request.data.get("protect_superuser_accounts")
            if not isinstance(requested, bool):
                return Response({"detail": "protect_superuser_accounts must be a boolean."}, status=400)

            current = None
            current_error = None
            try:
                current = get_policy()
            except AccountSecurityPolicyError as exc:
                # A corrupt root-owned policy must remain repairable by an effective
                # superuser. The unreadable prior state is recorded explicitly in
                # the Core audit record instead of blocking the repair operation.
                current_error = exc

            updated = set_policy(requested, updated_by=str(request.user.username))
            before = (
                {"protect_superuser_accounts": current["protect_superuser_accounts"]}
                if current is not None
                else {"policy_state": "unreadable"}
            )
            metadata = {"root_owned": True}
            if current_error is not None:
                metadata["repaired_corrupt_policy"] = True

            try:
                record(
                    actor=request.user,
                    module_id="core",
                    action="modify",
                    object_type="account_security_policy",
                    object_id="global",
                    before=before,
                    after={"protect_superuser_accounts": updated["protect_superuser_accounts"]},
                    metadata=metadata,
                    request=request,
                    strict=True,
                )
            except (AuditContractError, AuditWriteError):
                # D1 requires every policy change to be audited. Restore the prior
                # logical value when it was readable. If the prior file was corrupt,
                # fail closed to protection=ON rather than retaining an unaudited
                # requested state or recreating corrupt bytes.
                rollback_value = (
                    current["protect_superuser_accounts"]
                    if current is not None
                    else True
                )
                try:
                    set_policy(rollback_value, updated_by=str(request.user.username))
                except Exception:
                    logger.exception("Account security policy audit failed and rollback also failed")
                return Response({"detail": "Policy change was not retained because the audit record could not be written."}, status=500)
            return Response({"policy": updated, "can_change": True})
        except (AccountSecurityPolicyError, TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)
