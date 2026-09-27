from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from .capabilities import build_operation_context
from .server_backup import (
    ServerBackupError,
    recovery_identity_core,
    trust_recovery_signer_core,
)
from .session_security import SessionAuthenticated


def _effective_superuser(user) -> bool:
    if bool(getattr(user, "is_superuser", False)):
        return True
    try:
        role = user.get_and_set_role_cache()
    except Exception:
        role = getattr(user, "role", None)
    return bool(role and getattr(role, "is_superuser", False))


def _context(request, action: str) -> dict:
    return build_operation_context(
        source_module="core",
        source_action=action,
        requested_by=str(getattr(request.user, "username", "") or "")[:150],
    )


class RecoveryTrustView(APIView):
    """Superuser boundary for recovery-key identity and one-confirmation trust."""

    permission_classes = [SessionAuthenticated]

    def get(self, request):
        try:
            identity = recovery_identity_core(
                context=_context(request, "recovery.identity")
            )
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response({
            "identity": identity,
            "can_trust_signer": _effective_superuser(request.user),
            "trust_endpoint": "/api/tfd/system/recovery/trust/",
        })

    def post(self, request):
        if not _effective_superuser(request.user):
            raise PermissionDenied("Only an effective superuser may trust a recovery signing key.")
        payload = request.data if isinstance(request.data, dict) else {}
        backup_ref = str(payload.get("backup_ref") or "").strip()
        if not backup_ref:
            raise ValidationError("backup_ref is required.")
        destination = payload.get("destination")
        if destination is not None and not isinstance(destination, dict):
            raise ValidationError("destination must be an object or null.")
        try:
            result = trust_recovery_signer_core(
                backup_ref=backup_ref,
                destination=destination,
                context=_context(request, "recovery.trust_signer"),
            )
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response(result)
