from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from .audit import AuditContractError, AuditWriteError, record
from .capabilities import build_operation_context
from .server_backup import (
    ServerBackupError,
    recovery_identity_core,
    recovery_trust_job_status_core,
    trust_recovery_signer_core,
    get_server_backup_provider,
    list_registered_destinations_core,
    list_registered_backups_core,
    validate_registered_restore_core,
    restore_registered_backup_core,
    require_successful_restore_validation_core,
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
    """Effective-superuser boundary for recovery identity and signer trust."""

    permission_classes = [SessionAuthenticated]

    def _require_superuser(self, request):
        if not _effective_superuser(request.user):
            raise PermissionDenied("Only an effective superuser may inspect or trust recovery signing identities.")

    def get(self, request):
        self._require_superuser(request)
        job_id = str(request.query_params.get("job_id") or "").strip()
        if job_id:
            try:
                return Response({"job": recovery_trust_job_status_core(job_id=job_id)})
            except ServerBackupError as exc:
                raise ValidationError(str(exc)) from exc
        try:
            identity = recovery_identity_core(
                context=_context(request, "recovery.identity")
            )
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response({
            "identity": identity,
            "can_trust_signer": True,
            "trust_endpoint": "/api/tfd/system/recovery/trust/",
        })

    def post(self, request):
        self._require_superuser(request)
        payload = request.data if isinstance(request.data, dict) else {}
        fields = {
            "backup_ref": str(payload.get("backup_ref") or "").strip(),
            "destination_id": str(payload.get("destination_id") or "").strip(),
            "expected_key_id": str(payload.get("expected_key_id") or "").strip(),
            "expected_fingerprint": str(payload.get("expected_fingerprint") or "").strip().lower(),
            "expected_server_name": str(payload.get("expected_server_name") or "").strip(),
            "expected_installation_id": str(payload.get("expected_installation_id") or "").strip(),
        }
        missing = [key for key, value in fields.items() if not value]
        if missing:
            raise ValidationError({key: "This field is required." for key in missing})

        # The Core audit records the exact trust approval before dispatch. The
        # privileged helper writes a second root-owned audit only after the
        # downloaded bundle matches this identity and the key is trusted.
        try:
            record(
                actor=request.user,
                module_id="core",
                action="approve",
                object_type="recovery_signer_trust",
                object_id=fields["expected_key_id"],
                message="Recovery signer trust approved; privileged verification queued.",
                after={
                    "key_id": fields["expected_key_id"],
                    "public_key_sha256": fields["expected_fingerprint"],
                    "server_name": fields["expected_server_name"],
                    "installation_id": fields["expected_installation_id"],
                    "backup_ref": fields["backup_ref"],
                    "destination_id": fields["destination_id"],
                },
                metadata={"root_verification_required": True},
                request=request,
                strict=True,
            )
        except (AuditContractError, AuditWriteError) as exc:
            raise ValidationError("Recovery trust was not queued because the Core audit record could not be written.") from exc

        try:
            result = trust_recovery_signer_core(
                **fields,
                context=_context(request, "recovery.trust_signer"),
            )
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response(result, status=status.HTTP_202_ACCEPTED)



class BackupRestoreView(APIView):
    """Effective-superuser HTTP boundary for the native Backup & Restore UI."""

    permission_classes = [SessionAuthenticated]

    def _require_superuser(self, request):
        if not _effective_superuser(request.user):
            raise PermissionDenied("Only an effective superuser may manage server backup restore operations.")

    def get(self, request):
        self._require_superuser(request)
        try:
            destinations = list_registered_destinations_core(context=_context(request, "backup_restore.destinations"))
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response({"destinations": destinations})

    def post(self, request):
        self._require_superuser(request)
        payload = request.data if isinstance(request.data, dict) else {}
        action = str(payload.get("action") or "").strip()
        try:
            if action == "list":
                ids = payload.get("destination_ids")
                if not isinstance(ids, list):
                    raise ValidationError({"destination_ids": "An array of registered destination ids is required."})
                result = list_registered_backups_core(destination_ids=ids, context=_context(request, "backup_restore.list"))
            elif action == "validate":
                result = validate_registered_restore_core(
                    backup_ref=str(payload.get("backup_ref") or "").strip(),
                    destination_id=str(payload.get("destination_id") or "").strip(),
                    restore_mode=str(payload.get("restore_mode") or "").strip(),
                    overrides=payload.get("overrides") if isinstance(payload.get("overrides"), list) else [],
                    context=_context(request, "backup_restore.validate"),
                )
            elif action == "restore":
                if payload.get("confirmed") is not True:
                    raise ValidationError({"confirmed": "Explicit restore confirmation is required."})
                validation_job_id = str(payload.get("validation_job_id") or "").strip()
                if not validation_job_id:
                    raise ValidationError({"validation_job_id": "A successful restore validation job is required."})
                backup_ref = str(payload.get("backup_ref") or "").strip()
                destination_id = str(payload.get("destination_id") or "").strip()
                restore_mode = str(payload.get("restore_mode") or "").strip()
                require_successful_restore_validation_core(
                    validation_job_id=validation_job_id,
                    backup_ref=backup_ref,
                    destination_id=destination_id,
                    restore_mode=restore_mode,
                )
                result = restore_registered_backup_core(
                    backup_ref=backup_ref,
                    destination_id=destination_id,
                    restore_mode=restore_mode,
                    overrides=payload.get("overrides") if isinstance(payload.get("overrides"), dict) else {},
                    context=_context(request, "backup_restore.restore"),
                )
            else:
                raise ValidationError({"action": "Action must be list, validate, or restore."})
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        return Response(result, status=status.HTTP_202_ACCEPTED)


class BackupRestoreJobView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        if not _effective_superuser(request.user):
            raise PermissionDenied("Only an effective superuser may inspect server backup restore jobs.")
        try:
            job = get_server_backup_provider().get_job_status(job_id=str(job_id), context=_context(request, "backup_restore.job"))
        except ServerBackupError as exc:
            raise ValidationError(str(exc)) from exc
        allowed = {"list_registered_backups", "validate_registered_restore", "restore_registered_backup"}
        if str(job.get("action") or "") not in allowed:
            raise PermissionDenied("This job is not a native Backup & Restore UI job.")
        return Response({"job": job})
