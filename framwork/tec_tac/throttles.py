from rest_framework.throttling import SimpleRateThrottle

class _AuthenticatedAttemptThrottle(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        user = getattr(request, "user", None)
        ident = str(getattr(user, "pk", "anon") or "anon")
        remote = str(request.META.get("REMOTE_ADDR") or "")[:64]
        return self.cache_format % {"scope": self.scope, "ident": f"{ident}:{remote}"}

class TotpEnrollmentMinThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_totp_enrollment_min"
    rate = "5/min"

class TotpEnrollmentDayThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_totp_enrollment_day"
    rate = "20/day"


class AuditWriteMinThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_audit_write_min"
    rate = "60/min"

class AuditWriteDayThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_audit_write_day"
    rate = "1000/day"

class MfaBackupProofMinThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_mfa_backup_proof_min"
    rate = "5/min"

class MfaBackupProofDayThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_mfa_backup_proof_day"
    rate = "20/day"
