from django.core.management.base import BaseCommand
from tec_tac.scheduler import dispatch_due_schedules
from tec_tac.session_security import cleanup_session_history_if_due, sweep_expired_sessions


class Command(BaseCommand):
    help = "Evaluate Tec-Tac schedules, queue due runs, and run due Core retention work."

    def handle(self, *args, **options):
        result = dispatch_due_schedules()
        cleanup = None
        cleanup_error = ""
        try:
            cleanup = cleanup_session_history_if_due()
        except Exception as exc:
            # Retention must retry on the next minute without taking the general
            # Scheduler tick down. The due marker advances only after success.
            cleanup_error = f"{exc.__class__.__name__}: {exc}"
            self.stderr.write(f"TEC-TAC session history cleanup failed; retrying next tick: {cleanup_error}")

        sweep = None
        sweep_error = ""
        try:
            sweep = sweep_expired_sessions()
        except Exception as exc:
            # Same rule: the sweep can never take the tick, or Tactical, down.
            sweep_error = f"{exc.__class__.__name__}: {exc}"
            self.stderr.write(f"TEC-TAC session expiry sweep failed; retrying next tick: {sweep_error}")

        reconciled = []
        try:
            # 1.17.11 (AD-20): a replacement enabled next to the module it replaces gets a job that disables it. The
            # step never raises, and a failure here never takes the tick or Tactical down.
            from tec_tac.module_replacement import reconcile_conflicts

            reconciled = reconcile_conflicts()
        except Exception as exc:
            self.stderr.write(f"TEC-TAC replacement conflict check failed; retrying next tick: {exc.__class__.__name__}: {exc}")

        audited = 0
        try:
            # 1.17.12 (AD-20): the outcome audit rows of finished module switch jobs. Audit follows what happened, so
            # this runs after the root helper has finished. Never raises.
            from tec_tac.module_replacement import audit_finished_jobs

            audited = audit_finished_jobs()
        except Exception as exc:
            self.stderr.write(f"TEC-TAC replacement audit sweep failed; retrying next tick: {exc.__class__.__name__}: {exc}")

        failure_notices = 0
        try:
            # 1.17.14 (CQ36): one notice per failed module job, for the superusers and the person who started it. The
            # step never raises, and a failure here never takes the tick or Tactical down.
            from tec_tac.module_failure_notices import sweep_failed_jobs

            failure_notices = sweep_failed_jobs()
        except Exception as exc:
            self.stderr.write(f"TEC-TAC module failure notice sweep failed; retrying next tick: {exc.__class__.__name__}: {exc}")

        sweep_state = "error" if sweep_error else "ran"
        cleanup_state = "error" if cleanup_error else ("ran" if cleanup and cleanup.get("ran") else "not_due")
        self.stdout.write(
            "TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} session_expiry_sweep={sweep_state} sweep_revoked={sweep_revoked} sweep_skipped_no_digest={sweep_skipped} sweep_orphan_tokens={sweep_orphans} now={now} replacement_conflicts_queued={replacement_queued} replacement_audit_rows={replacement_audit} module_failure_notices={failure_notices}".format(
                checked=result["checked"],
                queued=len(result["queued"]),
                skipped=len(result["skipped"]),
                cleaned=result.get("cleaned", 0),
                session_cleanup=cleanup_state,
                sweep_state=sweep_state,
                sweep_revoked=(sweep or {}).get("revoked", 0),
                sweep_skipped=(sweep or {}).get("skipped_no_digest", 0),
                sweep_orphans=(sweep or {}).get("orphan_tokens_deleted", 0),
                now=result["now"],
                replacement_queued=sum(1 for row in reconciled if row.get("queued")),
                replacement_audit=audited,
                failure_notices=failure_notices,
            )
        )
