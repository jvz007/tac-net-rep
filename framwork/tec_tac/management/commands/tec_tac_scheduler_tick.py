import logging

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
        failure_report = {}
        try:
            # 1.17.14 (CQ36): one notice per failed module job, for the superusers and the person who started it. The
            # step never raises, and a failure here never takes the tick or Tactical down. Since 1.17.38 only jobs finished in the
            # last seven days count (1.17.34 used six hours). A failure is never announced again for a person the notice ledger
            # already holds (no daily reminder); the report counts what the sweep left alone.
            from tec_tac.module_failure_notices import sweep_failed_jobs

            failure_notices = sweep_failed_jobs(report=failure_report)
        except Exception as exc:
            self.stderr.write(f"TEC-TAC module failure notice sweep failed; retrying next tick: {exc.__class__.__name__}: {exc}")

        try:
            # 1.17.28 (AD-30 amendment): clear the retired mail-setting column once, with its audit row. The function never raises;
            # the guard here keeps a failed import from taking the tick down either.
            from tec_tac.runtime_settings import clear_retired_private_relay

            clear_retired_private_relay()
        except Exception:
            # Logged, not written to the command's output: the step is a retry, and the tick's own output stays the same.
            logging.getLogger("tec_tac.runtime_settings").warning("The retired mail setting clear did not run; the next tick retries.", exc_info=True)

        repo_seeded = []
        repo_schedule_created = False
        try:
            # 1.17.42 (CQ121, CQ122): seed the official repository once and make sure the daily sync schedule exists. Both calls
            # never raise. This guard only catches an import or unexpected failure, and it logs rather than writing to the output.
            from tec_tac.module_repository import ensure_repository_sync_schedule, seed_default_repositories

            repo_seeded = seed_default_repositories()
            repo_schedule_created = ensure_repository_sync_schedule()
        except Exception:
            logging.getLogger("tec_tac.module_repository").warning("The module repository tick step failed; the next tick retries.", exc_info=True)

        try:
            # 1.17.60: finished module job records older than MODULE_JOB_RETENTION_DAYS are removed, at most once an hour and a
            # bounded number per run. The step never raises; it logs rather than writing to the output, so the tick's own line
            # stays the same. Only the root helpers can delete the logs (they sweep a log once its record is gone).
            from tec_tac import module_job_logs

            module_job_logs.prune_expired()
        except Exception:
            logging.getLogger("tec_tac.module_job_logs").warning("The module job retention step failed; the next tick retries.", exc_info=True)

        sweep_state = "error" if sweep_error else "ran"
        cleanup_state = "error" if cleanup_error else ("ran" if cleanup and cleanup.get("ran") else "not_due")
        self.stdout.write(
            "TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} session_expiry_sweep={sweep_state} sweep_revoked={sweep_revoked} sweep_skipped_no_digest={sweep_skipped} sweep_orphan_tokens={sweep_orphans} now={now} replacement_conflicts_queued={replacement_queued} replacement_audit_rows={replacement_audit} module_failure_notices={failure_notices} module_failure_skipped_old={failure_old} module_failure_already_notified={failure_known} module_failure_emails={failure_emails} repository_defaults_seeded={repo_seeded} repository_sync_schedule_created={repo_schedule_created}".format(
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
                failure_old=failure_report.get("skipped_old", 0),
                failure_known=failure_report.get("skipped_notified", 0),
                failure_emails=failure_report.get("emailed", 0),
                repo_seeded=len(repo_seeded),
                repo_schedule_created=int(bool(repo_schedule_created)),
            )
        )
