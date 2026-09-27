from django.core.management.base import BaseCommand
from tec_tac.scheduler import dispatch_due_schedules
from tec_tac.session_security import cleanup_session_history_if_due


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

        cleanup_state = "error" if cleanup_error else ("ran" if cleanup and cleanup.get("ran") else "not_due")
        self.stdout.write(
            "TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} now={now}".format(
                checked=result["checked"],
                queued=len(result["queued"]),
                skipped=len(result["skipped"]),
                cleaned=result.get("cleaned", 0),
                session_cleanup=cleanup_state,
                now=result["now"],
            )
        )
