from django.core.management.base import BaseCommand
from tec_tac.scheduler import dispatch_due_schedules


class Command(BaseCommand):
    help = "Evaluate Tec-Tac schedules and queue due runs into Tactical Celery."

    def handle(self, *args, **options):
        result = dispatch_due_schedules()
        self.stdout.write(
            "TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} now={now}".format(
                checked=result["checked"], queued=len(result["queued"]), skipped=len(result["skipped"]), cleaned=result.get("cleaned", 0), now=result["now"]
            )
        )
