import json
import os

from django.core.management.base import BaseCommand, CommandError

ACTOR_LABEL = "server command (tectac_module_state)"
HELPER = "/usr/local/sbin/tec-tac-module-v2-job"


class Command(BaseCommand):
    help = (
        "Audit step of the server command that switches an installed module on or off (1.18.11). The owner runs "
        f"'sudo {HELPER} --server-command enable|disable <module id> [--cascade]'; the helper changes the state as root "
        "and then runs this command as the Tactical user with --record-outcome. This command never runs as root."
    )

    def add_arguments(self, parser):
        parser.add_argument("module_id", help="The id of the installed module.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--enable", action="store_true", help="Not run from here: shows the helper command.")
        group.add_argument("--disable", action="store_true", help="Not run from here: shows the helper command.")
        parser.add_argument("--cascade", action="store_true", help="With --disable, on the helper command.")
        parser.add_argument("--record-outcome", dest="record_outcome", default="",
                            help="Internal: the helper's JSON outcome, written as one audit row.")

    def handle(self, *args, **options):
        module_id = str(options.get("module_id") or "").strip()
        if os.geteuid() == 0:
            raise CommandError(
                "Do not run manage.py as root: it loads Tactical's own code. Run the helper as root instead: "
                f"sudo {HELPER} --server-command enable|disable {module_id or '<module_id>'} [--cascade]"
            )
        if not module_id or not all(ch.isalnum() or ch in "-_" for ch in module_id):
            raise CommandError("The module id may use letters, digits, hyphens and underscores only.")
        raw = str(options.get("record_outcome") or "")
        if not raw:
            action = "disable" if options.get("disable") else "enable"
            raise CommandError(
                "Module state is root-owned, so this command cannot change it. As root on the server run: "
                f"sudo {HELPER} --server-command {action} {module_id}" + (" --cascade" if options.get("cascade") else "")
            )
        try:
            result = json.loads(raw)
        except ValueError:
            raise CommandError("The outcome is not valid JSON. Nothing was audited.")
        if not isinstance(result, dict):
            raise CommandError("The outcome is not a JSON object. Nothing was audited.")
        enabled = bool(result.get("after"))
        cascade = bool(result.get("cascade"))
        # Lazy import keeps start-up cheap (Core 1.18.1 rule).
        from tec_tac import audit

        actor = audit.service_audit_actor(module_id="core", service="module-state-command", identity=ACTOR_LABEL)
        audit.record(
            actor=actor, module_id="core", action="modify", object_type="module", object_id=module_id,
            message=f"The module {module_id} was switched {'on' if enabled else 'off'} from the server by {ACTOR_LABEL}.",
            before={"enabled": bool(result.get("before"))}, after={"enabled": enabled},
            metadata={"module": module_id, "command": "tectac_module_state", "cascade": cascade,
                      "affected": list(result.get("affected") or []), "enabled_back": list(result.get("enabled_back") or [])},
            strict=False,
        )
        self.stdout.write(f"An audit row was written for {module_id}.")
