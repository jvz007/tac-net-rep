from django.core.management.base import BaseCommand, CommandError

IP_CHANGE_CHOICES = ("off", "audit", "reauthenticate", "terminate")
ACTOR_LABEL = "server command (tectac_session_policy)"


class Command(BaseCommand):
    help = (
        "Show the Tec-Tac session policy, or set what happens when a session's network address changes "
        "(off, audit, reauthenticate, terminate). Use it to recover when the setting signs everyone out."
    )

    def add_arguments(self, parser):
        parser.add_argument("--show", action="store_true", help="Print the effective global session policy.")
        parser.add_argument("--ip-change", choices=IP_CHANGE_CHOICES, help="Set the IP-change policy.")

    def handle(self, *args, **options):
        show = bool(options.get("show"))
        value = options.get("ip_change")
        if not show and value is None:
            raise CommandError("Give --show, --ip-change off|audit|reauthenticate|terminate, or both.")
        # Lazy imports keep start-up cheap (Core 1.18.1 rule).
        from tec_tac import session_security

        if value is not None:
            old = session_security.get_effective_policy().get("ip_change_policy")
            try:
                session_security._update_global_policy({"ip_change_policy": value}, requested_by=ACTOR_LABEL)
            except session_security.SessionSecurityError as exc:
                raise CommandError(str(exc))
            self.stdout.write(f"ip_change_policy changed: {old} -> {value}")
            self.stdout.write("Open sessions follow the new policy on their next request. An audit row (session_policy_changed) was written.")
        if show:
            policy = session_security.get_effective_policy()
            first = "ip_change_policy"
            self.stdout.write(f"{first}: {policy.get(first)}")
            for key in sorted(k for k in policy if k != first):
                self.stdout.write(f"{key}: {policy[key]}")
