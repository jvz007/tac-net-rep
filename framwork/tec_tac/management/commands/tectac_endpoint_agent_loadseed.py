"""Test-only load seed for the endpoint agent socket (Core 1.17.90, plan 9A step 4).

Creates N throwaway agent accounts (a Tactical User linked to a test Agent row) with their agent tokens in a STAGING database, and removes
exactly those rows again. Every row it makes carries the fixed prefix ``loadtest-ea-`` (the user name and the agent id), and cleanup deletes
only rows with that prefix. It does nothing unless the Django setting TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST is True (an absent setting
refuses). Shipped in Core, inert, no route, no UI.

Tokens are written only to the file given with --out (created with mode 0600), one ``agent_id token`` pair per line. They are never printed
and never logged. The command prints agent ids and counts only.
"""
from __future__ import annotations

import os

from django.core.management.base import BaseCommand, CommandError

PREFIX = "loadtest-ea-"
MAX_COUNT = 5000
SETTING = "TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST"
REFUSAL = f"Refused: the load seed runs only where the Django setting {SETTING} is True. Nothing was changed."


def allowed() -> bool:
    from django.conf import settings

    return getattr(settings, SETTING, False) is True


def _models():
    from agents.models import Agent
    from clients.models import Client, Site
    from django.contrib.auth import get_user_model
    from rest_framework.authtoken.models import Token

    return get_user_model(), Agent, Token, Client, Site


def seed(count: int, out_path: str, models) -> list[str]:
    """Create ``count`` prefixed accounts and write their tokens to ``out_path`` (0600). Returns the agent ids."""
    User, Agent, Token, Client, Site = models
    client, _ = Client.objects.get_or_create(name=f"{PREFIX}client")
    site, _ = Site.objects.get_or_create(client=client, name=f"{PREFIX}site")
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    ids: list[str] = []
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for number in range(1, count + 1):
            agent_id = f"{PREFIX}{number:05d}"
            agent = Agent.objects.create(agent_id=agent_id, hostname=agent_id, site=site)
            user = User.objects.create_user(username=agent_id, agent=agent, password=None)
            token = Token.objects.create(user=user)
            handle.write(f"{agent_id} {token.key}\n")
            ids.append(agent_id)
    return ids


def cleanup(models) -> dict:
    """Delete exactly the rows that carry the prefix: users (their tokens go with them), agents, then the seed client and site."""
    User, Agent, _Token, Client, Site = models
    users = User.objects.filter(username__startswith=PREFIX).delete()
    agents = Agent.objects.filter(agent_id__startswith=PREFIX).delete()
    Site.objects.filter(name=f"{PREFIX}site", client__name=f"{PREFIX}client").delete()
    Client.objects.filter(name=f"{PREFIX}client").delete()
    return {"users": users[0] if isinstance(users, tuple) else users, "agents": agents[0] if isinstance(agents, tuple) else agents}


class Command(BaseCommand):
    help = "Test only: create or remove throwaway endpoint agent accounts for a load test (needs the Django setting TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST)."

    def add_arguments(self, parser):
        parser.add_argument("--count", type=int, default=0, help=f"how many accounts to create (1 to {MAX_COUNT})")
        parser.add_argument("--out", default="", help="file that receives 'agent_id token' lines (mode 0600)")
        parser.add_argument("--cleanup", action="store_true", help="remove the rows this command made (prefix loadtest-ea-)")

    def handle(self, *args, **options):
        if not allowed():
            raise CommandError(REFUSAL)
        models = _models()
        if options["cleanup"]:
            done = cleanup(models)
            self.stdout.write(f"Removed {done['users']} accounts and {done['agents']} agents with the prefix {PREFIX}.")
            return
        count = options["count"]
        if not 1 <= count <= MAX_COUNT:
            raise CommandError(f"--count must be between 1 and {MAX_COUNT}.")
        if not options["out"]:
            raise CommandError("--out is required: the tokens are written to that file and never printed.")
        ids = seed(count, options["out"], models)
        self.stdout.write(f"Created {len(ids)} accounts, {ids[0]} to {ids[-1]}. Tokens are in {options['out']}.")
