"""1.17.31 dev-server check for the ticketed Tactical terminal socket. WRITTEN HERE, NOT RUN HERE (Django, channels, Redis and Tactical are not
installed on the development PC).

Run on the dev server from the Tactical backend directory, after the dev branch is installed and the server restarted:

    python manage.py shell -c "exec(open('<path to this file>').read())"

What it does: creates one probe user, a role that holds can_use_terminal with no client or site limits, a Knox token and a Tec-Tac session
row for it, and issues a ticket for the first agent in the database (remote-background must be enabled). It then opens the real ASGI
application (tacticalrmm.asgi.application) with channels' WebsocketCommunicator, checks the connect, one start message, the single use of
the ticket (a second connect with the same ticket must be refused 4401), and the audit rows. Everything it writes to the database is
rolled back. The ticket key is removed from Redis. The socket leg runs under async_to_sync, so every database_sync_to_async call uses
this thread's connection and the rollback covers them. No token or ticket is printed.

Expected: the probe prints PASS lines and ends with 'tactical-websocket-runtime-1.17.31: ok'. A NATS error after the start is expected
on a dev server without an agent; the audit row is written before Tactical starts, so one custom:terminal-start row still shows.
"""
import uuid
from datetime import timedelta
from types import SimpleNamespace

from asgiref.sync import async_to_sync
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from knox.models import AuthToken

from accounts.models import Role
from agents.models import Agent
from logs.models import AuditLog
from tacticalrmm.asgi import application
from tec_tac import tactical_websocket as tw
from tec_tac.models import TecTacSessionTrust


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("PASS", msg)


agent = Agent.objects.first()
if agent is None:
    raise SystemExit("skipped: the dev server has no agent to open a terminal on")

ticket = None
tag = uuid.uuid4().hex[:10]
try:
    with transaction.atomic():
        User = get_user_model()
        role = Role.objects.create(name=f"wsprobe-{tag}", can_use_terminal=True)
        user = User.objects.create_user(username=f"wsprobe-{tag}", password=uuid.uuid4().hex)
        user.role = role
        user.save()
        instance, _token = AuthToken.objects.create(user=user)
        digest = instance.digest
        now = timezone.now()
        trust = TecTacSessionTrust.objects.create(
            token_fingerprint=f"wsprobe-{tag}", user=user, username=user.username, last_activity_at=now, last_seen_at=now,
            absolute_expires_at=now + timedelta(hours=8), idle_expires_at=now + timedelta(hours=1), knox_digest=digest,
        )
        request = SimpleNamespace(user=user, auth=SimpleNamespace(digest=digest), tec_tac_session=trust, META={}, tec_tac_request_id=f"wsprobe-{tag}")
        issued = tw.issue_ticket(request, module_id="remote-background", kind="agent-terminal", agent_id=agent.agent_id)
        ticket = issued["ticket"]
        must(issued["kind"] == "agent-terminal" and issued["expires_in"] == 30, "the ticket is issued for the probe user")

        async def socket_probe():
            comm = WebsocketCommunicator(application, f"/ws/tfd/agent-terminal/{ticket}/", headers=[(b"host", b"localhost")])
            connected, code = await comm.connect()
            must(connected, "the relayed socket accepts a valid ticket")
            await comm.send_json_to({"action": "start", "shell": "", "run_as_user": False})
            await comm.send_json_to({"action": "start", "shell": ""})
            await comm.send_json_to({"action": "kill"})
            await comm.disconnect()

            again = WebsocketCommunicator(application, f"/ws/tfd/agent-terminal/{ticket}/", headers=[(b"host", b"localhost")])
            connected_again, code_again = await again.connect()
            must(not connected_again and code_again == 4401, "a second use of the ticket is refused 4401")
            await again.disconnect()

        async_to_sync(socket_probe)()

        starts = AuditLog.objects.filter(action="custom:terminal-start", username=user.username)
        must(starts.count() == 1, "one custom:terminal-start row for the session start, none for the second start")
        row = starts.first()
        must(row.debug_info.get("operation_context", {}).get("server_provenance") == "tactical-websocket", "the row carries Core's provenance")
        must(row.debug_info.get("module_id") == "remote-background", "the row names the owning module")
        transaction.set_rollback(True)
finally:
    if ticket is not None:
        cache.delete(tw.cache_key(ticket))

must(not AuditLog.objects.filter(username__startswith=f"wsprobe-{tag}").exists(), "the probe rows were rolled back")
must(not User.objects.filter(username=f"wsprobe-{tag}").exists(), "the probe user was rolled back")
print("tactical-websocket-runtime-1.17.31: ok")
