"""1.17.33 dev-server check for the ticketed Tactical terminal socket. WRITTEN HERE, NOT RUN HERE (Django, channels, Redis, nginx and
Tactical are not installed on the development PC).

Replaces tests/tactical-websocket-runtime-1.17.32.py, which had two faults:
- pick_agent filtered on `status`. In Tactical v1.5.2 Agent.status is a Python property (agents/models.py), not a column, so
  a database exclude on it raised FieldError. The agent is now chosen in Python.
- It ran everything inside transaction.atomic() and rolled back. channels.db.database_sync_to_async calls close_old_connections()
  around every call, and inside an atomic block that closes the shared connection mid-transaction, so the next read failed with 'the
  connection is closed' and Core refused a good ticket. This version commits real rows and deletes them at the end.

Run on the dev server as the tactical user, from the Tactical backend directory. Stdin form (no quoting needed):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.33.py

From root, the same stdin form as the tactical user:

    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.33.py'

To choose the agent, put TECTAC_WS_PROBE_AGENT=<agent_id> in front of ../env/bin/python. Without it the probe uses the first agent (by
primary key) whose status is not online. If every agent is online it uses the first agent and prints a warning: the one start message
then reaches NATS and starts a real shell on that live agent (killed straight after). If the agent cannot be chosen, the probe prints one
plain line and stops.

What it does: sweeps the leftovers of earlier runs (user, role, token and session rows named wsprobe-; audit rows are kept), then commits one probe user, a role with can_use_terminal and no
client or site limits, a Knox token and a Tec-Tac session row, and issues tickets for the chosen agent (remote-background must be
enabled). It opens the real ASGI application (tacticalrmm.asgi.application: ProtocolTypeRouter, KnoxAuthMiddlewareStack, URLRouter with
Core's route) by hand-built websocket scopes, and checks: a valid ticket is accepted; one start row is written for two start messages; a
second use of the ticket is refused 4401; a foreign Origin is refused 4003; a split-host Origin (Host = the API host, Origin = the first
CORS_ORIGIN_WHITELIST entry) is accepted, when that list is not empty; a malformed ticket is refused 4401; and after this thread's
database connection was closed, a socket with a fresh ticket is still accepted (the stale-connection check). Then, in a finally block, it
deletes what it created: session rows, Knox tokens, user and role, and every ticket key it minted. It keeps the wsprobe- audit rows (the
audit table is a record; Johan has not answered CQ103). It deletes only rows whose user name or role name starts with wsprobe-, and ends
by checking that none of those are left. No token or ticket is printed.

Expected: PASS lines, one 'deleted' line per kind, and a last line 'tactical-websocket-runtime-1.17.33: ok'. A NATS error after the start
is expected on a dev server without an agent online; the audit row is written before Tactical starts, so one custom:terminal-start row
still shows, and it stays in the audit log under the wsprobe- user name.
"""
import json
import os
import uuid
from datetime import timedelta
from types import SimpleNamespace

from accounts.models import Role
from agents.models import Agent
from asgiref.sync import async_to_sync
from asgiref.testing import ApplicationCommunicator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.utils import timezone
from knox.models import AuthToken
from logs.models import AuditLog
from tacticalrmm.asgi import application
from tec_tac import tactical_websocket as tw
from tec_tac.models import TecTacSessionTrust

ONLINE = "online"  # Tactical's AGENT_STATUS_ONLINE
TIMEOUT = 10  # seconds to wait for each step of the socket
PREFIX = "wsprobe-"  # every row this probe creates, and the only rows it ever deletes


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("PASS", msg)


def socket_path(ticket):
    return f"/ws/tfd/agent-terminal/{ticket}/"


def headers_for(host, origin=None):
    headers = [(b"host", host.encode("latin-1"))]
    if origin is not None:
        headers.append((b"origin", origin.encode("latin-1")))
    return headers


def ws_scope(path, headers):
    """A websocket scope built by hand, the way the ASGI server builds it for an HTTP upgrade request."""
    return {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8000),
        "subprotocols": [],
    }


class WsProbe:
    """One socket through tacticalrmm.asgi.application. Create it inside the running loop (async_to_sync)."""

    def __init__(self, path, headers):
        self.comm = ApplicationCommunicator(application, ws_scope(path, headers))

    async def connect(self):
        """(True, subprotocol) on websocket.accept, (False, code) on websocket.close."""
        await self.comm.send_input({"type": "websocket.connect"})
        message = await self.comm.receive_output(timeout=TIMEOUT)
        if message["type"] == "websocket.accept":
            return True, message.get("subprotocol")
        if message["type"] == "websocket.close":
            return False, message.get("code")
        raise AssertionError(f"the socket sent {message['type']} before it was accepted or closed")

    async def send_json_to(self, payload):
        await self.comm.send_input({"type": "websocket.receive", "text": json.dumps(payload)})

    async def disconnect(self):
        """Ends the socket and waits for Tactical's and Core's consumer cleanup to finish."""
        await self.comm.send_input({"type": "websocket.disconnect", "code": 1000})
        await self.comm.wait(timeout=TIMEOUT)


async def open_and_close(path, headers):
    probe = WsProbe(path, headers)
    result = await probe.connect()
    await probe.disconnect()
    return result


def pick_agent():
    """The agent to open a terminal on. Agent.status is a Python property in Tactical, so nothing here filters on it in the database."""
    wanted = os.environ.get("TECTAC_WS_PROBE_AGENT", "").strip()
    if wanted:
        agent = Agent.objects.filter(agent_id=wanted).first()
        must(agent is not None, "TECTAC_WS_PROBE_AGENT names an agent in this database")
        return agent
    first = None
    try:
        for agent in Agent.objects.order_by("pk").iterator():
            if first is None:
                first = agent
            if agent.status != ONLINE:
                return agent
    except Exception as exc:  # noqa: BLE001 - any failure here ends the probe with one plain line
        print(f"The probe could not choose an agent ({type(exc).__name__}: {exc}). Set TECTAC_WS_PROBE_AGENT=<agent_id> and run it again.")
        raise SystemExit(1)
    if first is not None:
        print("WARN every agent is online: the start message reaches a live agent and starts a shell there (killed straight after).")
        print("WARN set TECTAC_WS_PROBE_AGENT=<agent_id> to choose an agent.")
    return first


def remove_probe_rows(prefix):
    """Delete the committed rows of this probe: session rows, Knox tokens, users, roles. The wsprobe- audit rows are kept (CQ103 is open). Only user names and role names that
    start with the prefix (always wsprobe-) are touched. Prints one line per kind."""
    if not prefix.startswith(PREFIX):
        raise AssertionError("the probe deletes only rows named wsprobe-")
    User = get_user_model()

    def gone(label, queryset):
        count = queryset.count()
        queryset.delete()
        print(f"deleted {count} {label}")

    gone("session rows", TecTacSessionTrust.objects.filter(username__startswith=prefix))
    gone("Knox tokens", AuthToken.objects.filter(user__username__startswith=prefix))
    gone("users", User.objects.filter(username__startswith=prefix))
    gone("roles", Role.objects.filter(name__startswith=prefix))


def probe_rows_left():
    User = get_user_model()
    return {
        "session rows": TecTacSessionTrust.objects.filter(username__startswith=PREFIX).count(),
        "Knox tokens": AuthToken.objects.filter(user__username__startswith=PREFIX).count(),
        "users": User.objects.filter(username__startswith=PREFIX).count(),
        "roles": Role.objects.filter(name__startswith=PREFIX).count(),
    }


def break_this_threads_connection():
    """Make this thread's database connection stale, the way a Postgres restart or an idle kill does. The raw driver connection is closed
    while Django still holds it, so the next use fails once. When there is no raw connection, Django's own close() is used."""
    raw = getattr(connection, "connection", None)
    if raw is not None:
        try:
            raw.close()
            return "the driver connection was closed under Django"
        except Exception as exc:  # noqa: BLE001 - fall back to Django's own close
            print(f"driver close failed ({type(exc).__name__}), using Django's close")
    connection.close()
    return "Django's connection.close() was called"


agent = pick_agent()
if agent is None:
    raise SystemExit("skipped: the dev server has no agent to open a terminal on")

tag = uuid.uuid4().hex[:10]
issued_tickets = []  # every ticket minted here, so the finally can clear each cache key
print("sweeping the leftovers of earlier runs")
remove_probe_rows(PREFIX)
try:
    User = get_user_model()
    role = Role.objects.create(name=f"{PREFIX}{tag}", can_use_terminal=True)
    user = User.objects.create_user(username=f"{PREFIX}{tag}", password=uuid.uuid4().hex)
    user.role = role
    user.save()
    instance, _token = AuthToken.objects.create(user=user)
    digest = instance.digest
    now = timezone.now()
    trust = TecTacSessionTrust.objects.create(
        token_fingerprint=f"{PREFIX}{tag}", user=user, username=user.username, last_activity_at=now, last_seen_at=now,
        absolute_expires_at=now + timedelta(hours=8), idle_expires_at=now + timedelta(hours=1), knox_digest=digest,
    )
    request = SimpleNamespace(user=user, auth=SimpleNamespace(digest=digest), tec_tac_session=trust, META={}, tec_tac_request_id=f"{PREFIX}{tag}")

    def new_ticket():
        result = tw.issue_ticket(request, module_id="remote-background", kind="agent-terminal", agent_id=agent.agent_id)
        issued_tickets.append(result["ticket"])
        return result

    first = new_ticket()
    ticket = first["ticket"]
    must(first["kind"] == "agent-terminal" and first["expires_in"] == 30, "the ticket is issued for the probe user")
    must(first["path"] == socket_path(ticket), "the ticket path has the documented form")

    async def socket_leg():
        live = WsProbe(socket_path(ticket), headers_for("localhost"))
        connected, _subprotocol = await live.connect()
        must(connected, "the relayed socket accepts a valid ticket")
        await live.send_json_to({"action": "start", "shell": "", "run_as_user": False})
        await live.send_json_to({"action": "start", "shell": ""})
        await live.send_json_to({"action": "kill"})
        await live.disconnect()

        connected_again, code_again = await open_and_close(socket_path(ticket), headers_for("localhost"))
        must(not connected_again and code_again == 4401, "a second use of the ticket is refused 4401")

        foreign = new_ticket()["ticket"]
        connected, code = await open_and_close(socket_path(foreign), headers_for("localhost", "https://evil.example.invalid"))
        must(not connected and code == 4003, "a foreign Origin on a fresh ticket closes 4003")

        whitelist = list(getattr(settings, "CORS_ORIGIN_WHITELIST", None) or [])
        if whitelist:
            split = new_ticket()["ticket"]
            connected, _subprotocol = await open_and_close(socket_path(split), headers_for(settings.ALLOWED_HOSTS[0], whitelist[0]))
            must(connected, "the split-host layout is accepted: Host is the API host, Origin is the first CORS_ORIGIN_WHITELIST entry")
        else:
            print("SKIP the split-host check: CORS_ORIGIN_WHITELIST is empty on this server, so only same-host Origins are allowed.")

        connected, code = await open_and_close("/ws/tfd/agent-terminal/short-ticket/", headers_for("localhost"))
        must(not connected and code == 4401, "a malformed ticket closes 4401")

    async_to_sync(socket_leg)()

    starts = AuditLog.objects.filter(action="custom:terminal-start", username=user.username)
    must(starts.count() == 1, f"exactly one custom:terminal-start row for the session start, got {starts.count()}")
    row = starts.first()
    must(row.debug_info.get("operation_context", {}).get("server_provenance") == "tactical-websocket", "the row carries Core's provenance")
    must(row.debug_info.get("module_id") == "remote-background", "the row names the owning module")

    # The stale-connection check. The ticket is minted first, because the break leaves this thread's connection unusable for one call.
    stale_ticket = new_ticket()["ticket"]
    how = break_this_threads_connection()
    print(f"stale-connection step: {how}")

    async def stale_leg():
        connected, code = await open_and_close(socket_path(stale_ticket), headers_for("localhost"))
        must(connected, f"after this thread's database connection was closed, a socket with a fresh ticket is accepted (code {code})")

    async_to_sync(stale_leg)()
finally:
    # A stale or broken connection must not stop the cleanup: close it so the deletes below open a fresh one.
    try:
        connection.close()
    except Exception as exc:  # noqa: BLE001
        print(f"connection.close() failed ({type(exc).__name__}); the deletes open a fresh one")
    for value in issued_tickets:
        cache.delete(tw.cache_key(value))
    print(f"removed {len(issued_tickets)} ticket keys")
    remove_probe_rows(f"{PREFIX}{tag}")

left = probe_rows_left()
must(not any(left.values()), f"no wsprobe rows left ({left})")
print("tactical-websocket-runtime-1.17.33: ok")
