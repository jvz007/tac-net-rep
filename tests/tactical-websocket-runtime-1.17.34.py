"""1.17.34 dev-server check for the ticketed Tactical terminal sockets. WRITTEN HERE, NOT RUN HERE (Django, channels, Redis, nginx and
Tactical are not installed on the development PC).

Replaces tests/tactical-websocket-runtime-1.17.33.py (kept in the tree) and fixes what Johan's 1.17.33 run showed:
- The foreign-Origin and split-host steps called issue_ticket from inside the async leg. issue_ticket reads the database (the role scope)
  and writes the deny row, and Django refuses that from a running event loop (SynchronousOnlyOperation). Core logged "Tec-Tac audit
  write failed module=remote-background action=deny" and the ticket call raised TicketRefusal object_not_found. Every ticket call in an
  async leg now goes through sync_to_async(thread_sensitive=True) (new_ticket_async), which runs it in the thread that called
  async_to_sync, exactly like channels' own database_sync_to_async.
- A refusal now has its own step. The probe asks for an agent that is not in the probe user's scope, catches TicketRefusal, and checks
  the code (object_not_found) and that exactly one deny row was written. Before, the refusal escaped and ended the run.

New in 1.17.34 (AD-35):
- Activity. Terminal input refreshes the sign-in's idle timer and output alone does not. The probe backdates its own throwaway session
  row, then calls the same function the socket watcher calls (tactical_websocket.session_refusal with the time of the last input),
  and finally lets the idle limit end the session (session_idle_timeout, row revoked). It needs an idle policy of at least 4 minutes
  and is skipped with a printed line otherwise. It changes no policy.
- The server terminal (a shell on the server itself, as the Tactical service user). A throwaway wsprobe- superuser asks for a ticket as
  the module globalsettings; a non-superuser and the module remote-background are refused (one deny row each for the first; the owner
  check first for the second). If globalsettings is not an enabled core module here, or Tactical's server web terminal is off, the
  ticket steps print a SKIP line and the rest is skipped. The SOCKET step starts a real shell the moment the socket is accepted, so it
  only runs when TECTAC_WS_PROBE_SERVER_TERMINAL=1 is set. It sends NO input: it sends Tactical's trmmcli.disconnect straight away,
  then checks one custom:server-terminal-start row and a 4401 on a second use of the ticket.

Run on the dev server as the tactical user, from the Tactical backend directory. Stdin form (no quoting needed):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.34.py

From root, the same stdin form as the tactical user:

    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.34.py'

To choose the agent, put TECTAC_WS_PROBE_AGENT=<agent_id> in front of ../env/bin/python. To run the server terminal socket step as well,
put TECTAC_WS_PROBE_SERVER_TERMINAL=1 there too. Without TECTAC_WS_PROBE_AGENT the probe uses the first agent (by primary key) whose
status is not online. If every agent is online it uses the first agent and prints a warning: the one start message then reaches NATS and
starts a real shell on that live agent (killed straight after). If the agent cannot be chosen, the probe prints one plain line and stops.

What it does: sweeps the leftovers of earlier runs (user, role, token and session rows named wsprobe-; audit rows are kept), then commits
a probe user, a role with can_use_terminal and no client or site limits, a Knox token and a Tec-Tac session row, and issues tickets for
the chosen agent (remote-background must be enabled). It opens the real ASGI application (tacticalrmm.asgi.application) by hand-built
websocket scopes, and checks: a valid ticket is accepted; one start row for two start messages; a second use of the ticket is refused
4401; a foreign Origin is refused 4003; a split-host Origin is accepted, when CORS_ORIGIN_WHITELIST is not empty; a malformed ticket is
refused 4401; the out-of-scope agent refusal and its one deny row; a socket after this thread's database connection was closed; then
the server terminal and the activity steps above. In a finally block it deletes what it created: session rows, Knox tokens, users and
roles, and every ticket key it minted. It keeps the wsprobe- audit rows (CQ103, option b). It deletes only rows whose user name or role
name starts with wsprobe-, and ends by checking that none are left. No token or ticket is printed.

Expected: PASS lines, SKIP lines for what this server cannot do, one 'deleted' line per kind, and a last line
'tactical-websocket-runtime-1.17.34: ok'. A NATS error after the start is expected on a dev server without an agent online; the audit row
is written before Tactical starts, so one custom:terminal-start row still shows. The wsprobe- audit rows stay: one custom:terminal-start,
one or two deny rows, and one custom:server-terminal-start when the server socket step ran.
"""
import json
import os
import uuid
from datetime import timedelta
from types import SimpleNamespace

from accounts.models import Role
from agents.models import Agent
from asgiref.sync import async_to_sync, sync_to_async
from asgiref.testing import ApplicationCommunicator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.utils import timezone
from knox.models import AuthToken
from logs.models import AuditLog
from tacticalrmm.asgi import application
from tacticalrmm.urls import ws_urlpatterns
from tec_tac import session_security
from tec_tac import tactical_websocket as tw
from tec_tac.models import TecTacSessionTrust

ONLINE = "online"  # Tactical's AGENT_STATUS_ONLINE
TIMEOUT = 10  # seconds to wait for each step of the socket
PREFIX = "wsprobe-"  # every row this probe creates, and the only rows it ever deletes
SERVER_SOCKET = os.environ.get("TECTAC_WS_PROBE_SERVER_TERMINAL", "").strip() == "1"  # the server terminal socket starts a REAL shell


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("PASS", msg)


def socket_path(ticket, kind="agent-terminal"):
    return f"/ws/tfd/{kind}/{ticket}/"


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




def make_signin(label, tag, *, can_use_terminal=False, superuser=False):
    """Commit one throwaway person, role, Knox token and Tec-Tac session row, all named wsprobe-<tag>[-label]. Returns (user, trust, digest,
    request). The request has what issue_ticket reads: the user, the Knox digest and the session row."""
    User = get_user_model()
    name = f"{PREFIX}{tag}" + (f"-{label}" if label else "")
    role = Role.objects.create(name=name, can_use_terminal=can_use_terminal, is_superuser=superuser)
    user = User.objects.create_user(username=name, password=uuid.uuid4().hex)
    user.role = role
    if superuser:
        user.is_superuser = True
    user.save()
    instance, _token = AuthToken.objects.create(user=user)
    digest = instance.digest
    now = timezone.now()
    trust = TecTacSessionTrust.objects.create(
        token_fingerprint=name, user=user, username=user.username, last_activity_at=now, last_seen_at=now,
        absolute_expires_at=now + timedelta(hours=8), idle_expires_at=now + timedelta(hours=1), knox_digest=digest,
    )
    request = SimpleNamespace(user=user, auth=SimpleNamespace(digest=digest), tec_tac_session=trust, META={}, tec_tac_request_id=name)
    return user, trust, digest, request


def deny_rows_of(user):
    return AuditLog.objects.filter(action="deny", username=user.username)


agent = pick_agent()
if agent is None:
    raise SystemExit("skipped: the dev server has no agent to open a terminal on")

tag = uuid.uuid4().hex[:10]
issued_tickets = []  # every ticket minted here, so the finally can clear each cache key
print("sweeping the leftovers of earlier runs")
remove_probe_rows(PREFIX)
try:
    user, trust, digest, request = make_signin("", tag, can_use_terminal=True)

    def new_ticket():
        """Issue an agent-terminal ticket. Synchronous: it reads the database and writes rows, so never call it from an async def."""
        result = tw.issue_ticket(request, module_id="remote-background", kind="agent-terminal", agent_id=agent.agent_id)
        issued_tickets.append(result["ticket"])
        return result

    # What an async leg uses. Django refuses database access from a running event loop (SynchronousOnlyOperation), so the call runs in
    # the thread that called async_to_sync, as channels' database_sync_to_async does.
    new_ticket_async = sync_to_async(new_ticket, thread_sensitive=True)

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

        foreign = (await new_ticket_async())["ticket"]
        connected, code = await open_and_close(socket_path(foreign), headers_for("localhost", "https://evil.example.invalid"))
        must(not connected and code == 4003, "a foreign Origin on a fresh ticket closes 4003")

        whitelist = list(getattr(settings, "CORS_ORIGIN_WHITELIST", None) or [])
        if whitelist:
            split = (await new_ticket_async())["ticket"]
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

    # The refusal step. An agent that is not in the probe user's scope (here: one that does not exist, which Core answers with the same
    # text) is refused with object_not_found and ONE deny row. The refusal is caught here, so it can never end the run.
    denied_before = deny_rows_of(user).count()
    try:
        tw.issue_ticket(request, module_id="remote-background", kind="agent-terminal", agent_id=f"{PREFIX}no-such-agent")
    except tw.TicketRefusal as refusal:
        must(refusal.code == "object_not_found" and refusal.status == 404, f"an agent outside the user's scope is refused 404 object_not_found (got {refusal.status} {refusal.code})")
    else:
        raise AssertionError("an agent outside the user's scope must be refused, and a ticket was issued")
    deny_new = deny_rows_of(user).count() - denied_before
    must(deny_new == 1, f"exactly one deny row for the refusal, got {deny_new}")
    deny_row = deny_rows_of(user).order_by("-pk").first()
    must(deny_row.debug_info.get("operation_context", {}).get("server_provenance") == "tactical-websocket"
         and deny_row.debug_info.get("operation_context", {}).get("core_refusal") is True, "the deny row is Core's own refusal row")

    # The stale-connection check. The ticket is minted first, because the break leaves this thread's connection unusable for one call.
    stale_ticket = new_ticket()["ticket"]
    how = break_this_threads_connection()
    print(f"stale-connection step: {how}")

    async def stale_leg():
        connected, code = await open_and_close(socket_path(stale_ticket), headers_for("localhost"))
        must(connected, f"after this thread's database connection was closed, a socket with a fresh ticket is accepted (code {code})")

    async_to_sync(stale_leg)()

    # ---------------------------------------------------------------------------------------------- AD-35: the server terminal
    su_user, su_trust, su_digest, su_request = make_signin("su", tag, superuser=True)
    server_ticket = None
    try:
        server_ticket = tw.issue_ticket(su_request, module_id="globalsettings", kind="server-terminal")
        issued_tickets.append(server_ticket["ticket"])
    except tw.TicketRefusal as refusal:
        if refusal.code not in ("websocket_owner_required", "server_terminal_disabled"):
            raise
        print(f"SKIP the server terminal ticket steps: Core answered {refusal.status} {refusal.code}. "
              "globalsettings must be an enabled core module and Tactical's server web terminal must be on (Global Settings, not hosted).")
    if server_ticket is not None:
        must(server_ticket["kind"] == "server-terminal" and server_ticket["path"] == socket_path(server_ticket["ticket"], "server-terminal"),
             "a throwaway superuser gets a server-terminal ticket as globalsettings, with the documented path")
        denied_before = deny_rows_of(user).count()
        try:
            tw.issue_ticket(request, module_id="globalsettings", kind="server-terminal")
        except tw.TicketRefusal as refusal:
            must(refusal.status == 403 and refusal.code == "superuser_required", f"a non-superuser is refused 403 superuser_required (got {refusal.status} {refusal.code})")
        else:
            raise AssertionError("a non-superuser must not get a server terminal ticket")
        must(deny_rows_of(user).count() - denied_before == 1, "exactly one deny row for the non-superuser")
    denied_before = deny_rows_of(su_user).count()
    try:
        tw.issue_ticket(su_request, module_id="remote-background", kind="server-terminal")
    except tw.TicketRefusal as refusal:
        must(refusal.status == 403 and refusal.code == "websocket_owner_required", f"another module (remote-background) is refused 403 websocket_owner_required (got {refusal.status} {refusal.code})")
    else:
        raise AssertionError("only globalsettings may ask for a server terminal ticket")
    if server_ticket is not None:
        must(deny_rows_of(su_user).count() - denied_before == 1, "exactly one deny row for the wrong module")

    server_route_installed = any(str(getattr(p, "pattern", "")) == tw.SERVER_ROUTE_PATTERN for p in ws_urlpatterns)
    if server_ticket is None:
        pass
    elif not SERVER_SOCKET:
        print("SKIP the server terminal socket step: it starts a real shell on this server. Set TECTAC_WS_PROBE_SERVER_TERMINAL=1 to run it.")
    elif not server_route_installed:
        print("SKIP the server terminal socket step: Core did not install ws/tfd/server-terminal/ (Tactical is hosted, in demo mode, or has TRMM_DISABLE_WEB_TERMINAL).")
    else:
        server_path = server_ticket["path"]

        async def server_leg():
            live = WsProbe(server_path, headers_for("localhost"))
            connected, _subprotocol = await live.connect()
            must(connected, "the server terminal socket accepts a valid ticket (a shell starts on accept)")
            # No input is ever sent. Tactical's own disconnect frame ends the shell straight away.
            await live.send_json_to({"action": "trmmcli.disconnect"})
            await live.disconnect()
            connected_again, code_again = await open_and_close(server_path, headers_for("localhost"))
            must(not connected_again and code_again == 4401, "a second use of the server terminal ticket is refused 4401")

        async_to_sync(server_leg)()
        server_starts = AuditLog.objects.filter(action="custom:server-terminal-start", username=su_user.username)
        must(server_starts.count() == 1, f"exactly one custom:server-terminal-start row, got {server_starts.count()}")
        server_row = server_starts.first()
        must(server_row.debug_info.get("module_id") == "globalsettings"
             and server_row.debug_info.get("operation_context", {}).get("websocket") == "server-terminal", "the row names globalsettings and the server-terminal kind")

    # ---------------------------------------------------------------------------------------------- AD-35: input is activity (last: it ends the session)
    idle_minutes = int(session_security.get_effective_policy().get("idle_timeout_minutes") or 0)
    if idle_minutes < 4:
        print(f"SKIP the activity steps: the idle policy is {idle_minutes} minutes; the probe needs at least 4 and changes no policy.")
    else:
        value = {"user_id": user.pk, "trust_id": trust.pk, "knox_digest": digest}

        def sign_in_row():
            return TecTacSessionTrust.objects.get(pk=trust.pk)

        def backdate(minutes):
            then = timezone.now() - timedelta(minutes=minutes)
            TecTacSessionTrust.objects.filter(pk=trust.pk).update(
                last_activity_at=then, last_seen_at=then, idle_expires_at=then + timedelta(minutes=idle_minutes))

        backdate(idle_minutes // 2)
        before = sign_in_row()
        must(tw.session_refusal(value) is None, "the sign-in holds half way through its idle limit")
        output_only = sign_in_row()
        must(output_only.idle_expires_at == before.idle_expires_at and output_only.last_activity_at == before.last_activity_at,
             "output alone does not refresh the sign-in's idle timer (no input time is handed over)")
        must(tw.session_refusal(value, timezone.now()) is None, "input at this moment is accepted")
        after_input = sign_in_row()
        must(after_input.idle_expires_at > before.idle_expires_at and after_input.last_activity_at > before.last_activity_at,
             "input refreshes the sign-in's last_activity_at and idle_expires_at")
        backdate(idle_minutes + 1)
        must(tw.session_refusal(value, timezone.now()) == "session_idle_timeout", "an input after the idle limit passed is refused session_idle_timeout")
        must(sign_in_row().revoked, "the idle limit ended the sign-in row, as a REST idle timeout does")
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
print("tactical-websocket-runtime-1.17.34: ok")
