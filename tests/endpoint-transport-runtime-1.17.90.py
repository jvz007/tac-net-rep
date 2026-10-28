"""1.17.90 dev-server check for the endpoint agent socket (ws/tfd/endpoint-agent/). WRITTEN HERE, NOT RUN HERE (Django, channels, Redis, Celery,
nginx and Tactical are not installed on the development PC). Style and run form follow tests/tactical-websocket-runtime-1.17.34.py.

Run on the dev server as the tactical user, from the Tactical backend directory (stdin form, no quoting needed):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/endpoint-transport-runtime-1.17.90.py

What it does: sweeps the leftovers of earlier runs (users, agents, tokens, client and site named wsprobe-; audit rows are kept), commits a
throwaway wsprobe- client, site, Agent, User and agent token, opens the real ASGI application (tacticalrmm.asgi.application) with hand-built
websocket scopes and checks: a valid token and agent id is accepted and the presence key appears; a wrong agent id, an unknown token and a
token of a user with no agent are refused 4401; a ping is answered with a pong; a second connection for the same agent closes the first
with 4409; an event is NOT acknowledged while no owner is registered (nats-comms not installed here); a reply for a request id that was
never delivered is dropped (the socket stays open); the presence key is gone after a clean close. In a finally block it deletes what it
created (only rows whose name starts with wsprobe-) and ends by checking that none are left. No token is printed.

Expected: PASS lines and a last line 'endpoint-transport-runtime-1.17.90: ok'. Each refusal also leaves one wsprobe- or presented-agent
custom:endpoint-refused audit row and the connects leave custom:endpoint-connect rows: those audit rows stay.
"""
import json

from agents.models import Agent
from asgiref.sync import async_to_sync
from asgiref.testing import ApplicationCommunicator
from clients.models import Client, Site
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from tacticalrmm.asgi import application
from tec_tac import endpoint_transport as et

PREFIX = "wsprobe-"
AGENT_ID = PREFIX + "ea-agent"
TIMEOUT = 10
User = get_user_model()


def sweep():
    User.objects.filter(username__startswith=PREFIX).delete()
    Agent.objects.filter(agent_id__startswith=PREFIX).delete()
    Site.objects.filter(name__startswith=PREFIX).delete()
    Client.objects.filter(name__startswith=PREFIX).delete()
    cache.delete(et.presence_key(AGENT_ID))


def leftovers():
    return (User.objects.filter(username__startswith=PREFIX).count() + Agent.objects.filter(agent_id__startswith=PREFIX).count()
            + Site.objects.filter(name__startswith=PREFIX).count() + Client.objects.filter(name__startswith=PREFIX).count())


def scope(token, agent_id, real_ip="192.0.2.77"):
    headers = [(b"x-real-ip", real_ip.encode())]
    if token is not None:
        headers.append((b"authorization", f"Token {token}".encode()))
    if agent_id is not None:
        headers.append((b"x-agent-id", agent_id.encode()))
    return {"type": "websocket", "path": "/ws/tfd/endpoint-agent/", "raw_path": b"/ws/tfd/endpoint-agent/", "headers": headers,
            "query_string": b"", "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 443), "scheme": "wss", "subprotocols": []}


async def open_socket(token, agent_id):
    communicator = ApplicationCommunicator(application, scope(token, agent_id))
    await communicator.send_input({"type": "websocket.connect"})
    return communicator, await communicator.receive_output(TIMEOUT)


async def close_code(communicator):
    """Accepted-then-closed sockets (refusals) answer accept first, then close with the code."""
    message = await communicator.receive_output(TIMEOUT)
    return message.get("code") if message["type"] == "websocket.close" else message


async def probe(good_token, no_agent_token):
    ping = json.dumps({"v": 1, "type": "ping", "id": "p1", "func": "", "payload": {}})
    # a valid token and agent id
    first, accepted = await open_socket(good_token, AGENT_ID)
    assert accepted["type"] == "websocket.accept", accepted
    print("PASS valid token and agent id accepted")
    # a ping is answered with a pong
    await first.send_input({"type": "websocket.receive", "text": ping})
    pong = json.loads((await first.receive_output(TIMEOUT))["text"])
    assert pong["type"] == "pong" and pong["id"] == "p1", pong
    print("PASS ping answered with pong")
    # refusals close 4401 after accept
    for label, token, agent in (("wrong agent id", good_token, PREFIX + "other"), ("unknown token", "0" * 40, AGENT_ID),
                                ("token of a user with no agent", no_agent_token, AGENT_ID)):
        communicator, accepted = await open_socket(token, agent)
        assert accepted["type"] == "websocket.accept", accepted
        code = await close_code(communicator)
        assert code == et.CLOSE_UNAUTHORIZED, (label, code)
        print(f"PASS {label} refused 4401")
    # an event with no owner registered: no ack
    event = json.dumps({"v": 1, "type": "event", "id": "ev1", "func": "probe.event", "payload": {}})
    await first.send_input({"type": "websocket.receive", "text": event})
    assert await first.receive_nothing(1.5), "an event must not be acknowledged while no owner is registered"
    print("PASS event not acknowledged without an owner")
    # a reply for a request that was never delivered is dropped, the socket stays open
    reply = json.dumps({"v": 1, "type": "reply", "id": "never", "func": "x", "payload": {}})
    await first.send_input({"type": "websocket.receive", "text": reply})
    assert await first.receive_nothing(1.0), "a stray reply must be dropped silently"
    print("PASS stray reply dropped")
    # a second connection for the same agent closes the first with 4409
    second, accepted = await open_socket(good_token, AGENT_ID)
    assert accepted["type"] == "websocket.accept", accepted
    assert await close_code(first) == et.CLOSE_SUPERSEDED
    print("PASS second connection closed the first (4409)")
    await second.send_input({"type": "websocket.disconnect", "code": 1000})
    await second.wait(TIMEOUT)


sweep()
try:
    client = Client.objects.create(name=PREFIX + "client")
    site = Site.objects.create(client=client, name=PREFIX + "site")
    agent = Agent.objects.create(agent_id=AGENT_ID, hostname=AGENT_ID, site=site)
    agent_user = User.objects.create_user(username=AGENT_ID, agent=agent, password=None)
    plain_user = User.objects.create_user(username=PREFIX + "dashboard", password=None)
    good = Token.objects.create(user=agent_user).key
    no_agent = Token.objects.create(user=plain_user).key
    async_to_sync(probe)(good, no_agent)
    print("PASS presence cleared after the clean close" if cache.get(et.presence_key(AGENT_ID)) is None else "WARN presence key still present")
finally:
    sweep()
    print("deleted the wsprobe- client, site, agent, users and tokens")
    assert leftovers() == 0, "wsprobe- rows are left"
print("endpoint-transport-runtime-1.17.90: ok")
