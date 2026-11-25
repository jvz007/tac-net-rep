#!/usr/bin/env python3
"""1.18.47 regression (C2a): issue_tunnel_ticket of core.probe_transport 1.1.0 and the ticket store.

Covered: a ticket is 43 URL-safe characters, only its SHA-256 is in the cache, it expires at 60 seconds and works once (a second redeem and a
concurrent pair give exactly one winner); the launch link is tectac-console://open?host=<host>&ticket=<ticket>; the refusals (no signed-in
request, no Knox digest, permission missing, probe offline, bad spec, idle_s and cap_s out of range, session_exists); 10 tickets a minute per
engineer; 3 sessions per engineer, 5 per probe and 50 in all; a leaked slot heals after its expiry; no shared cache refuses (unavailable) and
issues nothing; every refusal writes one deny row; the ticket never appears in a row, a cache key or a log record; a caller that is not
networkprobe, or a module_id that is not the verified caller, is denied.
"""
from __future__ import annotations

import importlib.util
import logging
import re
import threading
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.probe_transport").addHandler(_Capture())
logging.getLogger("tec_tac.probe_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.probe_transport").propagate = False
TICKETS: list = []


def fresh():
    reset()
    H.set_owner()
    H.probe_online()


def issued(spec=None, request=None):
    result = H.issue(spec, request)
    if result.get("ticket"):
        TICKETS.append(result["ticket"])
    return result


def refusal_rows():
    return [a for a in AUDITS if a["action"] == "custom:probe-tunnel-refused"]


def end_all():
    for sid in list(tun.read_index()):
        must(pt.end_tunnel("networkprobe", sid, "engineer")["outcome"] == "ok", "end " + sid)


# ---------------------------------------------------------------- a ticket
fresh()
sid = H.new_session_id()
result = issued(H.tunnel_spec(session_id=sid, target_label="srv-9"))
must(result["outcome"] == "ok" and result["session_id"] == sid and result["expires_in"] == 60, result)
ticket = result["ticket"]
must(re.fullmatch(r"[A-Za-z0-9_-]{43}", ticket), "43 URL-safe characters")
must(result["launch_url"] == f"tectac-console://open?host=tec.example.com&ticket={ticket}", result["launch_url"])
key = tun.ticket_key(ticket)
must(key.startswith("tec-tac:pt:ticket:") and not key.startswith("tec-tac:wsticket"), "its own prefix, not the terminal ticket's")
must(CACHE.timeouts[key] == 60, "the ticket lives 60 seconds")
must(not any(ticket in k or ticket in repr(v) for k, v in CACHE.data.items()), "the raw ticket is nowhere in the cache")
stored = CACHE.data[key]
for field in ("user_id", "trust_id", "knox_digest", "session_id", "probe_id", "module_id", "permission", "idle_s", "cap_s", "expires_at"):
    must(field in stored, "ticket value has " + field)
must(stored["idle_s"] == 900 and stored["cap_s"] == 14400 and stored["module_id"] == "networkprobe" and stored["session_id"] == sid, stored)
must(not tun.TICKET_PREFIX.startswith(pt.GROUP_PREFIX) and tun.GROUP_PREFIX != pt.GROUP_PREFIX and not tun.GROUP_PREFIX.startswith("tectac-pn-"), "own group prefix")
ok_rows = [a for a in AUDITS if a["action"] == "custom:probe-tunnel-ticket"]
must(len(ok_rows) == 1 and ok_rows[0]["probe_id"] == H.PROBE and ok_rows[0]["metadata"]["engineer"] == H.ENGINEER
     and ok_rows[0]["metadata"]["session_id"] == sid and "target" not in ok_rows[0]["metadata"] and ok_rows[0]["refusal"] is False, ok_rows)
# the slot is held from issue
must(sid in tun.read_index(), "slot held from ticket issue")
must(pt.tunnel_status("networkprobe", [sid])["sessions"][sid]["state"] == "pending", "pending until the Console connects")

# ---------------------------------------------------------------- works once, expires at 60 seconds
must(tun.redeem_ticket("x" * 43) is None and tun.redeem_ticket("short") is None and tun.redeem_ticket(None) is None, "unknown and malformed")
value = tun.redeem_ticket(ticket)
must(value is not None and value["session_id"] == sid, "first redeem")
must(tun.redeem_ticket(ticket) is None, "second redeem")
fresh()
sid2 = H.new_session_id()
ticket2 = issued(H.tunnel_spec(session_id=sid2))["ticket"]
WALL[0] += 61
must(tun.redeem_ticket(ticket2) is None, "expired at 60 seconds")
fresh()
ticket3 = issued()["ticket"]
winners: list = []
barrier = threading.Barrier(8)


def racer():
    barrier.wait()
    winners.append(tun.redeem_ticket(ticket3) is not None)


threads = [threading.Thread(target=racer) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
must(sum(winners) == 1, winners)

# ---------------------------------------------------------------- refusals, each with one deny row and no ticket
fresh()
cases = [
    ("no session", {"request": H.engineer_request(session=False)}, "denied", "authenticated_request_required"),
    ("anonymous", {"request": H.engineer_request(authenticated=False)}, "denied", "authenticated_request_required"),
    ("no knox digest", {"request": H.engineer_request(digest="")}, "denied", "tactical_session_required"),
    ("bad probe id", {"spec": H.tunnel_spec(probe_id="bad id!")}, "invalid", "invalid_spec"),
    ("session id not a uuid4", {"spec": H.tunnel_spec(session_id="1" * 36)}, "invalid", "invalid_spec"),
    ("session id uuid1", {"spec": H.tunnel_spec(session_id=str(uuid.uuid1()))}, "invalid", "invalid_spec"),
    ("upper-case uuid", {"spec": H.tunnel_spec(session_id=H.new_session_id().upper())}, "invalid", "invalid_spec"),
    ("permission of another module", {"spec": H.tunnel_spec(permission="alerts.read")}, "invalid", "invalid_spec"),
    ("permission with spaces", {"spec": H.tunnel_spec(permission="networkprobe.tunnel x")}, "invalid", "invalid_spec"),
    ("unknown key", {"spec": {**H.tunnel_spec(), "port": 22}}, "invalid", "invalid_spec"),
    ("not a dict", {"spec": "x"}, "invalid", "invalid_spec"),
    ("idle too low", {"spec": H.tunnel_spec(idle_s=59)}, "invalid", "invalid_spec"),
    ("idle too high", {"spec": H.tunnel_spec(idle_s=901)}, "invalid", "invalid_spec"),
    ("idle a bool", {"spec": H.tunnel_spec(idle_s=True)}, "invalid", "invalid_spec"),
    ("cap too low", {"spec": H.tunnel_spec(cap_s=59)}, "invalid", "invalid_spec"),
    ("cap too high", {"spec": H.tunnel_spec(cap_s=14401)}, "invalid", "invalid_spec"),
    ("idle a float", {"spec": H.tunnel_spec(cap_s=100.5)}, "invalid", "invalid_spec"),
]
for label, kwargs, outcome, code in cases:
    before = len(refusal_rows())
    got = issued(kwargs.get("spec"), kwargs.get("request"))
    must(got["outcome"] == outcome and got["code"] == code and "ticket" not in got, (label, got))
    must(len(refusal_rows()) == before + 1 and refusal_rows()[-1]["metadata"]["reason"] == code and refusal_rows()[-1]["refusal"] is True, label)
must(not [k for k in CACHE.data if k.startswith(tun.TICKET_PREFIX)] and tun.read_index() == {}, "nothing was stored or held by a refusal")
for edge in ({"idle_s": 60, "cap_s": 60}, {"idle_s": 900, "cap_s": 14400}):
    must(issued(H.tunnel_spec(**edge))["outcome"] == "ok", edge)
end_all()
H.PERMS["granted"] = False
got = issued()
must(got["outcome"] == "denied" and got["code"] == "permission_missing", got)
H.PERMS["granted"] = True
CACHE.data.pop(pt.presence_key(H.PROBE))
got = issued()
must(got["outcome"] == "probe_offline" and got["code"] == "probe_offline", got)
rate_keys = [k for k in CACHE.data if k.startswith(tun.TICKET_RATE_PREFIX)]
H.probe_online()
before = len(rate_keys)
# an offline probe spends no slot and no rate count: the offline refusal came before the counter
must(len([k for k in CACHE.data if k.startswith(tun.TICKET_RATE_PREFIX)]) == before and tun.read_index() == {}, "an offline probe spends nothing")
# session_exists: one ticket per session
sid = H.new_session_id()
must(issued(H.tunnel_spec(session_id=sid))["outcome"] == "ok", "first ticket")
again = issued(H.tunnel_spec(session_id=sid))
must(again["outcome"] == "session_exists" and again["code"] == "session_exists", again)
pt.end_tunnel("networkprobe", sid, "engineer")
again = issued(H.tunnel_spec(session_id=sid))
must(again["outcome"] == "session_exists", "an ended session id is not reused (no resume)")

# ---------------------------------------------------------------- 10 tickets a minute per engineer
fresh()
for n in range(10):
    got = issued()
    must(got["outcome"] == "ok", (n, got))
    end_all()
over = issued()
must(over["outcome"] == "rate_limited" and over["code"] == "rate_limited", over)
H.USERS[77] = H.SimpleNamespace(pk=77, is_active=True)
must(issued(request=H.engineer_request(user_id=77))["outcome"] == "ok", "another engineer is not limited")
end_all()
WALL[0] += 60
must(issued()["outcome"] == "ok", "the next minute is free")
rate_key = [k for k in CACHE.data if k.startswith(tun.TICKET_RATE_PREFIX + str(H.ENGINEER) + ":")]
must(rate_key and all(k.startswith("tec-tac:pt:tkrate:") for k in rate_key), "rate key shape")

# ---------------------------------------------------------------- 3 per engineer, 5 per probe, 50 in all
fresh()
for n in range(3):
    must(issued()["outcome"] == "ok", n)
fourth = issued()
must(fourth["outcome"] == "limit_reached" and fourth["code"] == "sessions_per_engineer", fourth)
fresh()
for n in range(5):
    H.USERS[100 + n] = H.SimpleNamespace(pk=100 + n, is_active=True)
    must(issued(request=H.engineer_request(user_id=100 + n))["outcome"] == "ok", n)
H.USERS[200] = H.SimpleNamespace(pk=200, is_active=True)
sixth = issued(request=H.engineer_request(user_id=200))
must(sixth["outcome"] == "limit_reached" and sixth["code"] == "sessions_per_probe", sixth)
fresh()
for i in range(50):
    engineer, probe = 300 + i // 3, f"probe-{i // 5:04d}-aaaa"
    H.USERS[engineer] = H.SimpleNamespace(pk=engineer, is_active=True)
    H.probe_online(probe)
    got = issued(H.tunnel_spec(probe_id=probe), H.engineer_request(user_id=engineer))
    must(got["outcome"] == "ok", (i, got))
must(len(tun.read_index()) == 50, "fifty live sessions")
H.USERS[999] = H.SimpleNamespace(pk=999, is_active=True)
H.probe_online("probe-9999-zzzz")
last = issued(H.tunnel_spec(probe_id="probe-9999-zzzz"), H.engineer_request(user_id=999))
must(last["outcome"] == "limit_reached" and last["code"] == "sessions_total", last)
# freeing one slot lets the next in
first = next(iter(tun.read_index()))
pt.end_tunnel("networkprobe", first, "admin")
must(issued(H.tunnel_spec(probe_id="probe-9999-zzzz"), H.engineer_request(user_id=999))["outcome"] == "ok", "a freed slot is reused")

# ---------------------------------------------------------------- a leaked slot heals after its expiry
fresh()
for n in range(3):
    must(issued()["outcome"] == "ok", n)
must(issued()["outcome"] == "limit_reached", "full")
WALL[0] += tun.PENDING_SLOT_SECONDS - 1
must(issued()["outcome"] == "limit_reached", "not yet")
WALL[0] += 2
healed = issued()
must(healed["outcome"] == "ok", ("a pending slot heals after its expiry", healed))
must(len(tun.read_index()) == 1, "the expired entries are gone")

# ---------------------------------------------------------------- no shared cache: refuse, issue nothing


class NoSharedCache(H.FakeCache):
    """Presence and counters work, but the session index, the session records and the tickets are not kept (a dummy cache)."""

    def add(self, key, value, timeout=None):
        if key.startswith(("tec-tac:pt:ticket:", "tec-tac:pt:tun")):
            return True
        return super().add(key, value, timeout)

    def set(self, key, value, timeout=None):
        if key.startswith("tec-tac:pt:tun"):
            return
        super().set(key, value, timeout)


fresh()
real = H.sys.modules["django.core.cache"].cache
dummy = NoSharedCache()
H.sys.modules["django.core.cache"].cache = dummy
try:
    pt.set_presence(H.PROBE, "2026-11-25T08:00:00+00:00", "o", 3, 7)
    before = len(refusal_rows())
    got = issued()
    must(got["outcome"] == "unavailable" and got["code"] == "unavailable" and "ticket" not in got, got)
    must(len(refusal_rows()) == before + 1, "a deny row")
    must(not any(k.startswith(tun.TICKET_PREFIX) for k in dummy.data), "no ticket was left behind")
finally:
    H.sys.modules["django.core.cache"].cache = real
fresh()
CACHE.down = True
got = issued()
must(got["outcome"] == "unavailable", got)
CACHE.down = False

# ---------------------------------------------------------------- only networkprobe, and only for itself
fresh()
H.CALLER["module_id"] = "alerts"
must(pt.issue_tunnel_ticket(H.engineer_request(), "alerts", H.tunnel_spec()) == {"outcome": "denied"}, "another module")
H.CALLER["module_id"] = None
must(pt.issue_tunnel_ticket(H.engineer_request(), "networkprobe", H.tunnel_spec()) == {"outcome": "denied"}, "an unverifiable caller")
H.CALLER["module_id"] = "networkprobe"
got = pt.issue_tunnel_ticket(H.engineer_request(), "alerts", H.tunnel_spec())
must(got["outcome"] == "denied" and "verified" in got["reason"], got)
must(not [k for k in CACHE.data if k.startswith(tun.TICKET_PREFIX)] and not [a for a in AUDITS if a["action"] == "custom:probe-tunnel-ticket"], "nothing was issued")
provider = pt._PROVIDER
through = provider.issue_tunnel_ticket(request=H.engineer_request(), module_id="networkprobe", spec=H.tunnel_spec())
must(through["outcome"] == "ok", "through the provider")
TICKETS.append(through["ticket"])

# ---------------------------------------------------------------- the ticket never appears in a row or a log record
blob = repr(AUDITS) + "\n".join(LOGS)
for ticket in TICKETS:
    must(ticket not in blob, "a ticket leaked into an audit row or a log record")
must(TICKETS, "tickets were issued")
print("PASS probe tunnel ticket 1.18.47")
