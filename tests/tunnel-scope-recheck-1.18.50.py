#!/usr/bin/env python3
"""1.18.50 regression: Core ends a tunnel session when its opener loses access to the probe's site (core.probe_transport 1.2.0), on the in-memory
harness (tests/probe_transport_harness.py). Django, Tactical's models, Redis and uvicorn are not on this PC: tec_tac.resources.get_site is a stub
that answers from a table of what each person may see, the real probe_tunnel.py and probe_tunnel_consumer.py do the rest.

site_id in the ticket spec: a positive int, not a bool; absent means None and no Core scope check (the 1.18.49 behaviour). The ticket is refused
out_of_scope (one deny row, no ticket, no slot); the Console connect is refused 4401 scope_lost; a live session ends ended_by core with detail
scope_lost at the first re-check after the scope is removed, both sockets closed, one end row, one tunnel.closed. A fault while checking ends it
check_failed (fail closed). A session still in scope is untouched. Permission and account checks run first and end as before. The status row
carries site_id.
set_tunnel_site: owner only, only that probe's and only the caller's live sessions change, an ended one is skipped, the record holds the new site.
The access marker: a marker newer than the one the Console saw brings the re-check forward to the next 5 second tick; an older one does not; a
pass is not repeated; a transient failure retries after 30 seconds.
"""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, ae, must, reset, CACHE, AUDITS, WALL, LAYER, CELERY, run = H.pt, H.tun, H.ae, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.LAYER, H.CELERY, H.run
frame, Clock, SITES = H.frame, H.Clock, H.SITES
for name in ("tec_tac.probe_transport", "tec_tac.access_events"):
    logging.getLogger(name).addHandler(logging.NullHandler())
    logging.getLogger(name).propagate = False  # the fault cases log a warning on purpose
DATA = 2


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.add_probe(H.PROBE2, H.KEY2, 3, 7)
    H.probe_online()
    H.probe_online(H.PROBE2)
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


def closed_events():
    return [(task, args) for task, args in CELERY.sent if args[1]["func"] == "tunnel.closed"]


def ended(sid):
    return CACHE.data.get(tun.end_key(sid))


async def pair(site_id=7, clock=None, **spec_over):
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    over = dict(spec_over)
    if site_id is not None:
        over["site_id"] = site_id
    got = H.issue(H.tunnel_spec(session_id=sid, **over))
    must(got["outcome"] == "ok", got)
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    must(not console.closed and not probe.closed, (console.closed, probe.closed))
    return console, probe, sid, clock


async def finish(console, probe):
    await console.disconnect(1000)
    await H.settle(console)
    await H.settle(probe)


# ---------------------------------------------------------------- site_id in the spec
fresh()
for bad in (True, False, 0, -1, "7", 7.0, [7], {"id": 7}):
    got = H.issue(H.tunnel_spec(site_id=bad))
    must(got["outcome"] == "invalid" and got["code"] == "invalid_spec", (bad, got))
must(tun.read_index() == {} and not [k for k in CACHE.data if k.startswith((tun.TICKET_PREFIX, tun.SESSION_PREFIX))], "a bad site_id spends nothing")
got = H.issue(H.tunnel_spec(session_id=(sid_none := H.new_session_id())))
must(got["outcome"] == "ok" and CACHE.data[tun.session_key(sid_none)]["site_id"] is None, "absent means None")
got = H.issue(H.tunnel_spec(session_id=(sid_seven := H.new_session_id()), site_id=7))
must(got["outcome"] == "ok" and CACHE.data[tun.session_key(sid_seven)]["site_id"] == 7, "a valid site_id is stored in the record")
must(tun._clean_spec(H.tunnel_spec(site_id=7))["site_id"] == 7 and tun._clean_spec(H.tunnel_spec())["site_id"] is None, "_clean_spec")


# ---------------------------------------------------------------- the ticket
def case_issue():
    fresh()
    SITES["visible"][H.ENGINEER] = set()
    before = len(rows("custom:probe-tunnel-refused"))
    got = H.issue(H.tunnel_spec(site_id=7))
    must(got["outcome"] == "denied" and got["code"] == "out_of_scope" and "ticket" not in got and "launch_url" not in got, got)
    must(got["message"] == tun.REFUSAL_MESSAGES["out_of_scope"], got)
    refusals = rows("custom:probe-tunnel-refused")
    must(len(refusals) == before + 1 and refusals[-1]["metadata"]["reason"] == "out_of_scope" and refusals[-1]["refusal"] is True, "one deny row")
    must(tun.read_index() == {} and not [k for k in CACHE.data if k.startswith((tun.TICKET_PREFIX, tun.SESSION_PREFIX))], "no ticket, no record, no slot")
    must(not [k for k in CACHE.data if k.startswith(tun.TICKET_RATE_PREFIX)], "no ticket rate spent")
    must(SITES["calls"] == [(H.ENGINEER, 7)], "the engineer's own scope was asked, for the named site")
    # Tactical's own refusal reads the same way
    SITES["mode"] = "denied"
    got = H.issue(H.tunnel_spec(site_id=7))
    must(got["outcome"] == "denied" and got["code"] == "out_of_scope", got)
    # a fault while asking fails closed
    SITES["mode"] = "fault"
    got = H.issue(H.tunnel_spec(site_id=7))
    must(got["outcome"] == "unavailable" and got["code"] == "unavailable", got)
    must(tun.read_index() == {}, "nothing was started")
    # the permission is checked first
    SITES["mode"] = "normal"
    H.PERMS["granted"] = False
    SITES["calls"].clear()
    got = H.issue(H.tunnel_spec(site_id=7))
    must(got["code"] == "permission_missing" and not SITES["calls"], "the permission check runs before the scope check")
    H.PERMS["granted"] = True
    # in scope: the ticket is issued
    SITES["visible"][H.ENGINEER] = {7}
    got = H.issue(H.tunnel_spec(site_id=7))
    must(got["outcome"] == "ok", got)
    # no site_id: no scope check at all
    SITES["visible"][H.ENGINEER] = set()
    SITES["calls"].clear()
    got = H.issue(H.tunnel_spec())
    must(got["outcome"] == "ok" and not SITES["calls"], "without site_id nothing is asked (1.18.49)")


case_issue()


# ---------------------------------------------------------------- the connect
async def case_connect():
    for label, setup, reason in (
        ("scope removed after the ticket", lambda: SITES["visible"].update({H.ENGINEER: set()}), "scope_lost"),
        ("another site only", lambda: SITES["visible"].update({H.ENGINEER: {99}}), "scope_lost"),
        ("a fault while asking", lambda: SITES.update(mode="fault"), "check_failed"),
    ):
        fresh()
        sid = H.new_session_id()
        ticket = H.issue(H.tunnel_spec(session_id=sid, site_id=7))["ticket"]
        setup()
        c = H.make_console(ticket)
        await c.connect()
        await H.settle(c)
        must(c.accepted and c.closed == [4401] and c.close_reasons == [reason], (label, c.closed, c.close_reasons))
        must(not tun.side_attached(sid, "console"), label + ": the side was not taken")
    # no site_id: an engineer with no sites still connects, exactly as in 1.18.49
    fresh()
    SITES["visible"][H.ENGINEER] = set()
    sid = H.new_session_id()
    c = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"])
    await c.connect()
    await H.settle(c)
    must(c.accepted and not c.closed and not SITES["calls"], "no site_id, no scope check")


run(case_connect())


# ---------------------------------------------------------------- a live session at the 5-minute re-check
async def case_recheck():
    # the scope is removed: the first re-check ends it, ended_by core, detail scope_lost
    console, probe, sid, clock = await pair()
    clock.now += 299
    must(await console._tick() is True, "not yet 5 minutes")
    SITES["visible"][H.ENGINEER] = set()
    clock.now += 2
    must(await console._tick() is False, "the re-check ends it")
    marker = ended(sid)
    must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "scope_lost", marker)
    must(console.close_reasons[-1] == "ended_by_core" and probe.close_reasons[-1] == "ended_by_core", (console.close_reasons, probe.close_reasons))
    await finish(console, probe)
    end_rows = rows("custom:probe-tunnel-end")
    must(len(end_rows) == 1 and end_rows[0]["metadata"]["detail"] == "scope_lost" and end_rows[0]["metadata"]["reason"] == "ended_by_core", end_rows)
    must(len(closed_events()) == 1 and closed_events()[0][1][1]["payload"]["reason"] == "ended_by_core", closed_events())
    # a fault while asking ends it check_failed (fail closed)
    console, probe, sid, clock = await pair()
    SITES["mode"] = "fault"
    clock.now += 301
    must(await console._tick() is False and ended(sid)["detail"] == "check_failed", ended(sid))
    await finish(console, probe)
    must(len(rows("custom:probe-tunnel-end")) == 1, "one end row")
    # still in scope: untouched, and asked each time
    console, probe, sid, clock = await pair()
    clock.now += 301
    must(await console._tick() is True and ended(sid) is None, "a session still in scope is untouched")
    must(SITES["calls"][-1] == (H.ENGINEER, 7), "the re-check asked about the session's site")
    # permission and account end as before, and the site is not asked
    for label, setup, detail in (
        ("permission removed", lambda: H.PERMS.update(granted=False), "permission_missing"),
        ("sign-in revoked", lambda: H.SIGNIN.update(refusal="session_revoked"), "session_revoked"),
        ("user disabled", lambda: H.SIGNIN.update(refusal="user_unavailable"), "user_unavailable"),
        ("module disabled", lambda: H.REGISTRY.update(enabled=False), "module_disabled"),
    ):
        console, probe, sid, clock = await pair()
        setup()
        SITES["calls"].clear()
        clock.now += 301
        must(await console._tick() is False and ended(sid)["detail"] == detail, (label, ended(sid)))
        must(not SITES["calls"], label + ": the account check answered first")
    # no site_id: 1.18.49 exactly, whatever the engineer's sites are
    console, probe, sid, clock = await pair(site_id=None)
    SITES["visible"][H.ENGINEER] = set()
    SITES["calls"].clear()
    clock.now += 301
    must(await console._tick() is True and ended(sid) is None and not SITES["calls"], "no site_id: no scope check")
    must(CACHE.data[tun.session_key(sid)]["site_id"] is None, "the record holds None")
    # the probe being offline is still told as before when the scope holds
    console, probe, sid, clock = await pair()
    CACHE.data.pop(tun.side_key(sid, "probe"))
    CACHE.data.pop(pt.presence_key(H.PROBE))
    clock.now += 301
    must(await console._tick() is False and ended(sid)["reason"] == "probe_offline", "probe_offline as before")


run(case_recheck())


# ---------------------------------------------------------------- the status row
async def case_status():
    _console, _probe, sid, _clock = await pair(site_id=7)
    rows_ = tun.status_rows([sid, H.new_session_id()])
    must(rows_[sid]["site_id"] == 7 and rows_[sid]["state"] == "open", rows_[sid])
    unknown = next(v for k, v in rows_.items() if k != sid)
    must(unknown["state"] == "unknown" and unknown["site_id"] is None, unknown)
    got = pt.tunnel_status("networkprobe", [sid])
    must(got["outcome"] == "ok" and got["sessions"][sid]["site_id"] == 7, got)
    _console, _probe, sid, _clock = await pair(site_id=None)
    must(tun.status_rows([sid])[sid]["site_id"] is None, "None without a site")


run(case_status())


# ---------------------------------------------------------------- set_tunnel_site
async def two_probe_sessions():
    """Three live sessions: A and B on the first probe, C on the second; one engineer (the limit is 3)."""
    fresh()
    clock = Clock()
    made = {}
    for label, probe_id, key in (("A", H.PROBE, H.KEY), ("B", H.PROBE, H.KEY), ("C", H.PROBE2, H.KEY2)):
        sid = H.new_session_id()
        got = H.issue(H.tunnel_spec(session_id=sid, probe_id=probe_id, site_id=7))
        must(got["outcome"] == "ok", got)
        console = H.make_console(got["ticket"], clock=clock, channel=f"specific.console{label}")
        probe = H.make_tunnel_probe(sid, probe_id=probe_id, key=key, clock=clock, channel=f"specific.tprobe{label}")
        for consumer in (console, probe):
            await consumer.connect()
            await H.settle(consumer)
        must(not console.closed and not probe.closed, label)
        made[label] = (console, probe, sid)
    return made, clock


async def case_set_site():
    made, _clock = await two_probe_sessions()
    sids = {k: v[2] for k, v in made.items()}
    # the operation answers the owner only
    must(pt.set_tunnel_site.__module__ == "tec_tac.probe_transport" and "set_tunnel_site" in pt.OPERATIONS and "set_tunnel_site" in pt.TUNNEL_OPERATIONS_1_2_0, "published")
    for caller in ("someone-else", None):
        H.CALLER["module_id"] = caller
        got = pt.set_tunnel_site("networkprobe", H.PROBE, 8)
        must(got["outcome"] == "denied" and got["updated"] == [], (caller, got))
    H.CALLER["module_id"] = "networkprobe"
    for args, label in (
        (("someone-else", H.PROBE, 8), "module_id is not the caller"),
        (("networkprobe", "short", 8), "bad probe id"),
        (("networkprobe", 5, 8), "probe id not a string"),
        (("networkprobe", H.PROBE, True), "bool"),
        (("networkprobe", H.PROBE, 0), "zero"),
        (("networkprobe", H.PROBE, -3), "negative"),
        (("networkprobe", H.PROBE, "8"), "string"),
        (("networkprobe", H.PROBE, None), "None can never clear the check"),
    ):
        got = pt.set_tunnel_site(*args)
        must(got == {"outcome": "invalid", "updated": []}, (label, got))
    must(all(CACHE.data[tun.session_key(s)]["site_id"] == 7 for s in sids.values()), "an invalid call changed nothing")
    must(callable(pt._PROVIDER.set_tunnel_site), "the provider has it")
    # only that probe's live sessions, and only the caller's
    CACHE.data[tun.session_key(sids["B"])]["module_id"] = "other-module"
    got = pt.set_tunnel_site("networkprobe", H.PROBE, 8)
    must(got["outcome"] == "ok" and got["updated"] == [sids["A"]], got)
    must(CACHE.data[tun.session_key(sids["A"])]["site_id"] == 8, "A moved")
    must(CACHE.data[tun.session_key(sids["B"])]["site_id"] == 7, "another module's session is not touched")
    must(CACHE.data[tun.session_key(sids["C"])]["site_id"] == 7, "another probe's session is not touched")
    must(CACHE.timeouts[tun.session_key(sids["A"])] == tun._keep_seconds(), "the record keeps its lifetime")
    CACHE.data[tun.session_key(sids["B"])]["module_id"] = "networkprobe"
    # an ended session is skipped
    tun.end_session(sids["B"], "ended_by_engineer", "engineer")
    got = pt.set_tunnel_site("networkprobe", H.PROBE, 9)
    must(got["updated"] == [sids["A"]] and CACHE.data[tun.session_key(sids["B"])]["site_id"] == 7, got)
    # an offline-or-empty probe: nothing to update, still ok
    must(pt.set_tunnel_site("networkprobe", "probe-none-0009", 8) == {"outcome": "ok", "updated": []}, "no sessions")
    # a cache fault is unavailable, never an exception
    CACHE.down = True
    must(pt.set_tunnel_site("networkprobe", H.PROBE, 8)["outcome"] == "unavailable", "fault")
    CACHE.down = False


run(case_set_site())


async def case_move_ends_or_keeps():
    # the engineer cannot see the new site: the next tick ends the session, within about 5 seconds
    console, probe, sid, clock = await pair(site_id=7)
    WALL[0] += 10
    got = pt.set_tunnel_site("networkprobe", H.PROBE, 8)
    must(got["updated"] == [sid] and ae.changed_at(H.ENGINEER) == WALL[0], got)
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is False, "ended at the next tick, not at the 5-minute check")
    marker = ended(sid)
    must(marker["reason"] == "ended_by_core" and marker["detail"] == "scope_lost", marker)
    await finish(console, probe)
    must(len(rows("custom:probe-tunnel-end")) == 1 and len(closed_events()) == 1, "one row and one event")
    # the engineer can see the new site: the session stays, and the live record says so
    console, probe, sid, clock = await pair(site_id=7)
    SITES["visible"][H.ENGINEER] = {7, 8}
    WALL[0] += 10
    pt.set_tunnel_site("networkprobe", H.PROBE, 8)
    clock.now += tun.WATCH_TICK_SECONDS
    SITES["calls"].clear()
    must(await console._tick() is True and ended(sid) is None, "access to the new site: the session stays")
    must(SITES["calls"] == [(H.ENGINEER, 8)], "the re-check asked about the live site, not the one in the consumer's copy")
    SITES["visible"][H.ENGINEER] = {7}
    clock.now += 301
    must(await console._tick() is False and ended(sid)["detail"] == "scope_lost", "and the 5-minute check uses the live site too")


run(case_move_ends_or_keeps())


# ---------------------------------------------------------------- the access marker
async def case_marker():
    # a marker newer than the stamp: the re-check runs in the next tick and ends the session
    console, probe, sid, clock = await pair()
    must(console._access_seen == WALL[0] - 1, "the stamp is the time before the open decision, minus one")
    SITES["visible"][H.ENGINEER] = set()
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER], "role_scope")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is False and ended(sid)["detail"] == "scope_lost", "ended within one tick of the change")
    await finish(console, probe)
    # an older marker does not bring the re-check forward
    console, probe, sid, clock = await pair()
    CACHE.data[ae.marker_key(H.ENGINEER)] = WALL[0] - 100
    SITES["visible"][H.ENGINEER] = set()
    SITES["calls"].clear()
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and not SITES["calls"] and ended(sid) is None, "an old marker starts nothing")
    # somebody else's marker does not either
    ae.notify_access_changed([H.ENGINEER + 1], "role_scope")
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER + 1], "role_scope")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and not SITES["calls"], "another person's change starts nothing")
    # a change that touches nothing this person holds ends nothing, and the pass is not repeated
    console, probe, sid, clock = await pair()
    calls_before = len(H.SIGNIN["calls"])
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER], "role_permissions")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and ended(sid) is None and len(H.SIGNIN["calls"]) == calls_before + 1, "one re-check, and it passed")
    for _ in range(3):
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is True, "still open")
    must(len(H.SIGNIN["calls"]) == calls_before + 1, "the marker is not run again after a pass")
    must(console._next_recheck > clock.now, "the 5-minute schedule is back")
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER], "user_changed")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and len(H.SIGNIN["calls"]) == calls_before + 2, "a newer marker runs it once more")
    # permission lost: the same early re-check ends it with its own detail
    console, probe, sid, clock = await pair()
    H.PERMS["granted"] = False
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER], "role_permissions")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is False and ended(sid)["detail"] == "permission_missing", ended(sid))
    await finish(console, probe)
    # a transient failure of the re-check itself retries after 30 seconds
    console, probe, sid, clock = await pair()
    original, calls = tun.console_recheck, {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database down")
        return original(*args, **kwargs)

    tun.console_recheck = flaky
    try:
        WALL[0] += 10
        ae.notify_access_changed([H.ENGINEER], "role_scope")
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is True and calls["n"] == 1, "a transient failure keeps the session")
        must(console._next_recheck == clock.now + tun.RECHECK_RETRY_SECONDS, "retry in 30 seconds")
        clock.now += tun.RECHECK_RETRY_SECONDS - 1
        must(await console._tick() is True and calls["n"] == 1, "not before")
        clock.now += 1
        must(await console._tick() is True and calls["n"] == 2 and ended(sid) is None, "the retry ran and passed")
    finally:
        tun.console_recheck = original
    # a cache fault when reading the marker is not a reason to end anything
    console, probe, sid, clock = await pair()
    original = tun.access_changed_at
    tun.access_changed_at = lambda user_id: (_ for _ in ()).throw(RuntimeError("cache down"))
    try:
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is True and ended(sid) is None, "an unreadable marker ends nothing; the 5-minute check stays")
    finally:
        tun.access_changed_at = original


run(case_marker())

# ---------------------------------------------------------------- the files
source = (H.APP / "probe_tunnel.py").read_bytes()
must(b"\r" not in source, "probe_tunnel.py is LF")
consumer = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
must("tun.access_changed_at" in consumer and "_access_seen" in consumer and consumer.count("_access_seen") >= 4, "the Console reads the marker once a tick")
doc = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
for needle in ("Scope and access (1.2.0)", "set_tunnel_site", "site_id", "out_of_scope", "scope_lost", "core.access_events", "5 to 10 seconds", "queryset.update"):
    must(needle in doc, "the docs name " + needle)
print("PASS tunnel scope recheck 1.18.50")
