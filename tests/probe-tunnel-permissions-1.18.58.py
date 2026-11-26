#!/usr/bin/env python3
"""1.18.58 regression: issue_tunnel_ticket takes a list of permissions that must all hold (core.probe_transport 1.4.0, additive).

On the in-memory harness (tests/probe_transport_harness.py): the real probe_tunnel.py, probe_transport.py and probe_tunnel_consumer.py run. Covered:
the single `permission` form behaves as in 1.18.57 (answer, ticket value, record, audit row, connect, re-check); `permissions` of two codes issues
when the person holds both and is refused permission_missing (one deny row, no slot, no rate budget) when either is missing, in both orders; at
the connect a person who lost either permission is closed 4401 permission_missing; on a live session losing either permission ends it
ended_by_core (detail permission_missing, the detail the permission re-check has always used) at the next 5 second tick after the access marker
moves and at the 5 minute re-check, and losing an unrelated permission ends nothing; every invalid shape is invalid_spec; a record and ticket value
written the 1.18.57 way (no `permissions` key) still connect and re-check; a malformed list fails closed; the audit row carries permission_count and
never the list; CAPABILITY_VERSION is 1.4.0 and the earlier operations and answer shapes are unchanged; docs and contract rows name 1.4.0.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, ae, must, reset, CACHE, AUDITS, WALL, run = H.pt, H.tun, H.ae, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.run
Clock = H.Clock
ae._allow_caller_for_tests(__file__)  # the notify call below stands in for Core's own signal receivers

TUNNEL, CUSTOM, OTHER = "networkprobe.tunnel", "networkprobe.tunnel_custom", "networkprobe.view"
GRANTED = {TUNNEL, CUSTOM, OTHER}


def _has(user, code):
    H.PERMS["calls"].append((getattr(user, "pk", None), code))
    return code in GRANTED


sys.modules["tec_tac.rbac"].has_extension_permission = _has  # per-code answers (the harness stub answers one yes or no for all)


def fresh():
    reset()
    GRANTED.clear()
    GRANTED.update({TUNNEL, CUSTOM, OTHER})
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


def spec_with(**over):
    spec = H.tunnel_spec()
    spec.pop("permission", None)
    spec.update(over)
    return spec


def nothing_spent():
    return (tun.read_index() == {} and not [k for k in CACHE.data if k.startswith((tun.TICKET_PREFIX, tun.SESSION_PREFIX, tun.TICKET_RATE_PREFIX))])


async def pair(spec, clock=None):
    clock = clock or Clock()
    got = H.issue(spec)
    must(got["outcome"] == "ok", got)
    sid = spec["session_id"]
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


async def main():
    # ---- (1) the single `permission` form behaves as in 1.18.57
    fresh()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    must(got["outcome"] == "ok" and set(got) == {"outcome", "ticket", "launch_url", "expires_in", "session_id"}, f"the answer did not change: {sorted(got)}")
    stored = CACHE.data[tun.ticket_key(got["ticket"])]
    record = CACHE.data[tun.session_key(sid)]
    must(stored["permission"] == H.PERMISSION and record["permission"] == H.PERMISSION, "permission is kept in the value and the record")
    must(stored["permissions"] == [H.PERMISSION] and record["permissions"] == [H.PERMISSION], "and the list holds the one code")
    ticket_rows = rows("custom:probe-tunnel-ticket")
    must(len(ticket_rows) == 1 and ticket_rows[0]["metadata"]["permission"] == H.PERMISSION and "permission_count" not in ticket_rows[0]["metadata"], ticket_rows)
    clean = tun._clean_spec(H.tunnel_spec())
    must(clean["permission"] == H.PERMISSION and clean["permissions"] == [H.PERMISSION], clean)
    console = H.make_console(got["ticket"])
    await console.connect()
    await H.settle(console)
    must(console.accepted and not console.closed, f"connects: {console.closed} {console.close_reasons}")
    fresh()
    GRANTED.discard(TUNNEL)
    got = H.issue(H.tunnel_spec())
    must(got["outcome"] == "denied" and got["code"] == "permission_missing" and nothing_spent(), got)
    # a live session with the single form: removing the permission ends it at the re-check, as before
    fresh()
    console, probe, sid, clock = await pair(H.tunnel_spec())
    GRANTED.discard(TUNNEL)
    clock.now += 301
    must(await console._tick() is False and CACHE.data[tun.end_key(sid)]["detail"] == "permission_missing", CACHE.data.get(tun.end_key(sid)))
    await finish(console, probe)

    # ---- (2) two permissions: both must hold at the ticket, in both orders
    for order in ((TUNNEL, CUSTOM), (CUSTOM, TUNNEL)):
        fresh()
        sid = H.new_session_id()
        got = H.issue(spec_with(session_id=sid, permissions=list(order)))
        must(got["outcome"] == "ok", (order, got))
        stored, record = CACHE.data[tun.ticket_key(got["ticket"])], CACHE.data[tun.session_key(sid)]
        must(stored["permission"] == order[0] and stored["permissions"] == list(order), stored)
        must(record["permission"] == order[0] and record["permissions"] == list(order), record)
        must(CACHE.data[tun.session_key(sid)] and sid in tun.read_index(), "slot held")
        for missing in order:
            fresh()
            GRANTED.discard(missing)
            before = len(rows("custom:probe-tunnel-refused"))
            got = H.issue(spec_with(permissions=list(order)))
            must(got["outcome"] == "denied" and got["code"] == "permission_missing" and "ticket" not in got, (order, missing, got))
            refusals = rows("custom:probe-tunnel-refused")
            must(len(refusals) == before + 1 and refusals[-1]["metadata"]["reason"] == "permission_missing", "one deny row")
            must(nothing_spent(), "no slot, no ticket, no rate budget")
    # permission and permissions together: the single one is a member
    fresh()
    got = H.issue(spec_with(permission=CUSTOM, permissions=[TUNNEL, CUSTOM]))
    must(got["outcome"] == "ok" and next(v for k, v in CACHE.data.items() if k.startswith(tun.SESSION_PREFIX))["permission"] == CUSTOM, got)
    clean = tun._clean_spec(spec_with(permission=CUSTOM, permissions=[TUNNEL, CUSTOM]))
    must(clean["permission"] == CUSTOM and clean["permissions"] == [TUNNEL, CUSTOM], clean)
    fresh()
    GRANTED.update({"networkprobe.a", "networkprobe.b"})
    must(H.issue(spec_with(permissions=[TUNNEL, CUSTOM, "networkprobe.a", "networkprobe.b"]))["outcome"] == "ok", "four is allowed")
    # a permission that raises ValueError is invalid_spec (as in 1.18.57), a fault is unavailable
    fresh()

    def _raising(user, code):
        raise ValueError("unknown permission")

    sys.modules["tec_tac.rbac"].has_extension_permission = _raising
    got = H.issue(spec_with(permissions=[TUNNEL, CUSTOM]))
    must(got["outcome"] == "invalid" and got["code"] == "invalid_spec", got)
    sys.modules["tec_tac.rbac"].has_extension_permission = _has

    # ---- (3) at the connect: losing either permission after the ticket
    for order in ((TUNNEL, CUSTOM), (CUSTOM, TUNNEL)):
        for lost in order:
            fresh()
            sid = H.new_session_id()
            ticket = H.issue(spec_with(session_id=sid, permissions=list(order)))["ticket"]
            GRANTED.discard(lost)
            console = H.make_console(ticket)
            await console.connect()
            await H.settle(console)
            must(console.accepted and console.closed == [4401] and console.close_reasons == ["permission_missing"], (order, lost, console.closed, console.close_reasons))
            must(not tun.side_attached(sid, "console"), "the side was not taken")
    fresh()
    ticket = H.issue(spec_with(permissions=[TUNNEL, CUSTOM]))["ticket"]
    GRANTED.discard(OTHER)
    console = H.make_console(ticket)
    await console.connect()
    await H.settle(console)
    must(console.accepted and not console.closed, "an unrelated permission is not asked")

    # ---- (4) a live session: the 5 second tick after the access marker, and the 5 minute re-check
    for lost in (TUNNEL, CUSTOM):
        fresh()
        console, probe, sid, clock = await pair(spec_with(session_id=H.new_session_id(), permissions=[TUNNEL, CUSTOM]))
        GRANTED.discard(lost)
        WALL[0] += 10
        ae.notify_access_changed([H.ENGINEER], "role_permissions")
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is False, f"ended within one tick after losing {lost}")
        marker = CACHE.data[tun.end_key(sid)]
        must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "permission_missing", marker)
        await finish(console, probe)
        fresh()
        console, probe, sid, clock = await pair(spec_with(session_id=H.new_session_id(), permissions=[TUNNEL, CUSTOM]))
        GRANTED.discard(lost)
        clock.now += 299
        must(await console._tick() is True, "not yet 5 minutes")
        clock.now += 2
        must(await console._tick() is False and CACHE.data[tun.end_key(sid)]["detail"] == "permission_missing", f"the 5 minute re-check ends it after losing {lost}")
        await finish(console, probe)
    fresh()
    console, probe, sid, clock = await pair(spec_with(session_id=H.new_session_id(), permissions=[TUNNEL, CUSTOM]))
    GRANTED.discard(OTHER)
    WALL[0] += 10
    ae.notify_access_changed([H.ENGINEER], "role_permissions")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and CACHE.data.get(tun.end_key(sid)) is None, "an unrelated permission ends nothing")
    clock.now += 301
    must(await console._tick() is True and CACHE.data.get(tun.end_key(sid)) is None, "nor at the 5 minute re-check")
    must(H.PERMS["calls"] and {c for _u, c in H.PERMS["calls"]} <= {TUNNEL, CUSTOM}, "only the listed codes were asked")
    await finish(console, probe)

    # ---- (5) every invalid shape is invalid_spec and spends nothing
    shapes = {
        "empty list": spec_with(permissions=[]),
        "five codes": spec_with(permissions=[TUNNEL, CUSTOM, "networkprobe.a", "networkprobe.b", "networkprobe.c"]),
        "duplicates": spec_with(permissions=[TUNNEL, TUNNEL]),
        "a string": spec_with(permissions=TUNNEL),
        "a tuple": spec_with(permissions=(TUNNEL, CUSTOM)),
        "a dict": spec_with(permissions={TUNNEL: 1}),
        "null": spec_with(permissions=None),
        "a non-string member": spec_with(permissions=[TUNNEL, 5]),
        "a bool member": spec_with(permissions=[TUNNEL, True]),
        "a null member": spec_with(permissions=[TUNNEL, None]),
        "outside the pattern": spec_with(permissions=[TUNNEL, "other.tunnel"]),
        "an empty code": spec_with(permissions=[TUNNEL, ""]),
        "an upper-case code": spec_with(permissions=[TUNNEL, "networkprobe.Tunnel"]),
        "permission not in the list": spec_with(permission=OTHER, permissions=[TUNNEL, CUSTOM]),
        "permission malformed with a list": spec_with(permission=5, permissions=[TUNNEL]),
        "neither key": spec_with(),
        "permission null and no list": spec_with(permission=None),
        "an unknown key": spec_with(permissions=[TUNNEL], permissionz=[TUNNEL]),
    }
    for label, spec_ in shapes.items():
        fresh()
        got = H.issue(spec_)
        must(got["outcome"] == "invalid" and got["code"] == "invalid_spec" and "ticket" not in got, (label, got))
        must(nothing_spent() and H.PERMS["calls"] == [], f"{label}: nothing spent and no permission asked")
        must(tun._clean_spec(spec_) is None, label)

    # ---- (6) records written the 1.18.57 way, and malformed lists fail closed
    fresh()
    value = {"user_id": H.ENGINEER, "trust_id": "t", "knox_digest": "d", "session_id": "s", "probe_id": H.PROBE, "permission": TUNNEL}
    must(tun._permissions_of(value) == [TUNNEL], "a 1.18.57 value reads as its single permission")
    must(tun._permissions_of({"permission": TUNNEL, "permissions": [TUNNEL, CUSTOM]}) == [TUNNEL, CUSTOM], "the list wins when present")
    for bad in ({}, {"permission": 5}, {"permission": "x"}, {"permissions": []}, {"permissions": None}, {"permissions": "networkprobe.tunnel"},
                {"permissions": [TUNNEL, 3]}, {"permissions": [TUNNEL] * 5}, {"permissions": ["bad"]}, None, [], "networkprobe.tunnel"):
        must(tun._permissions_of(bad) == [], f"{bad!r} fails closed")
        must(tun.account_refusal(value, tun._permissions_of(bad)) == "permission_missing", f"{bad!r} is refused")
    must(tun.account_refusal(value, []) == "permission_missing" and tun.account_refusal(value, None) == "permission_missing", "an empty requirement is refused")
    must(tun.account_refusal(value, TUNNEL) is None and tun.account_refusal(value, [TUNNEL, CUSTOM]) is None, "a string and a list both work")
    GRANTED.discard(CUSTOM)
    must(tun.account_refusal(value, [TUNNEL, CUSTOM]) == "permission_missing", "one missing is refused")
    # a ticket value and a session record written by 1.18.57 (no `permissions` key) connect and re-check
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    stored = CACHE.data[tun.ticket_key(got["ticket"])]
    record = CACHE.data[tun.session_key(sid)]
    stored.pop("permissions")
    record.pop("permissions")
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    must(not console.closed and not probe.closed, f"an old-style ticket and record connect: {console.closed} {console.close_reasons}")
    clock.now += 301
    must(await console._tick() is True, "and re-check")
    GRANTED.discard(TUNNEL)
    clock.now += 301
    must(await console._tick() is False and CACHE.data[tun.end_key(sid)]["detail"] == "permission_missing", "and end when the permission goes")
    await finish(console, probe)
    # a record with a malformed list fails closed at the re-check
    fresh()
    console, probe, sid, clock = await pair(spec_with(session_id=H.new_session_id(), permissions=[TUNNEL, CUSTOM]))
    console._record = {**console._record, "permissions": "networkprobe.tunnel"}
    clock.now += 301
    must(await console._tick() is False and CACHE.data[tun.end_key(sid)]["detail"] == "permission_missing", "a malformed list ends the session")
    await finish(console, probe)
    # a malformed list in the ticket value is refused at the connect
    fresh()
    sid = H.new_session_id()
    got = H.issue(spec_with(session_id=sid, permissions=[TUNNEL, CUSTOM]))
    CACHE.data[tun.ticket_key(got["ticket"])]["permissions"] = [TUNNEL, 7]
    console = H.make_console(got["ticket"])
    await console.connect()
    await H.settle(console)
    must(console.closed == [4401] and console.close_reasons == ["permission_missing"], (console.closed, console.close_reasons))

    # ---- (7) the audit row: permission_count, never the list
    fresh()
    sid = H.new_session_id()
    must(H.issue(spec_with(session_id=sid, permissions=[TUNNEL, CUSTOM, OTHER]))["outcome"] == "ok", "issued")
    ticket_rows = rows("custom:probe-tunnel-ticket")
    meta = ticket_rows[0]["metadata"]
    must(len(ticket_rows) == 1 and meta["permission"] == TUNNEL and meta["permission_count"] == 3, meta)
    must(CUSTOM not in json.dumps(ticket_rows, default=str) and OTHER not in json.dumps(ticket_rows, default=str), "the list is in no row")
    must("permission_count" in pt.TUNNEL_AUDIT_KEYS, "the audit key is allowed")
    must(pt._tunnel_extra({"permission_count": 2, "permissions": [TUNNEL]}) == {"permission_count": 2}, "the list can never enter a row")
    must(pt._tunnel_extra({"permission_count": True}) == {}, "a bool is dropped")

    # ---- (8) the capability
    must(pt.CAPABILITY_VERSION == "1.4.0", pt.CAPABILITY_VERSION)
    meta = pt.probe_transport_contract_metadata()
    must(meta["version"] == "1.4.0" and "1.4.0 (Core 1.18.58, framework >=1.18.58)" in meta["added_in"], meta["added_in"])
    must(meta["operations"] == ["register_owner", "request", "send", "presence", "disconnect", "issue_tunnel_ticket", "end_tunnel", "end_tunnels_for_probe",
                                "tunnel_status", "set_tunnel_site"], meta["operations"])
    text = meta["operations_detail"]["issue_tunnel_ticket"]
    must("permissions (a list of 1 to 4 distinct" in text and "outcome: ok, ticket, launch_url, expires_in: 60, session_id" in text, "the operation text names the list and keeps the answer")
    tunnel = pt.tunnel_contract_metadata()
    must("1.4.0 (Core 1.18.58" in tunnel["permissions"] and "single permission form is unchanged" in tunnel["permissions"], tunnel["permissions"])
    contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes().decode("utf-8")
    must("core.probe_transport 1.4.0, framework >=1.18.58" in contracts and "permissions added 1.18.58" in contracts and "Compatibility path" in contracts, "contracts.py rows")
    doc = (ROOT / "docs" / "probe-transport.md").read_bytes().decode("utf-8")
    section = doc[doc.index("### Permission lists (1.4.0)"):doc.index("### Frames")]
    for needle in ("framework 1.18.58", "`permission_missing`", "`permission_count`", "compatibility path", "1.18.57", "`networkprobe.tunnel_custom`"):
        must(needle in section, f"docs/probe-transport.md names {needle}")
    caps = (ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
    must("`core.probe_transport` 1.4.0" in caps and "framework >=1.18.58" in caps, "docs/capabilities.md")
    must("tunnel_custom" not in (ROOT / "framwork" / "tec_tac" / "probe_tunnel.py").read_text(encoding="utf-8"), "Core names no module permission")


run(main())
print("probe tunnel permissions 1.18.58 regression: PASS")
