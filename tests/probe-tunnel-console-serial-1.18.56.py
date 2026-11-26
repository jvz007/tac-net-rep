#!/usr/bin/env python3
"""1.18.56 regression: a tunnel ticket asked for from an Engineer Console session connects only with that session's own certificate.

On the in-memory harness (tests/probe_transport_harness.py): the real probe_tunnel.py and probe_tunnel_consumer.py run; tec_tac.console_certificates is
the harness stub (the real certificate logic is covered by tests/console-certificates-connect-1.18.53.py). Covered: a ticket issued from a Console
session carries console_serial (cache only, never in an answer) and connects with that serial; another of the same person's active serials is refused
with certificate_engineer_mismatch (4401, one custom:console-cert-refused row with only reason, address, session id, engineer id and the serial, the
ticket burnt, the account not looked at); a browser ticket still connects with any serial; a request whose console_serial is not 32 hex is ignored like a
browser's; the attach marker holds cert_serial and server_id; core.probe_transport answers did not change.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, CERTS, SIGNIN, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.CERTS, H.SIGNIN, H.run

SERIAL_A, SERIAL_B = "a1" * 16, "b2" * 16


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def console_request(serial=SERIAL_A):
    request = H.engineer_request()
    request.auth = SimpleNamespace(digest="digest-1", console_serial=serial)  # what tec_tac.console_sessions.ConsoleAuth carries
    return request


async def connect(ticket, channel="specific.console"):
    console = H.make_console(ticket, channel=channel)
    await console.connect()
    await H.settle(console)
    return console


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


async def main():
    # ---- a Console-issued ticket carries the serial in the cache only
    fresh()
    got = H.issue(H.tunnel_spec(), console_request(SERIAL_A))
    must(got["outcome"] == "ok", got)
    must(set(got) == {"outcome", "ticket", "launch_url", "expires_in", "session_id"}, f"the answer did not change: {sorted(got)}")
    stored = CACHE.data[tun.ticket_key(got["ticket"])]
    must(stored["console_serial"] == SERIAL_A, "the ticket value is bound to the Console session's serial")
    must(SERIAL_A not in json.dumps(got) and SERIAL_A not in json.dumps(AUDITS, default=str), "the serial is in no answer and no audit row of the ticket")
    CERTS["serial"], CERTS["not_after"] = SERIAL_A, WALL[0] + 86400
    console = await connect(got["ticket"])
    must(console.accepted and not console.closed, f"it connects with its own certificate: {console.closed} {console.close_reasons}")
    marker = CACHE.data[tun.side_key(got["session_id"], "console")]
    must(marker["cert_serial"] == SERIAL_A and marker["server_id"] == CERTS["server_id"], f"the attach marker holds cert_serial and server_id: {marker}")
    must(tun._session_on_ca(got["session_id"], CERTS["server_id"]) and not tun._session_on_ca(got["session_id"], "f" * 32), "_session_on_ca reads the marker")

    # ---- another of the same person's active serials is refused
    fresh()
    got = H.issue(H.tunnel_spec(), console_request(SERIAL_A))
    sid = got["session_id"]
    CERTS["serial"] = SERIAL_B
    SIGNIN["refusal"] = "session_revoked"  # the account check would fail too: the serial check comes first
    console = await connect(got["ticket"])
    must(console.accepted and console.closed == [4401] and console.close_reasons == ["certificate_engineer_mismatch"], f"refused: {console.closed} {console.close_reasons}")
    must(console.accept_headers is None, "no server proof on a refusal")
    must(SIGNIN["calls"] == [], "the account is not looked at after the serial refusal")
    must(CERTS["refusals"] == [{"reason": "certificate_engineer_mismatch", "ip": console._ip, "session_id": sid, "engineer_id": H.ENGINEER, "serial": SERIAL_B}], CERTS["refusals"])
    must(tun.ticket_key(got["ticket"]) not in CACHE.data, "the ticket is burnt")
    must(CACHE.data.get(tun.side_key(sid, "console")) is None and CERTS["sign_calls"] == [] and CERTS["touched"] == [], "never attached, nothing signed, nothing marked used")
    must(not rows("custom:probe-tunnel-refused"), "no probe-tunnel-refused row for a certificate reason")
    text = json.dumps(CERTS["refusals"]) + json.dumps(AUDITS, default=str)
    must(got["ticket"] not in text, "no ticket in any row")
    SIGNIN["refusal"] = None

    # ---- a browser ticket connects with any serial of the person
    for serial in (SERIAL_A, SERIAL_B):
        fresh()
        got = H.issue(H.tunnel_spec())
        must("console_serial" not in CACHE.data[tun.ticket_key(got["ticket"])], "a browser ticket is not bound to a serial")
        CERTS["serial"], CERTS["not_after"] = serial, WALL[0] + 86400
        console = await connect(got["ticket"])
        must(console.accepted and not console.closed, f"a browser ticket connects with {serial[:4]}: {console.closed} {console.close_reasons}")

    # ---- a console_serial that is not 32 hex is not honoured as a binding (it cannot come from ConsoleAuth)
    for bad in ("short", "A" * 32, 123, None, "g" * 32):
        fresh()
        request = console_request(bad)
        got = H.issue(H.tunnel_spec(), request)
        must("console_serial" not in CACHE.data[tun.ticket_key(got["ticket"])], f"{bad!r} is ignored")
    # the request.auth of a browser is a Knox token: it has no console_serial
    fresh()
    request = H.engineer_request()
    request.auth = SimpleNamespace(digest="digest-1")
    must("console_serial" not in CACHE.data[tun.ticket_key(H.issue(H.tunnel_spec(), request)["ticket"])], "a Knox token carries no serial")
    request.auth = None
    must("console_serial" not in CACHE.data[tun.ticket_key(H.issue(H.tunnel_spec(), request)["ticket"])], "no auth at all: no serial")

    # ---- the refusals of issue_tunnel_ticket did not change
    fresh()
    CERTS["usable"] = False
    refusal = H.issue(H.tunnel_spec(), console_request())
    must(refusal["outcome"] == "denied" and refusal["code"] == "console_certificate_required", "the 1.18.53 refusal is unchanged")


run(main())
print("probe tunnel console serial 1.18.56 regression: PASS")
