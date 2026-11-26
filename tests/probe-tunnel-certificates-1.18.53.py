#!/usr/bin/env python3
"""1.18.53 regression: the Engineer Console certificate on the tunnel (core.probe_transport 1.3.0), on the in-memory harness
(tests/probe_transport_harness.py). The real probe_tunnel.py and probe_tunnel_consumer.py run; tec_tac.console_certificates is the harness stub that
the test configures (the real crypto and database logic are in tests/console-certificates-connect-1.18.53.py).

Header shape (certificate_required, certificate_invalid, proof_invalid) and the Host header; the close code and close text of every reason; accept
headers only on success; the ticket is not burnt by a header-shape refusal and is burnt by every later one; a replayed ticket is ticket_invalid; the
seven reasons write only console-cert-refused (never probe-tunnel-refused) and count against the address; cert_serial on the connect row, the end row
and the console marker; a master key that cannot sign closes 1013 and burns the ticket; the account checks run after the certificate and before the
server proof; the probe side ignores the headers; issue_tunnel_ticket refuses a person with no valid certificate before any slot or rate budget;
end_for_certificate and end_all_sessions end exactly the right sessions at once (since 1.18.55 the hooks only queue the end: tests/probe-tunnel-end-queue-1.18.55.py); the 5-second tick ends a session from the marker alone, at the
certificate's end, and survives a cache fault; the 5-minute re-check re-reads the certificate row.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, LAYER, CELERY, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.LAYER, H.CELERY, H.run
Clock, CERTS, SIGNIN, PERMS = H.Clock, H.CERTS, H.SIGNIN, H.PERMS
for name in ("tec_tac.probe_transport",):
    logging.getLogger(name).addHandler(logging.NullHandler())
    logging.getLogger(name).propagate = False  # the fault cases log a warning on purpose

SERIAL_X, SERIAL_Y = "1" * 32, "2" * 32
REASONS = ("certificate_required", "certificate_invalid", "certificate_expired", "certificate_revoked", "certificate_engineer_mismatch", "proof_invalid",
           "proof_stale")
must(tuple(tun.CERT_REASONS) == REASONS, "the seven reasons, in the documented order")


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


def closed_events():
    return [(task, args) for task, args in CELERY.sent if args[1]["func"] == "tunnel.closed"]


def end_marker(sid):
    return CACHE.data.get(tun.end_key(sid))


def issued(**over):
    got = H.issue(H.tunnel_spec(**over))
    must(got["outcome"] == "ok", got)
    return got


async def connect(ticket, headers=None, clock=None, channel="specific.console"):
    console = H.make_console(ticket, clock=clock, channel=channel, headers=headers)
    await console.connect()
    await H.settle(console)
    return console


async def pair(clock=None):
    """One connected Console and probe (the stub accepts the certificate)."""
    fresh()
    clock = clock or Clock()
    got = issued()
    sid = got["session_id"]
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    must(not console.closed and not probe.closed, (console.closed, probe.closed))
    return console, probe, sid, clock


async def off(func, *args):
    """The end functions are sync (a request thread or a task): run them off the event loop, as the callers do."""
    return await asyncio.to_thread(func, *args)


async def tick(console, clock, seconds=5):
    clock.now += seconds
    WALL[0] += seconds
    return await console._tick()


# ------------------------------------------------------------------------------------------------ header shape (pure)
def scope_of(rows_):
    return {"headers": rows_}


def shape(certs=None, proofs=None):
    return tun.parse_console_headers(scope_of([(b"x-tectac-console-cert", c) for c in (certs or [])] + [(b"x-tectac-console-proof", p) for p in (proofs or [])]))


GOOD_CERT = H.b64u_text(b"\x30\x82" + b"D" * 120).encode()
NONCE22, SIG86 = H.b64u_text(b"n" * 16), H.b64u_text(b"s" * 64)
must(len(NONCE22) == 22 and len(SIG86) == 86, "the shapes the wire format names")
GOOD_PROOF = f"v1.1764000000.{NONCE22}.{SIG86}".encode()
ok = shape([GOOD_CERT], [GOOD_PROOF])
must(ok == {"reason": None, "cert": b"\x30\x82" + b"D" * 120, "time": "1764000000", "nonce": NONCE22, "sig": SIG86}, ok)
for certs, proofs, wanted in (
    ([], [], "certificate_required"), ([GOOD_CERT], [], "certificate_required"), ([], [GOOD_PROOF], "certificate_required"),
    ([b"!!!"], [], "certificate_required"),  # either missing wins, even over a malformed other header
    ([GOOD_CERT, GOOD_CERT], [GOOD_PROOF], "certificate_invalid"),  # present once
    ([b"A" * 2049], [GOOD_PROOF], "certificate_invalid"),  # over 2048 characters
    ([b"not base64!"], [GOOD_PROOF], "certificate_invalid"),
    ([b"AB=="], [GOOD_PROOF], "certificate_invalid"),  # padding is not allowed
    ([b"AAB"], [GOOD_PROOF], "certificate_invalid"),  # not canonical: it does not re-encode to itself
    ([b"A\xc3\xa9"], [GOOD_PROOF], "certificate_invalid"),  # not ASCII
    ([GOOD_CERT], [GOOD_PROOF, GOOD_PROOF], "proof_invalid"),
    ([GOOD_CERT], [b"v2." + GOOD_PROOF[3:]], "proof_invalid"),
    ([GOOD_CERT], [f"v1.{'1' * 13}.{NONCE22}.{SIG86}".encode()], "proof_invalid"),  # time: 1 to 12 digits
    ([GOOD_CERT], [f"v1..{NONCE22}.{SIG86}".encode()], "proof_invalid"),
    ([GOOD_CERT], [f"v1.12.{NONCE22[:21]}.{SIG86}".encode()], "proof_invalid"),  # nonce: exactly 22 characters
    ([GOOD_CERT], [f"v1.12.{NONCE22}.{SIG86[:85]}".encode()], "proof_invalid"),  # signature: exactly 86 characters
    ([GOOD_CERT], [f"v1.12.{NONCE22}.{SIG86[:-1]}B".encode()], "proof_invalid"),  # not canonical
    ([GOOD_CERT], [f"v1.12.{NONCE22}.{SIG86}.extra".encode()], "proof_invalid"),
    ([GOOD_CERT], [b"v1.12." + b"A" * 400], "proof_invalid"),  # over 400 bytes
    ([GOOD_CERT], [b"v1.1x.AAAAAAAAAAAAAAAAAAAAAA." + SIG86.encode()], "proof_invalid"),
):
    got = shape(certs, proofs)
    must(got == {"reason": wanted}, (wanted, got))
must(shape([GOOD_CERT], [f"v1.{'9' * 12}.{NONCE22}.{SIG86}".encode()])["reason"] is None, "12 digits of time are allowed")
must(shape([b"A" * 2048], [GOOD_PROOF])["reason"] is None, "2048 characters exactly are allowed")


def host_of(*values):
    return tun.console_host(scope_of([(b"host", v) for v in values]))


must(host_of(b"tec.example.com") == "tec.example.com" and host_of(b"TEC.Example.COM") == "tec.example.com", "lower case")
must(host_of(b"tec.example.com:443") == "tec.example.com", "':443' removed")
must(host_of(b"tec.example.com:8443") is None and host_of(b"tec.example.com:80") is None, "any other port is unsupported")
must(host_of() is None and host_of(b"a.example.com", b"b.example.com") is None and host_of(b"-bad-") is None and host_of(b"a b") is None and host_of(b"\xff") is None, "no usable host")
must(tun.console_host(scope_of([])) is None, "no headers at all")
pure_source = (Path(tun.__file__)).read_text(encoding="utf-8")
must("console_certificate" in pure_source and "import console_certificates" in pure_source, "the lazy import is there")

# ------------------------------------------------------------------------------------------------ the connect: every reason
async def reasons_case():
    for reason in REASONS[1:]:
        fresh()
        got = issued()
        sid = got["session_id"]
        CERTS["refuse"] = (reason, SERIAL_X)
        console = await connect(got["ticket"])
        must(console.accepted and console.closed == [4401] and console.close_reasons == [reason], (reason, console.closed, console.close_reasons))
        must(console.accept_headers is None, "no server proof on a refusal")
        must(tun.ticket_key(got["ticket"]) not in CACHE.data, "the ticket is burnt by a refusal after redeem")
        must(CERTS["refusals"] == [{"reason": reason, "ip": console._ip, "session_id": sid, "engineer_id": H.ENGINEER, "serial": SERIAL_X}], CERTS["refusals"])
        must(not rows("custom:probe-tunnel-refused"), "no probe-tunnel-refused row for a certificate reason")
        must(not rows("custom:probe-tunnel-connect") and CACHE.data.get(tun.side_key(sid, "console")) is None, "never attached")
        must(any(key.startswith(pt.FAILURE_PREFIX) for key in CACHE.data), "counted against the address")
        must(SIGNIN["calls"] == [], "the account is not looked at after a certificate refusal")
        must(CERTS["sign_calls"] == [] and CERTS["touched"] == [], "nothing signed, nothing marked used")
        must(tun.read_index().get(sid, {}).get("expires", 0) < WALL[0] + 100, "the slot is still the pending one")
        replay = await connect(got["ticket"], channel="specific.console2")
        must(replay.close_reasons == ["ticket_invalid"] and replay.closed == [4401], "a replayed ticket is ticket_invalid")
        must([r["metadata"]["reason"] for r in rows("custom:probe-tunnel-refused")] == ["ticket_invalid"], "the replay writes the normal row")
        must(len(CERTS["refusals"]) == 1, "and no second certificate row")
    # the header-shape refusals: the ticket is NOT burnt, nothing is verified, one row each
    for headers_over, reason in (
        ({"certificate": False}, "certificate_required"),
        ({"certificate": False, "extra": [(b"x-tectac-console-cert", GOOD_CERT)]}, "certificate_required"),
        ({"certificate": False, "extra": [(b"x-tectac-console-cert", b"%%%"), (b"x-tectac-console-proof", GOOD_PROOF)]}, "certificate_invalid"),
        ({"certificate": False, "extra": [(b"x-tectac-console-cert", GOOD_CERT), (b"x-tectac-console-proof", b"v1.nope")]}, "proof_invalid"),
    ):
        fresh()
        got = issued()
        console = await connect(got["ticket"], headers=H.ticket_headers(got["ticket"], **headers_over))
        must(console.accepted and console.closed == [4401] and console.close_reasons == [reason], (reason, console.closed, console.close_reasons))
        must(tun.ticket_key(got["ticket"]) in CACHE.data, f"{reason}: the ticket is not burnt by a header-shape refusal")
        must(CERTS["verify_calls"] == [], "nothing was verified")
        must(CERTS["refusals"] == [{"reason": reason, "ip": console._ip, "session_id": None, "engineer_id": None, "serial": None}], CERTS["refusals"])
        must(not rows("custom:probe-tunnel-refused"), "no probe-tunnel-refused row")
        again = await connect(got["ticket"], channel="specific.console2")  # the same ticket, now with the headers: it works
        must(again.accepted and not again.closed and again.accept_headers is not None, "the unburnt ticket still connects")
    # a call without headers at all (the default of console_open) is certificate_required and burns nothing
    fresh()
    got = issued()
    must(tun.console_open(got["ticket"]) == ("certificate", None, None, "certificate_required"), "console_open without headers")
    must(tun.ticket_key(got["ticket"]) in CACHE.data, "not burnt")
    # the secrets are in no refusal record
    fresh()
    got = issued()
    CERTS["refuse"] = ("proof_invalid", SERIAL_X)
    await connect(got["ticket"])
    text = json.dumps(CERTS["refusals"]) + json.dumps(AUDITS, default=str)
    for secret in (got["ticket"], GOOD_CERT.decode(), NONCE22, SIG86, "v1.17"):
        must(secret not in text, "a ticket, certificate or proof is in a row")


run(reasons_case())


# ------------------------------------------------------------------------------------------------ the connect: success, key fault, order
async def success_case():
    fresh()
    got = issued()
    sid = got["session_id"]
    CERTS["serial"], CERTS["not_after"] = SERIAL_X, WALL[0] + 86400
    console = await connect(got["ticket"])
    must(console.accepted and not console.closed, console.closed)
    must(console.accept_headers == [(b"x-tectac-server-proof", H.SERVER_PROOF.encode("ascii"))], console.accept_headers)
    call = CERTS["verify_calls"][0]
    must(call["host"] == "tec.example.com" and call["user_id"] == H.ENGINEER and call["ticket"] == got["ticket"], call)
    must(call["cert"] == b"\x30\x82" + b"D" * 120 and call["proof"]["time"] == str(int(WALL[0])) and call["proof"]["nonce"] == H.b64u_text(b"n" * 16), call)
    must(CERTS["sign_calls"] == [(SERIAL_X, "tec.example.com", H.b64u_text(b"n" * 16))], "the server proof is signed for the Console's own nonce and the Host header")
    must(CACHE.data[tun.side_key(sid, "console")]["cert_serial"] == SERIAL_X, "the console marker carries cert_serial")
    must(CERTS["touched"] == [SERIAL_X], "last_used_at is touched once")
    connect_row = [a for a in rows("custom:probe-tunnel-connect") if a["metadata"].get("side") == "console"]
    must(len(connect_row) == 1 and connect_row[0]["metadata"]["cert_serial"] == SERIAL_X and connect_row[0]["metadata"]["engineer"] == H.ENGINEER, connect_row)
    must("cert_serial" in pt.TUNNEL_AUDIT_KEYS, "cert_serial is an allowed audit key")
    must(console._cert_serial == SERIAL_X and console._cert_not_after == CERTS["not_after"] and console._cert_server_id == CERTS["server_id"], "kept for the watcher")
    must("server_proof" not in console._value, "the server proof is not kept")
    text = json.dumps(AUDITS, default=str) + json.dumps(console._value, default=str)
    must(got["ticket"] not in text and H.SERVER_PROOF not in text and GOOD_CERT.decode() not in text, "no ticket, proof or certificate in a row")
    # the end row carries the serial too
    await console.disconnect(1000)
    await H.settle(console)
    end = rows("custom:probe-tunnel-end")
    must(len(end) == 1 and end[0]["metadata"]["cert_serial"] == SERIAL_X, end)

    # a key that cannot sign: 1013, the ticket is burnt, nothing attached, no certificate row, nothing counted
    fresh()
    got = issued()
    CERTS["key_fault"] = True
    console = await connect(got["ticket"])
    must(console.accepted and console.closed == [pt.CLOSE_RETRY_LATER] and console.close_reasons == ["master_key_unavailable"], (console.closed, console.close_reasons))
    must(console.accept_headers is None and tun.ticket_key(got["ticket"]) not in CACHE.data, "burnt, no proof")
    must(CACHE.data.get(tun.side_key(got["session_id"], "console")) is None and CERTS["refusals"] == [] and CERTS["touched"] == [], "not attached, no row, not used")
    must(not any(key.startswith(pt.FAILURE_PREFIX) for key in CACHE.data), "a server fault counts nothing")

    # the order: certificate, then the account; the server proof only when everything else passed
    fresh()
    got = issued()
    SIGNIN["refusal"] = "session_expired"
    console = await connect(got["ticket"])
    must(console.closed == [4401] and console.close_reasons == ["session_expired"], console.close_reasons)
    must(len(CERTS["verify_calls"]) == 1 and CERTS["sign_calls"] == [] and console.accept_headers is None, "certificate checked first, no proof signed for a refused account")
    must(len(rows("custom:probe-tunnel-refused")) == 1 and CERTS["refusals"] == [], "an account refusal keeps its own row")
    fresh()
    got = issued()
    CERTS["refuse"] = ("certificate_revoked", SERIAL_X)
    SIGNIN["refusal"] = "session_expired"
    console = await connect(got["ticket"])
    must(console.close_reasons == ["certificate_revoked"] and SIGNIN["calls"] == [], "a certificate refusal is answered before the account is read")

    # a database fault while verifying: 1013 (nothing counted); the ticket is burnt
    fresh()
    got = issued()
    real = H.sys.modules["tec_tac.console_certificates"].verify_connect
    H.sys.modules["tec_tac.console_certificates"].verify_connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("database down"))
    console = await connect(got["ticket"])
    H.sys.modules["tec_tac.console_certificates"].verify_connect = real
    must(console.closed == [pt.CLOSE_RETRY_LATER] and console.close_reasons == ["unavailable"] and console.accept_headers is None, (console.closed, console.close_reasons))

    # the probe side ignores the certificate headers
    fresh()
    got = issued()
    sid = got["session_id"]
    probe_headers = H.headers_for(H.PROBE, H.KEY, extra=[(b"x-tunnel-session", sid.encode()), *H.cert_header_rows()])
    probe = H.make_tunnel_probe(sid, headers=probe_headers)
    await probe.connect()
    await H.settle(probe)
    must(probe.accepted and not probe.closed and probe.accept_headers is None and CERTS["verify_calls"] == [], "the probe side neither needs nor reads the certificate")


run(success_case())


# ------------------------------------------------------------------------------------------------ issue_tunnel_ticket: console_certificate_required
def ticket_cases():
    fresh()
    CERTS["usable"] = False
    got = H.issue()
    must(got["outcome"] == "denied" and got["code"] == "console_certificate_required", got)
    must(got["message"] == tun.REFUSAL_MESSAGES["console_certificate_required"] == "this engineer has no valid Engineer Console certificate; enrol from My Account", got)
    must("ticket" not in got and "launch_url" not in got, "no ticket")
    refused = rows("custom:probe-tunnel-refused")
    must(len(refused) == 1 and refused[0]["metadata"]["reason"] == "console_certificate_required" and refused[0]["refusal"] is True, refused)
    must(tun.read_index() == {} and not any(key.startswith(tun.TICKET_RATE_PREFIX) for key in CACHE.data), "no slot and no rate budget spent")
    must(not any(key.startswith(tun.TICKET_PREFIX) or key.startswith(tun.SESSION_PREFIX) for key in CACHE.data), "no ticket and no record")
    must(CERTS["usable_calls"] == [H.ENGINEER], "one read for the signed-in person")
    # it is asked after the permission and the scope, before the probe's presence
    fresh()
    CERTS["usable"] = False
    PERMS["granted"] = False
    got = H.issue()
    must(got["code"] == "permission_missing" and CERTS["usable_calls"] == [], "the permission first")
    fresh()
    CERTS["usable"] = False
    got = H.issue(H.tunnel_spec(site_id=99))
    must(got["code"] == "out_of_scope" and CERTS["usable_calls"] == [], "the scope next")
    fresh()
    CERTS["usable"] = False
    CACHE.data.pop(pt.presence_key(H.PROBE), None)
    must(H.issue()["code"] == "console_certificate_required", "before the probe's presence: no certificate and an offline probe says certificate first")
    fresh()
    CACHE.data.pop(pt.presence_key(H.PROBE), None)
    must(H.issue()["outcome"] == "probe_offline", "with a certificate the offline probe is refused as before")
    # a usable certificate issues a ticket
    fresh()
    got = H.issue()
    must(got["outcome"] == "ok" and len(got["ticket"]) == 43 and CERTS["usable_calls"] == [H.ENGINEER], got)
    # a fault while reading: unavailable, fail closed
    fresh()
    CERTS["usable_fault"] = True
    got = H.issue()
    must(got["outcome"] == "unavailable" and got["code"] == "unavailable" and tun.read_index() == {}, got)
    must([r["metadata"]["reason"] for r in rows("custom:probe-tunnel-refused")] == ["unavailable"], "one deny row")


ticket_cases()


# ------------------------------------------------------------------------------------------------ ending sessions
async def end_cases():
    # three sessions of one engineer: two with certificate X, one with Y, one more pending (limit is 3 per engineer, so use two runs)
    fresh()
    consoles = []
    for number, serial in enumerate((SERIAL_X, SERIAL_X, SERIAL_Y)):
        got = issued()
        CERTS["serial"] = serial
        console = await connect(got["ticket"], channel=f"specific.console{number}")
        must(console.accepted and not console.closed, console.closed)
        consoles.append((console, got["session_id"]))
    (a, sid_a), (b, sid_b), (c, sid_c) = consoles
    started = WALL[0]
    ended_ids = await off(tun.end_for_certificate, SERIAL_X)
    must(sorted(ended_ids) == sorted([sid_a, sid_b]) and WALL[0] - started < 1, ended_ids)
    for sid in (sid_a, sid_b):
        marker = end_marker(sid)
        must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "certificate_revoked", marker)
    must(end_marker(sid_c) is None and not c.closed, "the other certificate's session is untouched")
    for console in (a, b):
        must(console.closed == [1000] and console.close_reasons == ["ended_by_core"], (console.closed, console.close_reasons))
    must(await off(tun.end_for_certificate, SERIAL_X) == [], "a second call ends nothing more")
    for console, sid in ((a, sid_a), (b, sid_b)):
        await console.disconnect(1000)
        await H.settle(console)
    ends = {r["metadata"]["session_id"]: r["metadata"] for r in rows("custom:probe-tunnel-end")}
    must(set(ends) == {sid_a, sid_b} and all(m["detail"] == "certificate_revoked" and m["cert_serial"] == SERIAL_X and m["ended_by"] == "core" for m in ends.values()), ends)
    must(len(closed_events()) == 2, "one tunnel.closed event per ended session")
    # the same certificate ends nothing for a session that connected with another one, and an unknown serial ends nothing
    must(await off(tun.end_for_certificate, "9" * 32) == [], "unknown serial")
    # every session, with the CA replacement detail; a pending session (no Console yet) is ended too
    pending = issued()
    ended_all = await off(tun.end_all_sessions, "ca_replaced")
    must(sorted(ended_all) == sorted([sid_c, pending["session_id"]]), ended_all)
    for sid in ended_all:
        must(end_marker(sid)["detail"] == "ca_replaced", end_marker(sid))
    must(c.close_reasons == ["ended_by_core"], "the live Console of the rest is closed too")
    must(await off(tun.end_all_sessions) == [], "nothing is left")

    # 1.18.55: the revoke hook writes the marker and queues the end (the ending runs in the worker: tests/probe-tunnel-end-queue-1.18.55.py);
    # a failing marker write never stops the ending
    fresh()
    got = issued()
    CERTS["serial"] = SERIAL_X
    live = await connect(got["ticket"])
    real_set = CACHE.set
    CACHE.set = lambda key, value, timeout=None: (_ for _ in ()).throw(ConnectionError("down")) if key.startswith(tun.CERT_REVOKED_PREFIX) else real_set(key, value, timeout)
    out = await off(tun.certificate_revoked, SERIAL_X)
    must(out == [] and not live.closed, "the hook ends nothing in the calling thread")
    out = await off(tun.run_end, "certificate_revoked", SERIAL_X)
    CACHE.set = real_set
    must(out == [got["session_id"]] and live.close_reasons == ["ended_by_core"], "ended although the marker could not be written")
    fresh()
    got = issued()
    live = await connect(got["ticket"])
    await off(tun.certificate_revoked, SERIAL_X)
    must(CACHE.data[tun.cert_revoked_key(SERIAL_X)] == 1 and CACHE.timeouts[tun.cert_revoked_key(SERIAL_X)] == tun._keep_seconds(), "the revoke marker")
    await off(tun.ca_replaced, CERTS["server_id"])
    must(CACHE.data[tun.ca_replaced_key(CERTS["server_id"])] == 1, "the CA marker")

    # the time budget: sessions that are not ended in time are left to the marker and their socket's tick
    fresh()
    sessions = []
    for number in range(3):
        got = issued()
        CERTS["serial"] = SERIAL_X
        console = await connect(got["ticket"], clock=Clock(), channel=f"specific.console{number}")
        sessions.append((console, got["session_id"]))
    real_end = tun.end_session

    def slow_end(*args, **kwargs):
        WALL[0] += 6
        return real_end(*args, **kwargs)

    tun.end_session = slow_end
    await off(tun.certificate_revoked, SERIAL_X)  # the request writes the marker; the worker then runs the end
    ended_ids = await off(tun.run_end, "certificate_revoked", SERIAL_X)
    tun.end_session = real_end
    must(len(ended_ids) == 2, f"two ended inside the {tun.END_BUDGET_SECONDS} second budget: {ended_ids}")
    left = [(console, sid) for console, sid in sessions if sid not in ended_ids]
    must(len(left) == 1 and end_marker(left[0][1]) is None, "one is left")
    clock = Clock()
    left[0][0]._clock = clock
    must(await tick(left[0][0], clock) is False, "its next tick ends it from the marker")
    must(end_marker(left[0][1])["detail"] == "certificate_revoked", end_marker(left[0][1]))


run(end_cases())


async def tick_cases():
    # the marker alone ends a live session at its next 5-second tick (end_for_certificate was never called: a connect that raced the revoke)
    console, probe, sid, clock = await pair()
    CERTS["serial"] = SERIAL_X
    must(await tick(console, clock) is True, "healthy")
    CACHE.data[tun.cert_revoked_key(console._cert_serial)] = 1
    must(await tick(console, clock) is False, "ended")
    marker = end_marker(sid)
    must(marker["reason"] == "ended_by_core" and marker["detail"] == "certificate_revoked", marker)
    must(console.close_reasons[-1] == "ended_by_core", console.close_reasons)
    # the replaced CA
    console, probe, sid, clock = await pair()
    CACHE.data[tun.ca_replaced_key(console._cert_server_id)] = 1
    must(await tick(console, clock) is False and end_marker(sid)["detail"] == "ca_replaced", "ca_replaced")
    # a marker for the NEW CA or another serial does nothing
    console, probe, sid, clock = await pair()
    CACHE.data[tun.ca_replaced_key("f" * 32)] = 1
    CACHE.data[tun.cert_revoked_key("e" * 32)] = 1
    must(await tick(console, clock) is True and end_marker(sid) is None, "markers of other certificates and CAs are ignored")
    # a cache fault in the marker read does not end a healthy session
    real_many = CACHE.get_many
    CACHE.get_many = lambda keys: (_ for _ in ()).throw(ConnectionError("cache down"))
    must(await tick(console, clock) is True and end_marker(sid) is None, "healthy through a cache fault")
    must(tun.certificate_end_reason(SERIAL_X, "a" * 32) is None, "a fault reads as none")
    CACHE.get_many = real_many
    must(await tick(console, clock) is True, "and after it")
    # one get_many for both markers
    CACHE.get_many_calls = 0
    await tick(console, clock)
    must(CACHE.get_many_calls == 1, f"one get_many a tick ({CACHE.get_many_calls})")
    # the expiry watcher: at the certificate's end, not before
    fresh()
    clock = Clock()
    got = issued()
    CERTS["not_after"] = WALL[0] + 20
    sid = got["session_id"]
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    must(await tick(console, clock) is True and await tick(console, clock) is True and await tick(console, clock) is True, "5, 10 and 15 seconds: before the end")
    ended = await tick(console, clock)  # 20 seconds: the certificate's end
    must(ended is False and end_marker(sid)["detail"] == "certificate_expired" and end_marker(sid)["reason"] == "ended_by_core", end_marker(sid))
    # the 5-minute re-check: a row that is no longer active, expired, or a database fault
    for answer, detail in (("certificate_revoked", "certificate_revoked"), ("certificate_expired", "certificate_expired")):
        console, probe, sid, clock = await pair()
        must(await tick(console, clock, 100) is True, "no re-check yet")
        CERTS["recheck"] = answer
        must(await tick(console, clock, 205) is False, "the 5-minute re-check ended it")
        must(end_marker(sid)["detail"] == detail and end_marker(sid)["reason"] == "ended_by_core", end_marker(sid))
        must(CERTS["recheck_calls"] == [console._cert_serial], "the certificate row is re-read first")
    console, probe, sid, clock = await pair()
    CERTS["recheck_fault"] = True
    must(await tick(console, clock, 305) is False and end_marker(sid)["detail"] == "check_failed", "a database fault is check_failed, like the account check")
    console, probe, sid, clock = await pair()
    must(await tick(console, clock, 305) is True and CERTS["recheck_calls"] == [console._cert_serial], "a clean re-check keeps the session")
    # the certificate row is read before the account: a revoked certificate is reported even when the account is refused too
    console, probe, sid, clock = await pair()
    CERTS["recheck"] = "certificate_revoked"
    SIGNIN["refusal"] = "session_expired"
    must(await tick(console, clock, 305) is False and end_marker(sid)["detail"] == "certificate_revoked", "certificate first")


run(tick_cases())

print("probe tunnel certificates 1.18.53 regression: PASS")
