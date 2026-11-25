#!/usr/bin/env python3
"""1.18.47 regression: docs/probe-transport.md names every operation, close code, limit constant, refusal code, disconnect reason, close reason and
audit action in the code, with the number the code holds (the 1.18.46 docs test, extended for the tunnel); the fleet-size note and the pool numbers
match POOL_SPECS; docs/capabilities.md names 1.1.0 and the framework >=1.18.47 floor; the docs carry no forbidden filler."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must = H.pt, H.tun, H.must
ROOT = H.ROOT

doc = (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
caps = (ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
meta = pt.probe_transport_contract_metadata()

must(doc.startswith("# Network Probe transport (Core 1.18.47)"), "the title names the release")
for operation in meta["operations"]:
    must(f"`{operation}" in doc, "the docs name " + operation)
must(len(meta["operations"]) == 10, "ten operations (1.18.50: set_tunnel_site)")
for code in meta["close_codes"]:
    if code.isdigit():
        must(re.search(r"\| " + code + r" \|", doc), "a close-code table has " + code)
for code in ("4401", "4403", "4404", "4409", "1002", "1009", "1013", "1001", "4503"):
    must(re.search(r"\| " + code + r" \|", doc.split("### Close codes")[1]), "the tunnel close-code table has " + code)
for constant in ("MAX_FRAME_BYTES", "MAX_FRAMES_PER_SECOND", "MAX_BAD_FRAMES", "PING_SECONDS", "MAX_UNANSWERED_PINGS", "PRESENCE_SECONDS", "RECHECK_SECONDS",
                 "RECHECK_JITTER_SECONDS", "RECHECK_GRACE_SECONDS", "FAILURES_PER_ADDRESS_PER_MINUTE", "FAILURES_PER_PROBE_PER_MINUTE"):
    value = getattr(pt, constant)
    must(f"`{constant}`" in doc, "the docs name " + constant)
    shown = "16 KiB" if constant == "MAX_FRAME_BYTES" else str(value)
    must(re.search(re.escape(f"`{constant}`") + r"[^.\n]*?\(?" + re.escape(shown), doc), f"the docs give {constant} as {shown}")
for text in pt.REFUSAL_CODES + pt.DISCONNECT_REASONS:
    must(f"`{text}`" in doc, "the docs name " + text)
for reason in ("wrong_scheme", "malformed_header"):
    must(f"`{reason}`" in doc, reason)
for action in ("custom:probe-connect", "custom:probe-disconnect", "custom:probe-refused", "custom:probe-tunnel-ticket", "custom:probe-tunnel-connect",
               "custom:probe-tunnel-end", "custom:probe-tunnel-refused"):
    must(f"`{action}`" in doc, action)
for needle in ("/ws/tfd/network-probe/", "Probe <probe_id>.<key>", "networkprobe", "probe-transport", "AD-54", "C2", "never the key", "authenticate(probe_id, key)",
               "1 second", "60 seconds", "4401"):
    must(needle in doc, needle)
must("never cross" in doc, "credentials never cross")
must("C2 is the tunnel (1.1.0)" in doc and "later release" not in doc and "not in this one" not in doc, "the 1.0.0 line 'C2 is a later release' is replaced")
must("No contract file for 1.18.47 exists" in doc, "the missing contract file is said plainly")

# ---------------------------------------------------------------- the tunnel section
tunnel = doc[doc.index("## The tunnel (contract 1.1.0)"):]
for operation in ("issue_tunnel_ticket", "end_tunnel", "end_tunnels_for_probe", "tunnel_status", "set_tunnel_site"):
    must(f"`{operation}(" in tunnel, "the tunnel section names " + operation)
for route in (tun.CONSOLE_SOCKET_PATH, tun.PROBE_SIDE_SOCKET_PATH):
    must(f"wss://<host>{route}" in tunnel, "route " + route)
for needle in ("Authorization: Ticket <43 characters>", "X-Tunnel-Session: <uuid>", "tectac-console://open?host=<server host>&ticket=<ticket>", "[type u8][stream u32 BE][payload]",
               "`OPEN` is 1, `DATA` 2, `ACK` 3 and `CLOSE` 4", "bytes_up", "Console to probe", "source: \"core\"", "no resume", "shared Django cache", "`tunnel.closed`", "`tunnel.close`",
               "framework 1.18.47 or later", "`protocol_error`"):
    must(needle in tunnel, needle)
for reason in tun.ALL_REASONS:
    must(f"`{reason}`" in tunnel, "the docs name the close reason " + reason)
for ended_by in tun.ENDED_BY_VALUES:
    must(f"`{ended_by}`" in tunnel, ended_by)
numbers = {
    "MAX_SESSIONS": (tun.MAX_SESSIONS, "50"), "MAX_SESSIONS_PER_PROBE": (tun.MAX_SESSIONS_PER_PROBE, "5"), "MAX_SESSIONS_PER_ENGINEER": (tun.MAX_SESSIONS_PER_ENGINEER, "3"),
    "TICKETS_PER_MINUTE": (tun.TICKETS_PER_MINUTE, "10"), "TICKET_TTL_SECONDS": (tun.TICKET_TTL_SECONDS, "60"), "IDLE_SECONDS_MAX": (tun.IDLE_SECONDS_MAX, "900"),
    "CAP_SECONDS_MAX": (tun.CAP_SECONDS_MAX, "14400"), "PAIR_WAIT_SECONDS": (tun.PAIR_WAIT_SECONDS, "15"), "BUFFER_CAP_BYTES": (tun.BUFFER_CAP_BYTES, "1 MiB"),
    "RECHECK_SECONDS": (tun.RECHECK_SECONDS, "300"), "MAX_DATA": (tun.MAX_DATA, "32 KiB"), "STREAM_WINDOW": (tun.STREAM_WINDOW, "128 KiB"), "MAX_STREAMS": (tun.MAX_STREAMS, "8"),
    "SESSION_IN_FLIGHT": (tun.SESSION_IN_FLIGHT, "1 MiB"),
}
must(tun.MAX_DATA == 32768 and tun.STREAM_WINDOW == 131072 and tun.BUFFER_CAP_BYTES == 1048576 and tun.SESSION_IN_FLIGHT == 1048576, "the byte sizes")
for name, (value, shown) in numbers.items():
    must(isinstance(value, int), name)
    must(re.search(re.escape(f"`{name}`") + r"[^.\n]*?" + re.escape(shown), tunnel), f"the docs give {name} as {shown}")
must(tun.MAX_FRAME == 5 + 32768 and "5 + 32768" in tunnel, "the frame length rule")
must((tun.IDLE_SECONDS_DEFAULT, tun.CAP_SECONDS_DEFAULT) == (900, 14400) and "default 900" in tunnel and "default 14400" in tunnel and "60 to 900" in tunnel and "60 to 14400" in tunnel, "idle and cap ranges")
must(tun.PENDING_SLOT_SECONDS == 75 and "75 seconds while pending" in tunnel and tun.SLOT_GRACE_SECONDS == 60 and "plus 60 seconds once open" in tunnel, "slot expiry")
must(tun.SEND_TIMEOUT_SECONDS == 5 and "takes over 5 seconds" in tunnel and tun.WATCH_TICK_SECONDS == 5 and "5 second tick" in tunnel and tun.RECHECK_JITTER_SECONDS == 30, "relay and watcher timing")

# ---------------------------------------------------------------- the fleet-size note and the pools
fleet = doc[doc.index("## Fleet size and pools"):doc.index("## The tunnel (contract 1.1.0)")]
must("up to 500 connected probes" in fleet and "50 concurrent tunnel sessions" in fleet and "jittered back-off" in fleet, "the fleet-size note")
for pool, (threads, backlog) in pt.POOL_SPECS.items():
    must(re.search(r"\| `" + pool + r"` \| `\(" + str(threads) + ", " + str(backlog) + r"\)` \|", fleet), f"the docs give {pool} as ({threads}, {backlog})")
must(f"`UNAUTHENTICATED_IN_FLIGHT` is {pt.UNAUTHENTICATED_IN_FLIGHT}" in fleet and pt.UNAUTHENTICATED_IN_FLIGHT == 64, "the in-flight ceiling")
must("RecursionError" in fleet, "the nested-frame note")

# ---------------------------------------------------------------- capabilities.md
section = caps[caps.index("## Core probe transport"):caps.index("## Core agent downloads")]
must("`core.probe_transport` 1.3.0" in section and ">=1.18.53" in section and "`console_certificate_required`" in section and ">=1.18.50" in section and "docs/probe-transport.md" in section and ">=1.18.47" in section and ">=1.18.46" in section, "the capabilities section")
for operation in meta["operations"]:
    must(f"`{operation}`" in section, "the capabilities section names " + operation)
must("/ws/tfd/probe-tunnel/" in section and "/ws/tfd/network-probe/tunnel/" in section, "the capabilities section names the routes")
must("\r\n" in caps and caps.count("\n") == caps.count("\r\n"), "capabilities.md stays CRLF")
# 1.18.53: the Console certificate section of the tunnel docs names every reason, header and audit name in the code
cert = doc[doc.index("### Console certificates (1.3.0)"):doc.index("### Frames")]
for reason in tun.CERT_REASONS:
    must(f"`{reason}`" in cert, "the certificate section names " + reason)
for needle in ("X-Tectac-Console-Cert", "X-Tectac-Console-Proof", "X-Tectac-Server-Proof", "console_certificate_required", "custom:console-cert-refused", "cert_serial",
               "`certificate_revoked`, `certificate_expired` or `ca_replaced`", "framework 1.18.53 or later", "120 seconds", "docs/console-certificates.md"):
    must(needle in cert, needle)
must(all(f"`{reason}`" in doc.split("### Close codes")[1] for reason in tun.CERT_REASONS), "the close-code table names the seven reasons")

for label, text in (("probe-transport.md", doc), ("capabilities section", section)):
    lowered = text.lower()
    for forbidden in ("kindly", "don't hesitate", "do not hesitate", "ethnocentric", "please be advised"):
        must(forbidden not in lowered, f"{label} has {forbidden!r}")
print("PASS probe transport docs 1.18.47")
