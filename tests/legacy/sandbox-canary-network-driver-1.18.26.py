#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch B, item 6; the own-domain row added): the root driver tests/sandbox-canary-network-1.18.26.py, with a stubbed socket layer and a fake launch.

Django-free, 127.0.0.1 only. The host's own probes (connect, resolve, ping, ss) are replaced, so nothing here opens a 0.0.0.0 listener or contacts a
public address. Covered:

* every one of the 31 rows is expected OK; the exit list names the 12 former ATTACK rows, the 9 proxy rows (pb-proxy-refuse-own-public-address is the new one) and the two either-result rows;
* the own-public-address row (1.18.26): the plan picks the server's public IPv4 address as its own names answer it in real DNS and a dashed-IP wildcard name for it
  (``<a-b-c-d>.sslip.io``), which must really resolve to that address; the name is listed in the run's allowed_hosts; an OK counts only with the proxy's audit reason
  address_blocked (no audit row, or another reason, is NOT RUN); a plan with no public address, or a wildcard name that does not resolve, is NOT RUN with the plain reason;
* the own-domain row: the driver lists an own name in the run's allowed_hosts, an OK counts only with the proxy's audit reason own_name (no audit row, or another reason, is NOT RUN); when the helper fails closed the row is NOT RUN with the helper's plain reason;
* the driver gives the run its door (``allowed_hosts`` on its copy of the row) and adds only the group choice, never touching the helper's constants;
* the listener row is decided from the HOST's own ``ss -ltnH``: the port listed in the host namespace is ATTACK SUCCEEDED, not listed is OK, an
  ``ss`` that gives nothing is NOT RUN; the host's own connect attempts stay as detail only;
* every attack row has its own host control in the plan (tcp 443 and 80 to 1.1.1.1, tcp 443 to 9.9.9.9, tcp 443 to the allowed host's address, udp 53
  to 9.9.9.9 and to the first listed name server); SKIPPED passes only for a row whose own control is missing, and fails when the control exists;
* ATTACK SUCCEEDED, NOT RUN, an unknown row and a missing row each fail; an unstartable unit is exit 2; a clean table is exit 0.

Not runnable here: the real unit (dev02: tests/sandbox-canary-1.18.26.sh).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load("sandbox_canary_driver_126", ROOT / "tests" / "sandbox-canary-network-1.18.26.py")
sh = load_helper(ROOT, "sandbox_helper_driver_125")
R = load("sandbox_runner_driver_125", ROOT / "scripts" / "sandbox-canary-runner.py")

# ------------------------------------------------------------------------------------------------ the tables
must(len(D.ROWS) == 31 and [name for name, _rid, _key in D.ROWS] == list(R.NETWORK_ROW_NAMES), "the driver and the runner list the same 31 rows in the same order")
must(len({rid for _n, rid, _k in D.ROWS}) == 31, "stable, unique row ids")
must(set(D.EXIT_LIST_FORMER_ATTACK) | set(D.EXIT_LIST_PROXY) | set(D.EXIT_LIST_ALSO) <= {rid for _n, rid, _k in D.ROWS}, "the exit list names only known rows")
must(len(D.EXIT_LIST_FORMER_ATTACK) == 12 and len(D.EXIT_LIST_PROXY) == 9 and len(D.EXIT_LIST_ALSO) == 2, "12 + 9 + 2 named rows")
summary = D.summary_line([{"verdict": "OK"}] * 31)
for rid in (*D.EXIT_LIST_FORMER_ATTACK, *D.EXIT_LIST_PROXY, *D.EXIT_LIST_ALSO):
    must(rid in summary, rid)
must("0 ATTACK SUCCEEDED, 0 NOT RUN" in summary and "expected before Patch B" not in summary, summary)
text = (ROOT / "tests" / "sandbox-canary-network-1.18.26.py").read_text(encoding="utf-8")
must('("0.0.0.0"' not in text and "bind(" not in text, "the driver binds nothing")
must(b"\r" not in (ROOT / "tests" / "sandbox-canary-network-1.18.26.py").read_bytes(), "LF")
# every control key the driver names is a key build_plan fills
plan_keys = set(D.build_plan.__code__.co_consts) | {"loopback_ports", "own", "gateways"}
for _name, rid, key in D.ROWS:
    must(key is None or key in plan_keys, (rid, key))

# ------------------------------------------------------------------------------------------------ build_plan: one host control per row
calls = []


def host_tcp(host, port, family=D.socket.AF_INET):
    calls.append((host, port))
    return (host, port) in WORKS


D.host_tcp = host_tcp
D.host_resolve = lambda name: ["93.184.216.34"] if name in ("example.com", "api.example.com") else []
D.host_dns_ask = lambda address, name="example.com": address in ASKS
D.host_ping = lambda address: PING
D.host_ss = lambda: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8000 0.0.0.0:*\n"
D.host_name_server = lambda: "127.0.0.53"
WORKS = {("1.1.1.1", 443), ("1.1.1.1", 80), ("9.9.9.9", 443), ("93.184.216.34", 443)}
ASKS = {"9.9.9.9", "127.0.0.53"}
PING = True


OWN_NAMES = ["api.example.test", "core.example.test", "rmm.example.test"]
D.socket.getfqdn = lambda *a: "core.example.test"  # the driver reads the host's own fqdn; no lookup happens


class FakeHelper:
    """The real helper's parsers, with the launch, status and address readers replaced."""

    def __getattr__(self, name):
        return getattr(sh, name)

    def local_deny_now(self):
        return {"addresses": ["127.0.0.1", "203.0.113.5"], "gateways": ["203.0.113.1"], "extra": []}

    def own_server_names(self):
        return list(OWN_NAMES)

    def resolve_own_names(self, names, **kw):
        return list(PUBLIC_ANSWERS)

    def upstream_resolvers(self):
        return ["192.0.2.53"]

    def dns_lookup_name(self, name, servers):
        return True, set(WILDCARD_ANSWERS.get(name, ()))


PUBLIC_ANSWERS = ["127.0.1.1", "93.184.216.34"]
PUBLIC_NAME = "93-184-216-34.sslip.io"
WILDCARD_ANSWERS = {PUBLIC_NAME: ["93.184.216.34"]}
helper = FakeHelper()
plan = D.build_plan(helper, "example.com")
must(plan["host_tcp443_1111"] and plan["host_tcp80_1111"] and plan["host_tcp443_9999"] and plan["host_tcp443_allowed"], plan)
must(plan["host_udp53_listed"] and plan["host_udp53_9999"] and plan["host_dns"] and plan["host_ping"], plan)
must(plan["own"] == ["203.0.113.5"] and plan["gateways"] == ["203.0.113.1"] and plan["loopback_ports"] and plan["allowed_host_address"] == "93.184.216.34", plan)
must(plan["listed_name_server"] == "127.0.0.53" and plan["allowed_host"] == "example.com", plan)
must(plan["own_domain"] == "api.example.test" and plan["own_domain_reason"] == "", "a dotted own name that is not the fqdn is chosen")
OWN_NAMES[:] = ["core.example.test"]
must(D.build_plan(helper, "example.com")["own_domain"] == "core.example.test", "else the fqdn")
OWN_NAMES[:] = ["api.example.test", "core.example.test", "rmm.example.test"]
must(plan["own_public_name"] == PUBLIC_NAME and plan["own_public_reason"] == "", ("the public address's dashed-IP name is chosen", plan["own_public_name"], plan["own_public_reason"]))
PUBLIC_ANSWERS[:] = ["127.0.1.1", "10.0.0.5"]
none_plan = D.build_plan(helper, "example.com")
must(none_plan["own_public_name"] == "" and "no public IPv4 address" in none_plan["own_public_reason"], none_plan)
PUBLIC_ANSWERS[:] = ["93.184.216.34", "2001:4860:4860::8888"]
WILDCARD_ANSWERS.clear()
nodns = D.build_plan(helper, "example.com")
must(nodns["own_public_name"] == "" and "does not resolve to 93.184.216.34" in nodns["own_public_reason"], nodns)
WILDCARD_ANSWERS[PUBLIC_NAME] = ["198.51.100.7"]
must(D.build_plan(helper, "example.com")["own_public_name"] == "", "a wildcard name that answers another address proves nothing")
WILDCARD_ANSWERS[PUBLIC_NAME] = ["93.184.216.34"]
PUBLIC_ANSWERS[:] = ["127.0.1.1", "93.184.216.34"]


class Closed(FakeHelper):
    Refusal = sh.Refusal

    def own_server_names(self):
        raise sh.Refusal("sandbox_unavailable", "this server's own names could not be read from Tactical's settings file")


closed_plan = D.build_plan(Closed(), "example.com")
must(closed_plan["own_domain"] == "" and "could not be read" in closed_plan["own_domain_reason"], closed_plan)
must(closed_plan["own_public_name"] == "" and "could not be read" in closed_plan["own_public_reason"], "the public-address row fails closed with the helper's plain text too")
WORKS.discard(("1.1.1.1", 80))
ASKS.discard("127.0.0.53")
plan = D.build_plan(helper, "example.com")
must(plan["host_tcp80_1111"] is False and plan["host_tcp443_1111"] is True and plan["host_udp53_listed"] is False and plan["host_udp53_9999"] is True,
     "each control is its own")
D.host_resolve = lambda name: []
plan = D.build_plan(helper, "nothing.example")
must(plan["allowed_host_address"] == "" and plan["host_tcp443_allowed"] is False and plan["host_dns"] is False, plan)
WORKS.add(("1.1.1.1", 80))
ASKS.add("127.0.0.53")
D.host_resolve = lambda name: ["93.184.216.34"] if name in ("example.com", "api.example.com") else []

# ------------------------------------------------------------------------------------------------ the listener row
watch = D.Watch(["203.0.113.5"])
must(D.listener_entry(None, watch)["verdict"] == "NOT RUN", "the runner printed nothing and never listened")
printed = {"actual": "socket refused: EAFNOSUPPORT", "verdict": "OK"}
must(D.listener_entry(printed, watch)["verdict"] == "OK", "no listener announced: the runner's own row is used")
watch.port = 43211
must(D.listener_entry(printed, watch)["verdict"] == "NOT RUN" and "proves nothing" in D.listener_entry(printed, watch)["actual"], "ss could not be read")
watch.host_listing = True
entry = D.listener_entry(printed, watch)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "43211" in entry["actual"] and "host's own network namespace" in entry["actual"], entry)
watch.host_listing = False
watch.attempts = ["127.0.0.1:43211 no", "203.0.113.5:43211 no"]
entry = D.listener_entry(printed, watch)
must(entry["verdict"] == "OK" and "private" in entry["actual"] and "host connect attempts" in entry["actual"], entry)
# the Watch reads the host's listening sockets after the run printed its port (a fake ss; no real connect)
D.SS_DELAY, D.CONNECT_PAUSE = 0, 0
for ss_text, expected in (("LISTEN 0 4 0.0.0.0:43211 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", True), ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", False)):
    D.host_ss = lambda ss_text=ss_text: ss_text
    watch = D.Watch(["203.0.113.5"])
    watch.helper = helper
    watch.feed(b"CANARYROW\tx\tOK\ty\nCANARYLISTEN\t43211\n")
    watch.thread.join(10)
    must(watch.port == 43211 and watch.host_listing is expected and watch.tried.is_set(), (ss_text, watch.host_listing))
    must(len(watch.attempts) == 2 * D.CONNECT_TRIES, "the old connect attempts are kept as detail")
D.host_ss = lambda: ""
watch = D.Watch([])
watch.helper = helper
watch.feed(b"CANARYLISTEN\t43212\n")
watch.thread.join(10)
must(watch.host_listing is None, "an ss that says nothing proves nothing")
D.host_ss = lambda: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"


# ------------------------------------------------------------------------------------------------ a whole run with a fake launch
def out_frame(text):
    return {"t": "out", "b": base64.b64encode(text.encode()).decode()}


def all_rows(overrides=None, drop=(), extra=()):
    overrides = overrides or {}
    lines = []
    for name, rid, _key in D.ROWS:
        if rid in drop:
            continue
        tag, actual = overrides.get(rid, ("OK", "nothing reachable"))
        lines.append(f"CANARYROW\t{name}\t{tag}\t{actual}\n")
    for name in extra:
        lines.append(f"CANARYROW\t{name}\tOK\tx\n")
    lines.append("CANARYLISTEN\t43999\n")
    return "".join(lines)


def run_main(output, plan_overrides=None, refuse=None, listed=False, audit=("api.example.test", "own_name"), public_audit=(PUBLIC_NAME, "address_blocked")):
    seen = {}
    saved = (sh.launch, sh.read_status)
    saved_audit = sh.append_audit_safely

    def fake_launch(row, **kw):
        seen["row"], seen["kw"] = row, kw
        if refuse:
            raise sh.Refusal(refuse)
        kw["emit"](out_frame(output))
        kw["emit"]({"t": "end", "reason": "exit", "exit": 0})
        if audit is not None:  # what egress_finish writes after the run; the driver reads it through the helper's own audit writer
            pairs = [pair for pair in (audit, public_audit) if pair is not None]
            sh.append_audit_safely("run.egress", {"rows": [{"host": host, "port": 443, "result": "refused", "reason": reason, "up": 0, "down": 0} for host, reason in pairs]})

    sh.launch, sh.read_status = fake_launch, lambda: {"ready": True}
    sh.append_audit_safely = lambda event, detail: None  # nothing is written to a real audit log on this PC
    D.host_ss = lambda: ("LISTEN 0 4 0.0.0.0:43999 0.0.0.0:*\n" if listed else "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
    lines = []
    old_plan = D.build_plan

    def plan_with(helper_, allowed):
        built = old_plan(helper_, allowed)
        built.update(plan_overrides or {})
        return built

    D.build_plan = plan_with
    try:
        code = D.main(helper=sh, out=lines.append)
    finally:
        sh.launch, sh.read_status = saved
        D.build_plan = old_plan
        sh.append_audit_safely = saved_audit
    return code, lines, seen


sh.local_deny_now = lambda: {"addresses": ["127.0.0.1", "203.0.113.5"], "gateways": ["203.0.113.1"], "extra": []}
sh.own_server_names = lambda: list(OWN_NAMES)
sh.resolve_own_names = lambda names, **kw: list(PUBLIC_ANSWERS)
sh.upstream_resolvers = lambda: ["192.0.2.53"]
sh.dns_lookup_name = lambda name, servers: (True, set(WILDCARD_ANSWERS.get(name, ())))
before_choices = tuple(sh.canary_row()["parameters"]["group"]["choices"])
code, lines, seen = run_main(all_rows())
must(code == 0, "\n".join(lines))
must(seen["row"]["allowed_hosts"] == ["example.com", "api.example.test", PUBLIC_NAME] and "patchb_network" in seen["row"]["parameters"]["group"]["choices"], "the run has its door and the group choice")
must(seen["kw"]["parameters"] == {"group": "patchb_network"} and json.loads(seen["kw"]["input_data"])["allowed_host"] == "example.com", seen["kw"]["parameters"])
must(tuple(sh.canary_row()["parameters"]["group"]["choices"]) == before_choices and "patchb_network" not in sh.CANARY_GROUPS, "the helper's own constants are untouched")
must(sum(1 for line in lines if line.startswith("ok   pb-")) == 31 and not any(line.startswith("FAIL") for line in lines), "\n".join(lines))
must(any("PATCH B EXIT LIST: 0 ATTACK SUCCEEDED, 0 NOT RUN" in line for line in lines), "the exit list is printed")
# the own-domain row: an OK counts only with the audit reason own_name
code, lines, _seen = run_main(all_rows(), audit=("api.example.test", "address_blocked"))
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-domain: NOT RUN") for line in lines) and any("not own_name" in line for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows(), audit=None)
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-domain: NOT RUN") for line in lines) and any("no row for api.example.test" in line for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-own-domain": ("SUCCEEDED", "the proxy opened a tunnel (200) to api.example.test:443")}))
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-domain: ATTACK SUCCEEDED") for line in lines), "a hairpin tunnel is a hole")
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-own-domain": ("NOTRUN", "this server's own names could not be read")}), {"own_domain": ""}, audit=None)
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-domain: NOT RUN") for line in lines), "a helper that fails closed is NOT RUN")
# the own-public-address row: an OK counts only with the audit reason address_blocked
code, lines, _seen = run_main(all_rows(), public_audit=(PUBLIC_NAME, "own_name"))
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-public-address: NOT RUN") for line in lines) and any("not address_blocked" in line for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows(), public_audit=None)
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-public-address: NOT RUN") for line in lines) and any("no row for " + PUBLIC_NAME in line for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-own-public-address": ("SUCCEEDED", "the proxy opened a tunnel (200) to " + PUBLIC_NAME + ":443")}))
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-public-address: ATTACK SUCCEEDED") for line in lines), "a hairpin through the public address is a hole")
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-own-public-address": ("NOTRUN", "no public address is known")}), {"own_public_name": ""}, public_audit=None)
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-own-public-address: NOT RUN") for line in lines), "no name to test is NOT RUN, with its reason printed")
# the listener row decided by the host: listed in the host namespace is a failure even when the runner says OK
code, lines, _seen = run_main(all_rows(), listed=True)
must(code == 1 and any(line.startswith("FAIL pb-listener-from-host: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
# any row that shows an attack, did not run, is unknown or is missing fails
code, lines, _seen = run_main(all_rows({"pb-public-tcp-443-1-1-1-1": ("SUCCEEDED", "connected: the run can reach it")}))
must(code == 1 and any(line.startswith("FAIL pb-public-tcp-443-1-1-1-1: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-ip-literal": ("SUCCEEDED", "the proxy opened a tunnel (200) to 1.1.1.1:443")}))
must(code == 1, "a 200 on a refusal row fails")
code, lines, _seen = run_main(all_rows({"pb-proxy-allowed-443": ("NOTRUN", "the proxy door is not reachable")}))
must(code == 1 and any(line.startswith("FAIL pb-proxy-allowed-443: NOT RUN") for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows(drop=("pb-default-route",)))
must(code == 1 and any(line.startswith("FAIL pb-default-route: NOT RUN") for line in lines), "a missing row is NOT RUN")
code, lines, _seen = run_main(all_rows(extra=("a row nobody listed",)))
must(code == 1 and any("not a row the driver knows" in line for line in lines), "\n".join(lines))
# SKIPPED passes only for a row whose OWN control is missing
code, lines, _seen = run_main(all_rows({"pb-tcp-443-ipv6": ("SKIP", "no IPv6 route")}), {"host_ipv6": False})
must(code == 0 and any("pb-tcp-443-ipv6: SKIPPED: skipped (this row's own host control is missing)" in line for line in lines), "\n".join(lines))
code, lines, _seen = run_main(all_rows({"pb-tcp-443-ipv6": ("SKIP", "no IPv6 route")}), {"host_ipv6": True})
must(code == 1 and any("pb-tcp-443-ipv6: SKIPPED: UNEXPECTED" in line for line in lines), "a SKIP although the control exists fails")
code, lines, _seen = run_main(all_rows({"pb-public-tcp-80-1-1-1-1": ("SKIP", "x")}), {"host_tcp80_1111": False})
must(code == 0, "the row's own control is false: skipped is fine")
code, lines, _seen = run_main(all_rows({"pb-public-tcp-80-1-1-1-1": ("SKIP", "x")}), {"host_tcp443_1111": False})
must(code == 1, "another row's control being false does not excuse this row")
code, lines, _seen = run_main(all_rows({"pb-sock-af-packet": ("SKIP", "x")}))
must(code == 1, "a row with no control may never be skipped")
code, lines, _seen = run_main(all_rows({"pb-proxy-refuse-own-address": ("SKIP", "no address")}), {"own": []})
must(code == 0, "the own-address proxy row is skipped when the plan has no own address")
# an unstartable unit is exit 2
code, lines, _seen = run_main("", refuse="sandbox_unavailable")
must(code == 2 and any("could not be started (sandbox_unavailable)" in line for line in lines), lines)
print("[TEST] PASS sandbox canary network driver 1.18.26")
