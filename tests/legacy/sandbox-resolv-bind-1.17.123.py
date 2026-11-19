#!/usr/bin/env python3
"""1.17.123 regression: no loopback allow at all; Core's own resolv.conf is bound over /etc/resolv.conf (core.sandbox canary, fix 1).

dev02 (Core 1.17.122) showed six loopback rows that connected: IPAddressAllow=127.0.0.53/32 allowed the whole stub, every port. Now:

* no IPAddressAllow exists anywhere in a unit, in an argv or in a probe; ADDRESS_DENY is unchanged and numeric;
* each start writes Core's own resolv.conf (root-owned 0644, at most three IPv4 nameserver lines, atomic) under RUN_ROOT and the unit binds it
  read only over /etc/resolv.conf; /etc/resolv.conf is no longer bound from the host;
* the upstream list comes from /run/systemd/resolve/resolv.conf; only when that file is missing is /etc/resolv.conf read, and only as a
  regular file (never the symlink to the stub);
* selftest: an upstream inside a denied range (the 127.0.0.53 stub, loopback, private, link-local, carrier-grade NAT), this server's own
  address or its gateway makes the sandbox NOT ready with a plain reason naming the address; IPv6 upstreams are skipped; never an allow;
  the 1.17.122 code let the stub through, so these checks can fail;
* a start keeps only upstreams that are in the proven list and still in the upstream file; none left is sandbox_unavailable;
* the canary's loopback group tries 127.0.0.53 on the listening ports and on 22, 80, 443, 1024, 4430 and 4433; the old 'resolver' rows are
  gone; 'other resolver dropped' tests the host's own resolv.conf entries and the stub, so it always has a row.

Not runnable here: real systemd (whether the bind over /etc/resolv.conf works under TemporaryFileSystem=/etc, whether 127.0.0.53 is refused).
tests/sandbox-canary-1.17.123.sh proves that on dev02.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_123a", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_123a", "sandbox-fake-runner-1.17.120.py")
sh, must, make_runner, BASE, start, header, unit_log = H.sh, H.must, H.make_runner, H.BASE, H.start, H.header, H.unit_log
CHMODS, CHOWNS, norm = H.CHMODS, H.CHOWNS, H.norm

# ---- ADDRESS_DENY is unchanged
must(sh.ADDRESS_DENY == "127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 224.0.0.0/4 ff00::/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7", sh.ADDRESS_DENY)

# ---- an end-to-end start through the helper with a fake systemd
make_runner("ai.chat", body="print('hello')")
H.write_ready_status(resolver="9.9.9.9", resolvers=["9.9.9.9", "1.1.1.1"])
Path(sh.RESOLV_UPSTREAM).write_text("nameserver 9.9.9.9\nnameserver 8.8.8.8\noptions edns0\n", encoding="utf-8")
code, frames = start(header("ai.chat"))
must(code == 0 and frames[-1]["t"] == "end", frames)
log = unit_log(frames[0]["run_id"])
props = log["props"]
must("IPAddressAllow" not in json.dumps(log), "no IPAddressAllow in the unit, the argv or anywhere in what systemd-run was given")
bound = f"BindReadOnlyPaths={sh.core_resolv_file()}:/etc/resolv.conf"
must(props.count(bound) == 1, [p for p in props if "resolv" in p])
must("BindReadOnlyPaths=/etc/resolv.conf" not in props and not any(p.startswith("BindReadOnlyPaths=/etc/resolv.conf") for p in props), "the host's file is not bound")
must("IPAddressDeny=" + sh.ADDRESS_DENY + " 203.0.113.5/32 203.0.113.1/32" in props, "own address and gateway added (tests/sandbox-local-deny-1.17.123.py)")
core = sh.core_resolv_file()
must(core.parent == sh.RUN_ROOT, core)
must(core.read_bytes() == b"# written by Tec-Tac core.sandbox at each start\nnameserver 9.9.9.9\n", core.read_bytes())  # 8.8.8.8 is listed but not proven, 1.1.1.1 proven but gone
must(CHMODS[norm(core)] == 0o644 and CHOWNS[norm(core)] == (0, 0), "root-owned 0644")
must(not [p for p in sh.RUN_ROOT.iterdir() if p.name.startswith(".resolv.conf.")], "atomic write leaves no temp file")

# ---- the resolv.conf text: IPv4 only, at most three
text = sh.resolv_conf_bytes(["1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4"]).decode()
must([line for line in text.splitlines() if not line.startswith("#")] == ["nameserver 1.1.1.1", "nameserver 8.8.8.8", "nameserver 9.9.9.9"], text)
for bad in ("::1", "2606:4700:4700::1111", "localhost", "1.1.1.1 extra", ""):
    try:
        sh.resolv_conf_bytes([bad])
    except ValueError:
        continue
    raise AssertionError(("resolv_conf_bytes took", bad))
must(b"IPAddress" not in sh.resolv_conf_bytes(["1.1.1.1"]), "")

# ---- upstream gone since the selftest, or never proven: a refusal and no Core file rewrite
core.unlink()
Path(sh.RESOLV_UPSTREAM).write_text("nameserver 4.4.4.4\n", encoding="utf-8")
code, frames = start(header("ai.chat"), hold=False)
must(frames[0].get("code") == "sandbox_unavailable" and not core.exists(), frames)
H.write_ready_status()  # back to 9.9.9.9
Path(sh.RESOLV_UPSTREAM).write_text("nameserver 9.9.9.9\n", encoding="utf-8")

# ---- where the upstream list is read
up, fb = BASE / "t-upstream.conf", BASE / "t-fallback.conf"
fb.write_text("nameserver 1.1.1.1\n", encoding="utf-8")
up.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
must("9.9.9.9" in sh.read_upstream_text(up, fb) and "1.1.1.1" not in sh.read_upstream_text(up, fb), "the upstream file wins")
up.unlink()
must("1.1.1.1" in sh.read_upstream_text(up, fb), "missing upstream file: the regular /etc/resolv.conf is the fallback")
must(sh.read_upstream_text(up, BASE / "no-such-file") == "", "neither readable: empty, never an exception")
link = BASE / "t-link.conf"
try:
    os.symlink(str(fb), str(link))
except (OSError, NotImplementedError, AttributeError):
    print("[NOTE] symlink not allowed on this system: the 'fallback must not be a symlink' case was skipped")
else:
    must(sh.read_upstream_text(up, link) == "", "a symlink fallback (the stub link on a systemd-resolved server) is never read")

# ---- selftest: an upstream inside a denied range, an own address or the gateway is NOT ready, naming the address


def selftest(resolv, fake=None):
    return F.run_selftest(sh, H.RUN, BASE, fake or F.Fake(), resolv)


good = selftest("nameserver 156.38.225.225\nnameserver 156.38.225.226\n")
must(good["ready"] is True and good["resolvers"] == ["156.38.225.225", "156.38.225.226"] and good["dns_method"] == "resolv_conf_bind", good)
for address, why in (("127.0.0.53", "a range a run may not reach"), ("127.0.0.1", "a range a run may not reach"), ("10.1.2.3", "a range a run may not reach"), ("172.20.0.2", "a range a run may not reach"),
                     ("192.168.1.1", "a range a run may not reach"), ("100.64.9.9", "a range a run may not reach"), ("169.254.1.1", "a range a run may not reach"),
                     ("129.232.197.50", "own addresses"), ("129.232.197.1", "gateway")):
    bad = selftest(f"nameserver {address}\n")
    must(bad["ready"] is False and bad["dns_ok"] is False and bad["resolver"] == "" and bad["resolvers"] == [], (address, bad))
    must(address in bad["reason"] and why in bad["reason"] and "public resolver" in bad["reason"], (address, bad["reason"]))
    must(bad["checks"]["dns"]["ok"] is False and address in bad["checks"]["dns"]["detail"], bad["checks"]["dns"])
# one public upstream does not make a private one acceptable (the literal rule: any upstream in a denied range)
mixed = selftest("nameserver 156.38.225.225\nnameserver 10.0.0.2\n")
must(mixed["ready"] is False and "10.0.0.2" in mixed["reason"], mixed)
# the probe is never run for a denied upstream: no automatic allow, no second chance
fake = F.Fake()
selftest("nameserver 127.0.0.53\n", fake)
must(not [c for c in fake.calls if c[0] == "dns"], "no DNS probe for a denied upstream")
# IPv6 upstreams are skipped (a run has AF_INET only); only IPv6 means no usable upstream
v6 = selftest("nameserver 2606:4700:4700::1111\n")
must(v6["ready"] is False and "no IPv4 name server" in v6["reason"], v6)
both = selftest("nameserver 2606:4700:4700::1111\nnameserver 156.38.225.225\n")
must(both["ready"] is True and both["resolvers"] == ["156.38.225.225"], both)

# ---- the canary: the stub on every listening port plus the six that connected, the host's own entries as 'other resolver'
RUNNER_SOURCE = (H.ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
spec = importlib.util.spec_from_file_location("canary_runner_123", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
seen, rows = [], []
runner.tcp_connect = lambda host, port, timeout=1.5, family=None: (seen.append((host, port)) or ("connected" if (host, port) == ("127.0.0.53", 4433) else "EPERM"))
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
runner.g_loopback({"ports": [22, 5432], "stub": "127.0.0.53", "stub_ports": [22, 80, 443, 1024, 4430, 4433, 5432]})
names = [r[0] for r in rows]
for port in (22, 80, 443, 1024, 4430, 4433, 5432):
    must(f"loopback 127.0.0.53:{port}" in names, (port, names))
must(not [n for n in names if n.startswith("resolver ")], "the old 'resolver <ip>:<port>' rows are gone")
must(next(r for r in rows if r[0] == "loopback 127.0.0.53:4433")[1] == "SUCCEEDED", "a connection to the stub is an attack that succeeded")
must(all(r[1] == "OK" for r in rows if r[0] != "loopback 127.0.0.53:4433"), rows)
rows.clear()
answers = {"127.0.0.53": False, "10.0.0.2": False, "9.9.9.9": True}
runner.dns_query = lambda address, name="example.com": answers[address]
runner.g_dns({"resolver": "9.9.9.9", "other_resolvers": ["127.0.0.53", "10.0.0.2"]})
must(rows == [("allowed resolver answers", "OK", "answered"), ("other resolver 127.0.0.53 dropped", "OK", "dropped"), ("other resolver 10.0.0.2 dropped", "OK", "dropped")], rows)
rows.clear()
answers["127.0.0.53"] = True
runner.g_dns({"resolver": "9.9.9.9", "other_resolvers": ["127.0.0.53"]})
must(rows[1] == ("other resolver 127.0.0.53 dropped", "SUCCEEDED", "answered"), rows)
rows.clear()
runner.g_dns({"resolver": "9.9.9.9", "other_resolvers": []})
must(not any(r[1] == "SKIP" for r in rows) and 'row("other resolver dropped", "SKIP"' not in RUNNER_SOURCE, "no SKIPPED path in the dns group")
# the table: without any 'other resolver' row the group is NOT RUN, and the stub rows are required
table = sh.group_table("DNS", "dns", "x", [{"attack": "allowed resolver answers", "tag": "OK", "actual": "answered"}])
must(any(r["verdict"] == "NOT RUN" and "other resolver" in r["attack"] for r in table), table)
table = sh.group_table("Loopback", "loopback", "x", [{"attack": "loopback 127.0.0.1:22", "tag": "OK", "actual": "EPERM"}])
must(any(r["verdict"] == "NOT RUN" and "127.0.0.53" in r["attack"] for r in table), table)

# ---- the plan the planner hands the unit (run_canary), through a fake collect
PLANS = {}


def collect(group, plan, **kwargs):
    PLANS[group] = plan
    return {"stdout": b"", "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": os.urandom(16).hex(), "frames": []}


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 4096 127.0.0.53:53 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n", ""
        if argv[0] == "ip" and argv[1] == "-o":
            return 0, "2: eth0    inet 129.232.197.50/24 scope global eth0\n", ""
        return 0, "default via 129.232.197.1 dev eth0\n" if argv[1] == "-4" else "", ""


sh._cancel_rows = lambda c, s: []
sh._holders_search = lambda token, unit: []
sh._credential_file_ready = lambda unit: True
sh._foreign_credential_probe = lambda unit: "DENIED"
sh._latency_rows = lambda c, s: []
sh._concurrency_rows = lambda c, s: []
sh._credential_rows = lambda c, s, *a, **k: []
sh.CANARY_MARKER_DIRS = ()
sh.CANARY_REAL_FILES = ()
Path(sh.RESOLV_CONF).write_text("nameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 9.9.9.9\n", encoding="utf-8")
sh.run_canary(status={"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}, collect=collect, outside=Outside())
must(PLANS["loopback"]["stub"] == "127.0.0.53" and set(PLANS["loopback"]["stub_ports"]) >= {22, 53, 80, 443, 1024, 4430, 4433}, PLANS["loopback"])
must("resolver" not in PLANS["loopback"] and "resolver_ports" not in PLANS["loopback"], PLANS["loopback"])
must(PLANS["dns"]["resolver"] == "9.9.9.9" and PLANS["dns"]["other_resolvers"] == ["127.0.0.53", "10.0.0.2"], PLANS["dns"])  # the proven 9.9.9.9 is not 'other'
# even when /etc/resolv.conf lists nothing else, the stub is tested: the row exists on every server
Path(sh.RESOLV_CONF).write_text("nameserver 9.9.9.9\n", encoding="utf-8")
sh.run_canary(status={"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}, collect=collect, outside=Outside())
must(PLANS["dns"]["other_resolvers"] == ["127.0.0.53"], PLANS["dns"])

print("[TEST] PASS sandbox resolv bind 1.17.123")
