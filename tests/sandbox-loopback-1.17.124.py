#!/usr/bin/env python3
"""1.17.124 regression: the loopback group probes in parallel so every row reports (core.sandbox canary, fix 3).

dev02 (Core 1.17.123) reported '1 of 6 results' for 127.0.0.53: a dropped TCP connect to loopback times out (the egress filter drops the SYN,
there is no EPERM), g_loopback tried every listening port on 127.0.0.1 and the stub one after another at 1.5 s each, and the 20 s run budget
ran out before the stub rows. Now: a pool of at most 12 workers, about 1 s per probe, the six stub ports before any other port, an in-unit
deadline from the plan, and a larger run time for the group. A probe that did not finish by the deadline prints no row, so the helper's table
reports NOT RUN ('N of 6 results'); the result words are unchanged.

Not runnable here: real dropped packets (dev02).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_124l", "sandbox-harness-1.17.118.py")
sh, must = H.sh, H.must
spec = importlib.util.spec_from_file_location("canary_runner_124l", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
STUB = sh.CANARY_STUB
STUB_PORTS = list(sh.CANARY_STUB_PORTS)


class Fake:
    """A tcp_connect that sleeps and counts how many calls run at once."""

    def __init__(self, delay=0.02, connect=()):
        self.delay, self.connect, self.live, self.peak, self.calls, self.lock = delay, set(connect), 0, 0, [], threading.Lock()

    def __call__(self, host, port, timeout=1.5, family=None):
        with self.lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
            self.calls.append((host, port, timeout))
        try:
            time.sleep(self.delay)
            return "connected" if (host, port) in self.connect else "timeout"
        finally:
            with self.lock:
                self.live -= 1


def run(plan, fake):
    out = io.StringIO()
    runner.tcp_connect = fake
    with contextlib.redirect_stdout(out):
        runner.g_loopback(plan)
    return out.getvalue().splitlines()


def parsed(lines):
    return sh.parse_runner_rows("\n".join(lines).encode())


ports = list(range(1000, 1200))  # 200 ports
plan = {"ports": ports, "stub": STUB, "stub_ports": STUB_PORTS + [p for p in ports if p not in STUB_PORTS], "loopback_seconds": 20}

# ---- every stub row and every 127.0.0.1 row is printed inside the deadline; the pool never exceeds 12 threads; the stub comes first
fake = Fake()
started = time.monotonic()
lines = run(plan, fake)
elapsed = time.monotonic() - started
rows = parsed(lines)
names = [r["attack"] for r in rows]
must(len(rows) == len(lines), "every printed line is a whole row")
for port in plan["stub_ports"]:
    must(f"loopback {STUB}:{port}" in names, port)
for port in ports:
    must(f"loopback 127.0.0.1:{port}" in names, port)
must(0 < fake.peak <= 12 and fake.peak > 1, f"peak concurrency {fake.peak}: parallel, never above 12 workers")
must(elapsed < 10, f"{len(fake.calls)} probes of 0.02 s took {elapsed:.1f} s, one at a time it would take {len(fake.calls) * 0.02:.1f} s")
must(all(c[2] <= 1.0 for c in fake.calls), "about 1 s per probe, not 1.5")
first_calls = [c[:2] for c in fake.calls[:6]]
must(all(h == STUB for h, _p in first_calls) and {p for _h, p in first_calls} == set(STUB_PORTS), first_calls)  # the six stub ports before any other port
stub_done = max(i for i, n in enumerate(names) if n.startswith(f"loopback {STUB}:"))
must(names.index("loopback 127.0.0.1:1000") > 5 and all(n.startswith("loopback") for n in names), "the stub rows are first in the queue")
must(all(r["tag"] == "OK" and r["actual"] == "timeout" for r in rows), "a timeout is OK")
must(len(fake.calls) == len(plan["stub_ports"]) + 2 * len(ports), len(fake.calls))

# ---- a connected stub probe is SUCCEEDED; a connected 127.0.0.1 probe too
fake = Fake(connect={(STUB, 443), ("127.0.0.1", 1005)})
rows = parsed(run(plan, fake))
tags = {r["attack"]: r["tag"] for r in rows}
must(tags[f"loopback {STUB}:443"] == "SUCCEEDED" and tags["loopback 127.0.0.1:1005"] == "SUCCEEDED", tags)
must(sum(1 for t in tags.values() if t == "SUCCEEDED") == 2, "only the connected ones")
table = sh.group_table("Loopback", "loopback", "x", rows)
must(sum(1 for r in table if r["verdict"] == "ATTACK SUCCEEDED") == 2, "the table says ATTACK SUCCEEDED for them")

# ---- an errno from tcp_connect (or one it raises) is OK
runner.tcp_connect = lambda host, port, timeout=1.5, family=None: "ECONNREFUSED"
out = io.StringIO()
with contextlib.redirect_stdout(out):
    runner.g_loopback({"ports": [22], "stub": STUB, "stub_ports": [22], "loopback_seconds": 5})


def raising(host, port, timeout=1.5, family=None):
    raise OSError(97, "no family")


runner.tcp_connect = raising
out2 = io.StringIO()
with contextlib.redirect_stdout(out2):
    runner.g_loopback({"ports": [22], "stub": STUB, "stub_ports": [22], "loopback_seconds": 5})
must(all(r["tag"] == "OK" for r in parsed(out.getvalue().splitlines())) and len(parsed(out2.getvalue().splitlines())) == 3, out2.getvalue())

# ---- a fake that hangs past the deadline leaves rows missing: the table says NOT RUN with 'N of 6 results'
slow = Fake(delay=0.4)
hang_plan = {"ports": ports[:60], "stub": STUB, "stub_ports": STUB_PORTS + ports[:60], "loopback_seconds": 0.5}
rows = parsed(run(hang_plan, slow))
stub_rows = [r for r in rows if r["attack"].startswith(f"loopback {STUB}:")]
must(len(rows) < len(STUB_PORTS) + 120, f"{len(rows)} rows: the deadline cut the rest")
# nothing finished in time at all (every probe sleeps past the deadline): no row, NOT RUN
none = parsed(run({"ports": ports[:30], "stub": STUB, "stub_ports": STUB_PORTS, "loopback_seconds": 0.1}, Fake(delay=0.3)))
table = sh.group_table("Loopback", "loopback", "x", none)
missing = [r for r in table if r["verdict"] == "NOT RUN"]
must(missing and any("0 of 6 results" in r["actual"] for r in missing), table)
# three of six stub rows only
partial = [{"attack": f"loopback {STUB}:{p}", "tag": "OK", "actual": "timeout"} for p in STUB_PORTS[:3]] + [{"attack": "loopback 127.0.0.1:80", "tag": "OK", "actual": "x"}]
table = sh.group_table("Loopback", "loopback", "x", partial)
must(any(r["verdict"] == "NOT RUN" and "3 of 6 results" in r["actual"] for r in table), table)
must(sh.CANARY_REQUIRED["loopback"][1][1] == ("loopback " + STUB + ":", 6), sh.CANARY_REQUIRED["loopback"])

# ---- lines are never interleaved: every line of a busy run is one whole row (checked on the real row() through the lock)
fake = Fake(delay=0.001)
lines = run({"ports": list(range(2000, 2300)), "stub": STUB, "stub_ports": STUB_PORTS, "loopback_seconds": 20}, fake)
must(len(lines) == len(STUB_PORTS) + 600, len(lines))
must(all(line.count(chr(9)) == 3 and line.startswith("CANARYROW" + chr(9) + "loopback ") for line in lines), "no torn or merged line")
must(hasattr(runner, "ROW_LOCK"), "the row printer holds a lock")

# ---- run_canary: the loopback group gets a long run time and a deadline below it, stub ports first
PLANS = {}


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 4096 127.0.0.53:53 0.0.0.0:*\nLISTEN 0 511 *:443 *:*\nLISTEN 0 128 [::]:22 [::]:*\n", ""
        if argv[0] == "ip" and argv[1] == "-o":
            return 0, "2: eth0    inet 192.168.1.5/24 scope global eth0\n", ""
        return 0, "default via 192.168.1.1 dev eth0\n" if argv[1] == "-4" else "", ""


def collect(group, plan, **kwargs):
    PLANS[group] = (plan, kwargs)
    return {"stdout": b"", "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": os.urandom(16).hex(), "frames": []}


sh._cancel_rows = lambda c, s: []
sh._holders_search = lambda token, unit: []
sh._credential_file_ready = lambda unit: True
sh._foreign_credential_probe = lambda unit: "DENIED"
sh._latency_rows = lambda c, s: []
sh._concurrency_rows = lambda c, s: []
sh._credential_rows = lambda c, s, *a, **k: []
sh._limit_rows = lambda c, s: []
sh.CANARY_MARKER_DIRS = ()
sh.CANARY_REAL_FILES = ()
sh.read_abstract_names = lambda: []
sh.run_canary(status={"ready": True, "resolver": "9.9.9.9", "resolvers": ["9.9.9.9"]}, collect=collect, outside=Outside())
plan, kwargs = PLANS["loopback"]
must(kwargs.get("run_seconds", 0) >= 60 and plan["loopback_seconds"] < kwargs["run_seconds"], (plan, kwargs))
must(plan["stub_ports"][:6] == STUB_PORTS and plan["stub_ports"][6:] == [53], plan["stub_ports"])
must(kwargs["run_seconds"] <= sh.LIMITS["run_seconds"][1], "under the Core ceiling")
sh.canary_row(run_seconds=kwargs["run_seconds"])  # does not raise: still under every ceiling

print("[TEST] PASS sandbox loopback 1.17.124")
