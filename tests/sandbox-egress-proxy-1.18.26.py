#!/usr/bin/env python3
"""1.18.26 regression (held Low, sandbox-egress.py): own-name resolution at proxy start has a time limit.

Django-free, no socket opened. The 1.18.25 proxy test (sandbox-egress-proxy-1.18.25.py) keeps covering the rules; this one covers start-up:

* the addresses the helper handed in (``own_name_addresses``) are used and the proxy does no lookup at all;
* with none handed in, the proxy looks the names up itself in worker threads with a total limit of OWN_LOOKUP_SECONDS (3 s): a resolver that
  sleeps for ever cannot hold start-up, a name that misses the deadline adds nothing and stays refused by name;
* a resolver that fails, returns junk or raises an unexpected error never breaks start-up;
* a fast name still contributes its addresses when another name is slow;
* with no own names at all there is nothing to look up.
"""
from __future__ import annotations

import importlib.util
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_egress_126", ROOT / "scripts" / "sandbox-egress.py")
eg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eg)
must(eg.OWN_LOOKUP_SECONDS == 3.0, "the limit is 3 s")

PUBLIC = "93.184.216.34"
BASE_CONFIG = {"allowed_hosts": ["example.com"], "own": ["10.0.0.5"], "gateways": [], "fqdn": "core.example.test"}


def make(config, resolve, clock=time.monotonic):
    return eg.Egress({**BASE_CONFIG, **config}, "audit.jsonl", resolve=resolve, probe_bind=lambda address: False, clock=clock)


# handed-in addresses: no lookup
def never(*args):
    raise AssertionError("a lookup was made although the helper handed in the addresses")


proxy = make({"own_names": ["a.example.test", "b.example.test"], "own_name_addresses": [PUBLIC]}, never)
must(proxy.fqdn_addresses == {PUBLIC}, proxy.fqdn_addresses)

# none handed in and a resolver that never returns: start-up is bounded
release = threading.Event()


def sleeping(name, port):
    release.wait(30)
    return [(2, 1, 6, "", (PUBLIC, 0))]


started = time.monotonic()
proxy = make({"own_names": ["a.example.test", "b.example.test", "c.example.test"]}, sleeping)
elapsed = time.monotonic() - started
must(elapsed < 5.5 and proxy.fqdn_addresses == set(), ("start-up is bounded and a slow name adds nothing", elapsed, proxy.fqdn_addresses))
must("a.example.test" in proxy.own_names, "a slow name stays refused by name")
release.set()


# a fast name still counts when another is slow; junk and errors are harmless
def mixed(name, port):
    if name.startswith("slow"):
        threading.Event().wait(30)
    if name.startswith("junk"):
        return [("bad",)]
    if name.startswith("err"):
        raise RuntimeError("boom")
    if name.startswith("oserr"):
        raise OSError("no such name")
    return [(2, 1, 6, "", (PUBLIC + "", 0)), (10, 1, 6, "", ("2001:db8::1%eth0", 0, 0, 0))]


started = time.monotonic()
proxy = make({"own_names": ["fast.example.test", "slow.example.test", "junk.example.test", "err.example.test", "oserr.example.test"]}, mixed)
must(time.monotonic() - started < 5.5, "bounded")
must(proxy.fqdn_addresses == {PUBLIC, "2001:db8::1"}, proxy.fqdn_addresses)

# no names: nothing to do (the fqdn alone is an own name, so give a config without one)
proxy = make({"fqdn": "", "own_names": []}, never)
must(proxy.fqdn_addresses == set(), "nothing to look up")

# a fake clock reaches the deadline at once: the join waits no time
ticks = iter([0.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0])
proxy = make({"own_names": ["x.example.test"]}, lambda name, port: [(2, 1, 6, "", (PUBLIC, 0))], clock=lambda: next(ticks, 10.0))
must(isinstance(proxy.fqdn_addresses, set), "a clock past the deadline still returns a set")
print("[TEST] PASS sandbox egress proxy 1.18.26")
