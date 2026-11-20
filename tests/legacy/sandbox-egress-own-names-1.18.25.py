#!/usr/bin/env python3
"""1.18.25 regression (AD-65 condition, held Medium): the helper learns every name this server answers to and hands them to the egress proxy.

Django-free; the settings file is a temp file, the resolver is a stub, no socket is opened. Covered:

* ``read_tactical_names`` reads ALLOWED_HOSTS, CORS_ORIGIN_WHITELIST, CORS_ALLOWED_ORIGINS and MESH_SITE from a temp file; a leading dot is stripped,
  the host part of a URL is taken, '*' and IP literals and single labels are skipped, names are lower-cased;
* the file is parsed with ast and never run: a side-effect expression (and an assignment from a call) leaves a sentinel unwritten and adds nothing;
* a missing file, a symlink, an oversized file, an unparsable file and a file that is not UTF-8 raise Refusal('sandbox_unavailable');
* ``own_server_names`` adds the fqdn and a dotted host name, and raises Refusal when there is no dotted name at all;
* ``resolve_own_names`` collects addresses, caches for 60 s, still returns when one name does not resolve, and raises Refusal when no lookup finishes in time
  (1.18.26: it now asks real DNS through a ``lookup`` stub; the stubs below stand in for it, see sandbox-own-public-address-1.18.26.py);
* ``egress_config_bytes`` carries own_names and own_name_addresses and still carries fqdn;
* ``egress_start`` fails closed (Refusal, nothing created, no systemctl call) when the names cannot be read, and writes own_names into the config when they can.

Not runnable here: real DNS, the settings file of a real Tactical server (dev02 shows the row pb-proxy-refuse-own-domain).
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="tectac-ownnames-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


loader = importlib.machinery.SourceFileLoader("sandbox_helper_own", str(ROOT / "scripts" / "sandbox-helper.py"))
spec = importlib.util.spec_from_loader(loader.name, loader)
sh = importlib.util.module_from_spec(spec)
loader.exec_module(sh)


def settings(text, name="local_settings.py"):
    path = BASE / name
    path.write_text(text, encoding="utf-8")
    return path


def refused(call):
    try:
        call()
    except sh.Refusal as exc:
        return exc.code == "sandbox_unavailable" and bool(exc.message)
    return False


SENTINEL = BASE / "sentinel"
good = settings(f'''
import os
ALLOWED_HOSTS = ["api.example.test", ".rmm.example.test", "*", "10.0.0.5", "localhost", "API.Example.Test"]
CORS_ORIGIN_WHITELIST = ["https://rmm.example.test", "https://other.example.test:8443"]
CORS_ALLOWED_ORIGINS = ("https://alt.example.test",)
MESH_SITE = "https://mesh.example.test"
OTHER = "never.example.test"
DEBUG = open({str(SENTINEL)!r}, "w").write("ran")
HOSTS2 = [open({str(SENTINEL)!r}, "w").write("ran")]
ALLOWED_HOSTS_EXTRA = ["extra.example.test"]
''')
names = sh.read_tactical_names(good)
must(names == {"api.example.test", "rmm.example.test", "other.example.test", "alt.example.test", "mesh.example.test"}, names)
must(not SENTINEL.exists(), "the settings file is never run")

# an assignment that is not a literal adds nothing and does not run
tricky = settings(f'ALLOWED_HOSTS = [open({str(SENTINEL)!r}, "w").write("x")]\nMESH_SITE = "https://mesh.example.test"\n', "tricky.py")
must(sh.read_tactical_names(tricky) == {"mesh.example.test"} and not SENTINEL.exists(), "a call in a value is skipped, never run")

# refusals
must(refused(lambda: sh.read_tactical_names(BASE / "missing.py")), "missing file")
must(refused(lambda: sh.read_tactical_names(settings("ALLOWED_HOSTS = [", "broken.py"))), "unparsable file")
(BASE / "binary.py").write_bytes(b"\xff\xfe\x00bad")
must(refused(lambda: sh.read_tactical_names(BASE / "binary.py")), "not UTF-8")
big = BASE / "big.py"
big.write_text("# " + "x" * (sh.OWN_SETTINGS_MAX_BYTES + 10) + "\nALLOWED_HOSTS = ['a.example.test']\n", encoding="utf-8")
must(refused(lambda: sh.read_tactical_names(big)), "oversized file")
link = BASE / "link.py"
try:
    os.symlink(str(good), str(link))
    flag = getattr(os, "O_NOFOLLOW", 0)
    must(not flag or refused(lambda: sh.read_tactical_names(link)), "a symlink is refused (O_NOFOLLOW)")
except (OSError, NotImplementedError):
    print("note: symlinks are not allowed on this PC; the O_NOFOLLOW open is covered by the source check below")
text = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
body = text[text.index("def read_tactical_names"):text.index("def own_server_names")]
must("O_NOFOLLOW" in body and "ast.parse" in body and "literal_eval" in body and "exec(" not in body and "import_module" not in body, "ast only, no follow")

# own_server_names
sh.socket.getfqdn = lambda *a: "Core.Example.Test"
sh.socket.gethostname = lambda: "core"
found = sh.own_server_names(good)
must("core.example.test" in found and "core" not in found and "api.example.test" in found, found)
sh.socket.gethostname = lambda: "box.lan.example.test"
must("box.lan.example.test" in sh.own_server_names(good), "a dotted host name is kept")
empty = settings("ALLOWED_HOSTS = ['*']\n", "empty.py")
sh.socket.getfqdn = lambda *a: "localhost"
sh.socket.gethostname = lambda: "localhost"
must(refused(lambda: sh.own_server_names(empty)), "no dotted name at all: fail closed")
must(refused(lambda: sh.own_server_names(BASE / "missing.py")), "no settings file: fail closed")

# resolve_own_names
calls = []


def resolver(name, port=None, *rest):
    calls.append(name)
    if name == "gone.example.test":
        raise OSError("no such name")
    return [(2, 1, 6, "", (f"198.51.100.{len(name) % 200 + 1}", 0)), (10, 1, 6, "", ("2001:db8::1%eth0", 0, 0, 0))]


def dns(name, servers):  # 1.18.26: the real-DNS lookup stub (a public address, so the public address is known)
    return (name != "gone.example.test"), ({"93.184.216.34"} if name != "gone.example.test" else set())


KW = {"lookup": dns, "servers": ["192.0.2.53"]}
sh._own_cache.update({"at": 0.0, "key": None, "value": None})
now = [1000.0]
got = sh.resolve_own_names(["api.example.test", "gone.example.test"], resolver=resolver, clock=lambda: now[0], **KW)
must("2001:db8::1" in got and all("%" not in a for a in got) and len(calls) == 2, (got, calls))
again = sh.resolve_own_names(["gone.example.test", "api.example.test"], resolver=resolver, clock=lambda: now[0] + 30, **KW)
must(again == got and len(calls) == 2, "cached for 60 s")
now[0] += 61
sh.resolve_own_names(["api.example.test", "gone.example.test"], resolver=resolver, clock=lambda: now[0], **KW)
must(len(calls) == 4, "looked up again after 60 s")
# every lookup hangs: fail closed in about the limit
release = threading.Event()


def hang(name, servers):
    release.wait(10)
    return True, set()


sh._own_cache.update({"at": 0.0, "key": None, "value": None})
started = time.monotonic()
must(refused(lambda: sh.resolve_own_names(["a.example.test", "b.example.test"], lookup=hang, servers=["192.0.2.53"], resolver=resolver, seconds=0.3)), "all lookups time out: fail closed")
must(time.monotonic() - started < 3, "bounded")
release.set()
must(sh.OWN_RESOLVE_SECONDS == 5 and sh.OWN_CACHE_SECONDS == 60, "5 s and 60 s")

# the config carries the new keys and keeps fqdn
config = json.loads(sh.egress_config_bytes(["example.com"], {"addresses": ["203.0.113.5"], "gateways": []}, "core.example.test", ["b.example.test", "a.example.test"], ["198.51.100.2"]))
must(config["own_names"] == ["a.example.test", "b.example.test"] and config["own_name_addresses"] == ["198.51.100.2"] and config["fqdn"] == "core.example.test", config)
old = json.loads(sh.egress_config_bytes(["example.com"], {}, "core.example.test"))
must(old["own_names"] == [] and old["own_name_addresses"] == [], "the old three-argument call still works")
must("own_name" in sh.EGRESS_REASONS, "own_name is a known audit reason")

# egress_start fails closed before anything is made, and passes the names on
sh.EGRESS_DOOR_ROOT, sh.EGRESS_CONFIG_ROOT = BASE / "door", BASE / "config"
sh.EGRESS_STATE_ROOT = BASE / "state"
sh.TACTICAL_LOCAL_SETTINGS = BASE / "missing.py"
cmds = []
rid = os.urandom(16).hex()
row = {"id": "x", "allowed_hosts": ["api.anthropic.com"]}
try:
    sh.egress_start(row, rid, {"addresses": [], "gateways": []}, run_cmd=lambda c: cmds.append(c) or (0, "", ""))
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable", exc.code)
else:
    raise AssertionError("no readable settings file: egress_start must refuse")
must(not cmds and not sh.EGRESS_DOOR_ROOT.exists() and not sh.EGRESS_CONFIG_ROOT.exists(), "nothing created and nothing started")
sh.TACTICAL_LOCAL_SETTINGS = good
sh.socket.getfqdn = lambda *a: "core.example.test"
sh.OWN_RESOLVER = resolver
sh.upstream_resolvers = lambda read=None: ["192.0.2.53"]
sh.dns_lookup_name = dns
sh._own_cache.update({"at": 0.0, "key": None, "value": None})
try:
    sh.egress_start(row, rid, {"addresses": [], "gateways": []}, run_cmd=lambda c: cmds.append(c) or (0, "", ""))
except sh.Refusal:
    pass  # the door socket does not exist on this PC; the config was written before the start call
written = json.loads((sh.EGRESS_CONFIG_ROOT / f"{rid}.json").read_text(encoding="utf-8")) if (sh.EGRESS_CONFIG_ROOT / f"{rid}.json").exists() else None
must(written is None or "api.example.test" in written["own_names"], written)
must(any("start" in c for c in cmds), "the proxy start is asked only after the names were read")
# the selftest row uses the same function, so it reports the same plain reason
must("egress_start(row, run_id, local, run_cmd=runner.run_cmd)" in text and "_check(checks, \"egress_proxy\", False, exc.message)" in text, "the selftest reports the refusal text")
print("[TEST] PASS sandbox egress own names 1.18.25")
