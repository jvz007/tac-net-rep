#!/usr/bin/env python3
"""Regression 1.18.6: core.client_address 1.0.0 returns Core's own client address and adds no trust. Runs without Django."""
import ast
import importlib.util
import inspect
import ipaddress
import json
import logging
import sys
import types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


logging.disable(logging.CRITICAL)  # the policy-error case logs one expected warning


def must(cond, message):
    if not cond:
        raise AssertionError(message)


# Pull the real resolver functions out of session_security.py by ast (the module itself needs Django).
source = (APP / "session_security.py").read_text(encoding="utf-8")
tree = ast.parse(source)
wanted = {"_ip", "_trusted_networks", "_is_trusted", "_parse_forwarded_for", "effective_client_ip"}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
must({n.name for n in nodes} == wanted, "resolver functions found")
POLICY = {"trusted_proxies": ["127.0.0.1/32", "::1/128"]}
CALLS = []
ns: dict = {"ipaddress": ipaddress, "Any": Any, "annotations": __import__("__future__").annotations}


def get_effective_policy(user, request):
    CALLS.append(1)
    if isinstance(POLICY, Exception):
        raise POLICY
    return POLICY


ns["get_effective_policy"] = get_effective_policy
exec(compile(ast.Module(body=nodes, type_ignores=[]), "session_security_extract", "exec"), ns)  # noqa: S102 - code of this repo

fake_pkg = types.ModuleType("catest")
fake_pkg.__path__ = []
fake_ss = types.ModuleType("catest.session_security")
fake_ss.effective_client_ip = ns["effective_client_ip"]
sys.modules["catest"] = fake_pkg
sys.modules["catest.session_security"] = fake_ss
spec = importlib.util.spec_from_file_location("catest.client_address", APP / "client_address.py")
ca = importlib.util.module_from_spec(spec)
sys.modules["catest.client_address"] = ca
spec.loader.exec_module(ca)
client_address = ca.client_address


class Req:
    def __init__(self, **meta):
        self.META = meta


def call(**meta):
    return client_address(Req(**meta))


# trusted loopback peer
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9") == "203.0.113.9", "left-most via trusted peer")
must(call(REMOTE_ADDR="127.0.0.1") == "127.0.0.1", "no headers gives the peer")
# two hops: nearest proxy trusted, the next one not, so we stop at the untrusted one
POLICY = {"trusted_proxies": ["127.0.0.1/32"]}
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9, 198.51.100.20") == "198.51.100.20", "stops at the untrusted hop")
POLICY = {"trusted_proxies": ["127.0.0.1/32", "198.51.100.20/32"]}
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9, 198.51.100.20") == "203.0.113.9", "both hops trusted")
POLICY = {"trusted_proxies": ["127.0.0.1/32", "::1/128"]}
# untrusted peer: never believes a header
must(call(REMOTE_ADDR="198.51.100.7", HTTP_X_FORWARDED_FOR="203.0.113.9") == "198.51.100.7", "spoofed X-Forwarded-For")
must(call(REMOTE_ADDR="198.51.100.7", HTTP_FORWARDED="for=203.0.113.9") == "198.51.100.7", "spoofed Forwarded")
must(call(REMOTE_ADDR="198.51.100.7", HTTP_X_REAL_IP="203.0.113.9") == "198.51.100.7", "spoofed X-Real-IP")
# Forwarded with quotes, brackets and ports
must(call(REMOTE_ADDR="127.0.0.1", HTTP_FORWARDED='for="[2001:db8::1]:4711";proto=https') == "2001:db8::1", "Forwarded ipv6 with port")
must(call(REMOTE_ADDR="127.0.0.1", HTTP_FORWARDED="for=203.0.113.5:1234") == "203.0.113.5", "Forwarded ipv4 with port")
# X-Real-IP only when nothing else
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="203.0.113.6") == "203.0.113.6", "X-Real-IP alone")
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="203.0.113.6", HTTP_X_FORWARDED_FOR="203.0.113.7") == "203.0.113.7", "X-Forwarded-For wins")
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="203.0.113.6", HTTP_FORWARDED="for=203.0.113.8") == "203.0.113.8", "Forwarded beats X-Real-IP")
# ipv6 peer
must(call(REMOTE_ADDR="::1", HTTP_X_FORWARDED_FOR="203.0.113.9") == "203.0.113.9", "ipv6 loopback peer")
must(call(REMOTE_ADDR="2001:db8::5", HTTP_X_FORWARDED_FOR="203.0.113.9") == "2001:db8::5", "ipv6 untrusted peer")
# garbage
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="not-an-ip") == "127.0.0.1", "garbage header gives the peer")
must(call(REMOTE_ADDR="garbage") == "", "garbage peer is unknown")
must(call() == "", "no REMOTE_ADDR is unknown")
must(client_address(object()) == "", "object without META")
must(client_address(None) == "", "None")
must(client_address(Req.__new__(Req)) == "", "request whose META is missing")
# a failure of the policy read never propagates
POLICY = RuntimeError("database down")
must(call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9") == "", "policy error gives ''")
POLICY = {"trusted_proxies": ["127.0.0.1/32", "::1/128"]}
# DRF-style wrapper: META reached through __getattr__
class Drf:
    def __init__(self, inner):
        self._request = inner

    def __getattr__(self, name):
        return getattr(self._request, name)


must(client_address(Drf(Req(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9"))) == "203.0.113.9", "DRF wrapper")
# same answer as Core's own resolver, and no policy keyword on the public function
for meta in (
    {"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_FOR": "203.0.113.9, 127.0.0.1"},
    {"REMOTE_ADDR": "198.51.100.7", "HTTP_X_FORWARDED_FOR": "203.0.113.9"},
    {"REMOTE_ADDR": "::1", "HTTP_FORWARDED": "for=203.0.113.1"},
):
    must(client_address(Req(**meta)) == ns["effective_client_ip"](Req(**meta)), meta)
params = list(inspect.signature(client_address).parameters)
must(params == ["request"], params)
must(list(inspect.signature(ca.ClientAddressProvider.client_address).parameters) == ["request"], "provider signature")
CALLS.clear()
call(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9")
must(len(CALLS) == 1, "one policy read per call")

# source checks
rows = None
rules = None
for node in ast.parse((APP / "contracts.py").read_text(encoding="utf-8")).body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id == "CORE_CONTRACTS":
            rows = ast.literal_eval(node.value)
        if node.targets[0].id == "RULES":
            rules = ast.literal_eval(node.value)
must(rows and rules, "contracts parsed")
pairs = [(r["import_path"], r["name"]) for r in rows]
must(len(pairs) == len(set(pairs)), "no repeated import_path and name pair")
mine = [r for r in rows if r["import_path"] == "tec_tac.client_address"]
must(len(mine) == 1 and mine[0]["name"] == "client_address", mine)
row = mine[0]
must(row["kind"] == "python" and row["audience"] == "consumer/backend" and row["area"] == "client-address", row)
for needle in ("1.18.6", "additive", ">=1.18.6", "'' means unknown", "refuse", "trusted_proxies", "no policy argument", "Nginx", "core.client_address"):
    must(needle in row["purpose"], needle)
must(hasattr(ca, row["name"]) and callable(getattr(ca, row["name"])), "row resolves to a real attribute")
must(any("core.client_address" in rule and "1.18.6" in rule for rule in rules), "RULES sentence")

meta = ca.client_address_contract_metadata()
must(meta["id"] == "core.client_address" == ca.CAPABILITY_ID and meta["version"] == "1.0.0" == ca.CAPABILITY_VERSION, meta)
must(meta["operations"] == ["client_address"] and meta["requires_framework"] == ">=1.18.6", meta)
must(meta["trust_source"] == "core.session_security trusted_proxies" and "empty_means" in meta, meta)
json.dumps(meta)
doc = (ROOT / "docs" / "client-address.md").read_text(encoding="utf-8")
caps = (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8")
for text in (doc, caps):
    for needle in ("core.client_address", "1.0.0", "client_address(request)", ">=1.18.6"):
        must(needle in text, needle)
must("module_id=\"core\"" in (APP / "client_address.py").read_text(encoding="utf-8"), "registered for core")

apps = (APP / "apps.py").read_text(encoding="utf-8")
idx = apps.index("register_core_client_address_capability()")
before, after = apps[:idx], apps[idx:]
must(before.rstrip().endswith("from .client_address import register_core_client_address_capability"), "import before call")
must(before.rsplit("try:", 1)[1].count("except") == 0 and after.split("except Exception:", 1)[0].count("try:") == 0, "inside a try")
must("except Exception:" in after.split("register_core_sandbox_capability", 1)[0], "guarded by except Exception")

# core.session_security is untouched
must('CAPABILITY_VERSION = "2.0.0"' in source, "session_security stays 2.0.0")
must("def effective_client_ip(request, *, policy" in source, "effective_client_ip unchanged")
installer = (ROOT / "install.sh").read_text(encoding="utf-8")
must("core.client_address" not in installer, "install.sh unchanged")

# line endings: each touched file keeps one style (CRLF where the repo has it, LF in the new files)
for rel, crlf in (
    ("framwork/tec_tac/client_address.py", False), ("docs/client-address.md", False), ("VERSION", False), ("tec_tac_package.json", False),
    ("RELEASE_NOTES_1.18.6.md", False), ("tests/client-address-1.18.6.py", False), ("tests/version-1.18.6.py", False),
    ("framwork/tec_tac/apps.py", True), ("framwork/tec_tac/contracts.py", True), ("docs/capabilities.md", True),
):
    data = (ROOT / rel).read_bytes()
    must(data, rel)
    crlfs = data.count(b"\r\n")
    lfs = data.count(b"\n")
    must((crlfs == lfs) if crlf else (crlfs == 0), f"{rel}: mixed or wrong line endings ({crlfs} CRLF of {lfs})")

print("[TEST] PASS client address 1.18.6")
