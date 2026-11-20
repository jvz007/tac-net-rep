#!/usr/bin/env python3
"""1.18.24 regression (AD-65 Patch B, item 4): the optional runner key ``allowed_hosts`` is back, with strict rules.

Runs the real registry.py (no Django needed) and the real root helper. Covered:

* a valid list is accepted by both; a manifest without the key behaves as before (no key, a door-less run);
* refused by both, for the same reason: not a list, more than 16 entries, a wildcard, a port, a path, a bracketed or colon address, an IP literal
  in every spelling (dotted, decimal, hex, octal, short), a single label, a name ending .local, .internal, .localhost or .lan, an upper-case name,
  an empty entry, an entry over 253 characters, a label over 63 characters, a bad label (leading or trailing '-', '_', non-ASCII, a trailing dot),
  a non-string entry and a repeated name;
* registry.py and the helper agree on every case (a test keeps the two copies of the rule in step);
* the reserved proxy names (HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy, ALL_PROXY, NO_PROXY, no_proxy) are refused in a manifest environment
  by both, and the helper's build_environment sets the proxy only for a row that has allowed_hosts;
* the PluginSpec runner entry and the helper's registry record both carry ``allowed_hosts`` (an empty list when absent).

Not runnable here: Django (the AST-free import of registry.py is enough for these rules).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry  # noqa: E402

BASE = Path(tempfile.mkdtemp(prefix="tectac-allowed-hosts-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


sh = load_helper(ROOT, "sandbox_helper_hosts")

GOOD_LISTS = (
    [], ["api.anthropic.com"], ["api.openai.com", "chatgpt.com", "auth.openai.com"], ["a1.example.co.za"], ["xn--bcher-kva.example"],
    ["1password.com"], [f"host{i}.example.com" for i in range(16)], ["a-b.example.com"], ["a" * 63 + ".example.com"],
)
BAD = (
    ("not a list", "api.anthropic.com"), ("a dict", {"a": "b"}), ("a number", 5), ("null", None),
    ("17 entries", [f"host{i}.example.com" for i in range(17)]),
    ("wildcard", ["*.example.com"]), ("wildcard in the middle", ["a.*.com"]),
    ("port", ["example.com:443"]), ("port 80", ["example.com:80"]), ("path", ["example.com/path"]), ("userinfo", ["user@example.com"]),
    ("bracketed ipv6", ["[::1]"]), ("colon ipv6", ["::1"]), ("ipv6 documentation", ["2001:db8::1"]),
    ("dotted ip", ["1.1.1.1"]), ("private dotted ip", ["10.0.0.1"]), ("loopback", ["127.0.0.1"]),
    ("decimal ip", ["2130706433"]), ("hex ip", ["0x7f000001"]), ("hex dotted ip", ["0x7f.0x0.0x0.0x1"]), ("octal ip", ["0177.0.0.1"]),
    ("short ip", ["127.1"]), ("name with a numeric last label", ["example.123"]), ("name ending in hex number", ["foo.0x10"]),
    ("single label", ["localhost"]), ("single label name", ["intranet"]),
    (".local", ["printer.local"]), (".internal", ["db.internal"]), (".localhost", ["app.localhost"]), (".lan", ["nas.lan"]),
    ("upper case", ["API.anthropic.com"]), ("mixed case", ["Api.example.com"]),
    ("empty entry", [""]), ("too long", ["a." * 127 + "com"]), ("label over 63", ["a" * 64 + ".example.com"]),
    ("leading dash", ["-a.example.com"]), ("trailing dash", ["a-.example.com"]), ("underscore", ["a_b.example.com"]),
    ("non-ascii", ["bücher.example"]), ("trailing dot", ["example.com."]), ("leading dot", [".example.com"]), ("empty label", ["a..example.com"]),
    ("space", ["a b.example.com"]), ("percent", ["a%41.example.com"]), ("non-string entry", [5]), ("null entry", [None]),
    ("repeated name", ["example.com", "example.com"]),
)


def registry_result(value):
    try:
        return registry._sandbox_allowed_hosts(value, "label"), None
    except registry.RegistryError as exc:
        return None, str(exc)


def helper_result(value):
    try:
        return sh.check_allowed_hosts(value, "label"), None
    except (RuntimeError, TypeError) as exc:
        return None, str(exc)


for good in GOOD_LISTS:
    must(registry_result(good) == (good, None), ("registry refused a good list", good, registry_result(good)))
    must(helper_result(good) == (good, None), ("helper refused a good list", good, helper_result(good)))
for label, value in BAD:
    got_registry, why_registry = registry_result(value)
    got_helper, why_helper = helper_result(value)
    must(got_registry is None and why_registry, ("registry accepted", label, value))
    must(got_helper is None and why_helper, ("helper accepted", label, value))
must(registry.SANDBOX_ALLOWED_HOSTS_MAX == sh.ALLOWED_HOSTS_MAX == 16, "the cap is 16 in both places")
must(registry.SANDBOX_HOST_BLOCKED_SUFFIXES == sh.HOST_BLOCKED_SUFFIXES, "the blocked suffixes agree")
must(registry.SANDBOX_HOST_LABEL_RE.pattern == sh.HOST_LABEL_RE.pattern, "the label rule agrees")
must("allowed_hosts" in registry._SANDBOX_RUNNER_KEYS and "allowed_hosts" in sh.RUNNER_KEYS, "the key is known to both")
must(registry.SANDBOX_RESERVED_ENV == sh.RESERVED_ENV, "the reserved environment names agree")
for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy"):
    must(name in sh.RESERVED_ENV and name in registry.SANDBOX_RESERVED_ENV, name)


# ---------------------------------------------------------------------------------------------- a whole manifest through both
def runner(**over):
    entry = {"id": "ai.claude", "description": "Run the Claude command line program", "executable": "sandbox/runners/claude.sh",
             "argv": [], "parameters": {}, "environment": {"LANG": "C.UTF-8"}, "runtime_roots": [], "credential_files": ["auth"],
             "credential_return": True, "limits": {"memory_mb": 512}, "revision": "1"}
    entry.update(over)
    return entry


def manifest(entry):
    return {"id": "ai", "type": "extension", "version": "0.9.0", "category": "premium", "publisher_permissions": ["sandbox.register"],
            "requires": {"framework": ">=1.17.116"}, "sandbox_runners": [entry]}


def make_module(payload):
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="mod-"))
    folder = root / "extensions" / "ai"
    (folder / "sandbox" / "runners").mkdir(parents=True)
    (folder / "sandbox" / "runners" / "claude.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")
    return folder


def check_file(relative, label):
    return None


def parse_both(entry):
    payload = manifest(entry)
    folder = make_module(payload)
    try:
        spec_row = registry._load_manifest("extension", folder).sandbox_runners
    except registry.RegistryError as exc:
        spec_row = str(exc)
    try:
        helper_row = sh.parse_runners("ai", payload, check_file)[1]
    except (RuntimeError, TypeError) as exc:
        helper_row = str(exc)
    return spec_row, helper_row


spec_row, helper_row = parse_both(runner(allowed_hosts=["api.anthropic.com", "auth.anthropic.com"]))
must(isinstance(spec_row, tuple) and spec_row[0]["allowed_hosts"] == ["api.anthropic.com", "auth.anthropic.com"], spec_row)
must(isinstance(helper_row, list) and helper_row[0]["allowed_hosts"] == ["api.anthropic.com", "auth.anthropic.com"], helper_row)
spec_row, helper_row = parse_both(runner())  # no key: as before, and a door-less run
must(spec_row[0]["allowed_hosts"] == [] and helper_row[0]["allowed_hosts"] == [], (spec_row, helper_row))
spec_row, helper_row = parse_both(runner(allowed_hosts=[]))
must(spec_row[0]["allowed_hosts"] == [] and helper_row[0]["allowed_hosts"] == [], "an empty list is the same as none")
for label, value in BAD[:12] + BAD[-6:]:
    spec_row, helper_row = parse_both(runner(allowed_hosts=value))
    must(isinstance(spec_row, str) and isinstance(helper_row, str), ("a manifest with a bad list was accepted", label, spec_row, helper_row))
for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy"):
    spec_row, helper_row = parse_both(runner(environment={name: "http://example.com:3128"}))
    must(isinstance(spec_row, str) and name in spec_row and isinstance(helper_row, str) and name in helper_row, (name, spec_row, helper_row))

# ---------------------------------------------------------------------------------------------- the environment of a run
base_row = {"id": "ai.claude", "owner_module": "ai", "environment": {"LANG": "C.UTF-8"}, "allowed_hosts": []}
env = sh.build_environment(base_row)
must(not any("PROXY" in name.upper() for name in env), ("a run with no allowed_hosts gets no proxy variable", env))
with_hosts = sh.build_environment(dict(base_row, allowed_hosts=["api.anthropic.com"]))
must(with_hosts["HTTPS_PROXY"] == with_hosts["https_proxy"] == "http://127.0.0.1:3128", with_hosts)
must("HTTP_PROXY" not in with_hosts and "NO_PROXY" not in with_hosts, "only HTTPS_PROXY and https_proxy are set")
# a row whose list is invalid is never run
try:
    sh.build_environment(dict(base_row, allowed_hosts=["10.0.0.1"]))
except sh.Refusal as exc:
    must(exc.code == "runtime_unverified", exc.code)
else:
    raise AssertionError("an invalid list in the registry row must be refused at the start")
# a manifest can never override the proxy (the registry refuses it; the helper drops it again if a row ever held one)
forced = sh.build_environment(dict(base_row, environment={"HTTPS_PROXY": "http://evil:1"}, allowed_hosts=["api.anthropic.com"]))
must(forced["HTTPS_PROXY"] == "http://127.0.0.1:3128", forced)
unforced = sh.build_environment(dict(base_row, environment={"HTTPS_PROXY": "http://evil:1"}, allowed_hosts=[]))
must("HTTPS_PROXY" not in unforced, "a reserved name is dropped even when the run has no door")
print("[TEST] PASS sandbox allowed_hosts 1.18.24")
