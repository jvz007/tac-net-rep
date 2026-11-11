#!/usr/bin/env python3
"""1.17.120 regression: every IPAddressDeny=/IPAddressAllow= string the sandbox helper builds is numeric (core.sandbox canary fixes 1 and 4).

dev02 showed that the symbolic names (localhost, link-local, multicast) make the address filter unreliable. Now:

* ``ADDRESS_DENY`` is a list of networks that all parse with ``ipaddress.ip_network(strict=True)``; no word such as localhost, link-local,
  multicast or any is left; loopback (127.0.0.1, 127.0.0.53, ::1), the five private probe targets and the metadata address sit inside it;
* ``allow_property`` gives ``IPAddressAllow=<address>/32`` for IPv4 and ``/128`` for IPv6;
* the probe property lists, the DNS probe calls, ``build_properties`` and a whole ``build_argv`` carry only numeric deny and allow values,
  with the Deny before the Allow;
* the DNS probe uses exactly the numeric deny and one Allow per resolver (up to three); a fake that answers only when the Allow carries a
  prefix length proves it; a fake that never answers gives ready=False with 'no DNS reply' and the upstream resolver text;
* no property list ever holds an Allow of all of loopback, an Allow of localhost or ``IPAddressDeny=any``.

Not runnable here: real systemd. tests/sandbox-canary-1.17.120.sh proves on dev02 that the numeric filter blocks and that 127.0.0.53/32 answers.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_120a", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_120a", "sandbox-fake-runner-1.17.120.py")
sh, must, make_runner, BASE = H.sh, H.must, H.make_runner, H.BASE


def selftest(fake, resolv="nameserver 127.0.0.53\noptions edns0\n"):
    return F.run_selftest(sh, H.RUN, BASE, fake, resolv)


def numeric_value(value):
    tokens = value.split()
    must(tokens, "an empty address list")
    for token in tokens:
        net = ipaddress.ip_network(token, strict=True)  # raises on a name or a host-bit address
        must(str(net) == token, ("not in canonical form", token))
    return [ipaddress.ip_network(t, strict=True) for t in tokens]


def check_numeric(properties, label):
    for item in properties:
        if item.startswith(("IPAddressDeny=", "IPAddressAllow=")):
            numeric_value(item.split("=", 1)[1])
            must(re.search(r"(localhost|link-local|multicast|\bany\b)", item) is None, (label, item))
            must(item not in ("IPAddressAllow=127.0.0.0/8", "IPAddressAllow=localhost", "IPAddressDeny=any"), (label, item))
            if item.startswith("IPAddressAllow="):
                must(item.split("=", 1)[1].endswith(("/32", "/128")), (label, "an Allow without a host prefix", item))


# ---- ADDRESS_DENY is numeric and covers what it must
nets = numeric_value(sh.ADDRESS_DENY)
must(sh.ADDRESS_DENY == "127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 224.0.0.0/4 ff00::/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7", sh.ADDRESS_DENY)
for word in ("localhost", "link-local", "multicast", "any"):
    must(word not in sh.ADDRESS_DENY.split(), word)
for target in (*sh.PRIVATE_PROBE_TARGETS, "127.0.0.1", "127.0.0.53", "::1", "169.254.169.254", "224.0.0.251", "fe80::1", "ff02::1"):
    must(any(ipaddress.ip_address(target) in net for net in nets), ("not denied", target))
for public in ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"):
    must(not any(ipaddress.ip_address(public) in net for net in nets), ("public address denied", public))

# ---- allow_property
must(sh.allow_property("127.0.0.53") == "IPAddressAllow=127.0.0.53/32", sh.allow_property("127.0.0.53"))
must(sh.allow_property("1.1.1.1") == "IPAddressAllow=1.1.1.1/32", "ipv4")
must(sh.allow_property("2606:4700:4700::1111") == "IPAddressAllow=2606:4700:4700::1111/128", sh.allow_property("2606:4700:4700::1111"))
must(sh.allow_property("2606:4700:4700:0:0:0:0:1111") == "IPAddressAllow=2606:4700:4700::1111/128", "an IPv6 resolver is written in its short form")
must(sh.allow_property("::1") == "IPAddressAllow=::1/128", "ipv6 loopback is a /128")
for bad in ("localhost", "10.0.0.0/8", "", "not-an-address"):
    try:
        sh.allow_property(bad)
    except ValueError:
        continue
    raise AssertionError(("allow_property took", bad))

# ---- the probe property lists
for name, properties in sh.PROBE_PROPERTIES.items():
    check_numeric(properties, name)
must(sum(1 for props in sh.PROBE_PROPERTIES.values() for p in props if p.startswith("IPAddressDeny=")) == 3, "deny only in loopback, private and dns probes")
for name in ("address_filter_loopback", "address_filter_private", "dns"):
    must("IPAddressDeny=" + sh.ADDRESS_DENY in sh.PROBE_PROPERTIES[name], name)

# ---- the DNS probe: the numeric deny plus one Allow per resolver
fake = F.Fake()
status = selftest(fake)
must(status["ready"] is True and status["resolver"] == "127.0.0.53" and status["resolvers"] == ["127.0.0.53"], status)
dns_calls = [c for c in fake.calls if c[0] == "dns"]
must(len(dns_calls) == 1 and dns_calls[0][1] == sh.PROBE_PROPERTIES["dns"] + ("IPAddressAllow=127.0.0.53/32",), dns_calls)
for call in fake.calls:
    check_numeric(call[1], call[0])
# up to three resolvers, IPv4 and IPv6, each with its own prefix length
fake = F.Fake(dns=lambda properties, command: (0, "reply 0\n", "") if command[-2] == "2606:4700:4700::1111" else (0, "noreply\n", ""))
status = selftest(fake, "nameserver 192.168.1.1\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nnameserver 8.8.8.8\n")
must(status["ready"] is True and status["resolver"] == "2606:4700:4700::1111" and status["resolvers"] == ["192.168.1.1", "1.1.1.1", "2606:4700:4700::1111"], status)
dns_calls = [c for c in fake.calls if c[0] == "dns"]
want = {"IPAddressAllow=192.168.1.1/32", "IPAddressAllow=1.1.1.1/32", "IPAddressAllow=2606:4700:4700::1111/128"}
must(len(dns_calls) == 3 and all({p for p in c[1] if p.startswith("IPAddressAllow=")} == want for c in dns_calls), dns_calls)
for call in dns_calls:
    must(call[1][:2] == sh.PROBE_PROPERTIES["dns"], call[1])
    must(call[1].index("IPAddressDeny=" + sh.ADDRESS_DENY) < min(call[1].index(p) for p in want), "deny before allow")


# a fake that answers only when the Allow carries a prefix length proves the property is the one used
def prefix_only(properties, command):
    allows = [p for p in properties if p.startswith("IPAddressAllow=")]
    ok = bool(allows) and all(p.endswith(("/32", "/128")) for p in allows) and "IPAddressDeny=" + sh.ADDRESS_DENY in properties
    return (0, "reply 0\n", "") if ok else (0, "noreply\n", "")


status = selftest(F.Fake(dns=prefix_only))
must(status["ready"] is True and status["dns_ok"] is True, status)

# a fake that never answers: not ready, a plain reason with the upstream text
real_upstream = sh.upstream_resolvers_text
sh.upstream_resolvers_text = lambda *a, **k: "192.168.1.1, 9.9.9.9"
try:
    status = selftest(F.Fake(dns=(0, "noreply\n")))
finally:
    sh.upstream_resolvers_text = real_upstream
must(status["ready"] is False and status["dns_ok"] is False and status["resolver"] == "", status)
must("no DNS reply" in status["reason"] and "upstream resolvers: 192.168.1.1, 9.9.9.9" in status["reason"], status["reason"])
must("upstream resolvers: 192.168.1.1, 9.9.9.9" in status["checks"]["dns"]["detail"], status["checks"]["dns"])

# the upstream text reads systemd-resolved's file read only: at most three addresses, plain text, never an exception
resolv = BASE / "upstream-resolv.conf"
resolv.write_text("# comment\nnameserver 192.168.1.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\nsearch lan\n", encoding="utf-8")
must(sh.upstream_resolvers_text(resolv) == "192.168.1.1, 1.1.1.1, 8.8.8.8", sh.upstream_resolvers_text(resolv))
resolv.write_text("search lan\n", encoding="utf-8")
must(sh.upstream_resolvers_text(resolv) == "none listed", "none listed")
must(sh.upstream_resolvers_text(BASE / "missing-upstream.conf") == "not readable", "not readable")
resolv.write_bytes(b"\xff\xfe\x00nameserver 1.1.1.1\n")
must(isinstance(sh.upstream_resolvers_text(resolv), str), "bad bytes never raise")

# ---- build_properties and a whole build_argv
RUN_ID = "ab" * 16
row = make_runner("ai.chat", parameters={"mode": {"type": "enum", "choices": ["a", "b"]}}, argv=["--m", {"param": "mode"}], credential_files=["auth"],
                  roots=[{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}])
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/ai") or str(path) == str(sh.LAUNCHER_FILE)
for resolvers in (["127.0.0.53"], ["192.168.1.1", "1.1.1.1", "2606:4700:4700::1111"], []):
    props = sh.build_properties(row, RUN_ID, resolvers=resolvers, credential_names=["auth"], exists=EXISTS)
    check_numeric(props, "build_properties")
    must(props.count("IPAddressDeny=" + sh.ADDRESS_DENY) == 1, "exactly one deny")
    allows = [p for p in props if p.startswith("IPAddressAllow=")]
    must(allows == [sh.allow_property(r) for r in resolvers], allows)
    if allows:
        must(props.index("IPAddressDeny=" + sh.ADDRESS_DENY) < props.index(allows[0]), "deny comes before allow")
    must(not any(p in props for p in ("IPAddressAllow=127.0.0.0/8", "IPAddressAllow=localhost", "IPAddressDeny=any")), props)
argv = sh.build_argv(row, RUN_ID, {"mode": "a"}, resolvers=["127.0.0.53"], credential_names=["auth"], exists=EXISTS)
check_numeric([a.split("=", 1)[1] for a in argv if a.startswith("--property=IPAddress")], "build_argv")
must("--property=IPAddressAllow=127.0.0.53/32" in argv and "--property=IPAddressDeny=" + sh.ADDRESS_DENY in argv, "argv carries the numeric strings")
must(not any(re.search(r"IPAddress(Allow|Deny)=(localhost|link-local|multicast|any)", a) for a in argv), "no symbolic name in argv")
# the helper source itself builds no symbolic address string
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(re.search(r'IPAddress(Allow|Deny)=(localhost|link-local|multicast|any)', source) is None, "no symbolic string in the helper source")

print("[TEST] PASS sandbox address numeric 1.17.120")
