#!/usr/bin/env python3
"""1.17.120 regression: every IPAddressDeny=/IPAddressAllow= string the sandbox helper builds is numeric (core.sandbox canary fixes 1 and 4).

dev02 showed that the symbolic names (localhost, link-local, multicast) make the address filter unreliable. Now:

* ``ADDRESS_DENY`` is a list of networks that all parse with ``ipaddress.ip_network(strict=True)``; no word such as localhost, link-local,
  multicast or any is left; loopback (127.0.0.1, 127.0.0.53, ::1), the five private probe targets and the metadata address sit inside it;
* (1.17.123) there is no IPAddressAllow any more: ``allow_property`` is gone, ``host_network`` gives ``<address>/32`` or ``/128``;
* the probe property lists, the DNS probe calls, ``build_properties`` and a whole ``build_argv`` carry only numeric deny values, the own
  addresses and gateways as /32 or /128, and never an Allow;
* the DNS probe talks to the upstream under the full deny list; a fake that answers only under that list proves it; a fake that never
  answers gives ready=False with 'no DNS reply' and the upstream resolver text;
* no property list ever holds an Allow, a ``localhost`` word or ``IPAddressDeny=any``.

Not runnable here: real systemd. tests/sandbox-canary-1.17.120.sh proves on dev02 that the numeric filter blocks and that 127.0.0.53/32 answers.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
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


def selftest(fake, resolv=F.PUBLIC):
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

# ---- 1.17.123: nothing is ever allowed by address; host_network gives /32 or /128 and nothing else
must(not hasattr(sh, "allow_property"), "the IPAddressAllow builder is gone")
must(sh.host_network("1.1.1.1") == "1.1.1.1/32" and sh.host_network("2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111/128", "host networks")
for bad in ("localhost", "10.0.0.0/8", "", "not-an-address"):
    try:
        sh.host_network(bad)
    except ValueError:
        continue
    raise AssertionError(("host_network took", bad))

# ---- the probe property lists
for name, properties in sh.PROBE_PROPERTIES.items():
    check_numeric(properties, name)
must(sum(1 for props in sh.PROBE_PROPERTIES.values() for p in props if p.startswith("IPAddressDeny=")) == 4, "deny in loopback, private, local and dns probes")
for name in ("address_filter_loopback", "address_filter_private", "address_filter_local", "dns"):
    must("IPAddressDeny=" + sh.ADDRESS_DENY in sh.PROBE_PROPERTIES[name], name)
must("IPAddressAllow" not in json.dumps(sh.PROBE_PROPERTIES), "no Allow in any probe")

# ---- the DNS probe: the full numeric deny list (ranges plus own addresses and gateways), no Allow
fake = F.Fake()
status = selftest(fake)
must(status["ready"] is True and status["resolver"] == "156.38.225.225" and status["resolvers"] == ["156.38.225.225"], status)
dns_calls = [c for c in fake.calls if c[0] == "dns"]
must(len(dns_calls) == 1 and dns_calls[0][1] == ("DynamicUser=yes", "IPAddressDeny=" + sh.ADDRESS_DENY + " 129.232.197.50/32 129.232.197.1/32"), dns_calls)
for call in fake.calls:
    check_numeric(call[1], call[0])
    must(not any(p.startswith("IPAddressAllow=") for p in call[1]), ("an Allow", call))
# up to three IPv4 upstreams are asked (IPv6 is skipped: a run has no IPv6); the ones that answer are the proven list
fake = F.Fake(dns=lambda properties, command: (0, "reply 0\n", "") if command[-2] == "1.1.1.1" else (0, "noreply\n", ""))
status = selftest(fake, "nameserver 2606:4700:4700::1111\nnameserver 9.9.9.9\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n")
must(status["ready"] is True and status["resolver"] == "1.1.1.1" and status["resolvers"] == ["1.1.1.1"], status)
dns_calls = [c for c in fake.calls if c[0] == "dns"]
must([c[2][-2] for c in dns_calls] == ["9.9.9.9", "1.1.1.1", "8.8.8.8"], [c[2] for c in dns_calls])


# a fake that answers only when the deny list is the numeric one proves the property is the one used
def numeric_only(properties, command):
    ok = any(p.startswith("IPAddressDeny=" + sh.ADDRESS_DENY) for p in properties) and not any(p.startswith("IPAddressAllow=") for p in properties)
    return (0, "reply 0\n", "") if ok else (0, "noreply\n", "")


status = selftest(F.Fake(dns=numeric_only))
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
RESOLV = str(BASE / "core-resolv.conf")
(BASE / "core-resolv.conf").write_text("nameserver 9.9.9.9" + chr(10), encoding="utf-8")
EXISTS2 = lambda path: EXISTS(path) or str(path) == RESOLV
for extra in ([], ["203.0.113.5/32", "203.0.113.1/32"], ["2001:db8::5/128"]):
    props = sh.build_properties(row, RUN_ID, credential_names=["auth"], exists=EXISTS2, deny_extra=extra, resolv_file=RESOLV)
    check_numeric(props, "build_properties")
    must(len([p for p in props if p.startswith("IPAddressDeny=")]) == 1, "exactly one deny property")
    must(props.count("IPAddressDeny=" + " ".join([sh.ADDRESS_DENY, *extra])) == 1, props)
    must(not any(p.startswith("IPAddressAllow=") for p in props), "no Allow at all")
    must(f"BindReadOnlyPaths={RESOLV}:/etc/resolv.conf" in props, "Core's file over /etc/resolv.conf")
for bad in (["203.0.113.5"], ["localhost/32"], ["203.0.113.0/24"], ["10.0.0.1/32 any"]):
    try:
        sh.build_properties(row, RUN_ID, credential_names=[], exists=EXISTS2, deny_extra=bad, resolv_file=RESOLV)
    except sh.Refusal:
        continue
    raise AssertionError(("a non-host deny entry was accepted", bad))
argv = sh.build_argv(row, RUN_ID, {"mode": "a"}, credential_names=["auth"], exists=EXISTS2, deny_extra=["203.0.113.5/32"], resolv_file=RESOLV)
check_numeric([a.split("=", 1)[1] for a in argv if a.startswith("--property=IPAddress")], "build_argv")
must("--property=IPAddressDeny=" + sh.ADDRESS_DENY + " 203.0.113.5/32" in argv and not any("IPAddressAllow" in a for a in argv), "argv carries the numeric strings")
must(not any(re.search(r"IPAddress(Allow|Deny)=(localhost|link-local|multicast|any)", a) for a in argv), "no symbolic name in argv")
# the helper source itself builds no symbolic address string
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(re.search(r'IPAddress(Allow|Deny)=(localhost|link-local|multicast|any)', source) is None, "no symbolic string in the helper source")

print("[TEST] PASS sandbox address numeric 1.17.120")
