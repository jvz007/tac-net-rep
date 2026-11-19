#!/usr/bin/env python3
"""1.18.24 regression (AD-65 Patch B, item 1): a run unit gets its own network space; the per-start deny list, resolver bind and resolver code are gone.

Django-free, against the shared fake file system (tests/sandbox-harness-1.17.118.py). Covered:

* the fixed property list holds PrivateNetwork=yes and RestrictAddressFamilies=AF_INET AF_UNIX (and no plain AF_INET entry);
* a built unit has no IPAddressDeny, no IPAddressAllow and no resolv.conf bind; build_properties and build_argv take no deny_extra and no resolv_file;
  the helper has no usable_resolvers, upstream_problem, read_upstream_text, core_resolv_file or resolv_conf_bytes any more;
* the closed set refuses a stray property (an address filter, a resolver bind, PrivateNetwork=no, another address family, a door bind for a runner that
  has none, a door bind of another run id or another target); the per-run door bind is exactly one more entry, built from the hex run id only;
* nothing in a unit property comes from a module string: a hostile allowed_hosts, runtime path or credential name never reaches a property;
* launch no longer reads this server's addresses or a resolver list for a run that has no allowed_hosts, and fails closed (sandbox_unavailable, no unit)
  when a run that has them cannot read the server's own addresses for the proxy;
* the skeleton has no etc/resolv.conf and no base bind for it, and the canary's view table does not allow it;
* the reserved proxy variables cannot be set by a manifest (helper and registry.py).

Not runnable here: real systemd (dev02: tests/sandbox-canary-1.18.24.sh proves the wall).
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sandbox_harness_124c", HERE / "sandbox-harness-1.17.118.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must, BASE = H.sh, H.must, H.BASE
sh.EGRESS_DOOR_ROOT = H.RUN / "egress-door"
sh.EGRESS_CONFIG_ROOT = H.RUN / "egress-config"
sh.EGRESS_STATE_ROOT = BASE / "egress-state"

# ---- the fixed list
fixed = list(sh.UNIT_FIXED_PROPERTIES)
must("PrivateNetwork=yes" in fixed and "RestrictAddressFamilies=AF_INET AF_UNIX" in fixed, fixed)
must("RestrictAddressFamilies=AF_INET" not in fixed and not any(p.startswith(("IPAddress", "RestrictAddressFamilies=AF_INET6")) for p in fixed), fixed)
must(sh.NETWORK_PROPERTIES == ("PrivateNetwork=yes", "RestrictAddressFamilies=AF_INET AF_UNIX"), sh.NETWORK_PROPERTIES)
must(len(fixed) == len(set(fixed)), "no duplicate")
must(sh.SANDBOX_ENABLED is False, "the kill switch stays off")

# ---- what is gone
for gone in ("usable_resolvers", "upstream_problem", "read_upstream_text", "core_resolv_file", "resolv_conf_bytes", "upstream_resolvers_text", "_probe_address_filter",
             "_probe_address_local", "_probe_dns", "RESOLV_UPSTREAM", "RESOLV_TARGET", "_PROBE_PRIVATE", "_PROBE_DNS"):
    must(not hasattr(sh, gone), ("still there", gone))
for fn in (sh.build_properties, sh.build_argv, sh.check_unit_properties):
    names = set(inspect.signature(fn).parameters)
    must(not names & {"deny_extra", "resolv_file"}, (fn.__name__, names))
must(sh.read_local_deny and sh.local_deny and sh.denied_by_ranges, "the address readers stay: they feed the proxy's own-address list and the canary")
must(sh.LOCAL_DENY_MAX == 64, "local_deny keeps its cap")

# ---- a built unit
row = H.make_runner("ai.chat", body="print('x')")
run_id = os.urandom(16).hex()
props = sh.build_properties(row, run_id, credential_names=[])
must("PrivateNetwork=yes" in props and "RestrictAddressFamilies=AF_INET AF_UNIX" in props, props)
must(not any(p.startswith(("IPAddressDeny", "IPAddressAllow")) or "resolv" in p for p in props), props)
must(not any("/run/egress" in p for p in props), "no door for a runner with no allowed_hosts")
argv = sh.build_argv(row, run_id, {}, credential_names=[])
must("--egress" not in argv and not any("PROXY" in a.upper() for a in argv), "no forwarder flag and no proxy variable")
hosted = dict(row, allowed_hosts=["api.example.com"])
door = str(sh.EGRESS_DOOR_ROOT / run_id)
props = sh.build_properties(hosted, run_id, credential_names=[])
must(f"BindReadOnlyPaths={door}:/run/egress" in props and sum(p.endswith(":/run/egress") for p in props) == 1, [p for p in props if "Bind" in p])
argv = sh.build_argv(hosted, run_id, {}, credential_names=[])
must("--egress" in argv and "--setenv=HTTPS_PROXY=http://127.0.0.1:3128" in argv and "--setenv=https_proxy=http://127.0.0.1:3128" in argv, argv)
must(argv.index("--") < argv.index("--egress") < len(argv) - 1 - argv[::-1].index("--"), "the flag goes to the launcher, before the runner")

# ---- the closed set
for stray in ("IPAddressDeny=" + sh.ADDRESS_DENY, "IPAddressAllow=127.0.0.53/32", f"BindReadOnlyPaths={BASE}/resolv.conf:/etc/resolv.conf", "PrivateNetwork=no",
              "PrivateNetwork=yes ", "RestrictAddressFamilies=AF_INET", "RestrictAddressFamilies=AF_INET AF_INET6", "RestrictAddressFamilies=AF_UNIX",
              "JoinsNamespaceOf=tectac-x.service", "NetworkNamespacePath=/proc/1/ns/net", f"BindReadOnlyPaths={door}:/run/egress/x", "ExecStartPre=/bin/true"):
    try:
        sh.check_unit_properties([*props, stray], hosted, run_id)
    except sh.Refusal as exc:
        must(exc.code == "sandbox_unavailable", exc.code)
    else:
        raise AssertionError(("a stray property passed the closed set", stray))
sh.check_unit_properties(props, hosted, run_id)  # the real list passes
for stray in (f"BindReadOnlyPaths={door}:/run/egress", f"BindReadOnlyPaths={sh.EGRESS_DOOR_ROOT / os.urandom(16).hex()}:/run/egress"):
    try:  # a door bind for a runner that has none, and a door of another run
        sh.check_unit_properties([*sh.build_properties(row, run_id, credential_names=[]), stray] if stray.endswith(f"{run_id}:/run/egress") else [*props, stray],
                                 row if stray.endswith(f"{run_id}:/run/egress") else hosted, run_id)
    except sh.Refusal:
        pass
    else:
        raise AssertionError(("an extra door bind passed", stray))
# every property is Core text, a number, a validated module id or the hex run id: a hostile module string never gets in
evil = dict(hosted, allowed_hosts=["api.example.com"], environment={"X": "a b"}, runtime_roots=[], credential_files=["auth"])
text = " ".join(sh.build_properties(evil, run_id, credential_names=["auth"]))
must("api.example.com" not in text and "auth" not in text.replace("LoadCredential=cred0:", "") .split("cred0")[0], "no module string in a property")
for bad_hosts in (["10.0.0.1"], "api.example.com", ["a b.example.com"], ["*.example.com"]):
    try:
        sh.build_properties(dict(row, allowed_hosts=bad_hosts), run_id, credential_names=[])
    except sh.Refusal as exc:
        must(exc.code == "runtime_unverified", exc.code)
    else:
        raise AssertionError(("a row with a bad host list was built", bad_hosts))
try:
    sh.build_properties(hosted, "../../etc", credential_names=[])
except sh.Refusal as exc:
    must(exc.code == "invalid_input", exc.code)
else:
    raise AssertionError("a run id that is not 32 hex is refused")

# ---- launch: no address or resolver read for a run that has no allowed_hosts; fail closed for one that has them
calls = []
saved_local, saved_read = sh.local_deny_now, sh.read_local_deny
sh.local_deny_now = lambda: calls.append("local") or (_ for _ in ()).throw(ValueError("the `ip` command could not read this server's addresses or routes"))
sh.read_local_deny = lambda *a, **k: calls.append("read") or (_ for _ in ()).throw(ValueError("x"))
H.make_runner("ai.chat", body="print('hello')", limits={"run_seconds": 20})
code, frames = H.start(H.header(run_id=os.urandom(16).hex()))
must(calls == [] and any(f["t"] == "out" for f in frames) and H.end_of(frames), ("a run without allowed_hosts never reads the addresses", calls, frames[:2]))
row = H.make_runner("ai.chat", body="print('hello')", limits={"run_seconds": 20})
row["allowed_hosts"] = ["api.example.com"]
(sh.REGISTRY_ROOT / "ai.chat.json").write_text(__import__("json").dumps(row), encoding="utf-8")
rid2 = os.urandom(16).hex()
code, frames = H.start(H.header(run_id=rid2))
must(calls == ["local"], calls)
must(any(f["t"] == "refused" and f["code"] == "sandbox_unavailable" for f in frames) and not (BASE / "log" / f"tectac-sbx-{rid2}.json").exists(),
     "unreadable own addresses with a door: no run (fail closed)")
sh.local_deny_now, sh.read_local_deny = saved_local, saved_read

# ---- the skeleton and the canary's view table
must("etc/resolv.conf" not in sh.SKELETON_FILES and "resolv.conf" not in sh.SKELETON_ENTRIES["etc"] and "/etc/resolv.conf" not in sh.BASE_BINDS_REQUIRED
     and "/etc/resolv.conf" not in sh.BASE_BINDS_OPTIONAL, "no resolv.conf anywhere in the skeleton")
must("resolv.conf" not in sh.CANARY_VIEW_ALLOWED["/etc"] and "egress" in sh.CANARY_VIEW_ALLOWED["/run"], sh.CANARY_VIEW_ALLOWED)
must("run/egress" in sh.SKELETON_DIRS and sh.SKELETON_ENTRIES["run/egress"] == (), "run/egress is an empty mount point of the skeleton")
exposed = sh.file_view_properties(lambda path: True)
must(not any("resolv" in p for p in exposed), exposed)

# ---- the reserved names, both copies
sys.path.insert(0, str(H.ROOT / "framwork"))
from tec_tac import registry  # noqa: E402

for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy"):
    must(name in sh.RESERVED_ENV and name in registry.SANDBOX_RESERVED_ENV, name)
env = sh.build_environment(dict(row, environment={"NO_PROXY": "x", "LANG": "C"}, allowed_hosts=["api.example.com"]))
must("NO_PROXY" not in env and env["LANG"] == "C" and env["HTTPS_PROXY"] == "http://127.0.0.1:3128", env)
print("[TEST] PASS sandbox private network 1.18.24")
