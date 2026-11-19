#!/usr/bin/env python3
"""1.18.8 regression: the fixed unit template (core.sandbox Patch A, part 2, AD-65: no module-supplied string in any property).

* a hostile registry row (a runtime root with a space, a colon, '%' and '$', a runner id with dots) gives exactly the property list of a plain
  row for the same module: the per-root paths never reach a property, the module's runtime is ONE bind ``/opt/tec-tac/runtimes/<module id>``;
* a module id that is not a plain id, a run id that is not 32 hex digits and a limit above its Core ceiling (or not a whole number) refuse
  before anything is formatted (``runtime_unverified`` or ``invalid_input``, fail closed);
* credentials: the unit property names are the fixed slots cred0 and cred1; the declared name only appears as a launcher argument;
* ``check_unit_properties`` (the closed set) accepts the real list and rejects an injected extra property of every shape.

Not runnable here: systemd itself.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_188t", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
RUN_ID = "cd" * 16
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/") or str(path) == str(sh.LAUNCHER_FILE)
ROOT = {"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}
HOSTILE = [{"path": "/opt/tec-tac/runtimes/ai/my dir:x%h$HOME", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64},
           {"path": "/opt/tec-tac/runtimes/ai/b\nc", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}]


def props_of(row, **kw):
    return sh.build_properties(row, RUN_ID, credential_names=kw.pop("credential_names", []), exists=EXISTS, **kw)


plain = H.make_runner("ai.chat", roots=[ROOT])
hostile = H.make_runner("ai.some.runner-1.x", roots=HOSTILE, environment={"A": "b c", "PATH": "/evil"}, argv=["--x", "%h", "$HOME", "a b"])
hostile["owner_module"] = "ai"
plain_props, hostile_props = props_of(plain), props_of(hostile)
must(plain_props == hostile_props, [p for p in hostile_props if p not in plain_props])
joined = "\n".join(hostile_props)
for text in ("my dir", "x%h", "$HOME", "b\nc", "/opt/tec-tac/runtimes/ai/claude", "evil", "some.runner"):
    must(text not in joined, text)
must(joined.count("/opt/tec-tac/runtimes/") == 1 and "BindReadOnlyPaths=/opt/tec-tac/runtimes/ai" in hostile_props, "one bind for the whole module runtime")
none = H.make_runner("ai.nort", roots=[])
must(not any("/opt/tec-tac/runtimes" in p for p in props_of(none)), "no runtime roots: no runtime bind at all")
# another module id: the lists differ only in the module id
other = dict(plain, owner_module="bee-2")
H.make_runner("bee-2.chat", roots=[ROOT])
other_props = props_of(other)
swapped = [p.replace("/runtimes/bee-2", "/runtimes/ai").replace(str(sh.RUNNERS_ROOT / "bee-2"), str(sh.RUNNERS_ROOT / "ai")) for p in other_props]
must(swapped == plain_props, [p for p in swapped if p not in plain_props])

# ---- the module id: a plain id only
for bad in ("../x", "a/b", "", "a b", None, 5, "x" * 101, ".a", "a:b", "a%b", "a$b"):
    try:
        props_of(dict(plain, owner_module=bad))
        raise AssertionError(f"owner {bad!r} was accepted")
    except sh.Refusal as exc:
        must(exc.code == "runtime_unverified", (bad, exc.code))
# ---- the run id
for bad in ("abc", "AB" * 16, "ab" * 15, "ab" * 17, "../" + "a" * 29, "", None):
    try:
        sh.build_properties(plain, bad, credential_names=[], exists=EXISTS)
        raise AssertionError(f"run id {bad!r} was accepted")
    except sh.Refusal as exc:
        must(exc.code == "invalid_input", (bad, exc.code))

# ---- limits above their ceiling, or not a whole number, refuse
for name, (default, ceiling) in sh.LIMITS.items():
    if name not in ("memory_mb", "cpu_percent", "tasks", "run_seconds", "scratch_mb"):
        continue
    for bad in (ceiling + 1, 0, -1, 1.5, "100", True, None, float("inf")):
        row = dict(plain, limits=dict(plain["limits"], **{name: bad}))
        try:
            props_of(row)
            raise AssertionError(f"{name}={bad!r} was accepted")
        except sh.Refusal as exc:
            must(exc.code == "runtime_unverified", (name, bad, exc.code))
    ok = props_of(dict(plain, limits=dict(plain["limits"], **{name: ceiling})))
    must(ok and any(str(ceiling + (sh.TIMER_SLACK_SECONDS if name == "run_seconds" else 0)) in p for p in ok), (name, "at the ceiling is fine"))
try:
    props_of(dict(plain, limits=None))
    raise AssertionError("no limits was accepted")
except (sh.Refusal, TypeError, KeyError):
    pass

# ---- credentials: fixed slot names in the unit, the declared name only as a launcher argument
slots = sh.credential_slots(["auth", "extra"])
must(slots == [("cred0", "auth"), ("cred1", "extra")], slots)
for bad in (["a", "b", "c"], ["auth", "auth"], ["Auth"], ["a b"], [""], [5], ["a:b"], ["a%b"], ["a$b"], ["x" * 65], ["../x"], ["a\nb"]):
    try:
        sh.credential_slots(bad)
        raise AssertionError(f"credential names {bad!r} were accepted")
    except sh.Refusal as exc:
        must(exc.code == "credential_invalid", (bad, exc.code))
with_cred = props_of(plain, credential_names=["auth", "extra"])
must([p for p in with_cred if p.startswith("LoadCredential=")] == [f"LoadCredential=cred0:{sh.SECRETS_ROOT / RUN_ID / 'cred0'}", f"LoadCredential=cred1:{sh.SECRETS_ROOT / RUN_ID / 'cred1'}"], with_cred)
must("auth" not in "\n".join(with_cred) and "extra" not in "\n".join(with_cred), "a declared name is not in any property")
argv = sh.build_argv(plain, RUN_ID, {}, credential_names=["auth", "extra"], exists=EXISTS)
split = argv.index("--")
launcher_words = argv[split + 1:split + 7]
must(launcher_words[:3] == [sh.UNIT_PYTHON, "-I", str(sh.LAUNCHER_FILE)] and launcher_words[3:5] == ["--credential=auth", "--credential=extra"], launcher_words)
must(not any("auth" in a or "extra" in a for a in argv[:split]), "no declared name before the --")
argv_return = sh.build_argv(dict(plain, credential_return=True), RUN_ID, {}, credential_names=["auth"], exists=EXISTS)
tail = argv_return[argv_return.index("--") + 1:]
must(tail[3:6] == ["--credential=auth", "--return-credential", "--"], tail)
try:
    sh.build_argv(plain, RUN_ID, {}, credential_names=["a b"], exists=EXISTS)
    raise AssertionError("a bad name reached the launcher arguments")
except sh.Refusal as exc:
    must(exc.code == "credential_invalid", exc.code)
# the secrets files carry the slot names
folder = sh.write_secrets(RUN_ID, {"extra": b"two", "auth": b"one"})
must(sorted(p.name for p in folder.iterdir()) == ["cred0", "cred1"] and (folder / "cred0").read_bytes() == b"one" and (folder / "cred1").read_bytes() == b"two", "sorted names map to cred0, cred1")
sh.remove_secrets(RUN_ID)

# ---- the closed set
resolv = str(sh.core_resolv_file())
good = props_of(plain, credential_names=["auth"], deny_extra=["203.0.113.5/32", "2001:db8::5/128"], zswap=True)
sh.check_unit_properties(good, plain, RUN_ID, resolv_file=resolv)
folder_text = str(sh.SECRETS_ROOT / RUN_ID)
INJECTED = [
    "Environment=X=1", "User=root", "Group=root", "ExecStart=/bin/sh", "PrivateNetwork=no", "BindPaths=/etc", "ReadWritePaths=/etc", "BindReadOnlyPaths=/etc/shadow",
    "BindReadOnlyPaths=/opt/tec-tac/runtimes/ai/claude", "BindReadOnlyPaths=/opt/tec-tac/runtimes/bee", "BindReadOnlyPaths=/home/x:/etc/passwd",
    "LoadCredential=auth:" + folder_text + "/auth", "LoadCredential=cred0:/etc/shadow", "LoadCredential=cred0:" + folder_text + "/cred0x",
    "LoadCredential=cred0:" + str(sh.SECRETS_ROOT / ("ef" * 16) / "cred0"), "ExecStartPost=+/bin/sh", f"ExecStopPost=+{sh.HELPER_COMMAND} --finish " + "ef" * 16,
    "MemoryMax=1G", "MemoryMax=infinity", "CPUQuota=100", "TasksMax=infinity", "RuntimeMaxSec=1e9", "LimitFSIZE=-1", "TemporaryFileSystem=/etc:rw",
    f"TemporaryFileSystem={sh.WORK_DIR}:rw,nosuid,nodev,size=1G,mode=1777", "IPAddressDeny=any", "IPAddressAllow=0.0.0.0/0",
    "IPAddressDeny=" + sh.ADDRESS_DENY + " ;evil", "IPAddressDeny=" + sh.ADDRESS_DENY + " 10.0.0.1/32\nUser=root", "RootDirectory=/", "ProtectSystem=no",
    "WorkingDirectory=/etc", "DynamicUser=no", "RestrictAddressFamilies=AF_INET AF_UNIX", "SystemCallFilter=@all", "NoNewPrivileges=no",
]
for extra in INJECTED:
    for position in (0, len(good)):
        try:
            sh.check_unit_properties(good[:position] + [extra] + good[position:], plain, RUN_ID, resolv_file=resolv)
            raise AssertionError(f"an injected property was accepted: {extra!r}")
        except sh.Refusal as exc:
            must(exc.code == "sandbox_unavailable" and "fixed list" in exc.message, (extra, exc.code, exc.message))
# every emitted key is on the fixed vocabulary
KEYS = {p.split("=")[0] for p in sh.UNIT_FIXED_PROPERTIES} | {"MemoryMax", "CPUQuota", "TasksMax", "LimitFSIZE", "RuntimeMaxSec", "TemporaryFileSystem", "WorkingDirectory", "BindReadOnlyPaths",
                                                              "IPAddressDeny", "LoadCredential", "RootDirectory", "MountAPIVFS", "MemoryZSwapMax"}
must({p.split("=")[0] for p in good} <= KEYS, {p.split("=")[0] for p in good} - KEYS)
for p in good:
    must(re.fullmatch(r"[A-Za-z]+=[^\n\x00]*", p), p)

print("[TEST] PASS sandbox template 1.18.8")
