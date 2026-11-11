#!/usr/bin/env python3
"""1.17.118 regression: the unit builder of scripts/sandbox-helper.py (core.sandbox Patch 2, part B).

Golden test: every hardening property is present, none is taken from the caller or from the module's manifest text, the address filter is
the section 15 string, IPAddressAllow is exactly the resolver the selftest proved and that resolv.conf still lists (three cases: proven,
changed since the selftest, none), IPv6 and zone-id resolvers are skipped, a not-ready status refuses, the binds are read only and a missing
bind fails the run loudly, reserved environment names cannot be overridden, and the limits come from the registry row and never exceed the
Core ceilings.

Not runnable here: systemd itself (does it accept each property, does TemporaryFileSystem=/work work under ProtectSystem=strict).
tests/sandbox-canary-1.17.118.sh proves that on dev02.
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
# The shared set-up (fake file system, helper loaded as sh, fake systemd), loaded by path; the names it gives are taken explicitly.
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, ROOT, header, make_runner, must, sh, start, write_ready_status,) = (H.BASE, H.ROOT, H.header, H.make_runner, H.must, H.sh, H.start, H.write_ready_status,)

RUN_ID = "ab" * 16
row = make_runner("ai.chat", parameters={"mode": {"type": "enum", "choices": ["a", "b"]}}, argv=["--m", {"param": "mode"}],
                  environment={"LANG": "C.UTF-8", "FOO": "bar"}, credential_files=["auth", "extra"], credential_return=True,
                  limits={"memory_mb": 512, "cpu_percent": 50, "tasks": 100, "run_seconds": 60, "scratch_mb": 32},
                  roots=[{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}])
(BASE / "opt-runtime").mkdir()
EXISTS = lambda path: path != "/missing" and (str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/ai") or str(path) == str(sh.LAUNCHER_FILE))

props = sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=["auth", "extra"], exists=EXISTS)
joined_props = "\n".join(props)

# ---- the golden hardening list (plan sections 3, 15 and the task): each exactly once unless it is a list property
GOLDEN = [
    "DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateIPC=yes", "NoNewPrivileges=yes",
    "CapabilityBoundingSet=", "AmbientCapabilities=", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
    "SystemCallArchitectures=native", "SystemCallErrorNumber=EPERM", "RestrictAddressFamilies=AF_INET AF_UNIX", "RestrictNamespaces=yes",
    "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=no", "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
    "ProtectProc=invisible", "ProcSubset=pid", "UMask=0077", "KillMode=control-group", "SendSIGKILL=yes", "MemorySwapMax=0", "LimitNOFILE=1024",
    "LimitCORE=0",
]
for item in GOLDEN:
    must(props.count(item) == 1, (item, props.count(item)))
must("RestrictAddressFamilies=AF_INET AF_UNIX" in props and "AF_INET6" not in joined_props, "no IPv6 (kept as a question for Johan)")
# limits come from the row
for item in ("MemoryMax=512M", "CPUQuota=50%", "TasksMax=100", f"LimitFSIZE={32 * 1024 * 1024}", "RuntimeMaxSec=65"):
    must(props.count(item) == 1, (item, [p for p in props if p.split("=")[0] == item.split("=")[0]]))
must(f"TemporaryFileSystem={sh.WORK_DIR}:rw,nosuid,nodev,size=32M,mode=1777" in props, "scratch tmpfs sized from the row")
must(f"WorkingDirectory={sh.WORK_DIR}" in props, "")
# hidden file system
hidden = [p for p in props if p.startswith("TemporaryFileSystem=") and sh.WORK_DIR not in p]
must(len(hidden) == 1 and hidden[0].split("=", 1)[1].split() == [f"{f}:ro" for f in ("/etc", "/var", "/run", "/opt", "/srv", "/mnt", "/media", "/home", "/root", "/rmm", "/meshcentral", "/usr/local/lib/tec-tac")], hidden)
# binds: all read only, the base set, the runtime root, the runner folder and the launcher; each is its own property
binds = [p.split("=", 1)[1] for p in props if p.startswith("BindReadOnlyPaths=")]
must(not [p for p in props if p.startswith(("BindPaths=", "ReadWritePaths="))], "no writable bind and no ReadWritePaths")
for path in sh.BASE_BINDS_REQUIRED + sh.BASE_BINDS_OPTIONAL:
    must(path in binds, path)
must("/opt/tec-tac/runtimes/ai/claude" in binds and str(sh.RUNNERS_ROOT / "ai") in binds and str(sh.LAUNCHER_FILE) in binds, binds)
must(len(binds) == len(set(binds)) and all(" " not in b for b in binds if b != str(sh.LAUNCHER_FILE)), "one path per property")
# the real constants name /etc/resolv.conf (a plan correction: without it a run cannot find its resolver)
real_line = next(line for line in (ROOT / "scripts/sandbox-helper.py").read_text(encoding="utf-8").splitlines() if line.startswith("BASE_BINDS_REQUIRED"))
must('"/etc/resolv.conf"' in real_line and '"/etc/ssl/certs"' in real_line, real_line)
must(sh.HELPER_COMMAND == "/usr/local/sbin/tec-tac-sandbox" and any(p == f"ExecStopPost=+{sh.HELPER_COMMAND} --finish {RUN_ID}" for p in props), "finish hook")
# network: the section 15 string exactly, then the resolver by address
must(f"IPAddressDeny={sh.ADDRESS_DENY}" in props and sh.ADDRESS_DENY == "localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7", "address filter")
must([p for p in props if p.startswith("IPAddressAllow=")] == ["IPAddressAllow=127.0.0.53"], "exactly the resolver")
must(props.index("IPAddressDeny=" + sh.ADDRESS_DENY) < props.index("IPAddressAllow=127.0.0.53"), "")
# credentials: LoadCredential per name from the run's own folder, and the folder is removed by a root ExecStartPost
must([p for p in props if p.startswith("LoadCredential=")] == [f"LoadCredential=auth:{sh.SECRETS_ROOT / RUN_ID / 'auth'}", f"LoadCredential=extra:{sh.SECRETS_ROOT / RUN_ID / 'extra'}"], props)
must(f"ExecStartPost=+/bin/rm -rf {sh.SECRETS_ROOT / RUN_ID}" in props, "")
none = sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
must(not [p for p in none if p.startswith(("LoadCredential=", "ExecStartPost="))], "no credential, no hook")
# every property is Key=Value from a fixed vocabulary
for p in props:
    must("=" in p and "\n" not in p and "\x00" not in p, p)
ALLOWED_KEYS = {p.split("=")[0] for p in GOLDEN} | {"MemoryMax", "CPUQuota", "TasksMax", "LimitFSIZE", "RuntimeMaxSec", "TemporaryFileSystem", "WorkingDirectory",
                                                  "BindReadOnlyPaths", "IPAddressDeny", "IPAddressAllow", "LoadCredential", "ExecStartPost", "ExecStopPost"}
must({p.split("=")[0] for p in props} <= ALLOWED_KEYS, {p.split("=")[0] for p in props} - ALLOWED_KEYS)

# ---- nothing comes from the caller or the manifest text
evil = make_runner("ai.evil", argv=["--x=1", "ProtectSystem=no", "\n[Service]\nUser=root"], environment={"NoNewPrivileges": "no", "X": "a=b", "IPAddressDeny": "any"})
evil_props = sh.build_properties(evil, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
must(evil_props.count("ProtectSystem=strict") == 1 and "ProtectSystem=no" not in evil_props and "NoNewPrivileges=no" not in evil_props, "manifest text is not a property")
must(not any("User=root" in p or "IPAddressDeny=any" in p for p in evil_props), evil_props)
argv = sh.build_argv(evil, RUN_ID, {}, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
must(argv[:len(sh.SYSTEMD_RUN) + 6] == [*sh.SYSTEMD_RUN, "--pipe", "--wait", "--collect", "--quiet", f"--unit=tectac-sbx-{RUN_ID}", f"--slice={sh.SLICE}"], argv[:9])
split = argv.index("--")
head, tail = argv[:split], argv[split + 1:]
must(not any(a.startswith("--property=") and ("ProtectSystem=no" in a or "User=root" in a) for a in head), "")
must(tail[:3] == [sh.UNIT_PYTHON, "-I", str(sh.LAUNCHER_FILE)] and tail[3] == "--" and tail[4] == evil["executable"], tail)
must(tail[5:] == ["--x=1", "ProtectSystem=no", "\n[Service]\nUser=root"], "argv literals are runner arguments only, after the second --")
# the env map: manifest names pass as --setenv only; reserved names always win
env = sh.build_environment(evil)
must(env["NoNewPrivileges"] == "no" and env["X"] == "a=b", "an ordinary name (not a property) is passed as an environment value")
over = make_runner("ai.over", environment={"LANG": "C"})
over["environment"] = {"HOME": "/root", "TMPDIR": "/etc", "SSL_CERT_FILE": "/x", "SANDBOX_WORK": "/", "SANDBOX_OUT": "/", "PATH": "/evil", "LANG": "C"}
env = sh.build_environment(over)
must(env["HOME"] == f"{sh.WORK_DIR}/home" and env["TMPDIR"] == f"{sh.WORK_DIR}/tmp" and env["SANDBOX_WORK"] == sh.WORK_DIR and env["SANDBOX_OUT"] == f"{sh.WORK_DIR}/out", env)
must(env["SSL_CERT_FILE"] == sh.CA_BUNDLE and env["PATH"] == sh.SANDBOX_PATH_ENV and env["LANG"] == "C", env)
# the launcher flag appears only for credential_return, never for another reason
must("--return-credential" in sh.build_argv(row, RUN_ID, {"mode": "a"}, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
     and "--return-credential" not in argv, "")
must(sh.build_argv(row, RUN_ID, {"mode": "a"}, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)[-2:] == ["--m", "a"], "param rendered")

# ---- binds that are missing fail loudly
real_required = sh.BASE_BINDS_REQUIRED
sh.BASE_BINDS_REQUIRED = real_required[:-1] + ("/missing",)
try:
    sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
    raise AssertionError("a missing required bind was accepted")
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable", exc.code)
sh.BASE_BINDS_REQUIRED = real_required
try:
    sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=lambda p: p != "/opt/tec-tac/runtimes/ai/claude" and EXISTS(p))
    raise AssertionError("a missing runtime folder was accepted")
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable", exc.code)
# an optional base bind that is absent is simply left out (it can only mean less is visible)
only = lambda p: EXISTS(p) and "localtime" not in p
opt = sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=only)
must(not any("localtime" in p for p in opt) and any("nsswitch.conf" in p for p in opt), "optional binds are skipped when absent")

# ---- limits: the registry row's, never above the Core ceilings (the registry parser refuses more, the canary row checks again)
for name, (default, ceiling) in sh.LIMITS.items():
    try:
        sh.canary_row(**{name: ceiling + 1})
        raise AssertionError(f"canary limit {name} over the ceiling")
    except RuntimeError:
        pass
    sh.canary_row(**{name: ceiling})
default_row = make_runner("ai.defaults")
dp = sh.build_properties(default_row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
must("MemoryMax=1024M" in dp and "CPUQuota=100%" in dp and "TasksMax=256" in dp and f"RuntimeMaxSec={20 + sh.TIMER_SLACK_SECONDS}" in dp, "defaults from the row")

# ---- the resolver rule at start time (three cases) and IPv6 / zone ids
U = sh.usable_resolvers
status = {"ready": True, "resolver": "127.0.0.53"}
must(U(status, "nameserver 127.0.0.53\noptions edns0\n") == ["127.0.0.53"], "proven and still listed")
must(U(status, "nameserver 10.0.0.2\n") == [], "changed since the selftest: no resolver")
must(U(status, "") == [] and U({"ready": True}, "nameserver 127.0.0.53\n") == [], "none")
must(U({"resolver": "1.1.1.1"}, "nameserver 192.168.1.1\nnameserver 1.1.1.1\n") == ["1.1.1.1"], "only the proven one of several")
must(U({"resolver": "::1"}, "nameserver ::1\n") == [], "IPv6 skipped (the unit has no AF_INET6)")
must(U({"resolver": "fe80::1"}, "nameserver fe80::1%eth0\n") == [], "zone id skipped")
must(U({"resolver": "2606:4700:4700::1111"}, "nameserver 2606:4700:4700::1111\nnameserver 1.1.1.1\n") == [], "a proven IPv6 resolver is not used, and an unproven IPv4 one is not either")
# the same, end to end through launch(): refuses before anything starts
write_ready_status(resolver="10.9.9.9")
code, frames = start(header("ai.defaults"), hold=False)
must(frames == [{"t": "refused", "code": "sandbox_unavailable", "message": "no resolver that the selftest proved is in resolv.conf now"}], frames)
write_ready_status(ready=False, reason="x")
code, frames = start(header("ai.defaults"), hold=False)
must(frames[0]["code"] == "sandbox_unavailable" and "selftest" in frames[0]["message"], frames)
write_ready_status()
must(not (BASE / "log").exists() or not list((BASE / "log").iterdir()), "no unit was built or started in any refused case")

# ---- the renderer: params
must(sh.render_command(row, {"mode": "b"}) == ["--m", "b"], "")
try:
    sh.render_command(row, {})
    raise AssertionError("an omitted parameter was rendered")
except sh.Refusal:
    pass

# ---- every canary marker folder is hidden by the unit (a folder outside the hidden list would stay readable): Tactical's /rmm and MeshCentral too
def _hidden(folder):
    return any(folder == h or folder.startswith(h + "/") for h in sh.HIDDEN_FOLDERS)
for folder in sh.CANARY_MARKER_DIRS:
    must(_hidden(folder), f"canary marker folder {folder} is not under HIDDEN_FOLDERS")
for folder in ("/rmm", "/meshcentral"):
    must(folder in sh.HIDDEN_FOLDERS, f"{folder} is not hidden")
must(_hidden("/rmm/api/tacticalrmm/tacticalrmm/local_settings.py"), "local_settings.py readable")
must(any(f"{f}:ro" in p for p in props for f in ("/rmm",)) or "/rmm:ro" in joined_props, "TemporaryFileSystem does not hide /rmm")

print("[TEST] PASS sandbox unit builder 1.17.118")
shutil.rmtree(BASE, ignore_errors=True)
