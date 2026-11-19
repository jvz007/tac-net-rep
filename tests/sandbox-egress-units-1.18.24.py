#!/usr/bin/env python3
"""1.18.24 regression (AD-65 Patch B, item 2): the systemd units install.sh writes for the egress door, and the instance name.

Reads install.sh and uninstall.sh as text (the units cannot run here). Covered:

* the socket template: a Unix socket in the per-run folder below the root-only egress-door folder, SocketMode 0666, Accept=no, RemoveOnStop;
* the service template holds every hardening line of the plan: its own DynamicUser, the run's configuration as a root-only LoadCredential, no
  capabilities, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices, ProtectProc=invisible, ProcSubset=pid, the system call
  filter, only AF_INET AF_INET6 AF_UNIX, MemoryMax=64M, TasksMax=64, LimitNOFILE=256, a bounded RuntimeMaxSec, and the second wall: IPAddressDeny with the
  helper's own numeric ranges and IPAddressAllow=127.0.0.53/32 for the systemd-resolved stub only; RuntimeDirectory with preserve for the audit file;
* nothing in a unit comes from a module: no variable except the library folder;
* the instance name is the validated 32-hex run id and nothing else (egress_unit refuses anything else before any systemctl call);
* install.sh installs the proxy program root-owned, the skeleton has run/egress and no etc/resolv.conf and matches the helper's own skeleton lists,
  the sweep and uninstall remove the units, and the LF line endings are kept.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_units", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

raw = (ROOT / "install.sh").read_bytes()
must(b"\r" not in raw, "install.sh keeps LF")
must(b"\r" not in (ROOT / "uninstall.sh").read_bytes(), "uninstall.sh keeps LF")
install = raw.decode("utf-8")


def heredoc(variable):
    match = re.search(r'cat > "\$\{' + variable + r'\}" <<EOF\n(.*?)\nEOF\n', install, re.S)
    must(match, variable)
    return match.group(1)


socket_unit, service_unit = heredoc("SANDBOX_EGRESS_SOCKET"), heredoc("SANDBOX_EGRESS_SERVICE")
must('SANDBOX_EGRESS_SOCKET="/etc/systemd/system/tec-tac-sandbox-egress@.socket"' in install, "the socket template name")
must('SANDBOX_EGRESS_SERVICE="/etc/systemd/system/tec-tac-sandbox-egress@.service"' in install, "the service template name")
must(sh.EGRESS_UNIT_PREFIX == "tec-tac-sandbox-egress@", "the helper uses the same template name")

# ---- the socket
for line in ("ListenStream=/run/tec-tac/sandbox/egress-door/%i/door.sock", "SocketMode=0666", "Accept=no", "RemoveOnStop=yes", "DirectoryMode=0755"):
    must(line in socket_unit.splitlines(), ("socket", line))
must(str(sh.EGRESS_DOOR_ROOT).replace("\\", "/").endswith("/run/tec-tac/sandbox/egress-door") or sh.RUN_ROOT == Path("/run/tec-tac/sandbox"), "the door folder is below the sandbox run root")
must(str(sh.RUN_ROOT).replace("\\", "/").endswith("run/tec-tac/sandbox") and sh.EGRESS_DOOR_ROOT == sh.RUN_ROOT / "egress-door", (sh.RUN_ROOT, sh.EGRESS_DOOR_ROOT))
must(not re.search(r"ListenStream=\d|ListenStream=\[|0\.0\.0\.0|ListenDatagram|ListenSequential", socket_unit), "the door is a Unix socket and nothing else")

# ---- the service
lines = service_unit.splitlines()
must(not any(re.search(r"\$\{(?!SANDBOX_LIB\})", line) for line in lines) and "$(" not in service_unit, "no variable but the library folder")
for line in ("DynamicUser=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
             "PrivateDevices=yes", "ProtectProc=invisible", "ProcSubset=pid", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged",
             "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "MemoryMax=64M", "TasksMax=64", "LimitNOFILE=256", "RuntimeMaxSec=720",
             "IPAddressAllow=127.0.0.53/32", "RuntimeDirectory=tec-tac-sbx-egress/%i", "RuntimeDirectoryPreserve=yes", "RuntimeDirectoryMode=0700",
             "LoadCredential=run.json:/run/tec-tac/sandbox/egress-config/%i.json", "RestrictNamespaces=yes", "ProtectKernelTunables=yes",
             "RestrictSUIDSGID=yes", "LockPersonality=yes", "SystemCallArchitectures=native", "UMask=0077"):
    must(line in lines, ("service", line))
must("ExecStart=/usr/bin/python3 -I ${SANDBOX_LIB}/sandbox-egress.py" in lines, "the program is run isolated from the unit's folders")
deny = [line for line in lines if line.startswith("IPAddressDeny=")]
must(len(deny) == 1 and deny[0] == "IPAddressDeny=" + sh.ADDRESS_DENY, ("the second wall uses the helper's own numeric ranges", deny))
allow = [line for line in lines if line.startswith("IPAddressAllow=")]
must(allow == ["IPAddressAllow=127.0.0.53/32"], "only the systemd-resolved stub is allowed, by address")
must(not re.search(r"IP(Address)?(Allow|Deny)=.*(localhost|link-local|multicast|any)\b", service_unit), "numeric only, never a symbolic name")
must(not any(line.startswith(("User=", "Group=", "PrivateNetwork=", "AmbientCapabilities=CAP")) for line in lines), "no fixed user, no capability")
must(service_unit.count("[Service]") == 1 and "Type=simple" in lines, "one service section")
# the proxy's unit never grants itself the runs' own network or more families than it needs
must("AF_NETLINK" not in service_unit and "AF_PACKET" not in service_unit, "no raw families")
# the credential file the helper writes is the one the unit loads
must(str(sh.EGRESS_CONFIG_ROOT).replace("\\", "/").endswith("/run/tec-tac/sandbox/egress-config") and sh.EGRESS_CONFIG_ROOT == sh.RUN_ROOT / "egress-config", sh.EGRESS_CONFIG_ROOT)
must(str(sh.EGRESS_STATE_ROOT).replace("\\", "/") == "/run/tec-tac-sbx-egress", "the helper reads the audit file where RuntimeDirectory puts it")

# ---- the instance name
good = "0123456789abcdef0123456789abcdef"
must(sh.egress_unit(good, "socket") == f"tec-tac-sandbox-egress@{good}.socket" and sh.egress_unit(good, "service") == f"tec-tac-sandbox-egress@{good}.service", "names")
for bad in ("", "0123", good.upper(), good + "0", good[:-1], good[:-1] + "g", "../" + good, good + ".service", good + " --now", "a b", "%n" + good[2:], None, 5):
    try:
        sh.egress_unit(bad, "socket")
    except sh.Refusal as exc:
        must(exc.code == "invalid_input", exc.code)
    else:
        raise AssertionError(("a run id that is not 32 hex was accepted as an instance name", bad))
for fn in (sh.egress_door_folder, sh.egress_door_socket, sh.egress_config_path, sh.egress_audit_path):
    try:
        fn("../../etc")
    except sh.Refusal:
        pass
    else:
        raise AssertionError(("a path built from a bad id", fn.__name__))
try:
    sh.egress_unit(good, "mount")
except ValueError:
    pass
else:
    raise AssertionError("only socket and service")

# ---- install.sh: the program, the skeleton, the removal
must('install_root_script "${REPO_ROOT}/scripts/sandbox-egress.py" "${SANDBOX_LIB}/sandbox-egress.py"' in install, "the proxy is installed root-owned like the launcher")
must("chmod 0644 \"${SANDBOX_EGRESS_SOCKET}\" \"${SANDBOX_EGRESS_SERVICE}\"" in install and 'chown root:root "${SANDBOX_EGRESS_SOCKET}" "${SANDBOX_EGRESS_SERVICE}"' in install, "root-owned units")
must(install.index("SANDBOX_EGRESS_SERVICE}\" <<EOF") < install.index("systemctl daemon-reload", install.index("SANDBOX_EGRESS_SERVICE}\" <<EOF")), "daemon-reload follows the units")
dirs = re.search(r"for sandbox_entry in (usr work tmp [^;]*); do", install).group(1).split()
files = re.search(r"for sandbox_entry in (etc/passwd [^;]*); do", install).group(1).split()
must("run/egress" in dirs and "etc/resolv.conf" not in files and "etc/resolv.conf" not in dirs, (dirs, files))
must(tuple(dirs) == sh.SKELETON_DIRS and tuple(files) == sh.SKELETON_FILES, ("install.sh and the helper describe the same skeleton", dirs, files))
must(sh.SKELETON_ENTRIES["run"] == ("systemd", "egress") and sh.SKELETON_ENTRIES["run/egress"] == () and "resolv.conf" not in sh.SKELETON_ENTRIES["etc"], "skeleton entries")
uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
must("tec-tac-sandbox-egress@.socket" in uninstall and "tec-tac-sandbox-egress@.service" in uninstall and "/run/tec-tac-sbx-egress" in uninstall, "uninstall removes the units")
print("[TEST] PASS sandbox egress units 1.18.24")
