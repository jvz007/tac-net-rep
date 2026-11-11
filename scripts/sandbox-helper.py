#!/usr/bin/python3
"""Root-owned helper for core.sandbox (Core 1.17.118, Patch 2: the launch path; the kill switch is still off).

core.sandbox runs a signed module's declared program as an unprivileged, resource-limited process that cannot see the server's files
or reach the server itself or private networks (AD-63, docs/planning/sandbox/PLAN-CORE-SANDBOX.md sections 2, 3 and 15).

* ``--register-module <id>`` and ``--unregister-module <id>`` (root callers: the module job helpers): the registry of declared runners;
* ``--selftest`` (root: install.sh, an administrator): proves systemd, cgroup v2, DynamicUser, the hidden file system, credential
  hand-in, separate stdout and stderr pipes, ProtectProc and the section 15 address filter work here, and writes ``status.json``. A failed
  check means ``ready: false`` with a plain reason, never a weaker mode;
* ``--selftest --canary`` (root only, never in sudoers): the full attack test with an in-memory runner ``core.canary``; writes canary.json;
* ``--status`` (the Tactical account, through sudo): read only, with slot numbers and the canary result;
* ``--sweep`` (root: a boot and daily timer): re-verifies runtime folders; removes stray selftest folders, secrets folders, handoff and run
  files of units that are not active, and old canary markers;
* ``--start`` and ``--stop`` (the Tactical account, through sudo): the launch path. While ``SANDBOX_ENABLED`` is False both refuse with the
  ``sandbox_disabled`` frame BEFORE they read stdin. When on, ``--start`` reads one JSON header line and the input, re-checks the registry
  row, builds the unit itself from the row and Core constants, takes a server slot and a per-person slot, hands credentials in through
  LoadCredential from tmpfs, and streams one JSON frame per line (started, out, err, end). Closing its stdin or stdout stops the unit;
* ``--finish <run-id>`` (root, ExecStopPost=+): writes the unit's usage and result to a root-only handoff file for the end frame.

``SANDBOX_ENABLED`` is a constant in this file, so a fault in Django cannot switch the sandbox on. Nothing here reads a command, a path or a
limit from a caller: every rule is applied again to the root-owned registry row.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import io
import ipaddress
import json
import os
import queue as queue_module
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:  # Linux only; the tests load this file on other systems too
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

# The kill switch. It is switched on by a later Core release, only after the dev02 canary passes in full (AD-63). Not a setting.
SANDBOX_ENABLED = False

DEFAULT_CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
CONFIG_POINTER = Path("/etc/tec-tac/config-path")


def _installed_config_path(pointer=CONFIG_POINTER, default=DEFAULT_CONFIG):
    try:
        st = pointer.lstat()
    except FileNotFoundError:
        return default
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"Tec-Tac config-path pointer is not a regular file: {pointer}")
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise RuntimeError(f"Tec-Tac config-path pointer must be root-owned and not group/world writable: {pointer}")
    raw = pointer.read_text(encoding="utf-8").strip()
    path = Path(raw)
    if not raw or "\n" in raw or "\r" in raw or not path.is_absolute():
        raise RuntimeError(f"Tec-Tac config-path pointer is invalid: {pointer}")
    return path


CONFIG = _installed_config_path()
DEFAULT_EXTENSIONS_ROOT = Path("/opt/tec-tac/extensions")


def _root_owned_layout():
    """Load the one trusted root this helper needs from a verified, no-follow config descriptor."""
    values = {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(CONFIG, flags)
    except FileNotFoundError:
        return values
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"Tec-Tac config is not a regular file: {CONFIG}")
        if st.st_uid != 0 or (st.st_mode & 0o022):
            raise RuntimeError(f"Tec-Tac config must be root-owned and not group/world writable: {CONFIG}")
        with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    finally:
        os.close(fd)
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _trusted_root(layout, key, default):
    path = Path(str(layout.get(key) or default))
    if not path.is_absolute():
        raise RuntimeError(f"{key} must be an absolute path in the root-owned Tec-Tac config")
    return path


_ROOT_LAYOUT_ERROR = None
try:
    EXTENSIONS_ROOT = _trusted_root(_root_owned_layout(), "TEC_TAC_EXTENSIONS_ROOT", DEFAULT_EXTENSIONS_ROOT)
except (OSError, UnicodeError, RuntimeError, ValueError) as exc:
    # Imports stay safe; every privileged operation fails closed through _require_layout() when the root-owned config is invalid.
    _ROOT_LAYOUT_ERROR = exc
    EXTENSIONS_ROOT = DEFAULT_EXTENSIONS_ROOT

# Fixed locations (plan section 3): code and registry, state, and tmpfs. Not configurable: a config line cannot move them.
LIB_ROOT = Path("/usr/local/lib/tec-tac/sandbox")
RUNNERS_ROOT = LIB_ROOT / "runners"
REGISTRY_ROOT = LIB_ROOT / "registry"
STATE_ROOT = Path("/var/lib/tec-tac/sandbox")
RUN_ROOT = Path("/run/tec-tac/sandbox")
STATUS_FILE = STATE_ROOT / "status.json"
AUDIT_FILE = STATE_ROOT / "audit.jsonl"
SELFTEST_PREFIX = "selftest-"

# ---------------------------------------------------------------------------------------------------- the manifest rules
# The same rules as framwork/tec_tac/registry.py (_sandbox_runners), applied again here to the root-owned installed manifest.
MODULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
RUNNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PARAM_NAME_RE = RUNNER_ID_RE
PARAMETER_TYPES = frozenset({"string", "integer", "boolean", "enum"})
CREDENTIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SECRET_ENV_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|API_KEY|PRIVATE)", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUNNERS_MAX = 4
REGISTER_PERMISSION = "sandbox.register"
MIN_FRAMEWORK = (1, 17, 116)
EXECUTABLE_PREFIX = "sandbox/runners/"
RUNNER_KEYS = frozenset({
    "id", "description", "executable", "argv", "parameters", "environment", "runtime_roots", "credential_files", "credential_return",
    "limits", "revision",
})
# name -> (default, Core ceiling). A Core patch raises a ceiling, never a module.
LIMITS = {
    "memory_mb": (1024, 2048), "cpu_percent": (100, 200), "tasks": (256, 512), "run_seconds": (240, 600), "stdout_kib": (512, 1024),
    "stderr_kib": (64, 64), "scratch_mb": (64, 256), "input_kib": (64, 256), "queue_seconds": (10, 30),
}
RESERVED_ENV = frozenset({"HOME", "TMPDIR", "SSL_CERT_FILE", "SANDBOX_WORK", "SANDBOX_OUT"})
CREDENTIAL_FILES_MAX = 2
CREDENTIAL_FILE_MAX_BYTES = 16 * 1024  # used by Patch 2 when a credential is handed in
RUNTIME_ROOTS_MAX = 8
ENV_MAX = 32
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 8 * 1024 * 1024
MAX_TREE_LISTING_BYTES = 4 * 1024 * 1024
MAX_TREE_FILES = 50000
RUNTIME_BASE = "/opt/tec-tac/runtimes"  # 1.17.117: every runtime path sits strictly below RUNTIME_BASE/<module id>/
# 1.17.117: runtime_reason is a fixed code plus a fixed sentence. Never a path, a file name or an error text: the registry file is world-readable.
REASON_SENTENCES = {
    "runtime_missing": "the runtime folder is not there yet; the module builds it after install",
    "unreadable": "the runtime folder or one of its files could not be read",
    "unsafe_path": "the runtime path is not inside the module's own runtime folder",
    "unsafe_entry": "a link, a special file, or an entry that is not root-owned or is writable by others was found in the runtime folder or its path",
    "extra_file": "the runtime folder holds a file that is not in the signed listing",
    "missing_file": "a file in the signed listing is missing from the runtime folder",
    "hash_mismatch": "a file in the runtime folder differs from the signed listing",
    "too_many_files": "the runtime folder holds too many files",
    "listing_empty": "the signed tree listing is empty",
    "listing_unreadable": "the signed tree listing could not be read",
    "listing_changed": "the signed tree listing changed after the module registered; the module must register again",
    "listing_not_recorded": "the signed tree listing was not recorded at registration; the module must register again",
}
ROOT_UID = 0
REGISTERED_BY = "module-manifest"

# ----------------------------------------------------------------------------------------------------- the selftest rules
MIN_SYSTEMD_VERSION = 249  # Ubuntu 22.04, the oldest server Tec-Tac supports (plan section 10)
# Plan section 15: private ranges and the server itself are blocked; public HTTPS stays open. 169.254.169.254 is inside link-local.
ADDRESS_DENY = "localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"
PRIVATE_PROBE_TARGETS = ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254")
DNS_PROBE_NAME = "example.com"
RESOLVERS_MAX = 3
UNIT_TIMEOUT_SECONDS = 30
PROBE_PROPERTIES = {
    "transient": (),
    "dynamic_user": ("DynamicUser=yes",),
    "filesystem_view": ("DynamicUser=yes", "TemporaryFileSystem=/etc:ro", "BindReadOnlyPaths=/etc/passwd"),
    "credential": ("DynamicUser=yes",),  # plus LoadCredential and ExecStartPost, which carry the run's own paths
    "proc_hidden": ("DynamicUser=yes", "ProtectProc=invisible", "ProcSubset=pid"),
    "address_filter_control": ("DynamicUser=yes",),
    "address_filter_loopback": ("DynamicUser=yes", "IPAddressDeny=" + ADDRESS_DENY),
    "address_filter_private": ("DynamicUser=yes", "IPAddressDeny=" + ADDRESS_DENY),
    "pipe_streams": ("DynamicUser=yes",),
    "dns": ("DynamicUser=yes", "IPAddressDeny=" + ADDRESS_DENY),  # plus one IPAddressAllow= per resolver
}

# The python the probes run inside a unit. Each prints one plain word or line and nothing else.
_PROBE_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket();s.settimeout(3)\n"
    "try:\n s.connect(('127.0.0.1',int(sys.argv[1])));print('connected')\n"
    "except Exception as e:\n print('blocked')\n"
)
_PROBE_PRIVATE = (
    "import socket,sys\n"
    "for a in sys.argv[1:]:\n"
    " s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)\n"
    " try:\n  s.connect((a,9));s.send(b'x');print(a,'sent')\n"
    " except PermissionError:\n  print(a,'eperm')\n"
    " except Exception:\n  print(a,'other')\n"
)
_PROBE_DNS = (
    "import socket,struct,sys\n"
    "q=struct.pack('>HHHHHH',0x7a31,0x0100,1,0,0,0)\n"
    "for part in sys.argv[2].split('.'):\n q+=bytes([len(part)])+part.encode()\n"
    "q+=b'\\x00'+struct.pack('>HH',1,1)\n"
    "fam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\n"
    "s=socket.socket(fam,socket.SOCK_DGRAM);s.settimeout(4)\n"
    "try:\n s.sendto(q,(sys.argv[1],53));d,_=s.recvfrom(2048)\n"
    " ok=len(d)>=12 and d[:2]==q[:2] and d[2]&0x80\n"
    " print('reply %d'%(d[3]&15) if ok else 'noreply')\n"
    "except Exception:\n print('noreply')\n"
)


# --------------------------------------------------------------------------------------------------- small shared helpers
def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


_lstat = os.lstat  # one place for the no-follow stat, so a test can describe a fake file system


def _untrusted(st):
    """Not root-owned, or writable by a group or anyone else (the test of privileged-trust._require_root_owned_nonwritable)."""
    return st.st_uid != ROOT_UID or bool(st.st_mode & 0o022)


def _require_layout():
    if _ROOT_LAYOUT_ERROR is not None:
        raise RuntimeError(f"root-owned Tec-Tac config is not usable: {_ROOT_LAYOUT_ERROR}")


def _module_id(value):
    if not isinstance(value, str) or not MODULE_ID_RE.fullmatch(value):
        raise RuntimeError("module id is invalid")
    return value


def _require_trusted_path(path, label, *, directory=False):
    """lstat, never follow: the path is a real file or directory, root-owned and not group or world writable."""
    try:
        st = _lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} is not available: {path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise RuntimeError(f"{label} may not be a symlink: {path}")
    if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
        raise RuntimeError(f"{label} is not a {'directory' if directory else 'regular file'}: {path}")
    if _untrusted(st):
        raise RuntimeError(f"{label} must be root-owned and not group/world writable: {path}")


def _read_trusted_file(path, label, *, max_bytes):
    """Read one regular file with no symlink following. Owner and mode are checked on the open descriptor, so a swap after the check
    cannot change what is read."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        if stat.S_ISLNK(_lstat(path).st_mode):
            raise RuntimeError(f"{label} may not be a symlink: {path}")
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} is not readable: {path}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"{label} is not a regular file: {path}")
        if _untrusted(st):
            raise RuntimeError(f"{label} must be root-owned and not group/world writable: {path}")
        if st.st_size > max_bytes:
            raise RuntimeError(f"{label} is larger than {max_bytes} bytes: {path}")
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(max_bytes + 1)
    finally:
        os.close(fd)


def _sha256_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"not a regular file: {path}")
        digest = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _write_root_file(path, data, mode):
    """Atomically write root-owned bytes: unique temp file, mode and owner set before the rename, no symlink followed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _json_bytes(payload):
    return (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")


def append_audit(event, *, detail=None):
    """The helper's own append-only log: registered, removed, selftest, sweep. Never a credential, an input or an output."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    row = {"at": now(), "event": str(event), "detail": detail or {}}
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    try:
        os.chmod(AUDIT_FILE, 0o640)
    except OSError:
        pass


def ensure_layout():
    _require_layout()
    for folder, mode in ((LIB_ROOT, 0o755), (RUNNERS_ROOT, 0o755), (REGISTRY_ROOT, 0o755), (STATE_ROOT, 0o755), (RUN_ROOT, 0o700),
                         (SLOTS_ROOT, 0o700), (PERSON_SLOTS_ROOT, 0o700), (SECRETS_ROOT, 0o700), (HANDOFF_ROOT, 0o700), (RUNS_ROOT, 0o700)):
        folder.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(folder, 0, 0)
        os.chmod(folder, mode)


# ------------------------------------------------------------------------------------------------ manifest validation
def _framework_floor(payload):
    requires = payload.get("requires")
    spec = requires.get("framework") if isinstance(requires, dict) else None
    match = re.search(r">=\s*(\d+)\.(\d+)\.(\d+)", spec) if isinstance(spec, str) else None
    return tuple(int(part) for part in match.groups()) if match else ()


def _plain(value, limit):
    return isinstance(value, str) and len(value) <= limit and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _check_parameters(schema, label):
    if not isinstance(schema, dict) or len(schema) > 64:
        raise RuntimeError(f"{label} parameters must be an object with at most 64 entries")
    for name, spec in schema.items():
        if not isinstance(name, str) or not PARAM_NAME_RE.fullmatch(name):
            raise RuntimeError(f"{label} parameter name {name!r} is invalid")
        if not isinstance(spec, dict):
            raise TypeError(f"{label} parameter {name!r} schema must be an object")
        ptype = spec.get("type", "string")
        if ptype not in PARAMETER_TYPES:
            raise RuntimeError(f"{label} parameter {name!r} has an unsupported type")
        if ptype == "enum" and (not isinstance(spec.get("choices"), list) or not spec["choices"]):
            raise RuntimeError(f"{label} enum parameter {name!r} requires choices")
        if "pattern" in spec:
            try:
                re.compile(str(spec["pattern"]))
            except re.error as exc:
                raise RuntimeError(f"{label} parameter {name!r} has an invalid pattern") from exc
    return schema


def _check_relative(value, label, *, prefix="", min_parts=1):
    """The syntax rules for a relative path inside the module folder (the file itself is checked by the caller)."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value or value.startswith("/") or len(value) > 512:
        raise RuntimeError(f"{label} must be a relative path inside the module folder")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"{label} may not contain empty, '.' or '..' path parts")
    if prefix and (not value.startswith(prefix) or len(parts) < min_parts):
        raise RuntimeError(f"{label} must be a file below {prefix!r} in the module folder")
    return parts


_RUNTIME_PART_RE = re.compile(r"[A-Za-z0-9._-]+")  # 1.17.119: one path part is never more than one bind (no space, ':', '%', '$', quote, non-ASCII)


def _check_runtime_path(value, label, module_id):
    """1.17.117: the same rule as registry.py ``_sandbox_runtime_path``: absolute, normalised, and strictly below
    /opt/tec-tac/runtimes/<module id>/ (the module's own folder, at least one further part)."""
    if (not isinstance(value, str) or not value.startswith("/") or "\x00" in value or "\\" in value or len(value) > 512
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise RuntimeError(f"{label} path must be an absolute path without control characters")
    parts = value.split("/")[1:]
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"{label} path must be absolute and normalised, with at least two parts and no '..'")
    if not all(_RUNTIME_PART_RE.fullmatch(part) for part in parts):
        raise RuntimeError(f"{label} path parts may only hold letters, digits, '.', '_' and '-'")
    own = RUNTIME_BASE.split("/")[1:] + [module_id]
    if parts[:len(own)] != own or len(parts) <= len(own):
        raise RuntimeError(f"{label} path must sit below {RUNTIME_BASE}/{module_id}/ (at least one folder deeper)")
    return value


def parse_runners(module_id, payload, check_file):
    """The runners an installed manifest declares, after every rule of part 1 (registry.py) again. ``check_file(relative, label)`` raises
    unless the file exists in the module folder without a symlink and (in the helper) is root-owned. Returns (version, runners);
    runners is [] when the key is absent or empty."""
    if str(payload.get("id", module_id)) != module_id:
        raise RuntimeError("installed manifest id does not match the module folder")
    if str(payload.get("type", "extension")) != "extension":
        raise RuntimeError("only an extension may register sandbox runners")
    version = str(payload.get("version", "0.0.0")).strip()
    if "sandbox_runners" not in payload:
        return version, []
    raw = payload["sandbox_runners"]
    if not isinstance(raw, list):
        raise TypeError("manifest key sandbox_runners must be a JSON array")
    if len(raw) > RUNNERS_MAX:
        raise RuntimeError(f"manifest sandbox_runners may not contain more than {RUNNERS_MAX} entries")
    if not raw:
        return version, []
    permissions = payload.get("publisher_permissions") or []
    if not isinstance(permissions, list) or REGISTER_PERMISSION not in permissions:
        raise RuntimeError(f"module {module_id} declares sandbox_runners without publisher_permissions {REGISTER_PERMISSION}")
    if _framework_floor(payload) < MIN_FRAMEWORK:
        raise RuntimeError("manifest sandbox_runners needs requires.framework >=1.17.116 or higher")
    runners, seen = [], set()
    for index, entry in enumerate(raw):
        label = f"sandbox_runners entry {index + 1}"
        if not isinstance(entry, dict):
            raise TypeError(f"{label} must be a JSON object")
        if "allowed_hosts" in entry:
            raise RuntimeError(f"{label} declares allowed_hosts; the smaller sandbox has no host list")
        unknown = sorted(set(entry) - RUNNER_KEYS)
        if unknown:
            raise RuntimeError(f"{label} contains unsupported keys {unknown!r}")
        runner_id = entry.get("id")
        if not isinstance(runner_id, str) or not RUNNER_ID_RE.fullmatch(runner_id):
            raise RuntimeError(f"{label} id is invalid")
        if not runner_id.startswith(module_id + ".") or runner_id == module_id + ".":
            raise RuntimeError(f"runner id {runner_id!r} must begin with {module_id + '.'!r}")
        if runner_id in seen:
            raise RuntimeError(f"manifest declares {runner_id!r} more than once")
        seen.add(runner_id)
        label = f"runner {runner_id}"
        description = entry.get("description")
        if not isinstance(description, str) or not description.strip() or not _plain(description, 200):
            raise RuntimeError(f"{label} description must be plain text of 1 to 200 characters")
        executable = entry.get("executable")
        _check_relative(executable, f"{label} executable", prefix=EXECUTABLE_PREFIX, min_parts=3)
        check_file(executable, f"{label} executable")
        schema = _check_parameters(entry.get("parameters", {}), label)
        argv = entry.get("argv", [])
        if not isinstance(argv, list) or len(argv) > 64:
            raise RuntimeError(f"{label} argv must be an array with at most 64 entries")
        for item in argv:
            if isinstance(item, str):
                if "\x00" in item or len(item) > 4096:
                    raise RuntimeError(f"{label} has an invalid literal argv entry")
            elif not (isinstance(item, dict) and set(item) == {"param"} and isinstance(item["param"], str) and item["param"] in schema):
                raise RuntimeError(f"{label} argv entries must be literal strings or {{'param': name}}")
        environment = entry.get("environment", {})
        if not isinstance(environment, dict) or len(environment) > ENV_MAX:
            raise RuntimeError(f"{label} environment must be an object with at most {ENV_MAX} entries")
        for name, value in environment.items():
            if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
                raise RuntimeError(f"{label} environment name {name!r} is invalid")
            if name in RESERVED_ENV or name.startswith("LD_") or SECRET_ENV_RE.search(name):
                raise RuntimeError(f"{label} environment name {name!r} is not allowed")
            if not _plain(value, 1024):
                raise RuntimeError(f"{label} environment value for {name!r} is invalid")
        roots_raw = entry.get("runtime_roots", [])
        if not isinstance(roots_raw, list) or len(roots_raw) > RUNTIME_ROOTS_MAX:
            raise RuntimeError(f"{label} runtime_roots must be a list of at most {RUNTIME_ROOTS_MAX} entries")
        roots, paths = [], set()
        for root_entry in roots_raw:
            if not isinstance(root_entry, dict) or set(root_entry) != {"path", "tree_sha256_file"}:
                raise RuntimeError(f"{label} runtime_roots entries need path and tree_sha256_file")
            path = _check_runtime_path(root_entry["path"], f"{label} runtime_roots", module_id)
            if path in paths:
                raise RuntimeError(f"{label} runtime_roots repeats {path!r}")
            paths.add(path)
            tree_file = root_entry["tree_sha256_file"]
            _check_relative(tree_file, f"{label} tree_sha256_file")
            check_file(tree_file, f"{label} tree_sha256_file")
            roots.append({"path": path, "tree_sha256_file": tree_file})
        names = entry.get("credential_files", [])
        if not isinstance(names, list) or len(names) > CREDENTIAL_FILES_MAX or len(set(map(str, names))) != len(names):
            raise RuntimeError(f"{label} credential_files must be a list of at most {CREDENTIAL_FILES_MAX} different names")
        for name in names:
            if not isinstance(name, str) or not CREDENTIAL_NAME_RE.fullmatch(name):
                raise RuntimeError(f"{label} credential_files name is invalid")
        credential_return = entry.get("credential_return", False)
        if not isinstance(credential_return, bool) or (credential_return and not names):
            raise RuntimeError(f"{label} credential_return must be true or false, and needs a declared credential file name")
        raw_limits = entry.get("limits", {})
        if not isinstance(raw_limits, dict) or set(raw_limits) - set(LIMITS):
            raise RuntimeError(f"{label} limits must be an object with known keys")
        limits = {}
        for name, (default, ceiling) in LIMITS.items():
            value = raw_limits.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling:
                raise RuntimeError(f"{label} limit {name} must be a whole number from 1 to {ceiling}")
            limits[name] = value
        revision = entry.get("revision", "1")
        if isinstance(revision, bool) or not isinstance(revision, (str, int)) or not str(revision).strip() or len(str(revision)) > 64:
            raise RuntimeError(f"{label} revision must be a short text or whole number")
        runners.append({
            "id": runner_id, "description": description.strip(), "executable": executable, "argv": list(argv), "parameters": dict(schema),
            "environment": dict(environment), "runtime_roots": roots, "credential_files": list(names),
            "credential_return": credential_return, "limits": limits, "revision": str(revision).strip(),
        })
    return version, runners


# --------------------------------------------------------------------------------------------------- runtime verification
def parse_tree_listing(data):
    """The signed listing of a runtime tree: one ``<sha256>  <relative path>`` line per file (blank lines and # comments ignored)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("runtime tree listing is not UTF-8 text") from exc
    listing = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]?(.+)", line)
        if not match:
            raise RuntimeError("runtime tree listing has a line that is not '<sha256>  <path>'")
        rel = match.group(2)
        parts = rel.split("/")
        if rel.startswith("/") or any(part in ("", ".", "..") for part in parts) or "\\" in rel:
            raise RuntimeError("runtime tree listing has an unsafe path")
        if rel in listing:
            raise RuntimeError("runtime tree listing repeats a path")
        listing[rel] = match.group(1)
    if len(listing) > MAX_TREE_FILES:
        raise RuntimeError("runtime tree listing is too long")
    return listing


def reason_text(code, index=None):
    """The one place a runtime_reason is built: the root's number (when there is one) and a fixed code and sentence."""
    where = f"root {index}: " if index else ""
    return f"{where}{code} ({REASON_SENTENCES[code]})"


def verify_runtime(path, listing):
    """(ok, code). The folder and every parent are real directories, root-owned and not group or world writable; nothing inside is a
    link or a special file or writable by others; the files are exactly the listed ones with the listed SHA-256. ``code`` is "" when ok,
    else a key of REASON_SENTENCES. A missing folder is the normal first state (the module builds its runtime after install). The
    ``os.walk`` below is the only place that touches names, and no name leaves this function."""
    parts = Path(path).parts
    current = Path(parts[0])
    for index, part in enumerate(parts):
        if index:
            current = current / part
        try:
            st = _lstat(current)
        except FileNotFoundError:
            return False, "runtime_missing"
        except OSError:
            return False, "unreadable"
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or _untrusted(st):
            return False, "unsafe_entry"
    if not listing:
        return False, "listing_empty"
    found = {}
    count = 0
    for folder, dirnames, filenames in os.walk(path, followlinks=False):
        for name in dirnames + filenames:
            count += 1
            if count > MAX_TREE_FILES:
                return False, "too_many_files"
            full = os.path.join(folder, name)
            try:
                st = _lstat(full)
            except OSError:
                return False, "unreadable"
            if stat.S_ISLNK(st.st_mode) or _untrusted(st):
                return False, "unsafe_entry"
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                return False, "unsafe_entry"
            found[os.path.relpath(full, path).replace(os.sep, "/")] = full
    if set(found) - set(listing):
        return False, "extra_file"
    if set(listing) - set(found):
        return False, "missing_file"
    for rel in sorted(found):
        try:
            digest = _sha256_nofollow(found[rel])
        except (OSError, RuntimeError):
            return False, "unreadable"
        if digest != listing[rel]:
            return False, "hash_mismatch"
    return True, ""


def _check_installed_file(folder):
    """The ``check_file`` for the installed (root-owned) module folder."""
    def check(relative, label):
        current = folder
        parts = relative.split("/")
        for index, part in enumerate(parts):
            current = current / part
            _require_trusted_path(current, f"{label} path", directory=index < len(parts) - 1)
    return check


def _read_installed(module_id):
    _require_layout()
    folder = EXTENSIONS_ROOT / module_id
    _require_trusted_path(folder, "installed module folder", directory=True)
    raw = _read_trusted_file(folder / "tec_tac.json", "installed module manifest", max_bytes=MAX_MANIFEST_BYTES)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeError("installed module manifest is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("installed module manifest is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("installed module manifest must be a JSON object")
    return folder, payload


def _tree_listing(folder, relative):
    """(sha256 hex of the file's bytes, parsed listing), both from one read of the trusted file, so the hash and the listing cannot differ."""
    data = _read_trusted_file(folder.joinpath(*relative.split("/")), "runtime tree listing", max_bytes=MAX_TREE_LISTING_BYTES)
    if len(data) > MAX_TREE_LISTING_BYTES:
        raise RuntimeError("runtime tree listing is too large")
    return hashlib.sha256(data).hexdigest(), parse_tree_listing(data)


def runner_path(runner_id):
    if not isinstance(runner_id, str) or not RUNNER_ID_RE.fullmatch(runner_id):
        raise RuntimeError("runner id is invalid")
    return REGISTRY_ROOT / f"{runner_id}.json"


def _load_registry_file(path):
    """The registry JSON of one runner, or None when it is missing, a link, not root-trusted or not an object."""
    try:
        data = _read_trusted_file(path, "registry file", max_bytes=MAX_MANIFEST_BYTES)
        payload = json.loads(data.decode("utf-8"))
    except (RuntimeError, ValueError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _owned_registry_files(module_id):
    """(path, payload) for each registry file this helper wrote for the module."""
    rows = []
    if not REGISTRY_ROOT.is_dir():
        return rows
    for path in sorted(REGISTRY_ROOT.glob("*.json")):
        payload = _load_registry_file(path)
        if payload and payload.get("owner_module") == module_id and payload.get("registered_by") == REGISTERED_BY:
            rows.append((path, payload))
    return rows


def register_module(module_id):
    """``--register-module <module-id>``: register the runners an installed module declares.

    Reads the root-owned installed manifest, applies every rule again, copies each runner executable root-owned 0755 under
    ``runners/<module>/`` with its SHA-256, verifies each runtime folder against its signed listing (a failure is registered but
    ``runtime_unverified``, with a plain reason; the runtime is built after install), writes ``registry/<runner-id>.json`` and drops what
    the manifest no longer declares. A runner id owned by another module is refused. A module that declares none loses all."""
    module_id = _module_id(module_id)
    ensure_layout()
    try:
        folder, payload = _read_installed(module_id)
        version, runners = parse_runners(module_id, payload, _check_installed_file(folder))
    except TypeError as exc:  # a wrongly typed manifest value: the same plain refusal as every other rule
        raise RuntimeError(str(exc)) from exc
    staged = []
    for runner in runners:  # phase 1: read and check everything before anything changes
        data = _read_trusted_file(folder.joinpath(*runner["executable"].split("/")), f"runner {runner['id']} executable", max_bytes=MAX_EXECUTABLE_BYTES)
        if len(data) > MAX_EXECUTABLE_BYTES:
            raise RuntimeError(f"runner {runner['id']} executable is too large")
        existing = runner_path(runner["id"])
        if existing.is_file() or existing.is_symlink():
            owner = (_load_registry_file(existing) or {}).get("owner_module")
            if owner != module_id:
                raise RuntimeError(f"runner {runner['id']} is already registered by another module")
        listings = [_tree_listing(folder, root["tree_sha256_file"]) for root in runner["runtime_roots"]]
        staged.append((runner, data, listings))
    target_root = RUNNERS_ROOT / module_id
    if staged:
        target_root.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(target_root, 0, 0)
        os.chmod(target_root, 0o755)
    registered, wanted = [], set()
    for runner, data, listings in staged:  # phase 2
        subpath = runner["executable"][len(EXECUTABLE_PREFIX):]
        target = target_root / subpath
        if not target.resolve().is_relative_to(target_root.resolve()):
            raise RuntimeError(f"runner {runner['id']} executable would leave the module runner folder")
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_root_file(target, data, 0o755)
        wanted.add(target.resolve())
        reasons, stored_roots = [], []
        for number, (root, (digest, listing)) in enumerate(zip(runner["runtime_roots"], listings), 1):
            stored_roots.append({"path": root["path"], "tree_sha256_file": root["tree_sha256_file"], "listing_sha256": digest})
            ok, code = verify_runtime(root["path"], listing)
            if not ok:
                reasons.append(reason_text(code, number))
        record = {
            "id": runner["id"], "owner_module": module_id, "version": version, "revision": runner["revision"], "description": runner["description"],
            "executable": str(target), "executable_sha256": hashlib.sha256(data).hexdigest(), "argv": runner["argv"],
            "parameters": runner["parameters"], "environment": runner["environment"], "runtime_roots": stored_roots,
            "credential_files": runner["credential_files"], "credential_return": runner["credential_return"], "limits": runner["limits"],
            "runtime_verified": not reasons, "runtime_reason": "; ".join(reasons), "runtime_checked_at": now(),
            "registered_by": REGISTERED_BY, "registered_at": now(),
        }
        _write_root_file(runner_path(runner["id"]), _json_bytes(record), 0o644)
        append_audit("runner.registered", detail={"runner": runner["id"], "module": module_id, "module_version": version,
                                                   "executable_sha256": record["executable_sha256"], "runtime_verified": record["runtime_verified"],
                                                   "listing_sha256": [root["listing_sha256"] for root in stored_roots]})
        registered.append(runner["id"])
    removed = []
    for path, payload_row in _owned_registry_files(module_id):
        if str(payload_row.get("id") or path.stem) not in registered:
            path.unlink(missing_ok=True)
            removed.append(str(payload_row.get("id") or path.stem))
            append_audit("runner.removed", detail={"runner": removed[-1], "module": module_id, "reason": "no longer declared"})
    if target_root.is_dir() and not target_root.is_symlink():
        for path in sorted(target_root.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                if path.resolve() not in wanted:
                    path.unlink(missing_ok=True)
            elif path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    pass
        if not staged:
            try:
                target_root.rmdir()
            except OSError:
                pass
    append_audit("module.runners_registered", detail={"module": module_id, "module_version": version, "runners": registered, "removed": removed})
    print(",".join(registered))


def unregister_module(module_id):
    """``--unregister-module <module-id>``: remove the registry files this helper wrote for the module and the module's runner folder.
    Nothing of another module's."""
    module_id = _module_id(module_id)
    _require_layout()
    removed = []
    for path, payload in _owned_registry_files(module_id):
        path.unlink(missing_ok=True)
        removed.append(str(payload.get("id") or path.stem))
        append_audit("runner.removed", detail={"runner": removed[-1], "module": module_id, "reason": "module removed"})
    folder = RUNNERS_ROOT / module_id
    if folder.is_symlink():
        folder.unlink()
    elif folder.is_dir():
        shutil.rmtree(folder)
    append_audit("module.runners_unregistered", detail={"module": module_id, "runners": removed})
    print(",".join(removed))


# ----------------------------------------------------------------------------------------------------------- the selftest
def parse_systemd_version(text):
    """The major version from ``systemctl --version`` output ("systemd 252 (252.22-1~deb12u1)"), or None."""
    match = re.match(r"\s*systemd\s+(\d+)\b", text or "")
    return int(match.group(1)) if match else None


def parse_resolvers(text):
    """Up to three different nameserver addresses from resolv.conf text, in order. Zone ids and anything that is not an address are
    skipped. Returns [] when there is none."""
    found = []
    for raw in (text or "").splitlines():
        parts = raw.split("#", 1)[0].split(";", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            if "%" in parts[1]:
                continue  # a zone id (fe80::1%eth0) cannot be allowed by address
            try:
                address = str(ipaddress.ip_address(parts[1]))
            except ValueError:
                continue
            if address not in found:
                found.append(address)
        if len(found) >= RESOLVERS_MAX:
            break
    return found


class UnitRunner:
    """Runs one probe in a transient unit and returns (returncode, stdout, stderr). The selftest only talks to this interface, so a test
    can replace it. ``name`` is the probe name; ``properties`` the unit properties; ``command`` the argv inside the unit."""

    def run_unit(self, name, properties, command, *, timeout=UNIT_TIMEOUT_SECONDS):
        argv = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", f"--unit=tectac-selftest-{secrets.token_hex(6)}"]
        argv += [f"--property={item}" for item in properties]
        argv += ["--", *command]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, "", str(exc)
        return done.returncode, done.stdout, done.stderr

    def run_cmd(self, argv, *, timeout=15):
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, "", str(exc)
        return done.returncode, done.stdout, done.stderr


def _check(table, name, ok, detail):
    table[name] = {"ok": bool(ok), "detail": str(detail)[:300]}
    return bool(ok)


def selftest(runner=None, *, resolv_conf_path="/etc/resolv.conf", run_root=None):
    """Probe this server and return the status dict that ``status.json`` carries. Never raises for a failed probe: a failed probe is
    ``ready: false`` with a plain reason. There is no weaker mode."""
    runner = runner or UnitRunner()
    run_root = Path(run_root) if run_root else RUN_ROOT
    checks = {}
    reasons = []

    def fail(name, reason):
        reasons.append(reason)
        return False

    # systemd version and features
    code, out, err = runner.run_cmd(["systemctl", "--version"])
    version = parse_systemd_version(out) if code == 0 else None
    if version is None:
        _check(checks, "systemd_version", False, "systemctl --version gave no version")
        fail("systemd_version", "systemd is not available here")
    elif version < MIN_SYSTEMD_VERSION:
        _check(checks, "systemd_version", False, f"systemd {version}")
        fail("systemd_version", f"systemd {version} is older than {MIN_SYSTEMD_VERSION}")
    else:
        _check(checks, "systemd_version", True, f"systemd {version}")
    if "-BPF_FRAMEWORK" in (out or ""):
        _check(checks, "bpf_framework", False, "systemd is built without BPF")
        fail("bpf_framework", "systemd is built without cgroup BPF, so the address filter cannot work")
    else:
        _check(checks, "bpf_framework", True, "BPF_FRAMEWORK is not disabled")
    # cgroup v2
    code, out, err = runner.run_cmd(["stat", "-fc", "%T", "/sys/fs/cgroup"])
    if not _check(checks, "cgroup_v2", code == 0 and out.strip() == "cgroup2fs", out.strip() or err.strip() or "no answer"):
        fail("cgroup_v2", "the server does not use the unified cgroup v2 hierarchy")
    # a harmless transient unit
    code, out, err = runner.run_unit("transient", PROBE_PROPERTIES["transient"], ["/bin/echo", "tectac-probe"])
    if not _check(checks, "transient_unit", code == 0 and out.strip() == "tectac-probe", err.strip()[:200] or out.strip()):
        fail("transient_unit", "systemd-run could not start a transient unit")
    # DynamicUser
    code, out, err = runner.run_unit("dynamic_user", PROBE_PROPERTIES["dynamic_user"], ["/usr/bin/id", "-u"])
    uid = out.strip()
    dyn_ok = code == 0 and uid.isdigit() and int(uid) >= 61184
    if not _check(checks, "dynamic_user", dyn_ok, f"uid {uid}" if uid else err.strip()[:200]):
        fail("dynamic_user", "a unit could not run as a dynamic user")
    # hidden file system, read-only bind
    script = "if test -r /etc/passwd && ! test -e /etc/shadow && ! test -e /etc/tec-tac; then echo ok; else echo bad; fi"
    code, out, err = runner.run_unit("filesystem_view", PROBE_PROPERTIES["filesystem_view"], ["/bin/sh", "-c", script])
    if not _check(checks, "filesystem_view", code == 0 and out.strip() == "ok", out.strip() or err.strip()[:200]):
        fail("filesystem_view", "a unit could not be given a hidden file system with read-only binds")
    # credential hand-in
    ok, detail = _probe_credential(runner, run_root)
    if not _check(checks, "credential", ok, detail):
        fail("credential", "LoadCredential did not work: " + detail)
    # ProtectProc and ProcSubset
    script = ("n=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l); "
              "if [ \"$n\" -le 6 ] && [ ! -e /proc/cpuinfo ]; then echo ok; else echo bad $n; fi")
    code, out, err = runner.run_unit("proc_hidden", PROBE_PROPERTIES["proc_hidden"], ["/bin/sh", "-c", script])
    if not _check(checks, "proc_hidden", code == 0 and out.strip() == "ok", out.strip() or err.strip()[:200]):
        fail("proc_hidden", "ProtectProc=invisible or ProcSubset=pid is not working")
    # the section 15 address filter, with a control run so a probe that cannot connect anyway is never read as a pass
    filter_ok, detail = _probe_address_filter(runner, checks)
    if not filter_ok:
        fail("address_filter", detail)
    # stdout and stderr arrive on separate pipes through systemd-run --pipe (plan section 10, item 1)
    command = ["/usr/bin/python3", "-I", "-c", "import sys;sys.stdout.write('out');sys.stdout.flush();sys.stderr.write('err')"]
    code, out, err = runner.run_unit("pipe_streams", PROBE_PROPERTIES["pipe_streams"], command)
    if not _check(checks, "pipe_streams", code == 0 and out.strip() == "out" and err.strip() == "err", f"out={out.strip()[:40]!r} err={err.strip()[:40]!r}"):
        fail("pipe_streams", "systemd-run --pipe did not keep stdout and stderr apart")
    # DNS
    try:
        text = Path(resolv_conf_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    resolvers = parse_resolvers(text)
    resolver, dns_ok = "", False
    if not resolvers:
        _check(checks, "dns", False, "no nameserver in resolv.conf")
        fail("dns", "no name server is listed in /etc/resolv.conf, so a run could not look up names")
    else:
        resolver, detail = _probe_dns(runner, resolvers)
        dns_ok = bool(resolver)
        if not _check(checks, "dns", dns_ok, detail):
            fail("dns", detail)
    address_filter_ok = all(checks.get(name, {}).get("ok") for name in ("address_filter_control", "address_filter_loopback", "address_filter_private"))
    ready = not reasons
    return {
        "ready": ready, "reason": "ready" if ready else reasons[0], "enabled": False, "systemd_version": version,
        "address_filter_ok": address_filter_ok, "dns_ok": dns_ok, "resolver": resolver, "resolvers": resolvers,
        "dns_method": "ip_address_allow" if resolvers else "", "selftest_at": now(), "checks": checks,
        "slots_total": slot_count(mem_available_kib(), LIMITS["memory_mb"][0]),
    }


def _probe_credential(runner, run_root):
    """A random token in a root-only folder arrives through LoadCredential, is readable only by the unit's user, and the source can be
    removed after start. Returns (ok, plain detail)."""
    folder = Path(run_root) / (SELFTEST_PREFIX + secrets.token_hex(6))
    try:
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        source = folder / "probe"
        token = secrets.token_hex(16)
        source.write_text(token, encoding="utf-8")
        os.chmod(source, 0o600)
        properties = list(PROBE_PROPERTIES["credential"]) + [f"LoadCredential=probe:{source}", f"ExecStartPost=+/bin/rm -f {source}"]
        script = 'sleep 1; cat "$CREDENTIALS_DIRECTORY/probe"; echo; stat -c %a "$CREDENTIALS_DIRECTORY/probe"'
        code, out, err = runner.run_unit("credential", properties, ["/bin/sh", "-c", script])
        lines = out.strip().splitlines()
        if code != 0 or len(lines) < 2:
            return False, (err.strip()[:200] or "the unit did not start")
        if lines[0] != token:
            return False, "the credential did not arrive"
        if lines[1].strip() != "400":
            return False, f"the credential file mode is {lines[1].strip()}, not 400"
        if source.exists():
            return False, "the source file was not removable after the start"
        return True, "arrived, mode 400, source removed"
    except OSError as exc:
        return False, f"cannot prepare the probe folder ({exc.strerror or 'error'})"
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _probe_address_filter(runner, checks):
    """Loopback and private ranges must be refused under the section 15 filter, and the same probes must succeed without it."""
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.5)
        port = listener.getsockname()[1]
    except OSError as exc:
        listener.close()
        _check(checks, "address_filter_control", False, f"cannot open a loopback listener ({exc.strerror or 'error'})")
        _check(checks, "address_filter_loopback", False, "not run")
        _check(checks, "address_filter_private", False, "not run")
        return False, "the selftest could not open a loopback listener"
    try:
        def accepted():
            seen = 0
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return seen
                conn.close()
                seen += 1

        command = ["/usr/bin/python3", "-I", "-c", _PROBE_CONNECT, str(port)]
        code, out, err = runner.run_unit("address_filter_control", PROBE_PROPERTIES["address_filter_control"], command)
        control_ok = code == 0 and out.strip() == "connected" and accepted() >= 1
        _check(checks, "address_filter_control", control_ok, out.strip() or err.strip()[:200])
        code, out, err = runner.run_unit("address_filter_loopback", PROBE_PROPERTIES["address_filter_loopback"], command)
        loop_ok = code == 0 and out.strip() == "blocked" and accepted() == 0
        _check(checks, "address_filter_loopback", loop_ok, out.strip() or err.strip()[:200])
    finally:
        listener.close()
    command = ["/usr/bin/python3", "-I", "-c", _PROBE_PRIVATE, *PRIVATE_PROBE_TARGETS]
    code, out, err = runner.run_unit("address_filter_private", PROBE_PROPERTIES["address_filter_private"], command)
    results = {}
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) == 2:
            results[parts[0]] = parts[1]
    private_ok = code == 0 and "sent" not in results.values() and "eperm" in results.values()
    _check(checks, "address_filter_private", private_ok, ", ".join(f"{a} {r}" for a, r in results.items()) or err.strip()[:200])
    if not control_ok:
        return False, "the address filter probe could not be checked (a loopback connection without the filter did not work)"
    if not loop_ok:
        return False, "the address filter does not stop a unit from reaching the server itself (cgroup BPF may be missing)"
    if not private_ok:
        return False, "the address filter did not refuse private-range traffic"
    return True, "loopback and private ranges refused"


def _probe_dns(runner, resolvers):
    """Allow exactly the listed resolvers and prove any DNS reply arrives from inside the filtered unit. NXDOMAIN counts, no reply does not.
    Returns (answering resolver or '', plain detail)."""
    allow = [f"IPAddressAllow={address}" for address in resolvers]
    for address in resolvers:
        command = ["/usr/bin/python3", "-I", "-c", _PROBE_DNS, address, DNS_PROBE_NAME]
        code, out, _err = runner.run_unit("dns", list(PROBE_PROPERTIES["dns"]) + allow, command)
        if code == 0 and out.strip().startswith("reply"):
            return address, f"{address} answered ({out.strip()})"
    return "", "no DNS reply from inside the unit from " + ", ".join(resolvers)


def write_status(status):
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    _write_root_file(STATUS_FILE, _json_bytes(status), 0o644)


def run_selftest():
    ensure_layout()
    status = selftest()
    write_status(status)
    append_audit("selftest", detail={"ready": status["ready"], "reason": status["reason"], "systemd_version": status["systemd_version"]})
    print(json.dumps(status, sort_keys=True))
    return 0 if status["ready"] else 1


# ------------------------------------------------------------------------------------------------------ status and sweep
def read_status():
    """status.json (read only, root-trust checked) or a plain not-ready answer."""
    try:
        data = _read_trusted_file(STATUS_FILE, "status file", max_bytes=64 * 1024)
        status = json.loads(data.decode("utf-8"))
        if isinstance(status, dict) and len(data) <= 64 * 1024:
            status["enabled"] = False if not SANDBOX_ENABLED else bool(status.get("enabled"))
            return status
    except (RuntimeError, ValueError, OSError):
        pass
    return {"ready": False, "reason": "the sandbox selftest has not run or its result cannot be read", "enabled": False}


def registered_runners():
    rows = []
    if not REGISTRY_ROOT.is_dir():
        return rows
    for path in sorted(REGISTRY_ROOT.glob("*.json")):
        payload = _load_registry_file(path)
        if payload:
            rows.append({key: payload.get(key) for key in ("id", "owner_module", "version", "revision", "executable_sha256", "runtime_verified", "runtime_reason", "limits")})
    return rows


def _sweep_reasons(payload):
    """The runtime_reason parts for one registry row. The path is checked against the row's owner first (defence in depth against a row
    from an older registration) and a path outside the module's own runtime folder is never walked. The listing file must still hash to
    what registration recorded: a changed listing means the runtime is not walked either."""
    reasons = []
    try:
        owner = _module_id(payload.get("owner_module"))
        folder = EXTENSIONS_ROOT / owner
        roots = payload.get("runtime_roots") or []
        if not isinstance(roots, list):
            raise TypeError("roots")
    except (RuntimeError, TypeError):
        return [reason_text("unreadable")]
    for number, root in enumerate(roots, 1):
        try:
            path, tree_file, recorded = root["path"], root["tree_sha256_file"], root.get("listing_sha256")
            _check_runtime_path(path, "runtime root", owner)
            _check_relative(tree_file, "runtime root tree_sha256_file")  # 1.17.118: the stored row is judged by the same syntax rule
        except (RuntimeError, KeyError, TypeError, AttributeError):
            reasons.append(reason_text("unsafe_path", number))
            continue
        if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{64}", recorded):
            reasons.append(reason_text("listing_not_recorded", number))
            continue
        try:
            digest, listing = _tree_listing(folder, tree_file)
        except (RuntimeError, OSError, TypeError, AttributeError):
            reasons.append(reason_text("listing_unreadable", number))
            continue
        if digest != recorded:
            reasons.append(reason_text("listing_changed", number))
            continue
        ok, code = verify_runtime(path, listing)
        if not ok:
            reasons.append(reason_text(code, number))
    return reasons


# ============================================================================ Patch 2 (1.17.118): the launch path
# ``--start`` and ``--stop`` (the Tactical account, through sudo), ``--finish`` (root, ExecStopPost), the unit builder, the slots, the
# credential hand-in, the framing and the canary. SANDBOX_ENABLED stays False: ``--start`` and ``--stop`` refuse before they read stdin.
LAUNCHER_FILE = LIB_ROOT / "sandbox-launcher.py"
CANARY_DIR = LIB_ROOT / "canary"
CANARY_RUNNER_FILE = CANARY_DIR / "sandbox-canary-runner.py"
SLOTS_ROOT = RUN_ROOT / "slots"
PERSON_SLOTS_ROOT = SLOTS_ROOT / "person"
SECRETS_ROOT = RUN_ROOT / "secrets"
HANDOFF_ROOT = RUN_ROOT / "handoff"
RUNS_ROOT = RUN_ROOT / "runs"
CANARY_FILE = STATE_ROOT / "canary.json"
CANARY_MARKERS_FILE = RUN_ROOT / "canary-markers.json"
HELPER_COMMAND = "/usr/local/sbin/tec-tac-sandbox"
SYSTEMD_RUN = ["systemd-run"]  # a test replaces these names
SYSTEMCTL = ["systemctl"]
UNIT_PYTHON = "/usr/bin/python3"
CHILD_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}  # the only environment a child of the helper gets
WORK_DIR = "/work"
PROC_MEMINFO = "/proc/meminfo"
RESOLV_CONF = "/etc/resolv.conf"

SLICE = "tec-tac-sandbox.slice"
UNIT_PREFIX = "tectac-sbx-"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SERVER_SLOTS_MAX = 6
SLOT_RESERVE_KIB = int(1.5 * 1024 * 1024)
PERSON_SLOTS = 2
RETRY_AFTER_SECONDS = 5
HEADER_MAX_BYTES = 256 * 1024
HEADER_KEYS = frozenset({"runner_id", "run_id", "person", "parameters", "credentials", "input_bytes"})
FLUSH_SECONDS = 0.05
FLUSH_BYTES = 4096
STOP_GRACE_SECONDS = 5
TIMER_SLACK_SECONDS = 5  # RuntimeMaxSec is the run's own limit plus this, so the helper's timer fires first
LAUNCHER_HEADER_RE = re.compile(rb"TECTAC-SBX-LAUNCHER ([0-9a-f]{32})")
SANDBOX_PATH_ENV = "/usr/local/bin:/usr/bin:/bin"
# The unit's file system (plan sections 3 and 15). Hidden folders, then only what the runner needs bound back, read only.
HIDDEN_FOLDERS = ("/etc", "/var", "/run", "/opt", "/srv", "/mnt", "/media", "/home", "/root", "/rmm", "/meshcentral", "/usr/local/lib/tec-tac")
BASE_BINDS_REQUIRED = ("/etc/ssl/certs", "/etc/passwd", "/etc/group", "/etc/ld.so.cache", "/etc/resolv.conf")
BASE_BINDS_OPTIONAL = ("/etc/ca-certificates", "/etc/nsswitch.conf", "/etc/localtime")
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

_REFUSAL_TEXT = {
    "sandbox_unavailable": "this server cannot host a sandbox run right now",
    "runtime_unverified": "the runner's runtime is not verified",
    "runner_unknown": "that runner is not registered",
    "invalid_input": "the start request is not valid",
    "input_too_large": "the input is larger than the runner allows",
    "credential_invalid": "a credential is not allowed for this runner",
    "busy": "all sandbox slots are in use",
    "person_busy": "this person already has the most runs allowed at once",
    "start_failed": "the run could not be started",
}


class Refusal(Exception):
    """A refusal before or at the start of a run. ``code`` is one of the SandboxError codes of the Django side."""

    def __init__(self, code, message=None, retry_after=None):
        super().__init__(message or _REFUSAL_TEXT.get(code, code))
        self.code = code
        self.message = message or _REFUSAL_TEXT.get(code, code)
        self.retry_after = retry_after

    def frame(self):
        frame = {"t": "refused", "code": self.code, "message": self.message}
        if self.retry_after is not None:
            frame["retry_after"] = self.retry_after
        return frame


class DeadMan(Exception):
    """The caller is gone (stdin EOF or a broken stdout pipe): the run must be stopped."""


def _frame_bytes(payload):
    return (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def stdout_emitter(stream=None):
    """The frame writer for the real ``--start``: one JSON object per line on stdout. A broken pipe is a dead man."""
    stream = stream or sys.stdout.buffer

    def emit(payload):
        try:
            stream.write(_frame_bytes(payload))
            stream.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise DeadMan("stdout is closed") from exc
    return emit


# ---------------------------------------------------------------------------------------------------------------------- slots
_FAKE_LOCKS = set()  # used only where fcntl does not exist (tests on another system)


def norm_key(path):
    return os.path.normcase(os.path.abspath(str(path)))


def _lock_nonblocking(fd, key):
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True
    if key in _FAKE_LOCKS:
        return False
    _FAKE_LOCKS.add(key)
    return True


def _unlock(fd, key):
    if fcntl is None:
        _FAKE_LOCKS.discard(key)


def mem_available_kib(path=None):
    try:
        for line in Path(path or PROC_MEMINFO).read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def slot_count(available_kib, memory_max_mb):
    """N = min(6, floor((MemAvailable - 1.5 GiB) / memory_max)), at least 1 (plan section 6)."""
    free = int(available_kib) - SLOT_RESERVE_KIB
    per = max(1, int(memory_max_mb)) * 1024
    return max(1, min(SERVER_SLOTS_MAX, free // per if free > 0 else 0))


def person_key(person):
    return hashlib.sha256(str(person).encode("utf-8")).hexdigest()[:32]


class SlotHolder:
    """Holds flock'd files for the life of one run. A crash of the helper closes the descriptors, so a slot is never left behind."""

    def __init__(self):
        self.held = []

    def take(self, folder, names, *, deadline, clock=time.monotonic, sleep=time.sleep):
        folder.mkdir(parents=True, exist_ok=True)
        while True:
            for name in names:
                path = folder / name
                fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
                if _lock_nonblocking(fd, norm_key(path)):
                    self.held.append((fd, norm_key(path)))
                    return True
                os.close(fd)
            if clock() >= deadline:
                return False
            sleep(0.05)

    def release(self):
        while self.held:
            fd, key = self.held.pop()
            _unlock(fd, key)
            try:
                os.close(fd)
            except OSError:
                pass


def acquire_slots(person, row, *, slots_n=None, person_n=PERSON_SLOTS, clock=time.monotonic, sleep=time.sleep):
    """Per-person slot first, then a server slot; each waits up to queue_seconds. Returns the holder or raises busy / person_busy."""
    holder = SlotHolder()
    total = slots_n if slots_n else slot_count(mem_available_kib(), row["limits"]["memory_mb"])
    deadline = clock() + int(row["limits"]["queue_seconds"])
    try:
        if not holder.take(PERSON_SLOTS_ROOT, [f"{person_key(person)}-{k}" for k in range(person_n)], deadline=deadline, clock=clock, sleep=sleep):
            raise Refusal("person_busy", retry_after=RETRY_AFTER_SECONDS)
        if not holder.take(SLOTS_ROOT, [str(k) for k in range(total)], deadline=deadline, clock=clock, sleep=sleep):
            raise Refusal("busy", retry_after=RETRY_AFTER_SECONDS)
    except BaseException:
        holder.release()
        raise
    return holder


def slots_in_use(total):
    """How many server slots are held right now (a root read: try each lock and let it go)."""
    used = 0
    for k in range(total):
        path = SLOTS_ROOT / str(k)
        if not path.exists():
            continue
        try:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
        except OSError:
            continue
        try:
            if _lock_nonblocking(fd, norm_key(path)):
                _unlock(fd, norm_key(path))
            else:
                used += 1
        finally:
            os.close(fd)
    return used


# ------------------------------------------------------------------------------------------------------ the start request
def _plain_id(value, regex):
    return isinstance(value, str) and bool(regex.fullmatch(value))


def read_header(stdin):
    """One JSON header line. Returns (header, input size). Nothing is trusted yet."""
    line = stdin.readline(HEADER_MAX_BYTES + 1)
    if not line or len(line) > HEADER_MAX_BYTES or not line.endswith(b"\n"):
        raise Refusal("invalid_input", "the start request header is missing or too long")
    try:
        header = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal("invalid_input", "the start request header is not valid JSON") from exc
    if not isinstance(header, dict) or set(header) - HEADER_KEYS:
        raise Refusal("invalid_input", "the start request header has unknown keys")
    if not _plain_id(header.get("runner_id"), RUNNER_ID_RE):
        raise Refusal("invalid_input", "the runner id is invalid")
    if not _plain_id(header.get("run_id"), RUN_ID_RE):
        raise Refusal("invalid_input", "the run id is invalid")
    person = header.get("person")
    if not isinstance(person, str) or not 1 <= len(person) <= 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in person):
        raise Refusal("invalid_input", "the person is invalid")
    if not isinstance(header.get("parameters", {}), dict) or not isinstance(header.get("credentials", {}), dict):
        raise Refusal("invalid_input", "parameters and credentials must be objects")
    size = header.get("input_bytes", 0)
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise Refusal("invalid_input", "input_bytes must be a whole number")
    return header, size


def read_input(stdin, size, limits):
    """Exactly ``size`` bytes of input, refused first when ``size`` is over the runner's input_kib."""
    if size > int(limits["input_kib"]) * 1024:
        raise Refusal("input_too_large")
    data = b""
    while len(data) < size:
        chunk = stdin.read(size - len(data))
        if not chunk:
            raise Refusal("invalid_input", "the input ended early")
        data += chunk
    return data


def validate_run_parameters(schema, raw):
    """The registered schema applied again (enum, integer range, pattern, length). No value reaches a shell: the runner is exec'd."""
    unknown = sorted(set(raw) - set(schema))
    if unknown:
        raise Refusal("invalid_input", "unknown parameter(s): " + ", ".join(unknown))
    values = {}
    for name, spec in schema.items():
        if name in raw:
            value = raw[name]
        elif "default" in spec:
            value = spec["default"]
        elif spec.get("required", False):
            raise Refusal("invalid_input", f"required parameter {name!r} is missing")
        else:
            continue
        ptype = str(spec.get("type") or "string")
        bad = None
        if ptype == "string":
            if not isinstance(value, str):
                bad = "must be a string"
            elif "\x00" in value or len(value) > max(1, min(int(spec.get("max_length", 4096)), 65536)):
                bad = "is too long or holds a NUL"
            elif spec.get("pattern") and not re.fullmatch(str(spec["pattern"]), value):
                bad = "does not match its pattern"
        elif ptype == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                bad = "must be an integer"
            elif ("minimum" in spec and value < int(spec["minimum"])) or ("maximum" in spec and value > int(spec["maximum"])):
                bad = "is out of range"
        elif ptype == "boolean":
            if not isinstance(value, bool):
                bad = "must be true or false"
        elif ptype == "enum" and value not in spec.get("choices", []):
            bad = "must be one of its choices"
        if bad:
            raise Refusal("invalid_input", f"parameter {name!r} {bad}")
        values[name] = value
    return values


def decode_credentials(row, raw):
    """Names must be declared for the runner, each at most 16 KiB. Returns {name: bytes}."""
    declared = set(row.get("credential_files") or [])
    out = {}
    for name, value in raw.items():
        if name not in declared or not isinstance(value, str):
            raise Refusal("credential_invalid", "a credential name is not declared for this runner")
        try:
            data = base64.b64decode(value.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            raise Refusal("credential_invalid", "a credential is not valid base64") from exc
        if len(data) > CREDENTIAL_FILE_MAX_BYTES:
            raise Refusal("credential_invalid", "a credential is larger than 16 KiB")
        out[name] = data
    return out


def render_command(row, parameters):
    items = []
    for item in row["argv"]:
        if isinstance(item, str):
            items.append(item)
            continue
        name = str(item["param"])
        if name not in parameters:
            raise Refusal("invalid_input", f"the runner's argv needs the omitted optional parameter {name!r}")
        value = parameters[name]
        items.append(("true" if value else "false") if isinstance(value, bool) else str(value))
    return items


# --------------------------------------------------------------------------------------------- readiness at every start
def runner_base(owner):
    """Where a runner's root-installed executable must live: the module's own runner folder, or Core's canary folder."""
    return CANARY_DIR if owner == CANARY_OWNER else RUNNERS_ROOT / owner


def load_runner_row(runner_id):
    row = _load_registry_file(runner_path(runner_id))
    if not row or row.get("registered_by") != REGISTERED_BY or row.get("id") != runner_id or row.get("owner_module") == CANARY_OWNER:
        raise Refusal("runner_unknown")  # a registry row can never claim the canary's owner id
    try:
        _module_id(row.get("owner_module"))
    except RuntimeError as exc:
        raise Refusal("runner_unknown") from exc
    if not runner_id.startswith(row["owner_module"] + "."):
        raise Refusal("runner_unknown")
    return row


def check_runner_ready(row):
    """The root registry row is checked again at every start: verified runtime, runtime roots still root-owned with no writable parent,
    runner executable root-owned, inside its folder and unchanged."""
    if row.get("runtime_verified") is not True:
        raise Refusal("runtime_unverified")
    owner = row["owner_module"]
    for root in row.get("runtime_roots") or []:
        try:
            path = _check_runtime_path(root["path"], "runtime root", owner)
        except (RuntimeError, KeyError, TypeError) as exc:
            raise Refusal("runtime_unverified") from exc
        current = None
        for index, part in enumerate(Path(path).parts):
            current = Path(part) if index == 0 else current / part
            try:
                st = _lstat(current)
            except OSError as exc:
                raise Refusal("runtime_unverified") from exc
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or _untrusted(st):
                raise Refusal("runtime_unverified")
    executable = Path(str(row.get("executable") or ""))
    try:
        if not executable.is_absolute() or not executable.resolve().is_relative_to(runner_base(owner).resolve()):
            raise RuntimeError("outside the runner folder")
        _require_trusted_path(executable, "runner executable")
        digest = _sha256_nofollow(executable)
    except (RuntimeError, OSError) as exc:
        raise Refusal("runtime_unverified", "the runner executable is missing, not root-owned or outside its folder") from exc
    if not isinstance(row.get("executable_sha256"), str) or digest != row["executable_sha256"]:
        raise Refusal("runtime_unverified", "the runner executable changed since it was registered")


def ready_status():
    status = read_status()
    if status.get("ready") is not True:
        raise Refusal("sandbox_unavailable", "the sandbox selftest has not passed on this server")
    return status


def usable_resolvers(status, text):
    """The addresses a run may reach for DNS: the IPv4 resolvers in resolv.conf right now that the selftest proved (it got an answer
    from inside a filtered unit). IPv6 and zone-id addresses are skipped (a run has no IPv6). None means ``sandbox_unavailable``."""
    proven = status.get("resolver")
    return [a for a in parse_resolvers(text) if a == proven and ipaddress.ip_address(a).version == 4]


# -------------------------------------------------------------------------------------------------------- the unit builder
def unit_name(run_id):
    return UNIT_PREFIX + run_id


def _bind_path_safe(path):
    """1.17.119: a path that comes from the registry row must stay one BindReadOnlyPaths= entry: no whitespace (systemd splits a bind
    line on it), no ':' (source:destination:options), no '%' or '$' (expansion), no control character, no backslash."""
    return (isinstance(path, str) and bool(path) and "\\" not in path
            and not any(ch.isspace() or ch in ":%$" or ord(ch) < 32 or ord(ch) == 127 for ch in path))


def build_properties(row, run_id, *, resolvers, credential_names, exists=os.path.lexists):
    """Every property of the unit, as ``Key=Value`` strings. Built from the registry row and the constants above only: nothing here comes
    from the caller or from the module's manifest text (argv and environment values travel as arguments, never as properties)."""
    limits = row["limits"]
    scratch = int(limits["scratch_mb"])
    for path in BASE_BINDS_REQUIRED:
        if not exists(path):
            raise Refusal("sandbox_unavailable", f"this server has no {path} to hand a run")
    binds = list(BASE_BINDS_REQUIRED) + [path for path in BASE_BINDS_OPTIONAL if exists(path)]
    own = [root["path"] for root in row.get("runtime_roots") or []]
    if not all(_bind_path_safe(path) for path in own):
        raise Refusal("runtime_unverified")  # fail closed: never a unit with an extra bind
    own += [str(runner_base(row["owner_module"])), str(LAUNCHER_FILE)]
    for path in own:
        if not exists(path):
            raise Refusal("sandbox_unavailable", "a folder the run needs is missing")  # a missing bind fails loudly, never leaks
    binds += own
    props = [
        "DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateIPC=yes",
        "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
        "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources", "SystemCallArchitectures=native",
        "SystemCallErrorNumber=EPERM", "RestrictAddressFamilies=AF_INET AF_UNIX", "RestrictNamespaces=yes", "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=no", "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
        "ProtectProc=invisible", "ProcSubset=pid", "UMask=0077", "KillMode=control-group", "SendSIGKILL=yes",
        f"MemoryMax={int(limits['memory_mb'])}M", "MemorySwapMax=0", f"CPUQuota={int(limits['cpu_percent'])}%",
        f"TasksMax={int(limits['tasks'])}", "LimitNOFILE=1024", "LimitCORE=0", f"LimitFSIZE={scratch * 1024 * 1024}",
        f"RuntimeMaxSec={int(limits['run_seconds']) + TIMER_SLACK_SECONDS}",
        "TemporaryFileSystem=" + " ".join(f"{folder}:ro" for folder in HIDDEN_FOLDERS),
        f"TemporaryFileSystem={WORK_DIR}:rw,nosuid,nodev,size={scratch}M,mode=1777",
        f"WorkingDirectory={WORK_DIR}",
    ]
    props += [f"BindReadOnlyPaths={path}" for path in binds]
    props.append("IPAddressDeny=" + ADDRESS_DENY)
    props += [f"IPAddressAllow={address}" for address in resolvers]
    folder = SECRETS_ROOT / run_id
    props += [f"LoadCredential={name}:{folder / name}" for name in credential_names]
    if credential_names:
        props.append(f"ExecStartPost=+/bin/rm -rf {folder}")
    props.append(f"ExecStopPost=+{HELPER_COMMAND} --finish {run_id}")
    return props


def build_environment(row):
    """The manifest's fixed map first, the reserved names last, so a manifest can never override them (the registry refuses them too)."""
    env = {name: str(value) for name, value in (row.get("environment") or {}).items() if name not in RESERVED_ENV}
    env.update({
        "HOME": f"{WORK_DIR}/home", "TMPDIR": f"{WORK_DIR}/tmp", "SANDBOX_WORK": WORK_DIR, "SANDBOX_OUT": f"{WORK_DIR}/out",
        "SSL_CERT_FILE": CA_BUNDLE, "PATH": SANDBOX_PATH_ENV,
    })
    return env


def _exec_escape(text):
    """1.17.119: systemd expands '$VAR' and '%specifier' in the command of a transient unit. '$$' and '%%' reach the program as '$' and '%'."""
    return str(text).replace("$", "$$").replace("%", "%%")


def build_argv(row, run_id, parameters, *, resolvers, credential_names, exists=os.path.lexists):
    argv = [*SYSTEMD_RUN, "--pipe", "--wait", "--collect", "--quiet", f"--unit={unit_name(run_id)}", f"--slice={SLICE}"]
    argv += [f"--property={item}" for item in build_properties(row, run_id, resolvers=resolvers, credential_names=credential_names, exists=exists)]
    argv += [f"--setenv={name}={value}" for name, value in build_environment(row).items()]
    argv.append("--")
    command = [UNIT_PYTHON, "-I", str(LAUNCHER_FILE)]
    if row.get("credential_return"):
        command.append("--return-credential")
    command += ["--", str(row["executable"]), *render_command(row, parameters)]
    return argv + [_exec_escape(item) for item in command]


# ------------------------------------------------------------------------------------------------ the output stream parser
class LauncherError(Exception):
    pass


class StreamParser:
    """Strips the launcher's header line and its final credential frame from stdout. The nonce comes from the header line (printed before
    the runner starts, never given to it); only a line that begins with ``\\n<nonce> CRED `` counts, so a runner cannot forge one. The last
    len(marker)-1 bytes are held back until more arrives, so a frame split across reads is still found."""

    def __init__(self, frames=True):
        self.frames = frames  # False: the runner has no credential_return, so no frame is expected and nothing is held back
        self.header_done = False
        self.marker = b""
        self.buf = b""
        self.in_credential = False
        self.credential = None
        self.closed = False

    def feed(self, data):
        if self.closed:
            return b""
        self.buf += data
        if not self.header_done:
            i = self.buf.find(b"\n")
            if i < 0:
                if len(self.buf) > 200:
                    raise LauncherError("no launcher header")
                return b""
            match = LAUNCHER_HEADER_RE.fullmatch(self.buf[:i])
            if not match:
                raise LauncherError("bad launcher header")
            self.marker = b"\n" + match.group(1) + b" CRED "
            self.buf = self.buf[i + 1:]
            self.header_done = True
        if not self.frames:
            out, self.buf = self.buf, b""
            return out
        if self.in_credential:
            return self._credential()
        i = self.buf.find(self.marker)
        if i >= 0:
            out, self.buf, self.in_credential = self.buf[:i], self.buf[i + len(self.marker):], True
            self._credential()
            return out
        hold = len(self.marker) - 1
        if len(self.buf) > hold:
            out, self.buf = self.buf[:-hold], self.buf[-hold:]
            return out
        return b""

    def _credential(self):
        i = self.buf.find(b"\n")
        if i < 0:
            if len(self.buf) > CREDENTIAL_FILE_MAX_BYTES * 2:
                self.closed, self.buf = True, b""
            return b""
        try:
            data = base64.b64decode(self.buf[:i], validate=True)
            self.credential = data if len(data) <= CREDENTIAL_FILE_MAX_BYTES else None
        except ValueError:
            self.credential = None
        self.closed, self.buf = True, b""
        return b""

    def finish(self):
        """What is still held at the end of the stream (nothing when a credential frame was open)."""
        out = b"" if (self.in_credential or self.closed) else self.buf
        self.buf = b""
        return out


# ------------------------------------------------------------------------------------------------------ run bookkeeping
def _write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def write_secrets(run_id, credentials):
    """Credentials land only on tmpfs: /run/tec-tac/sandbox/secrets/<run id>/ (0700) with 0600 files. Never in argv, env, audit or a log."""
    folder = SECRETS_ROOT / run_id
    SECRETS_ROOT.mkdir(parents=True, exist_ok=True)
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    for name, data in credentials.items():
        _write_private(folder / name, data)
    return folder


def remove_secrets(run_id):
    shutil.rmtree(SECRETS_ROOT / run_id, ignore_errors=True)


def run_record_path(run_id):
    return RUNS_ROOT / f"{run_id}.json"


def cancel_flag_path(run_id):
    return RUNS_ROOT / f"{run_id}.cancel"


def handoff_path(run_id):
    return HANDOFF_ROOT / f"{run_id}.json"


def read_handoff(run_id):
    path = handoff_path(run_id)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    path.unlink(missing_ok=True)
    return data if isinstance(data, dict) else {}


def systemctl(*args, timeout=15):
    try:
        done = subprocess.run([*SYSTEMCTL, *args], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              env=dict(CHILD_ENV), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return done.returncode, done.stdout, done.stderr


def stop_unit(run_id):
    return systemctl("stop", unit_name(run_id) + ".service")[0] == 0


def finish_run(run_id, environ=None):
    """``--finish <run-id>`` (root, called by ExecStopPost=+): write usage and the unit's result to a root-only handoff file, which the
    ``--start`` of the same run puts into its end frame and deletes. SERVICE_RESULT is systemd's own word (success, exit-code, signal,
    timeout, oom-kill ...)."""
    if not _plain_id(run_id, RUN_ID_RE):
        raise RuntimeError("run id is invalid")
    environ = os.environ if environ is None else environ
    peak, cpu = None, None
    code, out, _err = systemctl("show", unit_name(run_id) + ".service", "-P", "MemoryPeak", "-P", "CPUUsageNSec")
    if code == 0:
        values = out.split()
        if len(values) >= 2:
            peak = int(values[0]) if values[0].isdigit() else None
            cpu = int(values[1]) if values[1].isdigit() else None
    result = re.sub(r"[^a-z-]", "", str(environ.get("SERVICE_RESULT", ""))[:32])
    HANDOFF_ROOT.mkdir(parents=True, exist_ok=True)
    _write_private(handoff_path(run_id), _json_bytes({"memory_peak": peak, "cpu_ns": cpu, "result": result}))
    return 0


# ------------------------------------------------------------------------------------------------------------- the launch
def launch(row, *, run_id, person, parameters, credentials, input_data, emit, stdin_eof=None, slots_n=None, person_n=PERSON_SLOTS,
           status=None, clock=time.monotonic, sleep=time.sleep):
    """Start one run and stream it. ``emit(frame)`` writes one frame (and raises DeadMan when the caller is gone); ``stdin_eof`` is a
    threading.Event set when the caller closed its end. Used by ``--start`` and by the root-only canary. The kill switch is the caller's
    business. Returns the end frame."""
    status = status or ready_status()
    try:
        text = Path(RESOLV_CONF).read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    resolvers = usable_resolvers(status, text)
    if not resolvers:
        raise Refusal("sandbox_unavailable", "no resolver that the selftest proved is in resolv.conf now")
    check_runner_ready(row)
    values = validate_run_parameters(row["parameters"], parameters)
    argv = build_argv(row, run_id, values, resolvers=resolvers, credential_names=sorted(credentials))
    holder = acquire_slots(person, row, slots_n=slots_n, person_n=person_n, clock=clock, sleep=sleep)
    process = None
    started_at = clock()
    try:
        RUNS_ROOT.mkdir(parents=True, exist_ok=True)
        _write_private(run_record_path(run_id), _json_bytes({"run_id": run_id, "runner": row["id"], "unit": unit_name(run_id), "at": now()}))
        if credentials:
            write_secrets(run_id, credentials)
        process = _spawn(argv)
        return _supervise(process, row, run_id, input_data, emit, stdin_eof, started_at, clock)
    finally:
        if process is not None and process.poll() is None:
            stop_unit(run_id)
            try:
                process.kill()
            except OSError:
                pass
        remove_secrets(run_id)
        run_record_path(run_id).unlink(missing_ok=True)
        cancel_flag_path(run_id).unlink(missing_ok=True)
        handoff_path(run_id).unlink(missing_ok=True)
        holder.release()


def _spawn(argv):
    options = {}
    if os.name == "posix":
        def die_with_parent():
            try:
                import ctypes

                ctypes.CDLL(None).prctl(1, 9, 0, 0, 0)  # PR_SET_PDEATHSIG = 1, SIGKILL
            except (ImportError, OSError, AttributeError, TypeError):
                return
        options["preexec_fn"] = die_with_parent
    try:
        return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                env=dict(CHILD_ENV), **options)
    except OSError as exc:
        raise Refusal("start_failed", "systemd-run could not be started") from exc


def _reader(stream, tag, sink):
    try:
        while True:
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                break
            sink.put((tag, chunk))
    except (OSError, ValueError):
        pass
    sink.put((tag, None))


def _feed_input(process, data):
    try:
        process.stdin.write(data)
        process.stdin.flush()
    except (OSError, ValueError):
        pass
    finally:
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass


def _supervise(process, row, run_id, input_data, emit, stdin_eof, started_at, clock):
    limits = row["limits"]
    caps = {"out": int(limits["stdout_kib"]) * 1024, "err": int(limits["stderr_kib"]) * 1024}
    sent = {"out": 0, "err": 0}
    truncated = {"out": False, "err": False}
    pending = {"out": bytearray(), "err": bytearray()}
    sink = queue_module.Queue()
    threading.Thread(target=_reader, args=(process.stdout, "out", sink), daemon=True).start()
    threading.Thread(target=_reader, args=(process.stderr, "err", sink), daemon=True).start()
    threading.Thread(target=_feed_input, args=(process, input_data), daemon=True).start()
    parser = StreamParser(bool(row.get("credential_return")))
    state = {"reason": None, "stopped": False, "launcher_ok": True, "last_flush": clock()}
    deadline = started_at + int(limits["run_seconds"])

    def flush(force=False):
        due = clock() - state["last_flush"] >= FLUSH_SECONDS
        for tag in ("out", "err"):
            if pending[tag] and (force or due or len(pending[tag]) >= FLUSH_BYTES):
                data = bytes(pending[tag])
                pending[tag].clear()
                emit({"t": tag, "b": base64.b64encode(data).decode("ascii"), "truncated": truncated[tag]})
        state["last_flush"] = clock()

    def take(tag, data):
        room = caps[tag] - sent[tag]
        if len(data) > room:
            data = data[:max(0, room)]
            truncated[tag] = True
            stop("output_limit")
        sent[tag] += len(data)
        pending[tag].extend(data)

    def stop(why):
        state["reason"] = state["reason"] or why
        if not state["stopped"]:
            state["stopped"] = True
            stop_unit(run_id)

    emit({"t": "started", "run_id": run_id, "unit": unit_name(run_id)})
    open_streams = 2
    try:
        while open_streams:
            try:
                tag, chunk = sink.get(timeout=FLUSH_SECONDS)
            except queue_module.Empty:
                tag, chunk = None, b""
            if tag is not None and chunk is None:
                open_streams -= 1
            elif tag == "out" and chunk:
                try:
                    clean = parser.feed(chunk)
                except LauncherError:
                    state["launcher_ok"] = False
                    clean = b""
                    stop("start_failed")
                if clean and not state["stopped"]:
                    take("out", clean)
            elif tag == "err" and chunk and not state["stopped"]:
                take("err", chunk)
            if stdin_eof is not None and stdin_eof.is_set():
                stop("cancelled")
                raise DeadMan("the caller closed stdin")
            if clock() >= deadline:
                stop("timeout")
            flush()
        tail = parser.finish()
        if tail and not state["stopped"]:
            take("out", tail)
        flush(force=True)
    except DeadMan:
        stop("cancelled")
        raise
    try:
        code = process.wait(timeout=STOP_GRACE_SECONDS * 3)
    except subprocess.TimeoutExpired:
        stop_unit(run_id)
        process.kill()
        code = process.wait()
    handoff = read_handoff(run_id)
    reason = state["reason"]
    if cancel_flag_path(run_id).exists():
        reason = "cancelled"
    result = str(handoff.get("result") or "")
    if reason is None:
        if result == "oom-kill":
            reason = "oom"
        elif result == "timeout":
            reason = "timeout"
        elif not parser.header_done or not state["launcher_ok"]:
            reason = "start_failed"
        else:
            reason = "exited"
    credential = parser.credential if row.get("credential_return") else None
    peak = handoff.get("memory_peak")
    end = {
        "t": "end", "exit": None if reason == "start_failed" else code, "reason": reason, "ms": int((clock() - started_at) * 1000),
        "peak_mb": round(peak / 1048576, 1) if isinstance(peak, int) else None,
        "credential_b64": base64.b64encode(credential).decode("ascii") if credential is not None else None,
        "bytes_out": sent["out"], "bytes_err": sent["err"],
    }
    emit(end)
    return end


# ------------------------------------------------------------------------------------------------------- --start / --stop
def start_command(stdin=None, *, canary=False, out_stream=None):
    """``--start``: read the header and the input, re-check everything, launch, stream frames, always clean up. ``canary`` is the root-only
    ``--canary-launch`` path: the same code, only for core.canary; the kill-switch constant is not asked there (main already refused the
    real ``--start`` while it is off)."""
    stdin = stdin or sys.stdin.buffer
    emit = stdout_emitter(out_stream)
    try:
        ensure_layout()
        header, size = read_header(stdin)
        if canary:
            if header["runner_id"] != CANARY_RUNNER_ID:
                raise Refusal("runner_unknown")
            row = canary_row()
        else:
            row = load_runner_row(header["runner_id"])
        data = read_input(stdin, size, row["limits"])
        credentials = decode_credentials(row, header.get("credentials", {}))
        eof = threading.Event()

        def watch_stdin():
            try:
                while stdin.read(1):
                    pass
            except (OSError, ValueError):
                pass
            eof.set()
        threading.Thread(target=watch_stdin, daemon=True).start()
        launch(row, run_id=header["run_id"], person=header["person"], parameters=header.get("parameters", {}), credentials=credentials,
               input_data=data, emit=emit, stdin_eof=eof)
        return 0
    except Refusal as exc:
        try:
            emit(exc.frame())
        except DeadMan:
            pass
        return 3
    except DeadMan:
        return 4
    except (RuntimeError, OSError) as exc:  # a fault is a refusal, never a traceback with a path
        append_audit_safely("start.fault", {"error": type(exc).__name__})
        try:
            emit(Refusal("start_failed").frame())
        except DeadMan:
            pass
        return 3


def append_audit_safely(event, detail):
    try:
        append_audit(event, detail=detail)
    except OSError:
        pass


def stop_command(stdin=None, out=None):
    """``--stop``: one run id on stdin. Only a unit this helper started (it holds a run record for it) is stopped."""
    stdin = stdin or sys.stdin.buffer
    out = out or sys.stdout
    run_id = stdin.readline(200).decode("ascii", "replace").strip()
    if not _plain_id(run_id, RUN_ID_RE):
        out.write(json.dumps({"t": "refused", "code": "invalid_input"}) + "\n")
        return 3
    record = _load_registry_file(run_record_path(run_id)) if run_record_path(run_id).is_file() else None
    if not record or record.get("unit") != unit_name(run_id):
        out.write(json.dumps({"t": "refused", "code": "runner_unknown"}) + "\n")
        return 3
    _write_private(cancel_flag_path(run_id), b"1")
    stop_unit(run_id)
    append_audit_safely("run.cancel_requested", {"run_id": run_id})
    out.write(json.dumps({"t": "stopped", "run_id": run_id}) + "\n")
    out.flush()
    return 0


# ======================================================================================================== the canary (attack test)
# ``--selftest --canary`` (root only, never in the sudo rule) runs every wall of plan 8.2 and section 15 against this server with an
# in-memory runner ``core.canary`` that is never written to the registry. It uses the same ``launch`` as ``--start`` and bypasses only
# the kill-switch constant, because nothing else can start a run while the switch is off. The result table goes to stdout and a
# secret-free summary to /var/lib/tec-tac/sandbox/canary.json, which status() reports as canary_ok and canary_at.
CANARY_RUNNER_ID = "core.canary"
CANARY_OWNER = "core"
CANARY_GROUPS = ("files", "work_hold", "work_peer", "sockets", "loopback", "lan", "dns", "public", "privilege", "writes", "processes",
                 "mem", "fork", "loop", "scratch", "flood", "abstract", "cred", "sleep", "noop")
CANARY_LATENCY_RUNS = 50
CANARY_LATENCY_TARGET_MS = 400
CANARY_MARKER_DIRS = ("/etc", "/var", "/opt", "/srv", "/mnt", "/media", "/home", "/root", "/etc/tactical", "/etc/tec-tac", "/opt/tec-tac",
                      "/rmm", "/usr/local/lib/tec-tac", "/var/lib/tec-tac", "/run/tec-tac")
CANARY_REAL_FILES = ("/rmm/api/tacticalrmm/tacticalrmm/local_settings.py", "/etc/tec-tac/config-path", "/opt/tec-tac/etc/tec-tac.conf",
                     "/etc/shadow")
CANARY_LAN_TARGETS = ("10.255.255.254", "172.31.255.254", "192.168.255.254", "100.127.255.254", "169.254.169.254")
CANARY_PUBLIC_TARGET = "1.1.1.1"
VERDICTS = ("OK", "ATTACK SUCCEEDED", "SKIPPED", "NOT RUN", "WARN")
CANARY_REQUIRED = {  # group -> (exact attack names, [(prefix, minimum count)])
    "sockets": ([], [("unix ", 13)]),
    "privilege": (["setuid(0)", "ptrace attach to parent", "mount", "unshare", "mknod", "raw socket", "write /proc/sys", "load a kernel module"], []),
    "writes": ([], [("write /", 9)]),
    "processes": (["host processes invisible", "pid 1 invisible"], []),
    "mem": (["memory beyond MemoryMax"], []), "fork": (["fork bomb"], []), "scratch": (["scratch past its size"], []),
    "cred": (["credential arrives", "credential mode", "credential not in environment"], []),
    "dns": (["allowed resolver answers"], []), "public": (["public tcp 443"], []), "abstract": ([], [("abstract sockets", 1)]),
    "work_peer": (["another run's /work"], []), "lan": ([], [("udp ", 5), ("tcp ", 5)]), "loopback": ([], [("loopback ", 1)]),
}


def canary_row(**limit_overrides):
    """The in-memory canary runner record. Limits are small and always under the Core ceilings. Never written to the registry."""
    limits = {"memory_mb": 256, "cpu_percent": 100, "tasks": 64, "run_seconds": 20, "stdout_kib": 64, "stderr_kib": 16, "scratch_mb": 16,
              "input_kib": 16, "queue_seconds": 3}
    limits.update(limit_overrides)
    for name, value in limits.items():
        if value > LIMITS[name][1]:
            raise RuntimeError(f"canary limit {name} is over the Core ceiling")
    try:
        digest = _sha256_nofollow(CANARY_RUNNER_FILE)
    except (OSError, RuntimeError):
        digest = ""
    return {
        "id": CANARY_RUNNER_ID, "owner_module": CANARY_OWNER, "version": "core", "revision": "1", "description": "Core's own attack test",
        "executable": str(CANARY_RUNNER_FILE), "executable_sha256": digest, "argv": [{"param": "group"}],
        "parameters": {"group": {"type": "enum", "choices": list(CANARY_GROUPS)}}, "environment": {}, "runtime_roots": [],
        "credential_files": ["auth"], "credential_return": True, "limits": limits, "runtime_verified": True, "registered_by": REGISTERED_BY,
    }


def parse_runner_rows(data):
    """CANARYROW lines from the (untrusted) in-unit program. Anything else is ignored."""
    rows = []
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "CANARYROW" and parts[1]:
            rows.append({"attack": parts[1][:200], "tag": parts[2], "actual": parts[3][:300]})
    return rows


def classify_tag(tag):
    """OK stays OK, SUCCEEDED is a finding, SKIP is SKIPPED (never OK). Any other word from the unit is NOT RUN, which also fails."""
    return {"OK": "OK", "SUCCEEDED": "ATTACK SUCCEEDED", "SKIP": "SKIPPED"}.get(tag, "NOT RUN")


def group_table(wall, group, expected, runner_rows, plan_names=()):
    """Table rows for one group of attacks. A row the program was expected to print and did not is NOT RUN."""
    table = [{"wall": wall, "attack": r["attack"], "expected": expected, "actual": r["actual"], "verdict": classify_tag(r["tag"])} for r in runner_rows]
    names = [r["attack"] for r in runner_rows]
    exact, prefixes = CANARY_REQUIRED.get(group, ([], []))
    for name in list(exact) + list(plan_names):
        if name not in names:
            table.append({"wall": wall, "attack": name, "expected": expected, "actual": "the probe printed no result", "verdict": "NOT RUN"})
    for prefix, minimum in prefixes:
        found = sum(1 for name in names if name.startswith(prefix))
        if found < minimum:
            table.append({"wall": wall, "attack": prefix.strip() + " probes", "expected": expected, "actual": f"{found} of {minimum} results", "verdict": "NOT RUN"})
    if not table:
        table.append({"wall": wall, "attack": group, "expected": expected, "actual": "the probe printed no result", "verdict": "NOT RUN"})
    return table


def canary_summary(table):
    """(passed, counts). PASSED only when no row is ATTACK SUCCEEDED and none is NOT RUN. SKIPPED and WARN never fail it and are never OK."""
    counts = {verdict: 0 for verdict in VERDICTS}
    for entry in table:
        counts[entry["verdict"] if entry["verdict"] in counts else "NOT RUN"] += 1
    return counts["ATTACK SUCCEEDED"] == 0 and counts["NOT RUN"] == 0, counts


def canary_record(table, passed, counts):
    """canary.json: counts and failing rows only. No marker, no credential, no path of a secret."""
    failing = [{"wall": e["wall"], "attack": e["attack"], "verdict": e["verdict"]} for e in table if e["verdict"] in ("ATTACK SUCCEEDED", "NOT RUN")]
    return {"ok": bool(passed), "at": now(), "counts": counts, "failing": failing[:50], "skipped": [e["attack"] for e in table if e["verdict"] == "SKIPPED"][:20]}


def parse_listening(text):
    """(ports, {address: ports}) from ``ss -ltnH`` output. A wildcard address belongs to every address."""
    ports, by_address = set(), {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        host, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        host = host.strip("[]")
        ports.add(int(port))
        by_address.setdefault(host, set()).add(int(port))
    return sorted(ports)[:200], by_address


def resolver_ports(by_address, resolver):
    wild = set()
    for host in ("*", "0.0.0.0", "::"):
        wild |= by_address.get(host, set())
    return sorted(by_address.get(resolver, set()) | wild)[:200]


def parse_gateway(text):
    match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", text or "")
    return match.group(1) if match else ""


def collect_run(group, plan, *, person="canary", slots_n=None, person_n=PERSON_SLOTS, credentials=None, status=None, run_id=None, **limit_overrides):
    """One canary run through the same ``launch`` as ``--start``. Returns {stdout, stderr, end, refused}. Never raises for a refusal."""
    out = {"stdout": b"", "stderr": b"", "end": None, "refused": None, "run_id": run_id or secrets.token_hex(16), "frames": []}
    row = canary_row(**limit_overrides)

    def emit(frame):
        out["frames"].append(frame["t"])
        if frame["t"] in ("out", "err"):
            out["stdout" if frame["t"] == "out" else "stderr"] += base64.b64decode(frame["b"])
        elif frame["t"] == "end":
            out["end"] = frame

    data = json.dumps(plan).encode("utf-8")
    try:
        launch(row, run_id=out["run_id"], person=person, parameters={"group": group}, credentials=credentials or {}, input_data=data,
               emit=emit, slots_n=slots_n, person_n=person_n, status=status)
    except Refusal as exc:
        out["refused"] = exc.code
    return out


def _plant_markers():
    """Random-content 0644 markers in the places a run must never see. The list is written first, so a crash leaves it for the sweep."""
    planted, entries = [], []
    for folder in CANARY_MARKER_DIRS:
        if Path(folder).is_dir():
            planted.append((str(Path(folder) / (".tectac-canary-" + secrets.token_hex(6))), secrets.token_hex(16)))
    _write_private(CANARY_MARKERS_FILE, _json_bytes({"paths": [p for p, _ in planted]}))
    for path, content in planted:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(path, 0o644)
            entries.append({"path": path, "content": content})
        except OSError:
            pass
    for real in CANARY_REAL_FILES:
        if os.path.exists(real):
            entries.append({"path": real, "content": None})  # None: being able to read it at all is the finding
    return entries


def remove_markers():
    try:
        paths = json.loads(CANARY_MARKERS_FILE.read_text(encoding="utf-8")).get("paths", [])
    except (OSError, ValueError, AttributeError):
        paths = []
    for path in paths:
        if isinstance(path, str) and os.path.basename(path).startswith(".tectac-canary-"):
            try:
                os.unlink(path)
            except OSError:
                pass
    CANARY_MARKERS_FILE.unlink(missing_ok=True)


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def _holders_search(token, unit):
    """Where the credential token shows up on the host while a run is live: other processes' command lines and environments, ps,
    systemctl show, journald. Returns the list of places (empty is the pass)."""
    found = []
    for pattern in ("/proc/[0-9]*/cmdline", "/proc/[0-9]*/environ"):
        try:
            for path in glob.glob(pattern):
                try:
                    with open(path, "rb") as handle:
                        if token.encode() in handle.read(262144):
                            found.append(path)
                except OSError:
                    continue
        except OSError:
            continue
    runner = UnitRunner()
    for label, argv in (("ps", ["ps", "-eo", "args"]), ("systemctl show", [*SYSTEMCTL, "show", unit + ".service"]),
                        ("journald", ["journalctl", "-u", unit + ".service", "-o", "cat", "--no-pager"])):
        _code, out, err = runner.run_cmd(argv)
        if token in (out or "") or token in (err or ""):
            found.append(label)
    return found


def run_canary(*, status=None, collect=None, outside=None):
    """Run every row and return the table. ``collect`` and ``outside`` can be replaced by a test."""
    collect = collect or collect_run
    outside = outside or UnitRunner()
    status = status or read_status()
    table = []
    if status.get("ready") is not True:
        return [{"wall": "Selftest", "attack": "selftest ready", "expected": "ready", "actual": status.get("reason", "not ready"), "verdict": "NOT RUN"}]
    resolver = status.get("resolver") or ""
    try:
        resolv_text = Path(RESOLV_CONF).read_text(encoding="utf-8", errors="replace")
    except OSError:
        resolv_text = ""
    others = [a for a in parse_resolvers(resolv_text) if a != resolver and ipaddress.ip_address(a).version == 4]
    _c, ss_text, _e = outside.run_cmd(["ss", "-ltnH"])
    ports, by_address = parse_listening(ss_text)
    _c, route_text, _e = outside.run_cmd(["ip", "-4", "route", "show", "default"])
    gateway = parse_gateway(route_text)
    lan = ([gateway] if gateway else []) + list(CANARY_LAN_TARGETS)

    def group(wall, name, expected, plan=None, plan_names=(), **kwargs):
        result = collect(name, plan or {}, status=status, **kwargs)
        if result["refused"]:
            table.append({"wall": wall, "attack": name, "expected": expected, "actual": "refused: " + str(result["refused"]), "verdict": "NOT RUN"})
            return result
        table.extend(group_table(wall, name, expected, parse_runner_rows(result["stdout"]), plan_names))
        return result

    markers = []
    try:
        markers = _plant_markers()
        group("Files", "files", "not found or other content", {"markers": markers}, plan_names=["read " + m["path"] for m in markers])
        peer_token = secrets.token_hex(8)
        holder = threading.Thread(target=collect, args=("work_hold", {"work_token": peer_token, "hold_seconds": 4}),
                                  kwargs={"person": "canary-hold", "status": status}, daemon=True)
        holder.start()
        time.sleep(1.5)
        group("Files", "work_peer", "not found", {"work_token": peer_token}, person="canary-peer")
        holder.join(10)
        group("Sockets", "sockets", "not present or refused")
        group("Loopback", "loopback", "connection refused", {"ports": ports, "resolver": resolver, "resolver_ports": resolver_ports(by_address, resolver)})
        group("LAN", "lan", "dropped (EPERM)", {"lan": lan})
        group("DNS", "dns", "allowed resolver answers; others dropped", {"resolver": resolver, "other_resolvers": others})
        group("Public", "public", "TCP 443 works (SKIPPED without a public route)", {"public": CANARY_PUBLIC_TARGET})
        group("Privilege", "privilege", "EPERM")
        group("Writes", "writes", "read-only or private")
        group("Processes", "processes", "host processes invisible")
        group("Abstract sockets", "abstract", "none reachable (Medium finding R1 otherwise)")
        table.extend(_limit_rows(collect, status))
        table.extend(_credential_rows(collect, status))
        table.extend(_cancel_rows(collect, status))
        table.extend(_concurrency_rows(collect, status))
        table.extend(_latency_rows(collect, status))
    finally:
        remove_markers()
    return table


def _limit_rows(collect, status):
    rows = []

    def one(attack, group, plan, expected_reason, **limits):
        result = collect(group, plan, status=status, **limits)
        end = result.get("end") or {}
        reason = result.get("refused") or end.get("reason") or "no end frame"
        verdict = "OK" if reason == expected_reason else "ATTACK SUCCEEDED"
        if result.get("refused") or not end:
            verdict = "NOT RUN"
        rows.append({"wall": "Limits", "attack": attack, "expected": expected_reason, "actual": str(reason), "verdict": verdict})
        return result

    one("memory beyond MemoryMax", "mem", {"alloc_mb": 600}, "oom", memory_mb=128)
    fork = collect("fork", {"forks": 300}, status=status, tasks=64)
    rows.extend(group_table("Limits", "fork", "EAGAIN before 64 tasks", parse_runner_rows(fork["stdout"])))
    one("infinite loop", "loop", {}, "timeout", run_seconds=4)
    scratch = collect("scratch", {"fill_mb": 32}, status=status, scratch_mb=8)
    rows.extend(group_table("Limits", "scratch", "ENOSPC or EFBIG", parse_runner_rows(scratch["stdout"])))
    one("stdout past its cap", "flood", {"flood_kib": 64}, "output_limit", stdout_kib=16)
    return rows


def _credential_rows(collect, status):
    token = secrets.token_hex(16)
    cred_run = secrets.token_hex(16)
    box = {}

    def live():
        box["result"] = collect("cred", {"credential_token": token, "hold_seconds": 3}, status=status, credentials={"auth": token.encode()},
                                person="canary-cred", run_id=cred_run)

    thread = threading.Thread(target=live, daemon=True)
    thread.start()
    time.sleep(1.5)
    leaks = _holders_search(token, unit_name(cred_run))
    thread.join(30)
    result = box.get("result") or {"stdout": b"", "end": None, "refused": "no result"}
    rows = []
    if result.get("refused"):
        return [{"wall": "Credential", "attack": "credential hand-in", "expected": "arrives", "actual": "refused: " + str(result["refused"]), "verdict": "NOT RUN"}]
    rows.extend(group_table("Credential", "cred", "only under CREDENTIALS_DIRECTORY", parse_runner_rows(result["stdout"])))
    rows.append({"wall": "Credential", "attack": "token in ps, /proc/*/cmdline, systemctl show, journald", "expected": "absent",
                 "actual": ", ".join(leaks) or "absent", "verdict": "ATTACK SUCCEEDED" if leaks else "OK"})
    left = [p.name for p in SECRETS_ROOT.iterdir()] if SECRETS_ROOT.is_dir() else []
    rows.append({"wall": "Credential", "attack": "nothing left in secrets folder", "expected": "empty", "actual": f"{len(left)} left",
                 "verdict": "ATTACK SUCCEEDED" if left else "OK"})
    expected_back = "refreshed-" + token
    end = result.get("end") or {}
    back = end.get("credential_b64")
    got = base64.b64decode(back).decode("utf-8", "replace") if back else ""
    rows.append({"wall": "Credential", "attack": "credential_return round trip", "expected": "refreshed token back",
                 "actual": "came back" if got == expected_back else "missing or wrong", "verdict": "OK" if got == expected_back else "ATTACK SUCCEEDED"})
    leaked_out = token.encode() in result.get("stdout", b"") or "CRED" in result.get("stdout", b"").decode("utf-8", "replace")
    rows.append({"wall": "Credential", "attack": "credential frame stripped from output", "expected": "no CRED line in stdout",
                 "actual": "found in output" if leaked_out else "stripped", "verdict": "ATTACK SUCCEEDED" if leaked_out else "OK"})
    return rows


def _unit_gone(run_id, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if systemctl("is-active", unit_name(run_id) + ".service")[0] != 0:
            return True
        time.sleep(0.25)
    return False


def _cancel_rows(collect, status):
    rows = []
    box = {}
    run_id = secrets.token_hex(16)

    def worker():
        row = canary_row(run_seconds=30)
        frames = []
        try:
            launch(row, run_id=run_id, person="canary-cancel", parameters={"group": "sleep"}, credentials={}, input_data=b'{"hold_seconds": 25}',
                   emit=frames.append, status=status)
        except Refusal as exc:
            box["refused"] = exc.code
        box["frames"] = frames

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(2)
    stop_command(io.BytesIO(run_id.encode() + b"\n"), out=io.StringIO())
    gone = _unit_gone(run_id)
    thread.join(15)
    end = next((f for f in box.get("frames", []) if f.get("t") == "end"), {})
    rows.append({"wall": "Cancel", "attack": "stop mid-run", "expected": "unit gone within 5 s, reason cancelled",
                 "actual": f"gone={gone} reason={end.get('reason')}", "verdict": "OK" if gone and end.get("reason") == "cancelled" else "ATTACK SUCCEEDED"})
    for label, how in (("SIGKILL the helper", "kill"), ("kill the caller (stdin closes)", "eof")):
        run_id = secrets.token_hex(16)
        header = json.dumps({"runner_id": CANARY_RUNNER_ID, "run_id": run_id, "person": "canary-" + how, "parameters": {"group": "sleep"},
                             "input_bytes": len(b'{"hold_seconds": 25}')}).encode() + b"\n" + b'{"hold_seconds": 25}'
        child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--canary-launch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        child.stdin.write(header)
        child.stdin.flush()
        time.sleep(2.5)
        if how == "kill":
            child.kill()
        else:
            child.stdin.close()
        gone = _unit_gone(run_id)
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            child.kill()
        rows.append({"wall": "Cancel", "attack": label, "expected": "unit gone within 5 s", "actual": f"gone={gone}", "verdict": "OK" if gone else "ATTACK SUCCEEDED"})
    sweep(min_age=0)  # the canary is the only thing running: anything left over for a stopped unit goes now
    leftovers = [p.name for folder in (SECRETS_ROOT, HANDOFF_ROOT, RUNS_ROOT) if folder.is_dir() for p in folder.iterdir()]
    rows.append({"wall": "Cancel", "attack": "nothing left after cancel and kills", "expected": "no secrets, handoff or run files",
                 "actual": f"{len(leftovers)} left", "verdict": "OK" if not leftovers else "ATTACK SUCCEEDED"})
    return rows


def _concurrency_rows(collect, status):
    rows = []

    def trio(person_for, **kwargs):
        results, threads = [None] * 3, []
        for k in range(3):
            def go(k=k):
                results[k] = collect("sleep", {"hold_seconds": 4}, status=status, person=person_for(k), queue_seconds=1, **kwargs)
            thread = threading.Thread(target=go, daemon=True)
            threads.append(thread)
            thread.start()
            time.sleep(0.4)
        for thread in threads:
            thread.join(30)
        return [(r or {}).get("refused") or "ran" for r in results]

    server = trio(lambda k: f"canary-s{k}", slots_n=2)
    rows.append({"wall": "Concurrency", "attack": "3 starts on 2 slots", "expected": "2 run, 1 busy", "actual": ", ".join(server),
                 "verdict": "OK" if sorted(server) == ["busy", "ran", "ran"] else "ATTACK SUCCEEDED"})
    person = trio(lambda k: "canary-one-person", slots_n=4)
    rows.append({"wall": "Concurrency", "attack": "per-person limit", "expected": "2 run, 1 person_busy", "actual": ", ".join(person),
                 "verdict": "OK" if sorted(person) == ["person_busy", "ran", "ran"] else "ATTACK SUCCEEDED"})
    return rows


def _latency_rows(collect, status):
    times = []
    for _ in range(CANARY_LATENCY_RUNS):
        started = time.monotonic()
        result = collect("noop", {}, status=status, person="canary-latency")
        if result.get("refused") or not result.get("end"):
            return [{"wall": "Latency", "attack": "no-op runs", "expected": f"p95 under {CANARY_LATENCY_TARGET_MS} ms", "actual": "a run did not finish", "verdict": "NOT RUN"}]
        times.append((time.monotonic() - started) * 1000)
    p50, p95 = _percentile(times, 0.5), _percentile(times, 0.95)
    return [{"wall": "Latency", "attack": f"{CANARY_LATENCY_RUNS} no-op runs", "expected": f"p95 under {CANARY_LATENCY_TARGET_MS} ms",
             "actual": f"p50 {p50:.0f} ms, p95 {p95:.0f} ms", "verdict": "OK" if p95 <= CANARY_LATENCY_TARGET_MS else "WARN"}]


def format_table(table):
    widths = {key: max([len(key)] + [len(str(entry[key])) for entry in table]) for key in ("wall", "attack", "expected", "actual", "verdict")}
    widths = {key: min(width, 60) for key, width in widths.items()}
    header = "  ".join(key.upper().ljust(widths[key]) for key in widths)
    lines = [header, "-" * len(header)]
    for entry in table:
        lines.append("  ".join(str(entry[key])[:widths[key]].ljust(widths[key]) for key in widths))
    return "\n".join(lines)


def run_canary_command():
    ensure_layout()
    table = run_canary()
    passed, counts = canary_summary(table)
    print(format_table(table))
    print(f"\n{counts['OK']} OK, {counts['ATTACK SUCCEEDED']} ATTACK SUCCEEDED, {counts['NOT RUN']} NOT RUN, {counts['SKIPPED']} SKIPPED, {counts['WARN']} WARN")
    print("CANARY PASSED" if passed else "CANARY FAILED")
    _write_root_file(CANARY_FILE, _json_bytes(canary_record(table, passed, counts)), 0o644)
    append_audit("canary", detail={"passed": passed, "counts": counts})
    return 0 if passed else 1


# ------------------------------------------------------------------------------------------------------ status and sweep
def show_status():
    status = read_status()
    total = slot_count(mem_available_kib(), LIMITS["memory_mb"][0])
    status["slots_total"] = total
    status["slots_used"] = slots_in_use(total)
    try:
        canary = json.loads(_read_trusted_file(CANARY_FILE, "canary file", max_bytes=64 * 1024).decode("utf-8"))
        status["canary_ok"] = canary.get("ok") is True
        status["canary_at"] = canary.get("at") if isinstance(canary.get("at"), str) else None
    except (RuntimeError, ValueError, OSError):
        status["canary_ok"], status["canary_at"] = False, None
    print(json.dumps({"status": status, "runners": registered_runners()}, sort_keys=True))
    return 0


STALE_SECONDS = 120  # a run file younger than this may belong to a run that is still starting


def _unit_active(run_id):
    return systemctl("is-active", unit_name(run_id) + ".service")[0] == 0


def _stale(path, min_age=STALE_SECONDS, *, clock=time.time):
    try:
        return clock() - path.stat().st_mtime >= min_age
    except OSError:
        return False


def sweep(min_age=STALE_SECONDS):
    """``--sweep`` (boot and daily): re-verify the runtime folders of every registered runner; remove stray selftest folders; remove
    secrets folders, handoff files and run records whose unit ``tectac-sbx-<id>`` is not active; remove old canary markers."""
    _require_layout()
    checked, changed = 0, []
    if REGISTRY_ROOT.is_dir():
        for path in sorted(REGISTRY_ROOT.glob("*.json")):
            payload = _load_registry_file(path)
            if not payload or payload.get("registered_by") != REGISTERED_BY:
                continue
            checked += 1
            reasons = _sweep_reasons(payload)
            verified, reason = not reasons, "; ".join(reasons)
            if payload.get("runtime_verified") != verified or payload.get("runtime_reason") != reason:
                payload.update({"runtime_verified": verified, "runtime_reason": reason, "runtime_checked_at": now()})
                _write_root_file(path, _json_bytes(payload), 0o644)
                changed.append(str(payload.get("id")))
    removed = []
    if RUN_ROOT.is_dir():
        for entry in sorted(RUN_ROOT.iterdir()):
            if entry.name.startswith(SELFTEST_PREFIX) and entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
                removed.append(entry.name)
    for folder in (SECRETS_ROOT, HANDOFF_ROOT, RUNS_ROOT):
        if not folder.is_dir() or folder.is_symlink():
            continue
        for entry in sorted(folder.iterdir()):
            run_id = entry.name.split(".")[0]
            if _plain_id(run_id, RUN_ID_RE) and (_unit_active(run_id) or not _stale(entry, min_age)):
                continue  # a live run (or one that is still starting) keeps its files
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
            removed.append(f"{folder.name}/{entry.name}")
    remove_markers()
    append_audit("sweep", detail={"runners_checked": checked, "runtime_state_changed": changed, "removed": removed})
    print(json.dumps({"checked": checked, "changed": changed, "removed": removed}, sort_keys=True))


def refuse_disabled():
    """``--start`` and ``--stop`` while the kill switch is off: read nothing from stdin, start nothing, answer with the final refusal frame."""
    sys.stdout.write(json.dumps({"t": "refused", "code": "sandbox_disabled"}, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 3


def usage():
    raise SystemExit("usage: tec-tac-sandbox --start|--stop|--status | --finish <run-id> | --selftest [--canary] | --sweep | --register-module|--unregister-module <module-id>")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--start"], ["--stop"]) and not SANDBOX_ENABLED:
        return refuse_disabled()  # before anything else, and before stdin is read: the kill switch is a constant in this file
    if len(argv) not in (1, 2):
        usage()
    mode = argv[0]
    if mode not in ("--start", "--stop", "--status", "--selftest", "--sweep", "--register-module", "--unregister-module", "--finish", "--canary-launch"):
        usage()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if mode == "--start" and len(argv) == 1:
        return start_command()
    if mode == "--stop" and len(argv) == 1:
        return stop_command()
    if mode == "--canary-launch" and len(argv) == 1:
        return start_command(canary=True)  # root only, never in sudoers; core.canary only
    if mode == "--status" and len(argv) == 1:
        return show_status()
    if mode == "--selftest" and len(argv) == 1:
        return run_selftest()
    if mode == "--selftest" and argv[1:] == ["--canary"]:
        return run_canary_command()
    if mode == "--sweep" and len(argv) == 1:
        sweep()
        return 0
    if mode == "--finish" and len(argv) == 2:
        return finish_run(argv[1])
    if mode == "--register-module" and len(argv) == 2:
        register_module(argv[1])
        return 0
    if mode == "--unregister-module" and len(argv) == 2:
        unregister_module(argv[1])
        return 0
    usage()


if __name__ == "__main__":
    sys.exit(main())
