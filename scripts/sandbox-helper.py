#!/usr/bin/python3
"""Root-owned helper for core.sandbox (Core 1.17.116, Patch 1: the foundation; nothing can run yet).

core.sandbox will run a signed module's declared program as an unprivileged, resource-limited process that cannot see the server's files
or reach the server itself or private networks (AD-63, docs/planning/sandbox/PLAN-CORE-SANDBOX.md sections 2, 3 and 15). This first
patch only adds what has to exist before anything may run:

* ``--register-module <id>`` and ``--unregister-module <id>`` (root callers: the module job helpers): the registry of declared runners;
* ``--selftest`` (root: install.sh, an administrator): proves systemd, cgroup v2, DynamicUser, the hidden file system, credential
  hand-in, ProtectProc and the section 15 address filter work here, and writes ``status.json``. A failed check means ``ready: false``
  with a plain reason, never a weaker mode;
* ``--status`` (the Tactical account, through sudo): read only;
* ``--sweep`` (root: a boot and daily timer): re-verifies runtime folders, removes stray selftest folders;
* ``--start`` and ``--stop`` (the Tactical account, through sudo): stubs that read nothing and refuse with ``sandbox_disabled``.

``SANDBOX_ENABLED`` is a constant in this file, so a fault in Django cannot switch the sandbox on. There is no ``--finish`` and no
unit builder yet (Patch 2). Nothing here reads a command, a path or a limit from a caller: every rule is applied again to the root-owned
installed manifest.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
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
    for folder, mode in ((LIB_ROOT, 0o755), (RUNNERS_ROOT, 0o755), (REGISTRY_ROOT, 0o755), (STATE_ROOT, 0o755), (RUN_ROOT, 0o700)):
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


def _check_runtime_path(value, label):
    if (not isinstance(value, str) or not value.startswith("/") or "\x00" in value or "\\" in value or len(value) > 512
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise RuntimeError(f"{label} path must be an absolute path without control characters")
    parts = value.split("/")[1:]
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"{label} path must be absolute and normalised, with at least two parts and no '..'")
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
            path = _check_runtime_path(root_entry["path"], f"{label} runtime_roots")
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


def verify_runtime(path, listing):
    """(ok, reason). The folder and every parent are real directories, root-owned and not group or world writable; nothing inside is a
    link or a special file or writable by others; the files are exactly the listed ones with the listed SHA-256. A missing folder is the
    normal first state (the module builds its runtime after install) and is reported as such."""
    parts = Path(path).parts
    current = Path(parts[0])
    for index, part in enumerate(parts):
        if index:
            current = current / part
        try:
            st = _lstat(current)
        except FileNotFoundError:
            return False, "the runtime folder is not there yet; the module builds it after install"
        except OSError as exc:
            return False, f"the runtime folder cannot be read ({exc.strerror or 'error'})"
        if stat.S_ISLNK(st.st_mode):
            return False, f"a symlink sits in the path of the runtime folder: {current}"
        if not stat.S_ISDIR(st.st_mode):
            return False, f"not a folder: {current}"
        if _untrusted(st):
            return False, f"not root-owned, or writable by a group or anyone else: {current}"
    if not listing:
        return False, "the signed tree listing is empty"
    found = {}
    count = 0
    for folder, dirnames, filenames in os.walk(path, followlinks=False):
        for name in dirnames + filenames:
            count += 1
            if count > MAX_TREE_FILES:
                return False, "the runtime folder holds too many files"
            full = os.path.join(folder, name)
            try:
                st = _lstat(full)
            except OSError:
                return False, f"cannot read {full}"
            if stat.S_ISLNK(st.st_mode):
                return False, f"a symlink inside the runtime folder: {full}"
            if _untrusted(st):
                return False, f"not root-owned, or writable by a group or anyone else: {full}"
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                return False, f"a special file inside the runtime folder: {full}"
            found[os.path.relpath(full, path).replace(os.sep, "/")] = full
    extra = sorted(set(found) - set(listing))
    if extra:
        return False, f"a file that is not in the signed listing: {extra[0]}"
    missing = sorted(set(listing) - set(found))
    if missing:
        return False, f"a listed file is missing: {missing[0]}"
    for rel in sorted(found):
        try:
            digest = _sha256_nofollow(found[rel])
        except (OSError, RuntimeError):
            return False, f"cannot read {rel}"
        if digest != listing[rel]:
            return False, f"a file differs from the signed listing: {rel}"
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
    data = _read_trusted_file(folder.joinpath(*relative.split("/")), "runtime tree listing", max_bytes=MAX_TREE_LISTING_BYTES)
    if len(data) > MAX_TREE_LISTING_BYTES:
        raise RuntimeError("runtime tree listing is too large")
    return parse_tree_listing(data)


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
        reasons = []
        for root, listing in zip(runner["runtime_roots"], listings):
            ok, reason = verify_runtime(root["path"], listing)
            if not ok:
                reasons.append(f"{root['path']}: {reason}")
        record = {
            "id": runner["id"], "owner_module": module_id, "version": version, "revision": runner["revision"], "description": runner["description"],
            "executable": str(target), "executable_sha256": hashlib.sha256(data).hexdigest(), "argv": runner["argv"],
            "parameters": runner["parameters"], "environment": runner["environment"], "runtime_roots": runner["runtime_roots"],
            "credential_files": runner["credential_files"], "credential_return": runner["credential_return"], "limits": runner["limits"],
            "runtime_verified": not reasons, "runtime_reason": "; ".join(reasons), "runtime_checked_at": now(),
            "registered_by": REGISTERED_BY, "registered_at": now(),
        }
        _write_root_file(runner_path(runner["id"]), _json_bytes(record), 0o644)
        append_audit("runner.registered", detail={"runner": runner["id"], "module": module_id, "module_version": version,
                                                   "executable_sha256": record["executable_sha256"], "runtime_verified": record["runtime_verified"]})
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


def show_status():
    print(json.dumps({"status": read_status(), "runners": registered_runners()}, sort_keys=True))
    return 0


def sweep():
    """``--sweep`` (boot and daily): re-verify the runtime folders of every registered runner, and remove stray selftest folders. Patch 1
    keeps nothing else under /run/tec-tac/sandbox."""
    _require_layout()
    checked, changed = 0, []
    if REGISTRY_ROOT.is_dir():
        for path in sorted(REGISTRY_ROOT.glob("*.json")):
            payload = _load_registry_file(path)
            if not payload or payload.get("registered_by") != REGISTERED_BY:
                continue
            checked += 1
            reasons = []
            try:
                folder = EXTENSIONS_ROOT / str(_module_id(payload.get("owner_module")))
                for root in payload.get("runtime_roots") or []:
                    ok, reason = verify_runtime(root["path"], _tree_listing(folder, root["tree_sha256_file"]))
                    if not ok:
                        reasons.append(f"{root['path']}: {reason}")
            except (RuntimeError, KeyError, TypeError, OSError) as exc:
                reasons.append(f"the signed listing cannot be read: {exc}")
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
    append_audit("sweep", detail={"runners_checked": checked, "runtime_state_changed": changed, "removed": removed})
    print(json.dumps({"checked": checked, "changed": changed, "removed": removed}, sort_keys=True))


def refuse_disabled():
    """``--start`` and ``--stop`` in Patch 1: read nothing from stdin, start nothing, answer with the final refusal frame."""
    sys.stdout.write(json.dumps({"t": "refused", "code": "sandbox_disabled"}, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 3


def usage():
    raise SystemExit("usage: tec-tac-sandbox --start|--stop|--status | --selftest|--sweep | --register-module|--unregister-module <module-id>")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--start"], ["--stop"]):
        return refuse_disabled()  # before anything else: the kill switch is a constant in this file
    if len(argv) not in (1, 2):
        usage()
    mode = argv[0]
    if mode not in ("--status", "--selftest", "--sweep", "--register-module", "--unregister-module"):
        usage()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if mode == "--status" and len(argv) == 1:
        return show_status()
    if mode == "--selftest" and len(argv) == 1:
        return run_selftest()
    if mode == "--sweep" and len(argv) == 1:
        sweep()
        return 0
    if mode == "--register-module" and len(argv) == 2:
        register_module(argv[1])
        return 0
    if mode == "--unregister-module" and len(argv) == 2:
        unregister_module(argv[1])
        return 0
    usage()


if __name__ == "__main__":
    sys.exit(main())
