#!/usr/bin/python3 -I
"""Root-owned helper for core.sandbox (Core 1.18.26 shape; 1.18.8, Patch A: allow-list file view, fixed unit template, memory evidence and root audit rows; the kill switch is on since 1.18.28, behind the readiness and canary gates).

core.sandbox runs a signed module's declared program as an unprivileged, resource-limited process that cannot see the server's files
or reach the server itself or private networks (AD-63, docs/planning/sandbox/PLAN-CORE-SANDBOX.md sections 2, 3 and 15). Since 1.18.24 (AD-65 Patch B)
a run has its own, empty network space and reaches only its runner's ``allowed_hosts`` on port 443, through a per-run egress proxy (the egress_* functions).

* ``--register-module <id>`` and ``--unregister-module <id>`` (root callers: the module job helpers): the registry of declared runners;
* ``--verify-module <id>`` (root only, 1.18.29: the server-maintenance worker, after a module's action job ends): re-verifies that module's runners
  against the recorded listing hash, as the sweep does, and writes one ``module.runners_verified`` audit row. Not in sudoers;
* 1.18.26 (AD-65 Patch C): the selftest and the canary (``--selftest``, ``--selftest --canary``, ``--canary-launch``) left this file. They are in
  ``sandbox-selftest.py``, which is root only, outside sudoers, and loads this file by path. This file keeps only what the Tactical account's
  sudo rule reaches (``--start``, ``--stop``, ``--status``) and the root registration and sweep modes;
* ``--status`` (the Tactical account, through sudo): read only, with slot numbers and the canary result;
* ``--sweep`` (root: a boot and daily timer): re-verifies runtime folders; removes stray selftest folders, secrets folders, handoff and run
  files of units that are not active, and old canary markers;
* ``--start`` and ``--stop`` (the Tactical account, through sudo): the launch path. ``SANDBOX_ENABLED`` is True since 1.18.28. Only if the constant is forced to False do both
  refuse with the ``sandbox_disabled`` frame BEFORE they read stdin. ``--start`` refuses with ``sandbox_not_ready`` unless the
  selftest's status.json says ready and the last full canary passed for this Core build and this selftest run (read fresh on every start; ``--stop`` is never gated by readiness). ``--start`` reads one JSON header line and the input, re-checks the registry
  row, builds the unit itself from the row and Core constants, takes a server slot and a per-person slot, hands credentials in through
  LoadCredential from tmpfs, and streams one JSON frame per line (started, out, err, end). Closing its stdin or stdout stops the unit;
* 1.18.14: no unit property runs a command (no ``ExecStartPost=+``, no ``ExecStopPost=+``): on systemd 255 such a command sees only the
  RootDirectory skeleton, not the host. The helper removes the run's credential folder itself once the unit holds its own copy, and builds
  the end frame's memory evidence from its own live cgroup poll.

``SANDBOX_ENABLED`` is a constant in this file, so a fault in Django cannot change it. Nothing here reads a command, a path or a
limit from a caller: every rule is applied again to the root-owned registry row.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import ipaddress
import json
import os
import posixpath
import queue as queue_module
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

try:  # Linux only; the tests load this file on other systems too
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

# The kill switch. On since Core 1.18.28 (AD-65 amendment, Johan, 20 November 2026: Ubuntu 24.04 on dev02 is the baseline). Not a setting.
# The readiness gate still applies: --start refuses with sandbox_not_ready unless this server's selftest is ready.
SANDBOX_ENABLED = True

# The installed Core VERSION file (root-owned, put there by install.sh). The canary must have run against exactly this text.
INSTALLED_VERSION_FILE = Path("/opt/tec-tac/VERSION")

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
    "limits", "revision", "allowed_hosts",
})
ALLOWED_HOSTS_MAX = 16  # 1.18.24 (AD-65 Patch B): registry.py applies the same rules (_sandbox_allowed_hosts)
HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
HOST_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan")
# name -> (default, Core ceiling). A Core patch raises a ceiling, never a module.
LIMITS = {
    "memory_mb": (1024, 2048), "cpu_percent": (100, 200), "tasks": (256, 512), "run_seconds": (240, 600), "stdout_kib": (512, 1024),
    "stderr_kib": (64, 64), "scratch_mb": (64, 256), "input_kib": (64, 256), "queue_seconds": (10, 30),
}
RESERVED_ENV = frozenset({
    "HOME", "TMPDIR", "SSL_CERT_FILE", "SANDBOX_WORK", "SANDBOX_OUT",
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy",  # 1.18.24: Core alone sets the proxy
})
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

# Plan section 15: private ranges and the server itself are blocked; public HTTPS stays open. 169.254.169.254 is inside link-local.
# 1.17.120: numeric only. dev02 showed that the symbolic names (localhost, link-local, multicast) make the filter unreliable, so every
# IPAddressDeny=/IPAddressAllow= string the helper builds is an address or a network. 169.254.169.254 is inside 169.254.0.0/16.
ADDRESS_DENY = ("127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 224.0.0.0/4 ff00::/8 "
                "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7")
RESOLVERS_MAX = 3
LOCAL_DENY_MAX = 64  # 1.17.123: most local addresses and gateways read for the egress proxy's own-address list (those already inside the ranges are not counted)
CGROUP_ROOT = Path("/sys/fs/cgroup")  # a test replaces this
ZSWAP_MIN_SYSTEMD = 255  # MemoryZSwapMax= is only added from this systemd version on (an unknown property must not make every start fail)
UNIT_TIMEOUT_SECONDS = 30
NETWORK_PROPERTIES = ("PrivateNetwork=yes", "RestrictAddressFamilies=AF_INET AF_UNIX")  # 1.18.24 (AD-65 Patch B): a run has its own, empty network space; AF_UNIX only for the egress door
DENIED_NETWORKS = tuple(ipaddress.ip_network(item) for item in ADDRESS_DENY.split())


def denied_by_ranges(address):
    """True when the address is inside the numeric ranges of ``ADDRESS_DENY`` (or is the unspecified address)."""
    parsed = ipaddress.ip_address(str(address))
    return parsed.is_unspecified or any(parsed.version == net.version and parsed in net for net in DENIED_NETWORKS)


def host_network(address):
    """``<address>/32`` or ``/128``: the only form an address ever takes in IPAddressDeny=."""
    parsed = ipaddress.ip_address(str(address))
    return f"{parsed}/{32 if parsed.version == 4 else 128}"




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


PERCENT_REFUSAL = "may not contain '%' (systemd would read it as a specifier; refused until the dev02 canary shows how it is treated)"


PATTERN_REFUSAL = "pattern is not supported; use enum choices or max_length"
MAX_LENGTH_LIMIT = 65536
INT_LIMIT = 2 ** 31


def _parameter_limit_problem(spec):
    """The plain reason a parameter's rule is not valid (1.18.26), or None. ``pattern`` is not a field; ``max_length``, ``minimum`` and
    ``maximum`` are real whole numbers in a sane range. registry.py applies the same rules."""
    if not isinstance(spec, dict):
        return "schema must be an object"
    if "pattern" in spec:
        return PATTERN_REFUSAL
    for key in ("max_length", "minimum", "maximum"):
        if key not in spec:
            continue
        value = spec[key]
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{key} must be a whole number"
        if key == "max_length" and not 1 <= value <= MAX_LENGTH_LIMIT:
            return f"max_length must be 1 to {MAX_LENGTH_LIMIT}"
        if key != "max_length" and abs(value) > INT_LIMIT:
            return f"{key} is out of range"
    if "minimum" in spec and "maximum" in spec and spec["minimum"] > spec["maximum"]:
        return "minimum may not be above maximum"
    return None


def _check_parameter_limits(spec, where):
    """1.18.26 (AD-65 Patch C): a plain RuntimeError (never an uncaught TypeError) for a rule that is not valid."""
    problem = _parameter_limit_problem(spec)
    if problem:
        raise RuntimeError(f"{where}: {problem}" if problem == PATTERN_REFUSAL else f"{where} {problem}")


def _check_parameters(schema, label):
    if not isinstance(schema, dict) or len(schema) > 64:
        raise RuntimeError(f"{label} parameters must be an object with at most 64 entries")
    for name, spec in schema.items():
        if not isinstance(name, str) or not PARAM_NAME_RE.fullmatch(name):
            raise RuntimeError(f"{label} parameter name {name!r} is invalid")
        _check_parameter_limits(spec, f"{label} parameter {name!r}")  # first: it also refuses a spec that is not an object
        ptype = spec.get("type", "string")
        if ptype not in PARAMETER_TYPES:
            raise RuntimeError(f"{label} parameter {name!r} has an unsupported type")
        if ptype == "enum" and (not isinstance(spec.get("choices"), list) or not spec["choices"]):
            raise RuntimeError(f"{label} enum parameter {name!r} requires choices")
        # 1.17.120: '%' never reaches a systemd-run command word (string default, enum choices)
        if ptype == "string" and isinstance(spec.get("default"), str) and "%" in spec["default"]:
            raise RuntimeError(f"{label} parameter {name!r} default {PERCENT_REFUSAL}")
        if ptype == "enum" and any(isinstance(choice, str) and "%" in choice for choice in spec["choices"]):
            raise RuntimeError(f"{label} enum parameter {name!r} choices {PERCENT_REFUSAL}")
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


def check_allowed_hosts(value, label):
    """1.18.24: the ``allowed_hosts`` rules of registry.py (_sandbox_allowed_hosts) again: an optional list of at most 16 exact lower-case DNS names
    (at least two labels, at most 253 characters), no wildcard, no port, no IP literal in any spelling, no .local/.internal/.localhost/.lan, no
    repeats. Returns the list; raises RuntimeError (TypeError for a value that is not a list) with a plain message."""
    if not isinstance(value, list):
        raise TypeError(f"{label} allowed_hosts must be a list of host names")
    if len(value) > ALLOWED_HOSTS_MAX:
        raise RuntimeError(f"{label} allowed_hosts may not contain more than {ALLOWED_HOSTS_MAX} hosts")
    found = []
    for host in value:
        if not isinstance(host, str) or not host or len(host) > 253:
            raise RuntimeError(f"{label} allowed_hosts entries must be host names of 1 to 253 characters")
        if host != host.lower():
            raise RuntimeError(f"{label} allowed_hosts entries must be lower case")
        if any(ch in host for ch in "*:/@[%"):
            raise RuntimeError(f"{label} allowed_hosts entry {host!r} must be a plain host name")
        parts = host.split(".")
        if len(parts) < 2 or any(not HOST_LABEL_RE.fullmatch(part) for part in parts):
            raise RuntimeError(f"{label} allowed_hosts entry {host!r} must be a full DNS name with at least two labels")
        last = parts[-1]
        if last.isdigit() or (last.startswith("0x") and all(ch in "0123456789abcdef" for ch in last[2:])):
            raise RuntimeError(f"{label} allowed_hosts entry {host!r} looks like an IP address")
        if any(host.endswith(suffix) for suffix in HOST_BLOCKED_SUFFIXES):
            raise RuntimeError(f"{label} allowed_hosts entry {host!r} is a local name")
        if host in found:
            raise RuntimeError(f"{label} allowed_hosts repeats {host!r}")
        found.append(host)
    return found


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
        if "%" in executable:
            raise RuntimeError(f"{label} executable path {PERCENT_REFUSAL}")
        check_file(executable, f"{label} executable")
        schema = _check_parameters(entry.get("parameters", {}), label)
        argv = entry.get("argv", [])
        if not isinstance(argv, list) or len(argv) > 64:
            raise RuntimeError(f"{label} argv must be an array with at most 64 entries")
        for item in argv:
            if isinstance(item, str):
                if "\x00" in item or len(item) > 4096:
                    raise RuntimeError(f"{label} has an invalid literal argv entry")
                if "%" in item:
                    raise RuntimeError(f"{label} literal argv entry {PERCENT_REFUSAL}")
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
        allowed_hosts = check_allowed_hosts(entry["allowed_hosts"], label) if "allowed_hosts" in entry else []
        revision = entry.get("revision", "1")
        if isinstance(revision, bool) or not isinstance(revision, (str, int)) or not str(revision).strip() or len(str(revision)) > 64:
            raise RuntimeError(f"{label} revision must be a short text or whole number")
        runners.append({
            "id": runner_id, "description": description.strip(), "executable": executable, "argv": list(argv), "parameters": dict(schema),
            "environment": dict(environment), "runtime_roots": roots, "credential_files": list(names),
            "credential_return": credential_return, "limits": limits, "revision": str(revision).strip(),
            "allowed_hosts": allowed_hosts,
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
            "allowed_hosts": runner["allowed_hosts"],
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




def parse_resolvers(text, limit=RESOLVERS_MAX, ipv4_only=False):
    """Up to ``limit`` (three) different nameserver addresses from resolv.conf text, in order. Zone ids and anything that is not an address
    are skipped; ``ipv4_only`` also skips IPv6 (a run has AF_INET only). Returns [] when there is none."""
    found = []
    for raw in (text or "").splitlines():
        parts = raw.split("#", 1)[0].split(";", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            if "%" in parts[1]:
                continue  # a zone id (fe80::1%eth0) cannot be allowed by address
            try:
                parsed = ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if ipv4_only and parsed.version != 4:
                continue
            address = str(parsed)
            if address not in found:
                found.append(address)
        if len(found) >= limit:
            break
    return found


def parse_local_addresses(text):
    """Every address of every local interface from ``ip -o addr show`` text (IPv4 and IPv6, no prefix length, no zone id), in order and
    without repeats. A peer address of a point-to-point link is not this server's own and is not listed."""
    found = []
    for line in (text or "").splitlines():
        parts = line.split()
        for index in range(2, len(parts) - 1):  # parts[0] is the index, parts[1] the interface name
            if parts[index] in ("inet", "inet6"):
                try:
                    address = str(ipaddress.ip_address(parts[index + 1].split("/", 1)[0].split("%", 1)[0]))
                except ValueError:
                    break
                if address not in found:
                    found.append(address)
                break
    return found


def parse_gateways(text):
    """Every next hop of a default route from ``ip route show default`` text (IPv4 or IPv6; a multipath route has one ``nexthop`` line each).
    A default route with no ``via`` (on-link, for example a tunnel) has no next hop to list. A ``via`` with no readable address raises
    ValueError: the caller fails closed."""
    found = []
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("default", "nexthop") or "via" not in parts:
            continue
        index = parts.index("via") + 1
        if index < len(parts) and parts[index] in ("inet", "inet6"):
            index += 1  # 'via inet6 fe80::1' (an IPv4 route through an IPv6 next hop)
        if index >= len(parts):
            raise ValueError("a default route has no readable next hop")
        try:
            address = str(ipaddress.ip_address(parts[index].split("%", 1)[0]))
        except ValueError as exc:
            raise ValueError("a default route has no readable next hop") from exc
        if address not in found:
            found.append(address)
    return found


def local_deny(addr_text, route4_text, route6_text):
    """1.17.123: this server's own addresses and default gateways as ``{addresses, gateways, extra}``. ``extra`` is each one that is not
    already inside the numeric ranges of ADDRESS_DENY, as ``<address>/32`` or ``/128``, numeric only, without repeats, at most LOCAL_DENY_MAX.
    Raises ValueError (the caller refuses the start: fail closed) when no address can be read, a default route has no readable next hop,
    or there are too many to list."""
    addresses = parse_local_addresses(addr_text)
    if not addresses:
        raise ValueError("this server's own addresses could not be read")
    gateways = parse_gateways(route4_text)
    gateways += [gateway for gateway in parse_gateways(route6_text) if gateway not in gateways]
    extra = []
    for address in addresses + gateways:
        if not denied_by_ranges(address) and host_network(address) not in extra:
            extra.append(host_network(address))
    if len(extra) > LOCAL_DENY_MAX:
        raise ValueError("this server has more local addresses than the address filter can list")
    return {"addresses": addresses, "gateways": gateways, "extra": extra}


def read_local_deny(run_cmd=None):
    """Read the live addresses and default routes with ``ip`` (as root, numeric output) and build ``local_deny``. ValueError when ``ip`` fails."""
    run_cmd = run_cmd or UnitRunner().run_cmd
    texts = []
    for argv in (["ip", "-o", "addr", "show"], ["ip", "-4", "route", "show", "default"], ["ip", "-6", "route", "show", "default"]):
        code, out, _err = run_cmd(argv)
        if code != 0:
            raise ValueError("the `ip` command could not read this server's addresses or routes")
        texts.append(out)
    return local_deny(*texts)


def local_deny_now():
    """The live answer at this moment (a test replaces this name)."""
    return read_local_deny()


class UnitRunner:
    """Runs one probe in a transient unit and returns (returncode, stdout, stderr). The selftest only talks to this interface, so a test
    can replace it. ``name`` is the probe name; ``properties`` the unit properties; ``command`` the argv inside the unit."""

    def run_unit(self, name, properties, command, *, timeout=UNIT_TIMEOUT_SECONDS, unit=None):
        argv = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", f"--unit={unit or 'tectac-selftest-' + secrets.token_hex(6)}"]
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

































def write_status(status):
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    _write_root_file(STATUS_FILE, _json_bytes(status), 0o644)




# ------------------------------------------------------------------------------------------------------ status and sweep
def read_status():
    """status.json (read only, root-trust checked) or a plain not-ready answer."""
    try:
        data = _read_trusted_file(STATUS_FILE, "status file", max_bytes=64 * 1024)
        status = json.loads(data.decode("utf-8"))
        if isinstance(status, dict) and len(data) <= 64 * 1024:
            status["enabled"] = bool(SANDBOX_ENABLED)  # the constant counts; the file's value is information only
            return status
    except (RuntimeError, ValueError, OSError):
        pass
    return {"ready": False, "reason": "the sandbox selftest has not run or its result cannot be read", "enabled": bool(SANDBOX_ENABLED)}


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
# ``--start`` and ``--stop`` (the Tactical account, through sudo), the unit builder, the slots, the
# credential hand-in, the framing and the canary. SANDBOX_ENABLED is True since 1.18.28; ``--start`` refuses with sandbox_not_ready when the selftest or the canary is not ready.
LAUNCHER_FILE = LIB_ROOT / "sandbox-launcher.py"
CANARY_DIR = LIB_ROOT / "canary"
SLOTS_ROOT = RUN_ROOT / "slots"
PERSON_SLOTS_ROOT = SLOTS_ROOT / "person"
SECRETS_ROOT = RUN_ROOT / "secrets"
HANDOFF_ROOT = RUN_ROOT / "handoff"
RUNS_ROOT = RUN_ROOT / "runs"
# 1.18.24 (AD-65 Patch B): the egress door. One socket-activated proxy per run that has allowed_hosts (templates written by install.sh).
EGRESS_DOOR_ROOT = RUN_ROOT / "egress-door"  # root 0700; <run id>/door.sock is bound read only into the run at /run/egress
EGRESS_CONFIG_ROOT = RUN_ROOT / "egress-config"  # root 0700; <run id>.json is the proxy's LoadCredential
EGRESS_STATE_ROOT = Path("/run/tec-tac-sbx-egress")  # RuntimeDirectory of the proxy service: <run id>/audit.jsonl
EGRESS_PRIVATE_ROOT = Path("/run/private/tec-tac-sbx-egress")  # 1.18.25: where systemd really keeps a DynamicUser's RuntimeDirectory (EGRESS_STATE_ROOT/<id> links here)
TACTICAL_LOCAL_SETTINGS = Path("/rmm/api/tacticalrmm/tacticalrmm/local_settings.py")  # 1.18.25: read only, parsed with ast, never run (same file as install.sh LOCAL_SETTINGS)
OWN_SETTINGS_MAX_BYTES = 256 * 1024
OWN_SETTINGS_NAMES = ("ALLOWED_HOSTS", "CORS_ORIGIN_WHITELIST", "CORS_ALLOWED_ORIGINS", "MESH_SITE")
OWN_RESOLVE_SECONDS = 5
OWN_CACHE_SECONDS = 60
EGRESS_BIND_TARGET = "/run/egress"
EGRESS_UNIT_PREFIX = "tec-tac-sandbox-egress@"
EGRESS_PROXY_PORT = 3128  # the in-unit forwarder's port (127.0.0.1, inside the run's own network space)
EGRESS_PROXY_URL = f"http://127.0.0.1:{EGRESS_PROXY_PORT}"
EGRESS_AUDIT_NAME = "audit.jsonl"
EGRESS_AUDIT_MAX_BYTES = 256 * 1024
EGRESS_AUDIT_MAX_ROWS = 200
EGRESS_LIMITS = {"tunnels_live": 16, "tunnels_total": 100, "bytes_total": 256 * 1024 * 1024, "connect_seconds": 10, "idle_seconds": 60, "head_bytes": 8192,
                 "head_seconds": 10}
EGRESS_REASONS = frozenset({
    "listed", "method", "malformed", "head_too_large", "head_too_slow", "port", "ip_literal", "local_name", "not_listed", "limit",
    "resolve_failed", "address_blocked", "own_name", "connect_failed", "connect_timeout", "run_limit", "idle", "closed",
})
EGRESS_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
PROXY_ENV_NAMES = ("HTTPS_PROXY", "https_proxy")  # set only for a run that has allowed_hosts
CANARY_FILE = STATE_ROOT / "canary.json"
CANARY_MARKERS_FILE = RUN_ROOT / "canary-markers.json"
SYSTEMD_RUN = ["systemd-run"]  # a test replaces these names
SYSTEMCTL = ["systemctl"]
UNIT_PYTHON = "/usr/bin/python3"
CHILD_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}  # the only environment a child of the helper gets
WORK_DIR = "/work"
PROC_MEMINFO = "/proc/meminfo"
RESOLV_CONF = "/etc/resolv.conf"  # the host's own file: the canary reads it for the DNS detail only; a run never sees it

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
# The unit's file system (1.18.8, AD-65): an allow-list root. RootDirectory= points at a Core-made skeleton of empty mount points
# (install.sh builds it, check_skeleton re-checks it at every start); only what the runner needs is bound into it, read only.
SANDBOX_ROOT = LIB_ROOT / "root"
MERGED_USR_NAMES = ("bin", "sbin", "lib", "lib64", "lib32", "libx32")  # a symlink into /usr on a merged-/usr host, a real folder (then bound) otherwise
SKELETON_DIRS = ("usr", "work", "tmp", "var", "var/tmp", "proc", "sys", "dev", "run", "run/systemd", "run/systemd/incoming", "run/egress", "root", "opt", "opt/tec-tac", "opt/tec-tac/runtimes", "etc",
                 "etc/ssl", "etc/ssl/certs", "etc/ca-certificates")
SKELETON_FILES = ("etc/passwd", "etc/group", "etc/ld.so.cache", "etc/nsswitch.conf", "etc/localtime")  # 1.18.24: no resolv.conf: a run has no name server
SKELETON_TOP = ("usr", "work", "tmp", "var", "proc", "sys", "dev", "run", "root", "opt", "etc")  # merged-/usr names are added per host
# 1.18.13: a real run also leaves run/systemd/incoming (systemd makes it inside RootDirectory=); both are empty mount points, nothing else in run
# 1.18.24: run/egress is the empty mount point of the per-run egress door folder (the only bind that holds a socket)
SKELETON_ENTRIES = {"": SKELETON_TOP, "var": ("tmp",), "run": ("systemd", "egress"), "run/systemd": ("incoming",), "opt": ("tec-tac",), "opt/tec-tac": ("runtimes",), "etc": ("ssl", "ca-certificates", "passwd", "group", "ld.so.cache", "nsswitch.conf", "localtime"),
                    "etc/ssl": ("certs",),
                    **{name: () for name in ("usr", "work", "tmp", "var/tmp", "proc", "sys", "dev", "run/systemd/incoming", "run/egress", "root", "etc/ssl/certs", "etc/ca-certificates")}}
BASE_BINDS_REQUIRED = ("/etc/ssl/certs", "/etc/passwd", "/etc/group", "/etc/ld.so.cache")  # 1.18.24: no resolv.conf at all
BASE_BINDS_OPTIONAL = ("/etc/ca-certificates", "/etc/nsswitch.conf", "/etc/localtime")
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

_REFUSAL_TEXT = {
    "sandbox_unavailable": "this server cannot host a sandbox run right now",
    "sandbox_not_ready": "the sandbox selftest has not passed on this server",
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
    """The registered schema applied again (enum, integer range, length). No value reaches a shell: the runner is exec'd. 1.18.26: there is no
    pattern; a stored row that carries one, or a limit that is not a whole number, is refused (runtime_unverified), never a crash."""
    try:
        for spec in schema.values():
            _check_parameter_limits(spec, "a registered parameter")
    except (RuntimeError, AttributeError, TypeError) as exc:
        why = str(exc) if isinstance(exc, RuntimeError) and _plain(str(exc), 200) else "a limit is not a whole number or the row is malformed"
        raise Refusal("runtime_unverified", "a registered parameter rule is not valid: " + why) from exc
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
            elif "\x00" in value or len(value) > max(1, min(spec.get("max_length", 4096), 65536)):
                bad = "is too long or holds a NUL"
            elif "%" in value:
                raise Refusal("invalid_input", f"parameter {name!r} may not contain '%'")
        elif ptype == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                bad = "must be an integer"
            elif ("minimum" in spec and value < spec["minimum"]) or ("maximum" in spec and value > spec["maximum"]):
                bad = "is out of range"
        elif ptype == "boolean":
            if not isinstance(value, bool):
                bad = "must be true or false"
        elif ptype == "enum" and value not in spec.get("choices", []):
            bad = "must be one of its choices"
        elif ptype == "enum" and isinstance(value, str) and "%" in value:
            raise Refusal("invalid_input", f"parameter {name!r} may not contain '%'")
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
    if any("%" in item for item in items):  # second line of defence after validate_run_parameters and registration
        raise Refusal("invalid_input", "a command word may not contain '%'")
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


def installed_core_version():
    """The text of the root-owned installed VERSION file, or None when it cannot be read (fail closed)."""
    try:
        text = _read_trusted_file(INSTALLED_VERSION_FILE, "Core VERSION file", max_bytes=256).decode("utf-8").strip()
    except (RuntimeError, ValueError, OSError):
        return None
    return text or None


def canary_record_state(status):
    """``(passed, at)`` of canary.json against this Core build and this selftest run. Passed only when ok is True, core_version equals the
    installed VERSION text and selftest_at equals status.json's selftest_at (all text). Anything else is not passed."""
    try:
        canary = json.loads(_read_trusted_file(CANARY_FILE, "canary file", max_bytes=64 * 1024).decode("utf-8"))
    except (RuntimeError, ValueError, OSError):
        return False, None
    if not isinstance(canary, dict):
        return False, None
    at = canary.get("at") if isinstance(canary.get("at"), str) else None
    version, selftest_at = canary.get("core_version"), canary.get("selftest_at")
    current = installed_core_version()
    current_selftest = status.get("selftest_at") if isinstance(status, dict) else None
    passed = (canary.get("ok") is True and isinstance(version, str) and bool(version) and version == current
              and isinstance(selftest_at, str) and bool(selftest_at) and selftest_at == current_selftest
              and isinstance(current_selftest, str))
    return passed, at


def canary_passed(status):
    return canary_record_state(status)[0]


def ready_status(canary_required=True):
    """The selftest must be ready AND, for a real run (``canary_required``), the last full canary on this server must have passed for this Core
    build and this selftest run (AD-65). The canary's own runs and the root-only canary launch pass False: they are what makes the canary."""
    status = read_status()
    if status.get("ready") is not True:
        if status.get("skeleton_changed") is True and isinstance(status.get("reason"), str):  # 1.18.13: a run left a new entry; name it
            raise Refusal("sandbox_not_ready", status["reason"][:300])
        raise Refusal("sandbox_not_ready", "the sandbox selftest has not passed on this server")
    if not canary_required:
        return status
    if not canary_passed(status):
        raise Refusal("sandbox_not_ready", "the sandbox canary has not passed on this server")
    return status


# -------------------------------------------------------------------------------------------------------- the unit builder
def unit_name(run_id):
    return UNIT_PREFIX + run_id


def _bind_path_safe(path):
    """1.17.119: a path that comes from the registry row must stay one BindReadOnlyPaths= entry: no whitespace (systemd splits a bind
    line on it), no ':' (source:destination:options), no '%' or '$' (expansion), no control character, no backslash."""
    return (isinstance(path, str) and bool(path) and "\\" not in path
            and not any(ch.isspace() or ch in ":%$" or ord(ch) < 32 or ord(ch) == 127 for ch in path))


UNIT_FIXED_PROPERTIES = (  # 1.18.8: Core constants only; no module text, number or path is ever part of these
    "DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateIPC=yes",
    "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
    "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
    "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register userfaultfd keyctl add_key request_key",  # 1.18.26 (Patch C)
    "SystemCallArchitectures=native",
    "SystemCallErrorNumber=EPERM", *NETWORK_PROPERTIES, "RestrictNamespaces=yes", "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=no", "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
    "ProtectProc=invisible", "ProcSubset=pid", "UMask=0077", "KillMode=control-group", "SendSIGKILL=yes",
    "MemorySwapMax=0", "OOMPolicy=kill", "LimitNOFILE=1024", "LimitCORE=0",
)


def _limit_value(limits, name):
    """1.18.8: every number in a property is re-checked against its Core ceiling here, so nothing above a ceiling (or not a whole number) is formatted."""
    value = limits.get(name) if isinstance(limits, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > LIMITS[name][1]:
        raise Refusal("runtime_unverified")
    return value


def credential_slots(names):
    """1.18.8: a unit only ever sees the fixed slot names cred0, cred1 (in the order of ``names``); the declared name travels to the launcher as
    an argument and never reaches a unit property. Returns [(slot, name)]."""
    names = list(names)
    if len(names) > CREDENTIAL_FILES_MAX or len(set(names)) != len(names):
        raise Refusal("credential_invalid", "too many credentials for this runner")
    for name in names:
        if not isinstance(name, str) or not CREDENTIAL_NAME_RE.fullmatch(name):
            raise Refusal("credential_invalid", "a credential name is not allowed")
    return [(f"cred{index}", name) for index, name in enumerate(names)]


def file_view_properties(exists=os.path.lexists):
    """1.18.8: the file view of a unit, in one place for the real builder and the selftest probe so they cannot drift: the Core-made skeleton as
    RootDirectory=, API file systems, then read-only binds of /usr, the merged-/usr names that are real folders on this host, the base files,
    and an empty /usr/local over the host's own (the launcher and the runner folder are bound back inside it by the builder)."""
    for path in BASE_BINDS_REQUIRED:
        if not exists(path):
            raise Refusal("sandbox_unavailable", f"this server has no {path} to hand a run")
    # 1.18.14: a property command (``+`` or not) sees only this skeleton, never a host path, so no Exec* property may be built on a host path.
    props = [f"RootDirectory={SANDBOX_ROOT}", "MountAPIVFS=yes", "BindReadOnlyPaths=/usr"]
    for name in MERGED_USR_NAMES:
        path = "/" + name
        if exists(path) and not os.path.islink(path):
            props.append(f"BindReadOnlyPaths={path}")
    props += [f"BindReadOnlyPaths={path}" for path in BASE_BINDS_REQUIRED]
    props += [f"BindReadOnlyPaths={path}" for path in BASE_BINDS_OPTIONAL if exists(path)]
    props.append("TemporaryFileSystem=/usr/local:ro")
    return props


def _module_folders(row):
    """(runtime folder or None, runner folder, launcher file): the paths of the three module-related binds, from Core constants and the
    validated module id only. The per-root paths of ``runtime_roots`` are used by check_runner_ready for the tree hashes and never get here."""
    owner = row.get("owner_module")
    if not isinstance(owner, str) or not MODULE_ID_RE.fullmatch(owner):
        raise Refusal("runtime_unverified")
    runtime = f"{RUNTIME_BASE}/{owner}" if row.get("runtime_roots") else None
    return runtime, str(runner_base(owner)), str(LAUNCHER_FILE)


def check_unit_properties(props, row, run_id):
    """1.18.8: the closed set. Every emitted property must be fixed text, a number, a validated module id, the hex run id or one of Core's
    own folders. A later edit that adds a module string (or anything else) makes every start fail here instead of reaching systemd."""
    runtime, runner_folder, launcher = _module_folders(row)
    exact = set(UNIT_FIXED_PROPERTIES) | set(file_view_properties(lambda path: True)) | {
        f"BindReadOnlyPaths={path}" for path in (*BASE_BINDS_OPTIONAL, *("/" + name for name in MERGED_USR_NAMES), runner_folder, launcher, runtime) if path}
    if row_allowed_hosts(row):  # 1.18.24: the one extra bind, built from the hex run id only
        exact.add(f"BindReadOnlyPaths={egress_door_folder(run_id)}:{EGRESS_BIND_TARGET}")
    exact.add("MemoryZSwapMax=0")
    exact.add(f"WorkingDirectory={WORK_DIR}")
    folder = SECRETS_ROOT / run_id
    patterns = [re.compile(item) for item in (
        r"MemoryMax=[0-9]{1,6}M", r"CPUQuota=[0-9]{1,5}%", r"TasksMax=[0-9]{1,6}", r"LimitFSIZE=[0-9]{1,12}", r"RuntimeMaxSec=[0-9]{1,6}",
        re.escape(f"TemporaryFileSystem={WORK_DIR}:rw,nosuid,nodev,size=") + r"[0-9]{1,6}M,mode=1777",
        re.escape("LoadCredential=cred") + r"[0-9]:" + re.escape(str(folder / "cred")) + r"[0-9]")]
    for item in props:
        if item.startswith("Exec"):  # 1.18.14: a property command sees only the skeleton root, so none is ever allowed (never a `+` command)
            raise Refusal("sandbox_unavailable", "the unit would carry a property that is not on Core's fixed list (a command property is never allowed)")
        if item not in exact and not any(pattern.fullmatch(item) for pattern in patterns):
            raise Refusal("sandbox_unavailable", "the unit would carry a property that is not on Core's fixed list")


def build_properties(row, run_id, *, credential_names, exists=os.path.lexists, zswap=False):
    """Every property of the unit, as ``Key=Value`` strings. 1.18.8 (AD-65): built from Core constants, the validated module id and the hex
    run id only; no module-supplied string (a runtime root path, a credential name) is ever part of a property, and the last step checks
    the whole list against a closed set. Argv and environment values travel as arguments, never as properties.
    1.18.24 (AD-65 Patch B): the unit has its own, empty network space (PrivateNetwork=yes) and AF_INET plus AF_UNIX; there is no IPAddressDeny,
    no resolv.conf and no resolver address. A row with ``allowed_hosts`` gets exactly one more bind: the per-run egress door folder, read only,
    at /run/egress (built from the hex run id only). ``zswap`` adds MemoryZSwapMax=0 (systemd 255 or newer)."""
    if not _plain_id(run_id, RUN_ID_RE):
        raise Refusal("invalid_input", "the run id is not valid")
    limits = row["limits"]
    memory, cpu, tasks, seconds, scratch = (_limit_value(limits, name) for name in ("memory_mb", "cpu_percent", "tasks", "run_seconds", "scratch_mb"))
    view = file_view_properties(exists)
    hosts = row_allowed_hosts(row)
    door = None
    if hosts:
        door = str(egress_door_folder(run_id))
        if not _bind_path_safe(door):  # the folder is made by egress_start just before the unit; a bind of a missing folder fails loudly
            raise Refusal("sandbox_unavailable", "the egress door path is not usable")
    runtime, runner_folder, launcher = _module_folders(row)
    binds = [path for path in (runtime, runner_folder, launcher) if path]
    for path in binds:
        if not exists(path):
            raise Refusal("sandbox_unavailable", "a folder the run needs is missing")  # a missing bind fails loudly, never leaks
    props = [
        *UNIT_FIXED_PROPERTIES, *view,
        f"MemoryMax={memory}M", f"CPUQuota={cpu}%", f"TasksMax={tasks}", f"LimitFSIZE={scratch * 1024 * 1024}", f"RuntimeMaxSec={seconds + TIMER_SLACK_SECONDS}",
        f"TemporaryFileSystem={WORK_DIR}:rw,nosuid,nodev,size={scratch}M,mode=1777", f"WorkingDirectory={WORK_DIR}",
    ]
    props += [f"BindReadOnlyPaths={path}" for path in binds]
    if door:
        props.append(f"BindReadOnlyPaths={door}:{EGRESS_BIND_TARGET}")
    if zswap:
        props.insert(props.index("MemorySwapMax=0") + 1, "MemoryZSwapMax=0")
    folder = SECRETS_ROOT / run_id
    slots = credential_slots(credential_names)
    props += [f"LoadCredential={slot}:{folder / slot}" for slot, _name in slots]
    # 1.18.14: no Exec* property. The helper removes the folder once the unit holds its copy (remove_credentials_when_active).
    check_unit_properties(props, row, run_id)
    return props


def row_allowed_hosts(row):
    """The runner's ``allowed_hosts`` after the registration rules are applied again to the registry row (a row that holds an invalid list
    is not a runner this start may run). [] when it declares none: that run gets no door, no forwarder and no proxy variable."""
    hosts = row.get("allowed_hosts")
    if hosts is None:
        return []
    try:
        return check_allowed_hosts(hosts, "runner")
    except (RuntimeError, TypeError) as exc:
        raise Refusal("runtime_unverified") from exc


def build_environment(row):
    """The manifest's fixed map first, the reserved names last, so a manifest can never override them (the registry refuses them too).
    1.18.24: HTTPS_PROXY and https_proxy point at the in-unit forwarder (127.0.0.1:3128) only for a row that has allowed_hosts."""
    env = {name: str(value) for name, value in (row.get("environment") or {}).items() if name not in RESERVED_ENV}
    env.update({
        "HOME": f"{WORK_DIR}/home", "TMPDIR": f"{WORK_DIR}/tmp", "SANDBOX_WORK": WORK_DIR, "SANDBOX_OUT": f"{WORK_DIR}/out",
        "SSL_CERT_FILE": CA_BUNDLE, "PATH": SANDBOX_PATH_ENV,
    })
    if row_allowed_hosts(row):
        env.update({name: EGRESS_PROXY_URL for name in PROXY_ENV_NAMES})
    return env


def _exec_escape(text):
    """1.17.120: systemd expands '$VAR' in the command of a transient unit, and '$$' reaches the program as '$'. '%' is not escaped: it is
    refused instead (build_argv, validate_run_parameters, registration), until the dev02 canary shows how real systemd treats it."""
    return str(text).replace("$", "$$")


def build_argv(row, run_id, parameters, *, credential_names, exists=os.path.lexists, zswap=False):
    argv = [*SYSTEMD_RUN, "--pipe", "--wait", "--quiet", f"--unit={unit_name(run_id)}", f"--slice={SLICE}"]  # 1.18.17: no --collect, systemd keeps the unit record until the helper has read it
    argv += [f"--property={item}" for item in build_properties(row, run_id, credential_names=credential_names, exists=exists, zswap=zswap)]
    argv += [f"--setenv={name}={value}" for name, value in build_environment(row).items()]
    argv.append("--")
    command = [UNIT_PYTHON, "-I", str(LAUNCHER_FILE)]
    if row_allowed_hosts(row):
        command.append("--egress")  # 1.18.24: the launcher binds 127.0.0.1:3128 and relays it to /run/egress/door.sock
    command += [f"--credential={name}" for _slot, name in credential_slots(credential_names)]  # 1.18.8: the declared name only travels here
    if row.get("credential_return"):
        command.append("--return-credential")
    command += ["--", str(row["executable"]), *render_command(row, parameters)]
    if any("%" in item for item in command):  # 1.17.120: before any unit is started; the message never repeats the word
        raise Refusal("invalid_input", "a command word may not contain '%'")
    return argv + [_exec_escape(item) for item in command]


# ------------------------------------------------------------------------------------------------ the sandbox root (1.18.8)
SKELETON_PROBLEM = "the sandbox root folder does not match this server; run the Core install again"


def _skeleton_refusal(detail=None):
    return Refusal("sandbox_unavailable", SKELETON_PROBLEM)


def check_skeleton(exists=os.path.lexists, lstat=None, *, root=None, listdir=os.listdir, readlink=os.readlink):
    """1.18.8: the skeleton RootDirectory= points at must be exactly what install.sh builds: root-owned, not writable, no symlink where a
    folder is expected, every expected entry present and of the right type, the merged-/usr names in the form this host has, and nothing
    unexpected in the folders that hold only skeleton entries. A mismatch is a refusal (the selftest turns it into ready: false); there is
    no weaker mode. ``exists``, ``lstat``, ``listdir`` and ``readlink`` can be replaced by a test."""
    lstat = lstat or _lstat
    base = Path(root) if root is not None else SANDBOX_ROOT

    def info(relative):
        try:
            return lstat(base / relative if relative else base)
        except OSError:
            raise _skeleton_refusal() from None

    def require(relative, kind):
        st = info(relative)
        wanted = stat.S_ISDIR(st.st_mode) if kind == "dir" else stat.S_ISREG(st.st_mode)
        if stat.S_ISLNK(st.st_mode) or not wanted or _untrusted(st):
            raise _skeleton_refusal()

    require("", "dir")
    for relative in SKELETON_DIRS:
        require(relative, "dir")
    for relative in SKELETON_FILES:
        require(relative, "file")
    merged, real_dirs = [], []
    for name in MERGED_USR_NAMES:
        host_path = "/" + name
        if not exists(host_path):
            expected = None
        else:
            try:
                host = lstat(host_path)
            except OSError:
                raise _skeleton_refusal() from None
            expected = "link" if stat.S_ISLNK(host.st_mode) else "dir"
        if expected is None:
            if exists(base / name):
                raise _skeleton_refusal()
            continue
        merged.append(name)
        if expected == "dir":
            require(name, "dir")
            real_dirs.append(name)
        else:
            st = info(name)
            try:
                same = stat.S_ISLNK(st.st_mode) and readlink(base / name) == readlink(host_path)
            except OSError:
                same = False
            if not same or st.st_uid != ROOT_UID:
                raise _skeleton_refusal()
    for relative, allowed in SKELETON_ENTRIES.items():
        wanted = set(allowed) | (set(merged) if not relative else set())
        try:
            found = set(listdir(base / relative if relative else base))
        except OSError:
            raise _skeleton_refusal() from None
        if found != wanted:
            raise _skeleton_refusal()
    try:
        mounts = listdir(base / "opt" / "tec-tac" / "runtimes")
    except OSError:
        raise _skeleton_refusal() from None
    for name in mounts:  # one empty mount point per module that has run, never anything else
        if not MODULE_ID_RE.fullmatch(name):
            raise _skeleton_refusal()
        require(f"opt/tec-tac/runtimes/{name}", "dir")
    for relative in (*real_dirs, *(f"opt/tec-tac/runtimes/{name}" for name in mounts)):  # a mount point holds nothing of its own
        try:
            if listdir(base / relative):
                raise _skeleton_refusal()
        except OSError:
            raise _skeleton_refusal() from None


SKELETON_CHANGES_MAX = 10
SKELETON_CHANGE_NAME_LENGTH = 100


def _change_name(relative):
    text = "".join(c if c.isprintable() and c not in "\\" else "?" for c in str(relative))
    return text[:SKELETON_CHANGE_NAME_LENGTH]


def skeleton_changes(*, root=None, lstat=None, listdir=os.listdir, exists=os.path.lexists):
    """1.18.13: the relative paths (names only, sorted, at most 10, each at most 100 characters) inside the skeleton that are not on the lists
    check_skeleton uses, or are of the wrong type. It reads the same lists (SKELETON_DIRS, SKELETON_FILES, SKELETON_ENTRIES), so the two cannot
    drift. An unlisted folder is named once, never walked. Missing entries are not reported here (check_skeleton refuses them at the next start).
    Never raises: a folder that cannot be read is skipped."""
    lstat = lstat or _lstat
    base = Path(root) if root is not None else SANDBOX_ROOT
    found = set()
    merged = [name for name in MERGED_USR_NAMES if exists("/" + name)]

    def kind_of(relative):
        try:
            st = lstat(base / relative)
        except OSError:
            return None
        return "link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other"

    for relative, allowed in SKELETON_ENTRIES.items():
        allowed = set(allowed) | (set(merged) if not relative else set())
        try:
            names = listdir(base / relative if relative else base)
        except OSError:
            continue
        for name in names:
            child = f"{relative}/{name}" if relative else name
            if name not in allowed:
                found.add(child)
    for relative in SKELETON_DIRS:
        if kind_of(relative) not in (None, "dir"):
            found.add(relative)
    for relative in SKELETON_FILES:
        if kind_of(relative) not in (None, "file"):
            found.add(relative)
    for name in merged:  # a merged-/usr name is a link or a folder, never a file
        if kind_of(name) in ("file", "other"):
            found.add(name)
    mounts_path = "opt/tec-tac/runtimes"
    try:
        mounts = listdir(base / mounts_path)
    except OSError:
        mounts = []
    for name in mounts:  # one empty mount point per module that has run
        child = f"{mounts_path}/{name}"
        if not MODULE_ID_RE.fullmatch(name) or kind_of(child) != "dir":
            found.add(child)
            continue
        try:
            found.update(f"{child}/{inner}" for inner in listdir(base / child))
        except OSError:
            continue
    return sorted(_change_name(item) for item in found)[:SKELETON_CHANGES_MAX]


def recheck_skeleton_after_run(row, run_id):
    """1.18.13: after a run has ended (the unit stopped, the secrets removed, run.ended written) look at the skeleton again. A clean skeleton
    writes nothing. Otherwise: one ``skeleton.changed`` audit row naming the relative paths, and status.json goes to ready: false with a plain
    reason that names them, so the next start is refused with it and the status endpoint shows it. Only a new selftest (the install runs one)
    makes it ready again. The entry is reported, never accepted. Never raises and never touches the run's result."""
    try:
        names = skeleton_changes()
        if not names:
            return
        append_audit_safely("skeleton.changed", {"run_id": run_id, "runner": row.get("id"), "entries": names})
        status = read_status()
        status.pop("enabled", None)
        status["ready"] = False
        status["skeleton_changed"] = True
        status["reason"] = "a run left a new entry in the sandbox root: " + ", ".join(names)
        write_status(status)
    except (OSError, RuntimeError, ValueError, TypeError):
        pass


def ensure_runtime_mountpoint(module_id, *, root=None, lstat=None, mkdir=os.mkdir):
    """1.18.8: the one mount point a module's runtime bind needs, ``opt/tec-tac/runtimes/<module id>`` inside the skeleton, made by the helper
    (root, 0755). The id is validated, the parent chain was checked by check_skeleton, an existing entry must be a real root-owned folder
    that is not writable, and the result is checked again. Anything else is a refusal."""
    lstat = lstat or _lstat
    if not isinstance(module_id, str) or not MODULE_ID_RE.fullmatch(module_id):
        raise _skeleton_refusal()
    base = Path(root) if root is not None else SANDBOX_ROOT
    for relative in ("", "opt", "opt/tec-tac", "opt/tec-tac/runtimes"):
        try:
            st = lstat(base / relative if relative else base)
        except OSError:
            raise _skeleton_refusal() from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or _untrusted(st):
            raise _skeleton_refusal()
    target = base / "opt" / "tec-tac" / "runtimes" / module_id
    for attempt in (0, 1):
        try:
            st = lstat(target)
        except FileNotFoundError:
            if attempt:
                raise _skeleton_refusal() from None
            try:
                mkdir(target, 0o755)
                os.chmod(target, 0o755)
            except OSError:
                raise _skeleton_refusal() from None
            continue
        except OSError:
            raise _skeleton_refusal() from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or _untrusted(st):
            raise _skeleton_refusal()
        return target
    raise _skeleton_refusal()


def require_skeleton():
    """At every start (and in the selftest): the skeleton must match this server. A test replaces this name."""
    check_skeleton()


def prepare_runtime_mount(row):
    """At every start of a runner that has runtime roots: its single mount point exists inside the skeleton. A test replaces this name."""
    if row.get("runtime_roots"):
        ensure_runtime_mountpoint(row.get("owner_module"))


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
        """What is still held at the end of the stream. Nothing when a credential frame was open or closed, and nothing when the launcher
        header never arrived (that text is not the runner's). When the tail is the start of a marker (a prefix of the nonce line) that part
        is dropped, so no byte of the nonce can reach stdout."""
        buf, self.buf = self.buf, b""
        if self.in_credential or self.closed or not self.header_done:
            return b""
        if not self.frames:
            return buf
        for size in range(min(len(buf), len(self.marker) - 1), 1, -1):  # a lone newline shows nothing of the nonce and stays
            if self.marker.startswith(buf[-size:]):
                return buf[:-size]
        return buf


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
    """Credentials land only on tmpfs: /run/tec-tac/sandbox/secrets/<run id>/ (0700) with 0600 files. Never in argv, env, audit or a log.
    1.18.8: the files carry the fixed slot names cred0, cred1 (sorted declared names); the launcher maps the declared name to its slot."""
    slots = credential_slots(sorted(credentials))
    folder = SECRETS_ROOT / run_id
    SECRETS_ROOT.mkdir(parents=True, exist_ok=True)
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    for slot, name in slots:
        _write_private(folder / slot, credentials[name])
    return folder


def remove_secrets(run_id):
    shutil.rmtree(SECRETS_ROOT / run_id, ignore_errors=True)


CREDENTIALS_RUNTIME = Path("/run/credentials")  # systemd's own per-unit copies; a constant so a test can point it at a fake


def remove_credentials_when_active(unit, folder, slots, *, credentials_root=None, stop=None, clock=time.monotonic, sleep=time.sleep, timeout=15.0):
    """1.18.14: remove ``folder`` (the run's credential sources, root 0700 on tmpfs) as soon as the unit holds its own complete copy.
    Replaces ``ExecStartPost=+/bin/rm -rf``, which ran inside the RootDirectory skeleton on systemd 255 and could not see the host folder.
    A copy counts as complete only when it exists with the same size as its source. Returns True after removing the folder; False when
    the unit never showed its copies (or ``stop`` was set): the caller's own clean-up then removes the folder, so every failure path
    still ends with the folder gone. The folder is never read for content, only for sizes."""
    root = Path(credentials_root) if credentials_root is not None else CREDENTIALS_RUNTIME
    copies, folder = root / f"{unit}.service", Path(folder)
    deadline = clock() + timeout
    while clock() < deadline and not (stop is not None and stop.is_set()):
        try:
            ready = bool(slots) and all((copies / slot).stat().st_size == (folder / slot).stat().st_size for slot in slots)
        except OSError:
            ready = False
        if ready:
            shutil.rmtree(folder, ignore_errors=True)
            return True
        sleep(0.02)
    return False


CREDENTIAL_REMOVER_SECONDS = 15.0


def remove_credentials_noted(unit, folder, slots, *, run_id, runner, stop=None, audit=None, **kwargs):
    """1.18.15: ``remove_credentials_when_active`` plus a record when it genuinely gave up. A False answer with ``stop`` not set means the unit
    never showed its copies within the window (a run that ended early sets ``stop`` and is not a timeout). The row holds ids and a number only:
    no path, no credential, no slot name. The caller's own clean-up still removes the folder on every path, so nothing here widens trust."""
    kwargs.setdefault("timeout", CREDENTIAL_REMOVER_SECONDS)
    removed = remove_credentials_when_active(unit, folder, slots, stop=stop, **kwargs)
    if removed is False and not (stop is not None and stop.is_set()):
        (audit or append_audit_safely)("run.credentials_lingered", {"run_id": run_id, "runner": runner, "seconds": int(kwargs["timeout"])})
    return removed


def run_record_path(run_id):
    return RUNS_ROOT / f"{run_id}.json"


def cancel_flag_path(run_id):
    return RUNS_ROOT / f"{run_id}.cancel"


def handoff_path(run_id):
    return HANDOFF_ROOT / f"{run_id}.json"


def systemctl(*args, timeout=15):
    try:
        done = subprocess.run([*SYSTEMCTL, *args], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              env=dict(CHILD_ENV), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return done.returncode, done.stdout, done.stderr


def stop_unit(run_id):
    return systemctl("stop", unit_name(run_id) + ".service")[0] == 0


# ------------------------------------------------------------------------------------------------ the egress door (1.18.24, AD-65 Patch B)
def _egress_id(run_id):
    if not _plain_id(run_id, RUN_ID_RE):
        raise Refusal("invalid_input", "the run id is not valid")
    return run_id


def egress_unit(run_id, kind):
    """``tec-tac-sandbox-egress@<run id>.socket`` or ``.service``: the instance name is the validated 32-hex run id and nothing else."""
    if kind not in ("socket", "service"):
        raise ValueError("kind")
    return f"{EGRESS_UNIT_PREFIX}{_egress_id(run_id)}.{kind}"


def egress_door_folder(run_id):
    return EGRESS_DOOR_ROOT / _egress_id(run_id)


def egress_door_socket(run_id):
    return egress_door_folder(run_id) / "door.sock"


def egress_config_path(run_id):
    return EGRESS_CONFIG_ROOT / f"{_egress_id(run_id)}.json"


def egress_audit_path(run_id):
    return EGRESS_STATE_ROOT / _egress_id(run_id) / EGRESS_AUDIT_NAME


OWN_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
OWN_RESOLVER = socket.getaddrinfo  # a test replaces this
_own_cache = {"at": 0.0, "key": None, "value": None}


def _own_name(value):
    """A valid lower-case dotted DNS name, or None. IP literals, single labels, empty labels and other characters are dropped."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().lstrip(".")
    if len(name) > 253 or not OWN_NAME_RE.fullmatch(name) or "." not in name or ".." in name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    if name.rsplit(".", 1)[-1].isdigit():
        return None
    return name


def _settings_hosts(name, value):
    items = value if isinstance(value, (list, tuple, set)) else [value]
    found = set()
    for item in items:
        if not isinstance(item, str) or item.strip() == "*":
            continue
        text = item.strip()
        if name in ("CORS_ORIGIN_WHITELIST", "CORS_ALLOWED_ORIGINS", "MESH_SITE") or "://" in text:
            try:
                text = urlsplit(text if "://" in text else "//" + text).hostname or ""
            except ValueError:
                continue
        valid = _own_name(text)
        if valid:
            found.add(valid)
    return found


def read_tactical_names(path=None):
    """The host names in Tactical's settings file (ALLOWED_HOSTS, CORS_ORIGIN_WHITELIST, CORS_ALLOWED_ORIGINS, MESH_SITE). Read as root with
    O_NOFOLLOW, a regular file of at most 256 KiB, parsed with ast and never imported or run: only top-level literal assignments count.
    Raises Refusal when the file cannot be read or parsed."""
    path = Path(path or TACTICAL_LOCAL_SETTINGS)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > OWN_SETTINGS_MAX_BYTES:
                raise OSError("not a plain small file")
            with os.fdopen(os.dup(fd), "rb") as handle:
                data = handle.read(OWN_SETTINGS_MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > OWN_SETTINGS_MAX_BYTES:
            raise OSError("too large")
        tree = ast.parse(data.decode("utf-8"), filename="local_settings.py")
    except (OSError, ValueError, SyntaxError, RecursionError, MemoryError) as exc:
        raise Refusal("sandbox_unavailable", "this server's own names could not be read from Tactical's settings file") from exc
    names = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in OWN_SETTINGS_NAMES:
                try:
                    value = ast.literal_eval(node.value)
                except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
                    continue
                names |= _settings_hosts(target.id, value)
    return names


def own_server_names(settings_path=None):
    """Every name this server answers to: its FQDN, its host name when it has a dot, and Tactical's own names. Raises Refusal (fail closed)
    when the settings file cannot be read or no dotted name is found at all. Returns a sorted list."""
    names = read_tactical_names(settings_path)
    for getter in (socket.getfqdn, socket.gethostname):
        try:
            valid = _own_name(getter())
        except OSError:
            valid = None
        if valid:
            names.add(valid)
    if not names:
        raise Refusal("sandbox_unavailable", "no dotted name for this server could be found, so the egress door cannot tell its own names")
    return sorted(names)


DNS_TRY_SECONDS = 2.0  # 1.18.26: one query to one upstream resolver
DNS_TOTAL_SECONDS = 5.0  # and all queries for one name
DNS_PORT = 53
DNS_PACKET_MAX = 4096
DNS_QTYPES = (1, 28)  # A, AAAA
RESOLVED_UPSTREAM = "/run/systemd/resolve/resolv.conf"  # the real upstream resolvers (not the 127.0.0.53 stub)
DNS_FILE_MAX = 65536


def dns_query_packet(name, qtype, ident):
    """1.18.26: one DNS question as wire bytes (id, recursion desired, one question, class IN). ValueError for a label that is empty, over 63
    bytes or not ASCII."""
    out = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    for label in str(name).rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError("bad DNS label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00" + struct.pack(">HH", qtype, 1)


def _dns_skip_name(data, pos):
    steps = 0
    while True:
        if pos >= len(data):
            return None
        size = data[pos]
        if size == 0:
            return pos + 1
        if size & 0xC0 == 0xC0:
            return pos + 2 if pos + 1 < len(data) else None
        if size & 0xC0:
            return None
        pos += 1 + size
        steps += 1
        if steps > 128:
            return None


def dns_parse_answer(data, ident, name, qtype):
    """1.18.26: the A or AAAA addresses of one DNS answer as a set of strings (an empty set is a real answer: no such name or no record), or
    None for anything that must be ignored: too short or too long, another id, not a response, truncated, a question that is not ours, a server
    failure, or a record that runs past the packet."""
    if not isinstance(data, (bytes, bytearray)) or not 12 <= len(data) <= DNS_PACKET_MAX:
        return None
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", bytes(data[:12]))
    if rid != ident or not flags & 0x8000 or flags & 0x0200 or qdcount != 1 or flags & 0xF not in (0, 3):
        return None
    try:
        question = dns_query_packet(name, qtype, ident)[12:]
    except (ValueError, UnicodeError):
        return None
    if bytes(data[12:12 + len(question)]).lower() != question.lower():
        return None
    pos, found = 12 + len(question), set()
    for _ in range(ancount):
        pos = _dns_skip_name(data, pos)
        if pos is None or pos + 10 > len(data):
            return None
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", bytes(data[pos:pos + 10]))
        pos += 10
        if pos + rdlen > len(data):
            return None
        rdata = bytes(data[pos:pos + rdlen])
        pos += rdlen
        if rclass != 1:
            continue
        if rtype == 1 and rdlen == 4:
            found.add(str(ipaddress.IPv4Address(rdata)))
        elif rtype == 28 and rdlen == 16:
            found.add(str(ipaddress.IPv6Address(rdata)))
    return found


def _udp_socket(family):
    return socket.socket(family, socket.SOCK_DGRAM)


def dns_lookup_name(name, servers, *, sock_factory=None, clock=time.monotonic, per_try=DNS_TRY_SECONDS, total=DNS_TOTAL_SECONDS,
                    randbits=secrets.randbits):
    """1.18.26: the addresses a name has in real DNS, asked of the upstream resolvers directly (a plain UDP query, A then AAAA), never from
    /etc/hosts. A random id is used per query; an answer with another id, another source or another question is ignored; a truncated answer is
    ignored; 2 s per try and 5 s for the name. Returns ``(answered, addresses)``. Since 1.18.27 ``answered`` is True only when BOTH the A and the AAAA
    query got a valid answer (an empty set for NXDOMAIN or NODATA is valid; a timeout, SERVFAIL, truncated or mismatched reply is not), so a
    partial answer never stands for the name. The reply source must be the queried server (compared as addresses, so a non-canonically written
    IPv6 upstream matches) and port 53."""
    sock_factory = sock_factory or _udp_socket
    end = clock() + total
    answered, found = True, set()
    for qtype in DNS_QTYPES:
        got = None
        for server in servers:
            if clock() >= end:
                break
            sock = sock_factory(socket.AF_INET6 if ":" in server else socket.AF_INET)
            try:
                ident = randbits(16)
                sock.sendto(dns_query_packet(name, qtype, ident), (server, DNS_PORT))
                try_end = min(end, clock() + per_try)
                while got is None:
                    left = try_end - clock()
                    if left <= 0:
                        break
                    sock.settimeout(left)
                    try:
                        data, source = sock.recvfrom(DNS_PACKET_MAX)
                    except OSError:  # a timeout or a refused port: the next resolver
                        break
                    try:
                        same = ipaddress.ip_address(str(source[0]).split("%", 1)[0]) == ipaddress.ip_address(server) and source[1] == DNS_PORT
                    except (ValueError, IndexError, TypeError):
                        same = False
                    if not same:
                        continue
                    got = dns_parse_answer(data, ident, name, qtype)
            except (OSError, ValueError):
                got = None
            finally:
                sock.close()
            if got is not None:
                break
        if got is None:
            answered = False  # 1.18.27: one query type without a valid answer means the name is not answered
        else:
            found |= got
    return answered, found


def upstream_resolvers(read=None):
    """1.18.26: up to three upstream name servers: the ones in systemd-resolved's own file, else /etc/resolv.conf, with every loopback address
    (the 127.0.0.0/8 stubs and ::1) removed. [] when none is usable."""
    def read_text(path):
        try:
            with open(path, "rb") as handle:
                return handle.read(DNS_FILE_MAX).decode("utf-8", "replace")
        except OSError:
            return ""

    read = read or read_text
    for path in (RESOLVED_UPSTREAM, RESOLV_CONF):
        servers = [item for item in parse_resolvers(read(path), limit=RESOLVERS_MAX * 4) if not ipaddress.ip_address(item).is_loopback]
        if servers:
            return servers[:RESOLVERS_MAX]
    return []


def resolve_own_names(names, *, lookup=None, servers=None, local_addresses=(), seconds=None, clock=time.monotonic, resolver=None):
    """1.18.26 (held Medium of 1.18.25): every address this server's own names have in REAL DNS, asked of the upstream resolvers (``getaddrinfo``
    reads /etc/hosts, where a Tactical server maps its own names to 127.0.1.1, so it never shows the public address). The names are looked up in
    worker threads for at most 5 s in all (cached 60 s). ``resolver`` (the old getaddrinfo hook, ``OWN_RESOLVER`` by default) may add its
    addresses but never replaces the real answer. Fail closed with Refusal sandbox_unavailable and a plain reason when (a) no resolver is usable,
    (b) any own name did not get a full DNS answer (A and AAAA, 1.18.27; nothing is cached then), or (c) no own name has a global address AND no local interface holds one (the public address is then
    unknown). Any unexpected fault is the same Refusal. Returns a sorted list of address strings."""
    try:
        return _resolve_own_names(sorted(names), lookup, servers, local_addresses, seconds, clock, resolver)
    except Refusal:
        raise
    except Exception as exc:  # one plain refusal for any fault: the callers catch only Refusal
        raise Refusal("sandbox_unavailable", "this server's own names could not be looked up (" + type(exc).__name__ + "), so the egress door fails closed") from exc


def _is_global(address):
    try:
        return ipaddress.ip_address(str(address).split("%", 1)[0]).is_global
    except ValueError:
        return False


def _resolve_own_names(names, lookup, servers, local_addresses, seconds, clock, resolver):
    resolver = resolver or OWN_RESOLVER
    seconds = OWN_RESOLVE_SECONDS if seconds is None else seconds
    local_addresses = list(local_addresses or ())
    key = (tuple(names), tuple(sorted(str(a) for a in local_addresses)))
    nowt = clock()
    if _own_cache["key"] == key and _own_cache["value"] is not None and nowt - _own_cache["at"] < OWN_CACHE_SECONDS:
        return list(_own_cache["value"])
    servers = upstream_resolvers() if servers is None else list(servers)
    if not servers:
        raise Refusal("sandbox_unavailable", "this server has no upstream name server to ask (only a local stub), so its own public address cannot be found and the egress door fails closed")
    lookup = lookup or dns_lookup_name
    lock = threading.Lock()
    results, answered = {}, set()

    def work(name):
        try:
            got_answer, real = lookup(name, servers)
        except (OSError, ValueError, TypeError, RuntimeError, LookupError, AttributeError):  # a worker never dies with a traceback: a failed name did not answer
            got_answer, real = False, set()
        try:  # /etc/hosts and the system lookup may add addresses; they never stand in for the real answer
            extra = {str(item[4][0]).split("%", 1)[0] for item in resolver(name, None)}
        except (OSError, ValueError, IndexError, TypeError):
            extra = set()
        with lock:  # a lookup that finishes after the deadline writes here harmlessly
            results[name] = set(real) | extra
            if got_answer:
                answered.add(name)

    threads = [threading.Thread(target=work, args=(name,), daemon=True) for name in names]
    for thread in threads:
        thread.start()
    deadline = clock() + seconds
    for thread in threads:
        thread.join(max(0.0, deadline - clock()))
    with lock:
        got = {name: set(results[name]) for name in answered if name in results}
    if len(got) != len(names):  # 1.18.27: every own name must be fully answered; a partial answer could hide a public address
        raise Refusal("sandbox_unavailable", f"{len(names) - len(got)} of this server's {len(names)} own names did not get a full DNS answer (A and AAAA) in time, so the egress door fails closed")
    found = sorted(set().union(*got.values()) if got else set())
    if not any(_is_global(address) for address in found) and not any(_is_global(address) for address in local_addresses):
        raise Refusal("sandbox_unavailable", "this server's own names resolve only to private addresses and no local interface has a public one, so its public address is unknown and the egress door fails closed")
    _own_cache.update({"at": nowt, "key": key, "value": found})
    return found


def egress_config_bytes(hosts, local, fqdn, own_names=(), own_addresses=()):
    """The proxy's per-run configuration (root 0600, handed in through LoadCredential): the allowed hosts, this server's own addresses and
    gateways, this server's own names and their addresses (1.18.25; ``fqdn`` stays for compatibility), and the run limits. No credential, no
    module text beyond the validated host list."""
    payload = {"allowed_hosts": list(hosts), "own": list(local.get("addresses", [])), "gateways": list(local.get("gateways", [])),
               "fqdn": str(fqdn or "")[:253], "own_names": sorted(str(n) for n in own_names), "own_name_addresses": sorted(str(a) for a in own_addresses),
               "limits": dict(EGRESS_LIMITS)}
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def _egress_cmd(run_cmd, *args):
    """One systemctl call: through the helper's own ``systemctl`` (fixed environment), or through ``run_cmd`` (the selftest's runner)."""
    if run_cmd is None:
        return systemctl(*args)
    return run_cmd([*SYSTEMCTL, *args])


def egress_stop(run_id, *, run_cmd=None):
    """Stop the proxy's service and socket and forget a failed state. Never raises: this is the clean-up path."""
    try:
        _egress_cmd(run_cmd, "stop", egress_unit(run_id, "service"), egress_unit(run_id, "socket"))
        _egress_cmd(run_cmd, "reset-failed", egress_unit(run_id, "service"), egress_unit(run_id, "socket"))
    except (Refusal, OSError, ValueError):
        pass


def egress_remove_state(run_id):
    """Remove the proxy's audit state for a run (1.18.25). With a DynamicUser RuntimeDirectory, systemd makes ``EGRESS_STATE_ROOT/<id>`` a symlink to
    ``../private/tec-tac-sbx-egress/<id>``; rmtree refuses a symlink, so link and target both stayed. Built only from the validated 32-hex id.
    A plain directory goes with rmtree. A symlink is followed only when, normalised lexically (never resolved), it points at exactly
    ``EGRESS_PRIVATE_ROOT/<same id>`` and that target is a real directory: the target goes, then the link. Any other symlink is unlinked and nothing
    it points to is touched. Never raises."""
    try:
        run_id = _egress_id(run_id)
        link = EGRESS_STATE_ROOT / run_id
        try:
            info = _lstat(link)
        except OSError:
            return
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(link, ignore_errors=True)
            return
        if stat.S_ISLNK(info.st_mode):
            try:
                raw = os.readlink(link)
                if os.sep != "/":
                    raw = raw.replace(os.sep, "/")
                joined = posixpath.normpath(posixpath.join(posixpath.dirname(link.as_posix()), raw))
                expected = (EGRESS_PRIVATE_ROOT / run_id).as_posix()
                if joined == expected and stat.S_ISDIR(_lstat(EGRESS_PRIVATE_ROOT / run_id).st_mode):
                    shutil.rmtree(EGRESS_PRIVATE_ROOT / run_id, ignore_errors=True)
            except (OSError, ValueError):
                pass
        link.unlink(missing_ok=True)
    except (Refusal, OSError, ValueError):
        pass


def egress_clean(run_id):
    """Remove the run's door folder, proxy configuration and audit state. Only paths built from the validated run id; never raises."""
    try:
        shutil.rmtree(egress_door_folder(run_id), ignore_errors=True)
        egress_config_path(run_id).unlink(missing_ok=True)
    except (Refusal, OSError):
        pass
    egress_remove_state(run_id)


def egress_start(row, run_id, local, *, run_cmd=None, fqdn=None, own=None):
    """Start the one door for a run that has allowed_hosts (nothing for a run that has none: no proxy, no forwarder, no variable). Writes the proxy
    configuration and starts the socket unit before the run unit exists. Fail closed: a door that does not start is ``sandbox_unavailable`` and
    everything it made is removed. Returns True when a door was started."""
    hosts = row_allowed_hosts(row)
    if not hosts:
        return False
    _egress_id(run_id)
    if own is None:  # 1.18.25: fail closed before anything is made when this server's own names are unknown
        names = own_server_names()
        own = (names, resolve_own_names(names, local_addresses=local.get("addresses", [])))
    own_names, own_addresses = own
    try:
        for folder, mode in ((EGRESS_DOOR_ROOT, 0o700), (EGRESS_CONFIG_ROOT, 0o700)):
            folder.mkdir(parents=True, exist_ok=True)
            os.chmod(folder, mode)
        door = egress_door_folder(run_id)
        door.mkdir(exist_ok=True)
        os.chmod(door, 0o755)  # the run's user walks into this folder (through the bind) to reach the socket; the parent stays 0700
        if fqdn is None:
            try:
                fqdn = socket.getfqdn()
            except OSError:
                fqdn = ""
        _write_root_file(egress_config_path(run_id), egress_config_bytes(hosts, local, fqdn, own_names, own_addresses), 0o600)
    except OSError as exc:
        egress_clean(run_id)
        raise Refusal("sandbox_unavailable", "the egress door folder could not be prepared") from exc
    code, _out, _err = _egress_cmd(run_cmd, "start", egress_unit(run_id, "socket"))
    try:
        is_socket = stat.S_ISSOCK(_lstat(egress_door_socket(run_id)).st_mode)
    except OSError:
        is_socket = False
    if code != 0 or not is_socket:
        egress_stop(run_id, run_cmd=run_cmd)
        egress_clean(run_id)
        raise Refusal("sandbox_unavailable", "the egress door could not be started")
    return True


def egress_row(item):
    """One audit row of the proxy after the strict schema, or None. Exactly host, port, result, reason, up and down; nothing else is kept."""
    if not isinstance(item, dict) or set(item) != {"host", "port", "result", "reason", "up", "down"}:
        return None
    host, port, result, reason, up, down = (item[key] for key in ("host", "port", "result", "reason", "up", "down"))
    if not isinstance(host, str) or not (host == "<invalid>" or EGRESS_HOST_RE.fullmatch(host)):
        return None
    for number in (port, up, down):
        if isinstance(number, bool) or not isinstance(number, int) or number < 0 or number > 2 ** 40:
            return None
    if port > 65535 or result not in ("allowed", "refused") or reason not in EGRESS_REASONS:
        return None
    return {"host": host, "port": port, "result": result, "reason": reason, "up": up, "down": down}


def parse_egress_audit(data):
    """(rows, truncated) from the proxy's audit.jsonl bytes: at most 200 valid rows; a malformed, oversized or foreign line is dropped."""
    rows, truncated = [], False
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    for line in text.splitlines():
        if len(rows) >= EGRESS_AUDIT_MAX_ROWS:
            truncated = True
            break
        if not line.strip() or len(line) > 1024:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        found = egress_row(item)
        if found is not None:
            rows.append(found)
    return rows, truncated


def read_egress_audit(run_id):
    """The proxy's audit rows for the run, read as root with O_NOFOLLOW: a regular file, at most 256 KiB (a longer file is cut at its last whole line
    and counted as truncated). ([], False) when there is none."""
    path = egress_audit_path(run_id)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return [], False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return [], False
        data = os.read(fd, EGRESS_AUDIT_MAX_BYTES + 1)
    except OSError:
        return [], False
    finally:
        os.close(fd)
    cut_short = len(data) > EGRESS_AUDIT_MAX_BYTES
    if cut_short:
        data = data[:EGRESS_AUDIT_MAX_BYTES]
        data = data[:data.rfind(b"\n") + 1] if b"\n" in data else b""
    rows, truncated = parse_egress_audit(data)
    return rows, truncated or cut_short


def egress_counts(rows):
    return {"allowed": sum(1 for r in rows if r["result"] == "allowed"), "refused": sum(1 for r in rows if r["result"] == "refused"),
            "bytes": sum(r["up"] + r["down"] for r in rows)}


def egress_finish(row, run_id, progress, *, run_cmd=None):
    """After the run: stop the proxy (it writes what is left), read its audit, write the root audit row ``run.egress`` (counts plus the capped rows)
    BEFORE ``run.ended``, remember the counts for ``run.ended``, and remove the door, configuration and audit state. Never raises."""
    try:
        egress_stop(run_id, run_cmd=run_cmd)
        rows, truncated = read_egress_audit(run_id)
        counts = egress_counts(rows)
        progress["egress"] = counts
        append_audit_safely("run.egress", {"runner": row["id"], "run_id": run_id, **counts, "truncated": truncated, "rows": rows})
    except (OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        egress_clean(run_id)


UNIT_RESULTS = frozenset({"success", "exit-code", "signal", "core-dump", "timeout", "oom-kill", "watchdog", "resources", "protocol",
                          "start-limit-hit", "dependency", "skipped", "exec-condition", "capture-failure"})
UNIT_SHOW_KEYS = ("LoadState", "ActiveState", "Result", "ExecMainCode", "ExecMainStatus")
UNIT_ACTIVE_STATES = frozenset({"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"})
UNIT_NUMBER_RE = re.compile(r"^[0-9]{1,4}$")


def read_unit_result(run_id):
    """1.18.17: systemd's own record of a finished run unit, or None. One ``systemctl show`` (through systemctl(), so CHILD_ENV and the 15 s
    timeout apply), parsed line by line as an exact ``Key=Value``; every value is checked against a whitelist. None for a failed call, an
    unloaded unit (a unit that exited 0 is garbage-collected, and systemd then reports Result=success and status 0 by default, which proves
    nothing), a duplicate, an unknown or a malformed line. Nothing is guessed. Never reads the run's streams: the sandboxed program writes to
    the same stderr as systemd-run. Returns {"result", "code", "status", "active"} with code 'exited', 'killed' or 'dumped' (or None)."""
    code, out, _err = systemctl("show", "--property=" + ",".join(UNIT_SHOW_KEYS), unit_name(run_id) + ".service")
    if code != 0 or not isinstance(out, str):
        return None
    found = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in UNIT_SHOW_KEYS or key in found:
            return None
        found[key] = value
    if set(found) != set(UNIT_SHOW_KEYS) or found["LoadState"] != "loaded":
        return None
    if found["Result"] not in UNIT_RESULTS or found["ActiveState"] not in UNIT_ACTIVE_STATES:
        return None
    if not UNIT_NUMBER_RE.match(found["ExecMainCode"]) or not UNIT_NUMBER_RE.match(found["ExecMainStatus"]):
        return None
    main_code, status = int(found["ExecMainCode"]), int(found["ExecMainStatus"])
    kind = {1: "exited", 2: "killed", 3: "dumped"}.get(main_code)  # CLD_EXITED, CLD_KILLED, CLD_DUMPED; 0 means never ran
    return {"result": found["Result"], "code": kind, "status": status, "active": found["ActiveState"]}


def reset_failed_unit(run_id):
    """1.18.17: forget a failed run unit. The result is ignored: 'not loaded' is normal."""
    systemctl("reset-failed", unit_name(run_id) + ".service")


def slice_cgroup_folders(slice_name=None):
    """1.18.8: where the sandbox slice lives in the cgroup tree, from the slice name alone. systemd reads a dash in a slice name as nesting
    (``tec-tac-sandbox.slice`` sits in ``tec-tac.slice`` in ``tec.slice``), so the nested path is tried first and the flat one second. The
    plan named only the flat path; the nested one is what systemd builds, and a path that does not exist is never an error."""
    slice_name = slice_name or SLICE
    stem = slice_name.removesuffix(".slice")
    parts = stem.split("-")
    nested = [CGROUP_ROOT.joinpath(*("-".join(parts[:count]) + ".slice" for count in range(1, len(parts) + 1)))]
    return nested + [CGROUP_ROOT / slice_name]


def unit_cgroup_folders(run_id):
    """The candidate cgroup folders of one run, built from constants and the hex run id only (no systemctl, no module string, no '..')."""
    if not _plain_id(run_id, RUN_ID_RE):
        raise RuntimeError("run id is invalid")
    return [folder / (unit_name(run_id) + ".service") for folder in slice_cgroup_folders()]


MEMORY_COUNTERS = ("max", "high", "oom", "oom_kill")


def parse_memory_counters(text):
    """1.18.16: ``max``, ``high``, ``oom`` and ``oom_kill`` from memory.events text, as a dict holding only the counters that were present.
    Anything that is not ``<word> <digits>`` is ignored (same rule as before), and a number of more than 18 digits is ignored."""
    found = {}
    for line in str(text).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in MEMORY_COUNTERS and parts[1].isascii() and parts[1].isdigit() and len(parts[1]) <= 18:
            found[parts[0]] = int(parts[1])
    return found




def _read_small(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4096).decode("ascii", "replace")
    except (OSError, ValueError):
        return None


class CgroupWatch:
    """1.18.8: a live view of one run's memory evidence. The path is fixed (``unit_cgroup_folders``); ``sample()`` reads memory.events (oom_kill,
    oom) and memory.peak (the highest memory.current seen when memory.peak does not exist, a kernel older than 5.19) and keeps the maximum of
    each. A missing or vanished file is tolerated: never an error, never a guess. ``evidence`` names where a number came from."""

    INTERVAL = 0.2  # production runs: the cost stays as it was
    CANARY_INTERVAL = 0.02  # 1.18.15: the canary's runs end in a fraction of a second after the kill; the cgroup of a --collect unit is gone soon after

    def __init__(self, run_id, interval=None):
        self.interval = self.INTERVAL if interval is None else float(interval)
        self.folders = unit_cgroup_folders(run_id)
        self.oom_kill = None
        self.oom = None
        self.events = {}  # 1.18.16: the highest value seen of each memory.events counter (max, high, oom, oom_kill)
        self.peak = None
        self.current_max = None
        self.last = None

    @staticmethod
    def _keep(old, new):
        return new if old is None or (new is not None and new > old) else old

    def sample(self, now_value=None, *, force=False):
        if not force and now_value is not None and self.last is not None and now_value - self.last < self.interval:
            return
        self.last = now_value
        for folder in self.folders:
            events = _read_small(folder / "memory.events")
            if events is None:
                continue
            counters = parse_memory_counters(events)
            kill, oom = counters.get("oom_kill"), counters.get("oom")
            self.oom_kill, self.oom = self._keep(self.oom_kill, kill), self._keep(self.oom, oom)
            for name, value in counters.items():
                self.events[name] = self._keep(self.events.get(name), value)
            peak = _read_small(folder / "memory.peak")
            if peak is not None and peak.strip().isdigit():
                self.peak = self._keep(self.peak, int(peak.strip()))
            current = _read_small(folder / "memory.current")
            if current is not None and current.strip().isdigit():
                self.current_max = self._keep(self.current_max, int(current.strip()))
            return

    def peak_bytes(self):
        return self.peak if self.peak is not None else self.current_max




# ------------------------------------------------------------------------------------------------------------- the launch
def launch(row, *, run_id, person, parameters, credentials, input_data, emit, stdin_eof=None, slots_n=None, person_n=PERSON_SLOTS,
           status=None, canary_required=True, clock=time.monotonic, sleep=time.sleep):
    """Start one run and stream it. ``emit(frame)`` writes one frame (and raises DeadMan when the caller is gone); ``stdin_eof`` is a
    threading.Event set when the caller closed its end. Used by ``--start`` and by the root-only canary. The kill switch is the caller's
    business. Returns the end frame."""
    status = status or ready_status(canary_required)
    hosts = row_allowed_hosts(row)  # 1.18.24: a row with no allowed_hosts gets no door, no forwarder and no proxy variable
    local = None
    if hosts:
        try:  # read at every start; unreadable means no run (fail closed)
            local = local_deny_now()
        except ValueError as exc:
            raise Refusal("sandbox_unavailable", "this server's own addresses or gateway could not be read, so the egress door cannot be given them") from exc
    check_runner_ready(row)
    require_skeleton()  # 1.18.8: the allow-list root must still match this server (fail closed)
    prepare_runtime_mount(row)
    values = validate_run_parameters(row["parameters"], parameters)
    zswap = isinstance(status.get("systemd_version"), int) and status["systemd_version"] >= ZSWAP_MIN_SYSTEMD
    argv = build_argv(row, run_id, values, credential_names=sorted(credentials), zswap=zswap)
    holder = acquire_slots(person, row, slots_n=slots_n, person_n=person_n, clock=clock, sleep=sleep)
    process = None
    started_at = clock()
    progress = {}
    audited = False
    canary = row.get("owner_module") == CANARY_OWNER
    remover_stop = threading.Event()
    egress_begun = False
    try:
        RUNS_ROOT.mkdir(parents=True, exist_ok=True)
        _write_private(run_record_path(run_id), _json_bytes({"run_id": run_id, "runner": row["id"], "unit": unit_name(run_id), "at": now(),
                                                          "person": person_key(person), "canary": canary}))
        if credentials:
            write_secrets(run_id, credentials)
        try:  # 1.18.8: the root audit row comes BEFORE the unit is spawned; no row, no run
            append_audit("run.started", detail={"runner": row["id"], "run_id": run_id, "person": person_key(person), "canary": canary})
        except OSError as exc:
            raise Refusal("start_failed", "the run could not be recorded in the audit log") from exc
        audited = True
        if hosts:  # 1.18.24: the door is up before the unit exists; a door that does not start is a refusal and no run
            egress_begun = True
            egress_start(row, run_id, local)
        process = _spawn(argv)
        if credentials:  # 1.18.14: the helper removes the folder once the unit holds its copy; the finally below is the fail-closed path
            threading.Thread(target=remove_credentials_noted, daemon=True, kwargs={"stop": remover_stop, "run_id": run_id, "runner": row["id"]},
                             args=(unit_name(run_id), SECRETS_ROOT / run_id, [slot for slot, _n in credential_slots(sorted(credentials))])).start()
        return _supervise(process, row, run_id, input_data, emit, stdin_eof, started_at, clock, progress=progress, canary=canary)
    finally:
        remover_stop.set()
        if process is not None and process.poll() is None:
            stop_unit(run_id)
            try:
                process.kill()
            except OSError:
                pass
        if egress_begun:
            egress_finish(row, run_id, progress)
        remove_secrets(run_id)
        run_record_path(run_id).unlink(missing_ok=True)
        cancel_flag_path(run_id).unlink(missing_ok=True)
        handoff_path(run_id).unlink(missing_ok=True)
        if process is not None and progress.get("unit_loaded") is not False:  # 1.18.17: a failed run unit is forgotten (cancel, fault and refusal paths too)
            reset_failed_unit(run_id)
        holder.release()
        if audited:
            append_audit_safely("run.ended", run_ended_detail(row, run_id, person, canary, progress, int((clock() - started_at) * 1000)))
            recheck_skeleton_after_run(row, run_id)  # 1.18.13: a new entry in the sandbox root is named at once


def run_ended_detail(row, run_id, person, canary, progress, elapsed_ms):
    """1.18.8: the fields of the root ``run.ended`` audit row. Counts, words and ids only: never the input, an output, a parameter, a credential
    or a path. ``progress`` is what _supervise knew when the run ended (the whole end frame for a normal end, a few counters otherwise)."""
    end = progress.get("end") or {}
    return {
        "runner": row["id"], "run_id": run_id, "person": person_key(person), "canary": canary,
        "reason": end.get("reason") or progress.get("reason") or "aborted", "exit": end.get("exit"), "ms": end.get("ms", elapsed_ms),
        "bytes_out": end.get("bytes_out", progress.get("bytes_out")), "bytes_err": end.get("bytes_err", progress.get("bytes_err")),
        "peak_mb": end.get("peak_mb"), "oom_kills": end.get("oom_kills"), "evidence": end.get("evidence"),
        "egress_allowed": (progress.get("egress") or {}).get("allowed", 0), "egress_refused": (progress.get("egress") or {}).get("refused", 0),
        "egress_bytes": (progress.get("egress") or {}).get("bytes", 0),
    }


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


def _whole(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def in_memory_handoff(watch, exit_code, elapsed, run_seconds, stop_reason_set, unit=None):
    """1.18.14: what ``--finish`` used to hand over, built by the helper from its own last forced cgroup poll. ``result`` is 'oom-kill' only
    when the poll saw one or more kills and the exit code is not 0, 'timeout' only when no helper stop reason is set and the run lasted at
    least its limit plus the timer slack (systemd's RuntimeMaxSec fired), otherwise ''. A kill between the last poll and the cgroup going
    away is reported as unknown, never guessed. 1.18.17: ``unit`` is read_unit_result(); systemd's record is kept after the cgroup is gone, so
    its 'oom-kill' and its 'timeout' count too, and a helper stop reason still wins."""
    result = ""
    unit_result = unit.get("result") if isinstance(unit, dict) else None
    unit_said = None if stop_reason_set else unit_result  # a helper stop reason always wins over the unit's word
    if (_whole(watch.oom_kill) is not None and watch.oom_kill >= 1 and exit_code != 0) or unit_said == "oom-kill":
        result = "oom-kill"
    elif unit_said == "timeout" or (not stop_reason_set and unit_result is None and elapsed >= run_seconds + TIMER_SLACK_SECONDS):
        result = "timeout"
    return {"memory_peak": watch.peak_bytes(), "oom_kills": watch.oom_kill, "result": result}


def merge_memory_evidence(watch, handoff, result, unit=None):
    """1.18.8: (peak bytes, oom_kills, evidence). ``oom_kills`` is the larger of the live poll and ``handoff``; the peak the larger of the two.
    1.18.14: ``handoff`` is the helper's own in-memory copy of the last forced poll (no file, no ExecStopPost), so the two agree. ``evidence``
    names where the kill count came from: 'poll', 'finish', 'unit_result', 'service_result' (old tests) or None. Nothing is guessed."""
    kills = [value for value in (_whole(watch.oom_kill), _whole(handoff.get("oom_kills"))) if value is not None]
    peaks = [value for value in (_whole(watch.peak_bytes()), _whole(handoff.get("memory_peak"))) if value is not None]
    oom_kills = max(kills) if kills else None
    if _whole(watch.oom_kill) is not None and watch.oom_kill >= 1:
        evidence = "poll"
    elif _whole(handoff.get("oom_kills")) is not None and handoff["oom_kills"] >= 1:
        evidence = "finish"
    elif isinstance(unit, dict) and unit.get("result") == "oom-kill":
        evidence = "unit_result"
    elif result == "oom-kill":
        evidence = "service_result"
    else:
        evidence = None
    return (max(peaks) if peaks else None), oom_kills, evidence


def _supervise(process, row, run_id, input_data, emit, stdin_eof, started_at, clock, progress=None, canary=False):
    progress = progress if progress is not None else {}
    limits = row["limits"]
    watch = CgroupWatch(run_id, CgroupWatch.CANARY_INTERVAL if canary else None)  # 1.18.15: only canary runs poll fast
    wake = CgroupWatch.CANARY_INTERVAL if canary else FLUSH_SECONDS
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
                tag, chunk = sink.get(timeout=wake)
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
            watch.sample(clock())  # 1.18.8: at most every 0.2 s; a vanished cgroup is tolerated
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
        progress.update(reason="cancelled", bytes_out=sent["out"], bytes_err=sent["err"])
        raise
    try:
        code = process.wait(timeout=STOP_GRACE_SECONDS * 3)
    except subprocess.TimeoutExpired:
        stop_unit(run_id)
        process.kill()
        code = process.wait()
    watch.sample(force=True)
    unit = read_unit_result(run_id)  # 1.18.17: systemd's own record; the run unit is not collected, so it is still there
    progress["unit_loaded"] = unit is not None
    reason = state["reason"]
    if cancel_flag_path(run_id).exists():
        reason = "cancelled"
    handoff = in_memory_handoff(watch, code, clock() - started_at, int(limits["run_seconds"]), bool(state["reason"]), unit)
    result = handoff["result"]
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
    peak, oom_kills, evidence = merge_memory_evidence(watch, handoff, result, unit)
    # 1.18.22: 'exit' and 'signal' below describe the unit's main process, which is sandbox-launcher.py (it runs the runner as its child and returns
    # 128 plus the signal when the child died by one), not the sandboxed program itself. A cgroup OOM kill ends the whole unit, launcher included.
    real_exit, signal_number, exit_source = code, None, "systemd-run"
    if unit is not None and unit["code"] == "exited":  # 1.18.17: systemd's record of the unit's main process (the launcher), not systemd-run's code
        real_exit, exit_source = unit["status"], "unit"
    elif unit is not None and unit["code"] in ("killed", "dumped"):
        real_exit, signal_number, exit_source = None, unit["status"], "unit"
    end = {
        "t": "end", "exit": None if reason == "start_failed" else real_exit, "reason": reason, "ms": int((clock() - started_at) * 1000),
        "peak_mb": round(peak / 1048576, 1) if isinstance(peak, int) else None, "oom_kills": oom_kills, "evidence": evidence,
        "credential_b64": base64.b64encode(credential).decode("ascii") if credential is not None else None,
        "bytes_out": sent["out"], "bytes_err": sent["err"],
    }
    end.update(signal=signal_number, unit_result=unit["result"] if unit is not None else None, exit_source=exit_source)  # 1.18.17: additive, internal
    if watch.events:  # 1.18.16: additive and internal; Core's _end_event drops it and it is not in the run.ended audit row
        end["memory_events"] = {name: watch.events[name] for name in MEMORY_COUNTERS if name in watch.events}
    progress["end"] = end
    emit(end)
    return end


# ------------------------------------------------------------------------------------------------------- --start / --stop
def start_command(stdin=None, *, row=None, out_stream=None):
    """``--start``: read the header and the input, re-check everything, launch, stream frames, always clean up. ``row`` is for the root-only
    selftest file (``sandbox-selftest.py --canary-launch``, 1.18.26): it hands in the canary's own row, and the header must name that row's id.
    ``main`` never passes it, so the sudo-reachable ``--start`` always reads the root-owned registry; the kill-switch constant is not asked on
    the selftest path (main refuses the real ``--start`` only if the constant is forced off)."""
    stdin = stdin or sys.stdin.buffer
    emit = stdout_emitter(out_stream)
    try:
        ensure_layout()
        row_given = row  # only the root-only canary launch hands a row in; it does not need a passed canary (it makes it)
        header, size = read_header(stdin)
        if row is not None:
            if header["runner_id"] != row.get("id"):
                raise Refusal("runner_unknown")
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
               input_data=data, emit=emit, stdin_eof=eof, canary_required=row_given is None)
        return 0
    except Refusal as exc:
        if exc.code == "sandbox_not_ready":  # 1.18.27: a server whose selftest is not ready says so in its own log (other refusals already have run rows)
            append_audit_safely("start.refused", {"code": exc.code})
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


CANARY_OWNER = "core"
CANARY_STANDIN_PARENT = "/"  # 1.18.8: the one folder the canary makes directly under this folder (a test moves it); only this shape is ever removed
CANARY_STANDIN_NAME_RE = re.compile(r"^tectac-canary-[0-9a-f]{12}$")








































def _standin_ok(folder):
    """Only a folder named exactly ``tectac-canary-<12 hex>`` directly under CANARY_STANDIN_PARENT (``/``) that is not a link."""
    if not isinstance(folder, str):
        return False
    parent = CANARY_STANDIN_PARENT if CANARY_STANDIN_PARENT == "/" else CANARY_STANDIN_PARENT.rstrip("/\\")
    return (os.path.dirname(folder) == parent and bool(CANARY_STANDIN_NAME_RE.fullmatch(os.path.basename(folder)))
            and not os.path.islink(folder))


def remove_markers():
    """Remove what _plant_markers made: the marker files by their name, then the stand-in folder, which must be named exactly
    ``/tectac-canary-<12 hex>`` directly under /, is not a link and is empty by now (os.rmdir, never a recursive delete)."""
    try:
        record = json.loads(CANARY_MARKERS_FILE.read_text(encoding="utf-8"))
        paths, folders = record.get("paths", []), record.get("folders", [])
    except (OSError, ValueError, AttributeError):
        paths, folders = [], []
    for path in paths if isinstance(paths, list) else []:
        if isinstance(path, str) and os.path.basename(path).startswith(".tectac-canary-"):
            try:
                os.unlink(path)
            except OSError:
                pass
    for folder in folders if isinstance(folders, list) else []:
        if _standin_ok(folder):
            try:
                os.rmdir(folder)
            except OSError:
                pass
    CANARY_MARKERS_FILE.unlink(missing_ok=True)


















































































# ------------------------------------------------------------------------------------------------------ status and sweep
def show_status():
    status = read_status()
    total = slot_count(mem_available_kib(), LIMITS["memory_mb"][0])
    status["slots_total"] = total
    status["slots_used"] = slots_in_use(total)
    status["canary_ok"], status["canary_at"] = canary_record_state(status)
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


RUN_RECORD_RE = re.compile(r"^[0-9a-f]{32}\.json$")
PERSON_KEY_RE = re.compile(r"^[0-9a-f]{32}$")


AUDIT_TAIL_BYTES = 1048576


def run_already_ended(run_id):
    """1.18.16: True when the last 1 MiB of audit.jsonl holds a ``run.ended`` row for ``run_id`` (a record that still exists belongs to a
    recent run, so the tail is enough). Only lines containing ``"run.ended"`` are parsed; a corrupt line is ignored. An unreadable audit file
    claims nothing (False), so the caller still writes its one row."""
    try:
        with open(AUDIT_FILE, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - AUDIT_TAIL_BYTES))
            data = handle.read(AUDIT_TAIL_BYTES)
    except OSError:
        return False
    for line in data.decode("utf-8", "replace").splitlines():
        if '"run.ended"' not in line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        detail = row.get("detail") if isinstance(row, dict) else None
        if isinstance(row, dict) and row.get("event") == "run.ended" and isinstance(detail, dict) and detail.get("run_id") == run_id:
            return True
    return False


def note_swept_run(entry):
    """1.18.15: a run record the sweep removes belongs to a run that never reached its own ``run.ended`` (a killed helper cannot write it).
    Write that row now with reason ``swept``. Only ``runs/<32 hex>.json`` files that are plain files; never a live unit (the caller skips
    those), never secrets or handoff entries. Keys stay inside the run.ended allow-list: runner, run_id, person, canary, reason. A record
    from before 1.18.15 has no person or canary: the row then holds person None and canary False. No credential, input, output or path."""
    try:
        if not RUN_RECORD_RE.match(entry.name) or entry.is_symlink() or not entry.is_file():
            return False
        record = json.loads(_read_small(entry) or "")  # the runs folder is root 0700; a record is a few hundred bytes
    except (OSError, ValueError):
        record = None
    run_id = entry.name.split(".")[0]
    if not isinstance(record, dict):
        record = {}
    if run_already_ended(run_id) or not entry.exists():  # 1.18.16: the run wrote its own row (or just removed its record); a second row would contradict it
        return True
    runner, person = record.get("runner"), record.get("person")
    append_audit_safely("run.ended", {
        "runner": runner if isinstance(runner, str) and RUNNER_ID_RE.match(runner) else None, "run_id": run_id,
        "person": person if isinstance(person, str) and PERSON_KEY_RE.match(person) else None, "canary": record.get("canary") is True,
        "reason": "swept"})
    return True


FAILED_UNIT_RE = re.compile(r"^tectac-[a-z0-9-]+\.service$")
SBX_UNIT_RE = re.compile(r"^tectac-sbx-([0-9a-f]{32})\.service$")


def reset_failed_units(min_age=STALE_SECONDS):
    """1.18.17: run units are not collected, so a failed one stays in systemd until it is reset. List the failed ``tectac-*`` units and reset
    the ones that are safe: the name must match ``^tectac-[a-z0-9-]+\\.service$`` exactly (nothing else ever reaches systemctl), a run unit
    whose run record or handoff is younger than ``min_age`` is left (its helper may still be about to read its Result), an active unit is
    left. Returns the names that were reset. A failed call never aborts the sweep."""
    code, out, _err = systemctl("list-units", "--state=failed", "--plain", "--no-legend", "--no-pager", "tectac-*")
    if code != 0 or not isinstance(out, str):
        return []
    reset = []
    for line in out.splitlines():
        fields = line.split()
        name = fields[0] if fields else ""
        if not FAILED_UNIT_RE.match(name):
            continue
        sbx = SBX_UNIT_RE.match(name)
        if sbx:
            run_id = sbx.group(1)
            if any(path.exists() and not _stale(path, min_age) for path in (run_record_path(run_id), handoff_path(run_id))):
                continue
            if _unit_active(run_id):
                continue
        elif systemctl("is-active", name)[0] == 0:
            continue
        systemctl("reset-failed", name)
        reset.append(name)
    return reset


def reverify_runners(owner=None):
    """Judge every registry row this helper wrote against its recorded listing hash and rewrite a row only when its state changed.

    ``owner`` (a module id) limits the pass to that module's rows; other rows are not even read for change. Returns (checked, changed ids).
    Shared by ``--sweep`` (no owner) and ``--verify-module`` so both apply the same rule and widen no trust."""
    checked, changed = 0, []
    if REGISTRY_ROOT.is_dir():
        for path in sorted(REGISTRY_ROOT.glob("*.json")):
            payload = _load_registry_file(path)
            if not payload or payload.get("registered_by") != REGISTERED_BY:
                continue
            if owner is not None and payload.get("owner_module") != owner:
                continue
            checked += 1
            reasons = _sweep_reasons(payload)
            verified, reason = not reasons, "; ".join(reasons)
            if payload.get("runtime_verified") != verified or payload.get("runtime_reason") != reason:
                payload.update({"runtime_verified": verified, "runtime_reason": reason, "runtime_checked_at": now()})
                _write_root_file(path, _json_bytes(payload), 0o644)
                changed.append(str(payload.get("id")))
    return checked, changed


def verify_module(module_id):
    """``--verify-module <module-id>`` (root only, not in sudoers): re-verify one module's runners after its runtime action.

    The same check as the sweep against the recorded listing hash, for that module's rows only. A module with no registered runners is a quiet no-op."""
    module_id = _module_id(module_id)
    _require_layout()
    checked, changed = reverify_runners(module_id)
    append_audit("module.runners_verified", detail={"module": module_id, "runners_checked": checked, "runtime_state_changed": changed})
    print(json.dumps({"module": module_id, "checked": checked, "changed": changed}, sort_keys=True))


def sweep(min_age=STALE_SECONDS):
    """``--sweep`` (boot and daily): re-verify the runtime folders of every registered runner; remove stray selftest folders; remove
    secrets folders, handoff files and run records whose unit ``tectac-sbx-<id>`` is not active; remove old canary markers."""
    _require_layout()
    checked, changed = reverify_runners()
    removed = []
    if RUN_ROOT.is_dir():
        for entry in sorted(RUN_ROOT.iterdir()):
            if entry.name.startswith(SELFTEST_PREFIX) and entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
                removed.append(entry.name)
    egress_folders = (EGRESS_DOOR_ROOT, EGRESS_CONFIG_ROOT, EGRESS_STATE_ROOT)
    for folder in (SECRETS_ROOT, HANDOFF_ROOT, RUNS_ROOT, *egress_folders):
        # the proxy's RuntimeDirectory is a symlink into /run/private (systemd makes it for a DynamicUser): its entries are still swept
        if not folder.is_dir() or (folder.is_symlink() and folder != EGRESS_STATE_ROOT):
            continue
        for entry in sorted(folder.iterdir()):
            run_id = entry.name.split(".")[0]
            if _plain_id(run_id, RUN_ID_RE) and (_unit_active(run_id) or not _stale(entry, min_age)):
                continue  # a live run (or one that is still starting) keeps its files
            if folder == RUNS_ROOT:
                note_swept_run(entry)
            if folder in egress_folders and _plain_id(run_id, RUN_ID_RE):
                egress_stop(run_id)  # a stale instance: its units are stopped before its files go
            if folder == EGRESS_STATE_ROOT and _plain_id(entry.name, RUN_ID_RE):
                egress_remove_state(entry.name)  # 1.18.25: a stale link and its /run/private target both go
            elif entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
            removed.append(f"{folder.name}/{entry.name}")
    remove_markers()
    try:
        units_reset = reset_failed_units(min_age)
    except (OSError, ValueError):
        units_reset = []
    append_audit("sweep", detail={"runners_checked": checked, "runtime_state_changed": changed, "removed": removed, "units_reset": units_reset})
    print(json.dumps({"checked": checked, "changed": changed, "removed": removed, "units_reset": units_reset}, sort_keys=True))


def refuse_disabled():
    """``--start`` and ``--stop`` only if the kill-switch constant is forced to False: read nothing from stdin, start nothing, answer with the final refusal frame."""
    sys.stdout.write(json.dumps({"t": "refused", "code": "sandbox_disabled"}, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 3


def usage():
    raise SystemExit("usage: tec-tac-sandbox --start|--stop|--status | --sweep | --register-module|--unregister-module|--verify-module <module-id>")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--start"], ["--stop"]) and not SANDBOX_ENABLED:
        return refuse_disabled()  # before anything else, and before stdin is read: the kill switch is a constant in this file
    if len(argv) not in (1, 2):
        usage()
    mode = argv[0]
    if mode not in ("--start", "--stop", "--status", "--sweep", "--register-module", "--unregister-module", "--verify-module"):
        usage()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if mode == "--start" and len(argv) == 1:
        return start_command()
    if mode == "--stop" and len(argv) == 1:
        return stop_command()
    if mode == "--status" and len(argv) == 1:
        return show_status()
    if mode == "--sweep" and len(argv) == 1:
        sweep()
        return 0
    if mode == "--register-module" and len(argv) == 2:
        register_module(argv[1])
        return 0
    if mode == "--unregister-module" and len(argv) == 2:
        unregister_module(argv[1])
        return 0
    if mode == "--verify-module" and len(argv) == 2:
        verify_module(argv[1])
        return 0
    usage()


if __name__ == "__main__":
    sys.exit(main())
