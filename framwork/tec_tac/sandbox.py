"""Core sandbox: ``core.sandbox`` 1.0.0 (Core 1.17.116, Patch 1: the foundation; nothing can run yet).

core.sandbox will run a signed module's declared program as an unprivileged, resource-limited process that cannot see the server's files
or reach the server itself or private networks (AD-63, docs/sandbox-capability.md). This first release carries the part that has to exist
before anything may run:

* ``status()``: whether this server can host the sandbox (read from the root-owned status.json that the root helper's selftest writes) and
  which runners are registered. Read only. No secret.
* ``describe(runner_id)``: the declared limits, SHA-256, version and runtime state of one runner, for the owning module only.
* ``start()``, ``run()`` and ``cancel()`` exist from 1.0.0 so a module can code against the final shape. They raise ``SandboxError`` with
  ``sandbox_disabled`` before they read anything.

``SANDBOX_ENABLED`` is False here and in scripts/sandbox-helper.py. The root helper decides, not this file; it is switched on by a later
Core release after the full canary passes on a real server. There is no Django audit row, no permission and no HTTP route in this release.
The helper keeps its own append-only log of registrations and selftests.

Nothing in this file writes. It never returns a credential, a path outside the registry or an environment value.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat as stat_module
from pathlib import Path
from typing import Any

from .caller_identity import calling_module_for_core_provider

logger = logging.getLogger("tec_tac.sandbox")

# The kill switch of the Django side. Not a setting. The root helper has its own constant and is the one that counts.
SANDBOX_ENABLED = False

CAPABILITY_ID = "core.sandbox"
CAPABILITY_VERSION = "1.0.0"
OPERATIONS = ("status", "describe", "start", "run", "cancel")

# Fixed locations, the same as the root helper's (scripts/sandbox-helper.py). Not configurable.
LIB_ROOT = Path("/usr/local/lib/tec-tac/sandbox")
REGISTRY_ROOT = LIB_ROOT / "registry"
STATUS_FILE = Path("/var/lib/tec-tac/sandbox/status.json")
MAX_STATUS_BYTES = 64 * 1024
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_RUNNERS_LISTED = 200
ROOT_UID = 0

_RUNNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MODULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")

ERROR_CODES = (
    "sandbox_disabled", "sandbox_unavailable", "runner_unknown", "runner_disabled", "runtime_unverified", "not_owner", "invalid_input",
    "input_too_large", "credential_invalid", "busy", "person_busy", "start_failed", "timeout", "output_limit", "oom", "cancelled",
)

# The default and the Core ceiling of every limit a runner may declare (plan 2.1). The same numbers as registry.SANDBOX_LIMITS.
LIMITS = {
    "memory_mb": {"default": 1024, "ceiling": 2048}, "cpu_percent": {"default": 100, "ceiling": 200}, "tasks": {"default": 256, "ceiling": 512},
    "run_seconds": {"default": 240, "ceiling": 600}, "stdout_kib": {"default": 512, "ceiling": 1024}, "stderr_kib": {"default": 64, "ceiling": 64},
    "scratch_mb": {"default": 64, "ceiling": 256}, "input_kib": {"default": 64, "ceiling": 256}, "queue_seconds": {"default": 10, "ceiling": 30},
}


class SandboxError(Exception):
    """A refusal or failure of core.sandbox. ``code`` is one of ``ERROR_CODES``; ``message`` is plain English; ``retry_after`` (seconds) is
    set only for ``busy`` and ``person_busy``."""

    def __init__(self, code: str, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class _Unreadable(Exception):
    """A file that is missing, not trusted, too big or not JSON. ``reason`` is the status() reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _read_json_trusted(path: Path, *, max_bytes: int) -> dict:
    """One small JSON object, read with no symlink following. The file must be a regular file, root-owned and not writable by a group or
    anyone else (checked on the open descriptor, so a swap after the check changes nothing), and at most ``max_bytes`` long."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        if stat_module.S_ISLNK(os.lstat(path).st_mode):
            raise _Unreadable("status_unreadable")
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise _Unreadable("selftest_not_run") from exc
    except OSError as exc:
        raise _Unreadable("status_unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat_module.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022 or info.st_size > max_bytes:
            raise _Unreadable("status_unreadable")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise _Unreadable("status_unreadable")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _Unreadable("status_unreadable") from exc
    if not isinstance(payload, dict):
        raise _Unreadable("status_unreadable")
    return payload


def _text(value: Any, limit: int = 300) -> str:
    text = value if isinstance(value, str) else ""
    return "".join(ch for ch in text if ord(ch) >= 32 and ord(ch) != 127)[:limit]


def _registry_row(path: Path) -> dict | None:
    """One registry row the root helper wrote for a signed module's manifest, or None when it is not trusted or not in the expected shape."""
    try:
        row = _read_json_trusted(path, max_bytes=MAX_REGISTRY_BYTES)
    except _Unreadable:
        return None
    runner_id, owner = row.get("id"), row.get("owner_module")
    if (not isinstance(runner_id, str) or not _RUNNER_ID_RE.fullmatch(runner_id) or runner_id != path.stem
            or not isinstance(owner, str) or not _MODULE_ID_RE.fullmatch(owner) or row.get("registered_by") != "module-manifest"
            or not runner_id.startswith(owner + ".")):
        return None
    return row


def _registry_rows() -> list[dict]:
    rows: list[dict] = []
    try:
        if stat_module.S_ISLNK(os.lstat(REGISTRY_ROOT).st_mode):
            return rows
        names = sorted(name for name in os.listdir(REGISTRY_ROOT) if name.endswith(".json"))
    except OSError:
        return rows
    for name in names[:MAX_RUNNERS_LISTED]:
        row = _registry_row(REGISTRY_ROOT / name)
        if row is not None:
            rows.append(row)
    return rows


def status() -> dict:
    """What this server can do and which runners are registered. Read only, no secret.

    ``{enabled, ready, reason, systemd_version, address_filter_ok, dns_ok, selftest_at, runners: [{id, owner, version, runtime_verified}]}``.
    ``enabled`` is False in this release. ``ready`` is True only when the root selftest proved every wall works on this server; otherwise
    ``reason`` says why in plain words. A status file that is missing, not root-owned, writable by others, a link, too big or not JSON gives
    ``ready: false`` (``selftest_not_run`` when it is missing, ``status_unreadable`` otherwise). Never raises."""
    answer: dict[str, Any] = {
        "enabled": bool(SANDBOX_ENABLED), "ready": False, "reason": "status_unreadable", "systemd_version": None,
        "address_filter_ok": False, "dns_ok": False, "selftest_at": None, "runners": [],
    }
    try:
        raw = _read_json_trusted(STATUS_FILE, max_bytes=MAX_STATUS_BYTES)
    except _Unreadable as exc:
        answer["reason"] = exc.reason
    except Exception:  # never raises: a fault is an unready answer
        logger.warning("core.sandbox status could not be read.", exc_info=True)
    else:
        version = raw.get("systemd_version")
        answer.update({
            "ready": raw.get("ready") is True,
            "reason": _text(raw.get("reason")) or ("ready" if raw.get("ready") is True else "unknown"),
            "systemd_version": version if isinstance(version, int) and not isinstance(version, bool) else None,
            "address_filter_ok": raw.get("address_filter_ok") is True,
            "dns_ok": raw.get("dns_ok") is True,
            "selftest_at": _text(raw.get("selftest_at"), 40) or None,
        })
    try:
        answer["runners"] = [
            {"id": row["id"], "owner": row["owner_module"], "version": _text(row.get("version"), 64), "runtime_verified": row.get("runtime_verified") is True}
            for row in _registry_rows()
        ]
    except Exception:
        logger.warning("core.sandbox registry could not be listed.", exc_info=True)
    return answer


def describe(runner_id: Any) -> dict:
    """The declared limits, SHA-256, version and runtime state of one runner. Only the module that owns the runner may ask.

    The owner is the module whose code makes the call, found by Core from the call stack (AD-26); nothing is passed in. Core, a library, a
    generated frame, a disabled or legacy module and a module that does not own the runner all get ``not_owner`` (a module cannot tell
    another module's runner from a missing one). An id that is not a runner of the caller's own prefix is ``not_owner``; an unknown id with
    the caller's own prefix is ``runner_unknown``."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None:
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may describe it.")
    if not isinstance(runner_id, str) or not _RUNNER_ID_RE.fullmatch(runner_id):
        raise SandboxError("invalid_input", "The runner id must be letters, digits, '.', '_' or '-' (1 to 128 characters).")
    if not runner_id.startswith(identity.module_id + "."):
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may describe it.")
    row = _registry_row(REGISTRY_ROOT / f"{runner_id}.json")
    if row is None:
        raise SandboxError("runner_unknown", "That sandbox runner is not registered.")
    if row["owner_module"] != identity.module_id:
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may describe it.")
    limits = row.get("limits") if isinstance(row.get("limits"), dict) else {}
    return {
        "id": row["id"], "owner": row["owner_module"], "version": _text(row.get("version"), 64), "revision": _text(row.get("revision"), 64),
        "description": _text(row.get("description"), 200),
        "limits": {name: limits.get(name) for name in LIMITS if isinstance(limits.get(name), int) and not isinstance(limits.get(name), bool)},
        "executable_sha256": _text(row.get("executable_sha256"), 64),
        "credential_files": [name for name in (row.get("credential_files") or []) if isinstance(name, str)][:2],
        "credential_return": row.get("credential_return") is True,
        "runtime_verified": row.get("runtime_verified") is True, "runtime_reason": _text(row.get("runtime_reason"), 2000),
    }


def _refuse() -> None:
    """Every launch call ends here first, before it reads a file, a runner or an argument."""
    if not SANDBOX_ENABLED:
        raise SandboxError("sandbox_disabled", "The sandbox is switched off in this Core release. Nothing can run in it yet.")
    raise SandboxError("sandbox_unavailable", "The sandbox launch path is not part of this Core release.")


def start(runner_id: Any = None, *, input: Any = None, parameters: Any = None, credentials: Any = None, requested_by: Any = None, user: Any = None):
    """Start a run. The final signature is in place so a module can code against it; in this release it raises ``sandbox_disabled``
    before it reads anything."""
    _refuse()


def run(runner_id: Any = None, *, input: Any = None, parameters: Any = None, credentials: Any = None, requested_by: Any = None, user: Any = None):
    """Start a run and wait for it. In this release it raises ``sandbox_disabled`` before it reads anything."""
    _refuse()


def cancel(run_id: Any = None):
    """Cancel a run. In this release it raises ``sandbox_disabled`` before it reads anything."""
    _refuse()


class _CoreSandboxProvider:
    status = staticmethod(status)
    describe = staticmethod(describe)
    start = staticmethod(start)
    run = staticmethod(run)
    cancel = staticmethod(cancel)


_PROVIDER = _CoreSandboxProvider()


def sandbox_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.sandbox",
        "operations": list(OPERATIONS),
        "enabled": False,
        "limits": {name: dict(value) for name, value in LIMITS.items()},
        "errors": list(ERROR_CODES),
        "caller": (
            "verified (AD-26): describe() is for the module that owns the runner, found by Core from the call stack; nothing is passed in. "
            "Core, a library, a generated frame, a disabled or legacy module and any other module get not_owner."
        ),
        "network": (
            "the smaller sandbox (plan section 15): a run cannot reach loopback, link-local, multicast or private ranges; public HTTPS stays open. "
            "There is no host list."
        ),
        "manifest": "sandbox_runners (at most 4 entries) with publisher_permissions sandbox.register and requires.framework >=1.17.116.",
        "audit": "the root helper keeps its own append-only log (registered, removed, selftest, sweep; never a credential). Core writes no audit row in 1.17.116.",
        "requires_framework": ">=1.17.116",
        "notes": "1.17.116: status and describe are real; start, run and cancel exist and raise sandbox_disabled. The launch path arrives in a later release as additive keys and results.",
    }


def register_core_sandbox_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Runs a signed module's declared program as an unprivileged, resource-limited process. Off in 1.17.116: status and describe only.",
        operations=OPERATIONS,
        metadata=sandbox_contract_metadata(),
    )
