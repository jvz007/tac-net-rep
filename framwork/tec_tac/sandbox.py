"""Core sandbox: ``core.sandbox`` 1.0.0 (Core 1.17.118, Patch 2: the launch path; the kill switch is still off).

core.sandbox runs a signed module's declared program as an unprivileged, resource-limited process that cannot see the server's files
or reach the server itself or private networks (AD-63, docs/sandbox-capability.md).

* ``status(live=False)``: whether this server can host the sandbox (read from the root-owned status.json that the root helper's selftest
  writes), which runners are registered, the slot numbers and the last canary result. Read only. No secret.
* ``describe(runner_id)``: the declared limits, SHA-256, version and runtime state of one runner, for the owning module only.
* ``start()`` returns a ``RunHandle`` (events, wait, cancel, close); ``run()`` is the blocking form; ``cancel(run_id)`` stops a run. Since
  1.17.118 these are built. Each is the owning module's call (AD-26) and each checks ``SANDBOX_ENABLED`` first.

``SANDBOX_ENABLED`` is False here and in scripts/sandbox-helper.py. The root helper decides, not this file; it is switched on by a later
Core release after the full canary passes on a real server, so today start, run and cancel raise ``sandbox_disabled`` before they read a
file, a runner or an argument. With the switch on, a run is recorded in Core's audit log (module core, object type sandbox_run; one strict
row BEFORE the launch, then ended, refused and cancelled rows). Credentials travel to the helper on its stdin only.

Only the audit rows and the helper process are written or started here. It never returns a credential, a path outside the registry or an
environment value.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import queue
import re
import secrets
import stat as stat_module
import subprocess
import threading
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
CANARY_FILE = Path("/var/lib/tec-tac/sandbox/canary.json")
HELPER_ARGV = ("sudo", "-n", "/usr/local/sbin/tec-tac-sandbox")
MAX_STATUS_BYTES = 64 * 1024
LIVE_STATUS_TIMEOUT = 3  # seconds for the one ``sudo --status`` call of status(live=True)
CREDENTIAL_MAX_BYTES = 16 * 1024
PERSON_MAX = 128
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_RUNNERS_LISTED = 200
ROOT_UID = 0

_RUNNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MODULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_CREDENTIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

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


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def status(live: bool = False) -> dict:
    """What this server can do and which runners are registered. Read only, no secret.

    ``{enabled, ready, reason, systemd_version, address_filter_ok, dns_ok, selftest_at, slots_total, slots_used, canary_ok, canary_at,
    runners: [{id, owner, version, runtime_verified}]}``. ``enabled`` is False until the kill switch is switched on. ``ready`` is True only when
    the root selftest proved every wall works on this server; otherwise ``reason`` says why in plain words. A status file that is missing,
    not root-owned, writable by others, a link, too big or not JSON gives ``ready: false`` (``selftest_not_run`` when it is missing,
    ``status_unreadable`` otherwise). ``slots_total`` is the selftest's number (None when unknown); ``slots_used`` is None unless ``live`` is
    True, which makes one ``sudo --status`` call (3 s at most; its slot numbers then replace the selftest's). ``canary_ok`` is True only when the
    last full canary passed and ``canary_at`` says when (None when it never ran). The four slot and canary keys are additive since 1.17.118.
    Never raises."""
    answer: dict[str, Any] = {
        "enabled": bool(SANDBOX_ENABLED), "ready": False, "reason": "status_unreadable", "systemd_version": None,
        "address_filter_ok": False, "dns_ok": False, "selftest_at": None, "slots_total": None, "slots_used": None,
        "canary_ok": False, "canary_at": None, "runners": [],
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
            "slots_total": _int_or_none(raw.get("slots_total")),
        })
    try:
        canary = _read_json_trusted(CANARY_FILE, max_bytes=MAX_STATUS_BYTES)
        answer["canary_ok"] = canary.get("ok") is True
        answer["canary_at"] = _text(canary.get("at"), 40) or None
    except _Unreadable:
        pass
    except Exception:
        logger.warning("core.sandbox canary result could not be read.", exc_info=True)
    if live:
        helper = _live_status()
        if _int_or_none(helper.get("slots_total")) is not None:
            answer["slots_total"] = helper["slots_total"]
        answer["slots_used"] = _int_or_none(helper.get("slots_used"))
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


def _check_enabled() -> None:
    """Every launch call ends here first, before it reads a file, a runner or an argument."""
    if not SANDBOX_ENABLED:
        raise SandboxError("sandbox_disabled", "The sandbox is switched off in this Core release. Nothing can run in it yet.")


# ------------------------------------------------------------------------------------------------------------------ audit rows
def _safe_slug(value: Any, limit: int = 100) -> str:
    return re.sub(r"[^A-Za-z0-9_.:@-]", "-", str(value or ""))[:limit] or "unknown"


def _actor(user: Any, requested_by: Any, owner: str | None):
    from . import audit

    if getattr(user, "is_authenticated", False):
        return user
    return audit.service_audit_actor(module_id="core", service="sandbox", identity=f"{owner or 'core'}.{_safe_slug(requested_by)}"[:200])


def _audit(event: str, action: str, run_id: str, message: str, metadata: dict, *, user: Any = None, requested_by: Any = None,
           owner: str | None = None, strict: bool = False) -> bool:
    """One Core audit row: module core, object type sandbox_run. Never the credential, the input or the output (callers pass only
    names, sizes, codes and times). A strict row that cannot be written raises; a normal one returns False."""
    try:
        from . import audit

        audit.record(
            actor=_actor(user, requested_by, owner), module_id="core", action=action, object_type="sandbox_run", object_id=run_id,
            message=message, metadata={"event": event, **metadata}, strict=strict,
        )
        return True
    except Exception:
        if strict:
            raise
        logger.warning("core.sandbox could not write the audit row %s.", event, exc_info=True)
        return False


# ------------------------------------------------------------------------------------------------------------------ the helper
def _env() -> dict:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def _popen(argv, **kwargs):
    return subprocess.Popen(argv, **kwargs)


def _live_status() -> dict:
    """One ``sudo --status`` call (3 s at most): slot numbers. {} when it cannot be had."""
    try:
        done = subprocess.run([*HELPER_ARGV, "--status"], capture_output=True, text=True, timeout=LIVE_STATUS_TIMEOUT, env=_env(),
                              stdin=subprocess.DEVNULL, check=False)
        data = json.loads(done.stdout)
        inner = data.get("status") if isinstance(data, dict) else None
        return inner if done.returncode == 0 and isinstance(inner, dict) else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


_CODE_FOR_REASON = {"timeout": "timeout", "output_limit": "output_limit", "oom": "oom", "cancelled": "cancelled", "start_failed": "start_failed"}
_FRAME_MESSAGES = {
    "sandbox_unavailable": "This server cannot host a sandbox run right now.",
    "runtime_unverified": "The runner's runtime is not verified. The module has to build it again.",
    "runner_unknown": "That sandbox runner is not registered.", "invalid_input": "The helper refused the request as invalid.",
    "input_too_large": "The input is larger than the runner allows.", "credential_invalid": "A credential is not allowed for this runner.",
    "busy": "All sandbox slots are in use. Try again shortly.", "person_busy": "This person already has the most sandbox runs allowed at once.",
    "start_failed": "The sandbox run could not be started.", "sandbox_disabled": "The sandbox is switched off.",
}


def _error_from_frame(frame: dict) -> SandboxError:
    code = frame.get("code") if frame.get("code") in ERROR_CODES else "start_failed"
    retry = frame.get("retry_after")
    return SandboxError(code, _FRAME_MESSAGES.get(code, "The sandbox run could not be started."),
                        retry_after=retry if code in ("busy", "person_busy") and isinstance(retry, int) and not isinstance(retry, bool) else None)


class RunHandle:
    """A started run. ``run_id``; ``events(timeout=None)`` yields {'t': 'started'|'out'|'err'|'end', ...} (out and err carry ``data`` bytes and
    ``truncated``; end carries exit_code, reason, duration_ms, peak_mb, credentials_out, bytes_out, bytes_err); ``wait()`` returns the result;
    ``cancel()`` stops the run; ``close()`` closes the helper's pipes, which is the dead-man switch that stops the unit. Not thread-safe for
    two readers. Always call ``wait()`` or ``close()``."""

    def __init__(self, process, run_id: str, *, owner: str, runner_id: str, credential_name: str | None, user: Any, requested_by: Any, first: dict):
        self._process = process
        self.run_id = run_id
        self._owner, self._runner_id, self._credential_name = owner, runner_id, credential_name
        self._user, self._requested_by = user, requested_by
        self._queue: queue.Queue = queue.Queue()
        self._pending = [first]
        self._ended: dict | None = None
        self._closed = False
        self._lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        try:
            for raw in self._process.stdout:
                self._queue.put(raw)
        except (OSError, ValueError):
            pass
        self._queue.put(None)

    def _decode(self, raw: bytes) -> dict | None:
        try:
            frame = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return frame if isinstance(frame, dict) and isinstance(frame.get("t"), str) else None

    def _event(self, frame: dict) -> dict | None:
        kind = frame["t"]
        if kind == "started":
            return {"t": "started", "run_id": self.run_id}
        if kind in ("out", "err"):
            try:
                data = base64.b64decode(str(frame.get("b") or ""), validate=True)
            except ValueError:
                return None
            return {"t": kind, "data": data, "truncated": frame.get("truncated") is True}
        if kind == "end":
            return self._end_event(frame)
        return None

    def _end_event(self, frame: dict) -> dict:
        back = None
        if isinstance(frame.get("credential_b64"), str) and self._credential_name:
            try:
                back = {self._credential_name: base64.b64decode(frame["credential_b64"], validate=True).decode("utf-8")}
            except (ValueError, UnicodeDecodeError):
                back = None
        reason = frame.get("reason") if frame.get("reason") in ("exited", "timeout", "output_limit", "oom", "cancelled", "start_failed") else "start_failed"
        exit_code = frame.get("exit")
        return {
            "t": "end", "exit_code": exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None, "reason": reason,
            "duration_ms": frame.get("ms") if isinstance(frame.get("ms"), int) else None,
            "peak_mb": frame.get("peak_mb") if isinstance(frame.get("peak_mb"), (int, float)) and not isinstance(frame.get("peak_mb"), bool) else None,
            "credentials_out": back, "bytes_out": frame.get("bytes_out") if isinstance(frame.get("bytes_out"), int) else 0,
            "bytes_err": frame.get("bytes_err") if isinstance(frame.get("bytes_err"), int) else 0,
        }

    def events(self, timeout: float | None = None):
        """Yield events until the end event. ``timeout`` is the longest wait for the next frame; it raises TimeoutError (the run goes on)."""
        while self._ended is None:
            if self._pending:
                raw = self._pending.pop(0)
            else:
                try:
                    raw = self._queue.get(timeout=timeout)
                except queue.Empty as exc:
                    raise TimeoutError("No output from the sandbox run within the wait time. The run is still going.") from exc
            if raw is None or isinstance(raw, dict):
                frame = raw if isinstance(raw, dict) else None
            else:
                frame = self._decode(raw)
            if frame is None and raw is None:
                self._finish({"t": "end", "reason": "start_failed", "exit": None})
                yield self._ended
                return
            if frame is None:
                continue
            if frame["t"] == "refused":
                self._finish({"t": "end", "reason": "start_failed", "exit": None})
                raise _error_from_frame(frame)
            event = self._event(frame)
            if event is None:
                continue
            if event["t"] == "end":
                self._finish(frame, event)
                yield self._ended
                return
            yield event

    def _finish(self, frame: dict, event: dict | None = None) -> None:
        with self._lock:
            if self._ended is not None:
                return
            self._ended = event or self._end_event(frame)
        ended = self._ended
        _audit("sandbox.run.ended", "custom:sandbox-run-ended", self.run_id, f"Sandbox run {self.run_id} ended ({ended['reason']}).",
               {"run_id": self.run_id, "runner": self._runner_id, "owner_module": self._owner, "exit_code": ended["exit_code"], "reason": ended["reason"],
                "duration_ms": ended["duration_ms"], "bytes_out": ended["bytes_out"], "bytes_err": ended["bytes_err"], "peak_mb": ended["peak_mb"]},
               user=self._user, requested_by=self._requested_by, owner=self._owner)
        _RUNS.pop(self.run_id, None)
        self._shutdown()

    def _shutdown(self) -> None:
        for stream in (self._process.stdin, self._process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            self._process.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self._process.kill()
            except OSError:
                pass

    def wait(self, *, raise_on_failure: bool = False) -> dict:
        """Read to the end and return {run_id, exit_code, stdout, stderr, reason, duration_ms, peak_mb, credentials_out, stdout_truncated,
        stderr_truncated}. ``reason`` is exited, timeout, output_limit, oom, cancelled or start_failed. The partial output is kept for every
        reason. With ``raise_on_failure`` a reason other than exited raises SandboxError with that code instead."""
        out, err, truncated = bytearray(), bytearray(), {"out": False, "err": False}
        end = None
        for event in self.events():
            if event["t"] in ("out", "err"):
                (out if event["t"] == "out" else err).extend(event["data"])
                truncated[event["t"]] = truncated[event["t"]] or event["truncated"]
            elif event["t"] == "end":
                end = event
        end = end or self._ended or {}
        result = {
            "run_id": self.run_id, "exit_code": end.get("exit_code"), "stdout": bytes(out).decode("utf-8", "replace"),
            "stderr": bytes(err).decode("utf-8", "replace"), "reason": end.get("reason"), "duration_ms": end.get("duration_ms"),
            "peak_mb": end.get("peak_mb"), "credentials_out": end.get("credentials_out"), "stdout_truncated": truncated["out"],
            "stderr_truncated": truncated["err"],
        }
        if raise_on_failure and result["reason"] != "exited":
            raise SandboxError(_CODE_FOR_REASON.get(result["reason"], "start_failed"), f"The sandbox run ended: {result['reason']}.")
        return result

    def cancel(self) -> None:
        """Ask the helper to stop this run. The end event follows (reason cancelled)."""
        _helper_stop(self.run_id)

    def close(self) -> None:
        """Close the pipes to the helper. That stops the unit (dead-man switch). Safe to call twice."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self._ended is None:
            self._finish({"t": "end", "reason": "cancelled", "exit": None})
        else:
            self._shutdown()


_RUNS: dict[str, dict] = {}  # runs started by this process: run id -> {owner, handle}


def _helper_stop(run_id: str) -> None:
    try:
        done = subprocess.run([*HELPER_ARGV, "--stop"], input=(run_id + "\n").encode("ascii"), capture_output=True, timeout=15, env=_env(), check=False)
        frame = json.loads(done.stdout.decode("utf-8").strip().splitlines()[-1])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
        raise SandboxError("start_failed", "The sandbox helper could not be asked to stop the run.") from exc
    if frame.get("t") == "stopped":
        return
    if frame.get("code") == "sandbox_disabled":
        raise SandboxError("sandbox_disabled", _FRAME_MESSAGES["sandbox_disabled"])
    raise SandboxError("runner_unknown", "That sandbox run is not running.")


# ------------------------------------------------------------------------------------------------------------------ start and run
def _person(user: Any, requested_by: Any) -> str:
    if getattr(user, "is_authenticated", False):
        key = getattr(user, "pk", None)
        if key is None:
            key = getattr(user, "id", None)
        if key is not None:
            return f"user:{key}"[:PERSON_MAX]
    if isinstance(requested_by, str) and requested_by.strip() and len(requested_by) <= PERSON_MAX - 3 and not any(ord(ch) < 32 or ord(ch) == 127 for ch in requested_by):
        return f"by:{requested_by.strip()}"[:PERSON_MAX]
    raise SandboxError("invalid_input", "Pass the signed-in user, or requested_by as plain text (1 to 125 characters).")


def _input_bytes(value: Any, limit_kib: int) -> bytes:
    if value is None:
        data = b""
    elif isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        raise SandboxError("invalid_input", "input must be text or bytes.")
    if len(data) > limit_kib * 1024:
        raise SandboxError("input_too_large", f"The input is larger than this runner allows ({limit_kib} KiB).")
    return data


def _credentials(value: Any, declared: list) -> dict[str, bytes]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SandboxError("credential_invalid", "credentials must be a mapping of declared names to text.")
    out: dict[str, bytes] = {}
    for name, secret in value.items():
        if not isinstance(name, str) or not _CREDENTIAL_NAME_RE.fullmatch(name) or name not in declared:
            raise SandboxError("credential_invalid", "A credential name is not declared for this runner.")
        if isinstance(secret, str):
            data = secret.encode("utf-8")
        elif isinstance(secret, (bytes, bytearray)):
            data = bytes(secret)
        else:
            raise SandboxError("credential_invalid", "A credential must be text or bytes.")
        if len(data) > CREDENTIAL_MAX_BYTES:
            raise SandboxError("credential_invalid", "A credential is larger than 16 KiB.")
        out[name] = data
    return out


def _first_frame(process, wait_seconds: float) -> dict:
    """The helper's first line: ``started`` (go on) or ``refused`` (raise). The helper waits in its queue before it says started."""
    box: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: box.put(process.stdout.readline()), daemon=True).start()
    try:
        raw = box.get(timeout=wait_seconds)
    except queue.Empty:
        raw = b""
    try:
        frame = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        frame = None
    if not isinstance(frame, dict) or not isinstance(frame.get("t"), str):
        raise SandboxError("start_failed", "The sandbox helper did not answer.")
    return frame


def start(runner_id: Any = None, *, input: Any = None, parameters: Any = None, credentials: Any = None, requested_by: Any = None, user: Any = None):
    """Start a run and return a RunHandle. Only the module that owns the runner may call it (found by Core from the call stack, AD-26).

    While the kill switch is off it raises ``sandbox_disabled`` before it reads anything. Otherwise: the caller, the server's readiness,
    the runner and its runtime, the input size, the parameters and the credential names are checked (the root helper checks every one
    again); one strict audit row ``sandbox.run.started`` is written BEFORE the launch (a run that cannot be audited does not start); the
    helper is started through sudo and the header, the input and the credentials travel on its stdin only (never argv or environment).
    The call returns when the run has started, after waiting in the queue for at most the runner's queue_seconds. ``user`` (the signed-in
    Django user) is the person for the per-person limit; without it ``requested_by`` is used, which Core cannot verify, so it is used for
    the limit and the audit row only, never for access."""
    _check_enabled()
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None:
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may start it.")
    if not isinstance(runner_id, str) or not _RUNNER_ID_RE.fullmatch(runner_id):
        raise SandboxError("invalid_input", "The runner id must be letters, digits, '.', '_' or '-' (1 to 128 characters).")
    if not runner_id.startswith(identity.module_id + "."):
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may start it.")
    row = _registry_row(REGISTRY_ROOT / f"{runner_id}.json")
    if row is None:
        raise SandboxError("runner_unknown", "That sandbox runner is not registered.")
    if row["owner_module"] != identity.module_id:
        raise SandboxError("not_owner", "Only the module that owns a sandbox runner may start it.")
    state = status()
    if not state["ready"]:
        raise SandboxError("sandbox_unavailable", "This server cannot host a sandbox run right now: " + (state["reason"] or "not ready"))
    if row.get("runtime_verified") is not True:
        raise SandboxError("runtime_unverified", "The runner's runtime is not verified. The module has to build it again.")
    limits = row.get("limits") if isinstance(row.get("limits"), dict) else {}
    data = _input_bytes(input, int(limits.get("input_kib", LIMITS["input_kib"]["default"])))
    declared = [name for name in (row.get("credential_files") or []) if isinstance(name, str)]
    secret_values = _credentials(credentials, declared)
    if parameters is not None and not isinstance(parameters, dict):
        raise SandboxError("invalid_input", "parameters must be a mapping.")
    person = _person(user, requested_by)
    run_id = secrets.token_hex(16)
    header = {
        "runner_id": runner_id, "run_id": run_id, "person": person, "parameters": parameters or {},
        "credentials": {name: base64.b64encode(value).decode("ascii") for name, value in secret_values.items()}, "input_bytes": len(data),
    }
    try:
        _audit("sandbox.run.started", "run", run_id, f"Sandbox run {run_id} of runner {runner_id} was requested.",
               {"run_id": run_id, "runner": runner_id, "owner_module": identity.module_id, "requested_by": _safe_slug(requested_by) if requested_by else "",
                "input_bytes": len(data), "parameter_names": sorted(str(k) for k in (parameters or {}))[:64], "credential_names": sorted(secret_values)},
               user=user, requested_by=requested_by, owner=identity.module_id, strict=True)
    except Exception as exc:
        raise SandboxError("start_failed", "The run was not started because it could not be recorded in the audit log.") from exc
    try:
        process = _popen(list(HELPER_ARGV) + ["--start"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_env(), close_fds=True)
        process.stdin.write(json.dumps(header, separators=(",", ":")).encode("utf-8") + b"\n" + data)
        process.stdin.flush()  # stdin stays open: closing it is the dead-man switch
    except OSError as exc:
        _refused_row(run_id, runner_id, identity.module_id, "start_failed", user, requested_by)
        raise SandboxError("start_failed", "The sandbox helper could not be started.") from exc
    finally:
        del secret_values, header
    try:
        first = _first_frame(process, int(limits.get("queue_seconds", 10)) + 20)
        if first["t"] == "refused":
            raise _error_from_frame(first)
        if first["t"] != "started":
            raise SandboxError("start_failed", "The sandbox helper gave an unexpected answer.")
    except SandboxError as exc:
        _refused_row(run_id, runner_id, identity.module_id, exc.code, user, requested_by, retry_after=exc.retry_after)
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            process.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            process.kill()
        raise
    handle = RunHandle(process, run_id, owner=identity.module_id, runner_id=runner_id, credential_name=declared[0] if declared and row.get("credential_return") is True else None,
                       user=user, requested_by=requested_by, first=first)
    _RUNS[run_id] = {"owner": identity.module_id, "handle": handle}
    return handle


def _refused_row(run_id, runner_id, owner, code, user, requested_by, retry_after=None) -> None:
    _audit("sandbox.run.refused", "deny", run_id, f"Sandbox run {run_id} was refused ({code}).",
           {"run_id": run_id, "runner": runner_id, "owner_module": owner, "code": code, "retry_after": retry_after}, user=user, requested_by=requested_by, owner=owner)


def run(runner_id: Any = None, *, input: Any = None, parameters: Any = None, credentials: Any = None, requested_by: Any = None, user: Any = None):
    """Start a run and wait for it: ``{run_id, exit_code, stdout, stderr, reason, duration_ms, peak_mb, credentials_out, ...}`` (see
    RunHandle.wait). The same checks as start(), and the same ``sandbox_disabled`` first while the switch is off."""
    handle = start(runner_id, input=input, parameters=parameters, credentials=credentials, requested_by=requested_by, user=user)
    try:
        return handle.wait()
    finally:
        handle.close()


def cancel(run_id: Any = None):
    """Cancel a run this process started. Only the module that owns the run may cancel it (found by Core from the call stack). A run id that
    this process does not know, or that another module owns, gives ``not_owner``. While the switch is off it raises ``sandbox_disabled``
    before it reads anything."""
    _check_enabled()
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None:
        raise SandboxError("not_owner", "Only the module that owns a sandbox run may cancel it.")
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise SandboxError("invalid_input", "The run id must be 32 lowercase hexadecimal characters.")
    known = _RUNS.get(run_id)
    if known is None or known["owner"] != identity.module_id:
        raise SandboxError("not_owner", "Only the module that owns a sandbox run may cancel it.")
    known["handle"].cancel()
    _audit("sandbox.run.cancelled", "custom:sandbox-run-cancelled", run_id, f"Sandbox run {run_id} was cancelled by its module.",
           {"run_id": run_id, "owner_module": identity.module_id, "by": "module"}, owner=identity.module_id, requested_by=identity.module_id)


def cancel_by_person(run_id: Any, *, user: Any) -> None:
    """The cancel route (core.sandbox.manage, checked by the view): stop any run by id and write the audit row for the person. The root
    helper stops only a unit it started."""
    _check_enabled()
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise SandboxError("invalid_input", "The run id must be 32 lowercase hexadecimal characters.")
    _helper_stop(run_id)
    _audit("sandbox.run.cancelled", "custom:sandbox-run-cancelled", run_id, f"Sandbox run {run_id} was cancelled by an administrator.",
           {"run_id": run_id, "by": "person"}, user=user)


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
            "verified (AD-26): describe(), start(), run() and cancel() are for the module that owns the runner (or the run), found by Core from the call "
            "stack; nothing is passed in. Core, a library, a generated frame, a disabled or legacy module and any other module get not_owner."
        ),
        "network": (
            "the smaller sandbox (plan section 15): a run cannot reach loopback, link-local, multicast or private ranges; public HTTPS stays open. "
            "There is no host list."
        ),
        "manifest": "sandbox_runners (at most 4 entries) with publisher_permissions sandbox.register and requires.framework >=1.17.116.",
        "audit": (
            "since 1.17.118 Core writes rows (module core, object type sandbox_run, never the credential, the input or the output): sandbox.run.started "
            "(strict, before the launch), sandbox.run.ended, sandbox.run.refused and sandbox.run.cancelled. The root helper keeps its own append-only log too."
        ),
        "permissions": {"core.sandbox.view": "read the sandbox status route", "core.sandbox.manage": "cancel a run by id"},
        "routes": ["GET /api/tfd/system/sandbox/status/", "POST /api/tfd/system/sandbox/runs/<run_id>/cancel/"],
        "requires_framework": ">=1.17.116",
        "notes": (
            "1.17.118: the launch path is built (start returns a RunHandle, run waits, cancel stops) and still behind the kill switch, so start, run and cancel "
            "raise sandbox_disabled before they read anything. status() gains the additive keys slots_total, slots_used, canary_ok and canary_at. The switch is "
            "turned on by a later release after the dev02 canary passes in full."
        ),
    }


def register_core_sandbox_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Runs a signed module's declared program as an unprivileged, resource-limited process. Launch path built in 1.17.118, still switched off.",
        operations=OPERATIONS,
        metadata=sandbox_contract_metadata(),
    )
