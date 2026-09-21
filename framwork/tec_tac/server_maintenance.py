"""Durable Core privileged server-maintenance orchestration.

``core.server_maintenance`` is generic Core infrastructure for registered,
validated privileged actions.  Callers never submit a shell command.  Instead
they select an administrator-installed action manifest and typed parameters.
A root-owned helper re-validates the request and runs it in a detached systemd
unit so Tactical Django, Celery, NATS and nginx restarts do not own job lifetime.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capabilities import build_operation_context, register_capability
from .config import load_layout

CAPABILITY_ID = "core.server_maintenance"
CAPABILITY_VERSION = "1.0.0"
DEFAULT_STATE_ROOT = Path("/var/lib/tec-tac/server-maintenance")
DEFAULT_REGISTRY_ROOT = Path("/etc/tec-tac/server-maintenance/actions.d")
DEFAULT_ACTION_ROOT = Path("/usr/local/lib/tec-tac/server-maintenance/actions")
HELPER = Path("/usr/local/sbin/tec-tac-server-maintenance")
TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "dispatch_failed"})
ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_OUTPUT_BYTES = 65536


class ServerMaintenanceError(RuntimeError):
    """Base exception for ``core.server_maintenance``."""

    def __init__(self, message: str, *, job_id: str | None = None, classification: str | None = None):
        super().__init__(message)
        self.job_id = job_id
        self.classification = classification


class ServerMaintenanceValidationError(ServerMaintenanceError):
    pass


class ServerMaintenanceNotFound(ServerMaintenanceError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _layout() -> dict[str, str]:
    return load_layout()


def _state_root() -> Path:
    return Path(_layout().get("TEC_TAC_SERVER_MAINTENANCE_ROOT") or DEFAULT_STATE_ROOT)


def _registry_root() -> Path:
    return Path(_layout().get("TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT") or DEFAULT_REGISTRY_ROOT)


def _jobs_root() -> Path:
    return _state_root() / "jobs"


def _cancel_root() -> Path:
    return _state_root() / "cancel-requests"


def _logs_root() -> Path:
    return _state_root() / "logs"


def _validate_context(context: dict | None) -> dict:
    raw = dict(context or {})
    normalized = build_operation_context(
        source_module=str(raw.get("source_module") or "").strip(),
        source_action=str(raw.get("source_action") or "").strip(),
        source_run_id=raw.get("source_run_id"),
        requested_by=raw.get("requested_by"),
        **{k: v for k, v in raw.items() if k not in {"source_module", "source_action", "source_run_id", "requested_by"}},
    )
    if not normalized["source_module"]:
        raise ServerMaintenanceValidationError("operation context source_module is required.", classification="validation_failed")
    if not normalized["source_action"]:
        raise ServerMaintenanceValidationError("operation context source_action is required.", classification="validation_failed")
    if not normalized["requested_by"]:
        raise ServerMaintenanceValidationError("operation context requested_by is required; use 'system' for non-human automation.", classification="validation_failed")
    try:
        return json.loads(json.dumps(normalized, default=str))
    except (TypeError, ValueError) as exc:
        raise ServerMaintenanceValidationError("operation context must be JSON-serializable.", classification="validation_failed") from exc


def _safe_job_id(job_id: str) -> str:
    try:
        return str(uuid.UUID(str(job_id)))
    except (ValueError, TypeError) as exc:
        raise ServerMaintenanceValidationError("Invalid server-maintenance job id.", classification="validation_failed") from exc


def _read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ServerMaintenanceNotFound(f"{label} was not found.", classification="not_found") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ServerMaintenanceError(f"{label} is unreadable: {exc}", classification="state_unreadable") from exc
    if not isinstance(value, dict):
        raise ServerMaintenanceError(f"{label} has an invalid structure.", classification="state_unreadable")
    return value


def _read_action(action_id: str) -> dict:
    action_id = str(action_id or "").strip()
    if not ACTION_ID_RE.fullmatch(action_id):
        raise ServerMaintenanceValidationError("Invalid registered server-maintenance action id.", classification="validation_failed")
    path = _registry_root() / f"{action_id}.json"
    action = _read_json(path, f"Registered server-maintenance action {action_id!r}")
    if str(action.get("id") or "") != action_id:
        raise ServerMaintenanceError(f"Registered action file {path.name} contains the wrong id.", classification="action_invalid")
    if action.get("enabled", True) is not True:
        raise ServerMaintenanceValidationError(f"Registered action {action_id!r} is disabled.", classification="action_disabled")
    return action


def _normalize_parameters(action: dict, parameters: dict | None) -> tuple[dict, dict]:
    raw = dict(parameters or {}) if isinstance(parameters, dict) else None
    if raw is None:
        raise ServerMaintenanceValidationError("parameters must be an object.", classification="validation_failed")
    schema = action.get("parameters") or {}
    if not isinstance(schema, dict):
        raise ServerMaintenanceError("Registered action parameters schema is invalid.", classification="action_invalid")
    unknown = sorted(set(raw) - set(schema))
    if unknown:
        raise ServerMaintenanceValidationError("Unknown action parameter(s): " + ", ".join(unknown), classification="validation_failed")

    normalized: dict[str, Any] = {}
    public: dict[str, Any] = {}
    for name, spec in schema.items():
        if not isinstance(spec, dict):
            raise ServerMaintenanceError(f"Registered action parameter {name!r} schema is invalid.", classification="action_invalid")
        required = bool(spec.get("required", False))
        has_value = name in raw
        if not has_value and "default" in spec:
            value = spec.get("default")
            has_value = True
        elif has_value:
            value = raw[name]
        elif required:
            raise ServerMaintenanceValidationError(f"Required action parameter {name!r} is missing.", classification="validation_failed")
        else:
            continue

        ptype = str(spec.get("type") or "string")
        if ptype == "string":
            if not isinstance(value, str):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} must be a string.", classification="validation_failed")
            max_length = int(spec.get("max_length", 4096))
            if len(value) > max(1, min(max_length, 65536)):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} is too long.", classification="validation_failed")
            pattern = spec.get("pattern")
            if pattern and not re.fullmatch(str(pattern), value):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} does not match its registered pattern.", classification="validation_failed")
        elif ptype == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} must be an integer.", classification="validation_failed")
            if "minimum" in spec and value < int(spec["minimum"]):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} is below its minimum.", classification="validation_failed")
            if "maximum" in spec and value > int(spec["maximum"]):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} is above its maximum.", classification="validation_failed")
        elif ptype == "boolean":
            if not isinstance(value, bool):
                raise ServerMaintenanceValidationError(f"Parameter {name!r} must be true or false.", classification="validation_failed")
        elif ptype == "enum":
            choices = spec.get("choices") or []
            if not isinstance(choices, list) or value not in choices:
                raise ServerMaintenanceValidationError(f"Parameter {name!r} must be one of its registered choices.", classification="validation_failed")
        else:
            raise ServerMaintenanceError(f"Registered action parameter {name!r} has unsupported type {ptype!r}.", classification="action_invalid")
        normalized[name] = value
        public[name] = "<redacted>" if bool(spec.get("sensitive", False)) else value
    return normalized, public


def _atomic_job(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def _read_job(job_id: str) -> dict:
    job_id = _safe_job_id(job_id)
    return _read_json(_jobs_root() / f"{job_id}.json", f"Server-maintenance job {job_id}")


def _sensitive_values(job: dict) -> list[str]:
    private = dict(job.get("parameters") or {})
    public = dict(job.get("public_parameters") or {})
    values = []
    for name, shown in public.items():
        if shown == "<redacted>" and name in private:
            value = str(private[name])
            if value:
                values.append(value)
    return sorted(set(values), key=len, reverse=True)


def _read_output(path: Path, *, max_bytes: int = MAX_OUTPUT_BYTES, redact_values: list[str] | None = None) -> dict:
    if not path.is_file() or path.is_symlink():
        return {"text": "", "bytes": 0, "truncated": False}
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(-max_bytes, os.SEEK_END)
            raw = handle.read(max_bytes)
    except OSError:
        return {"text": "", "bytes": 0, "truncated": False}
    text = raw.decode("utf-8", errors="replace").replace("\x00", "")
    for value in redact_values or []:
        text = text.replace(value, "<redacted>")
    return {"text": text, "bytes": int(size), "truncated": size > max_bytes}


def _public_job(job: dict, *, include_output: bool = True) -> dict:
    result = {
        "id": str(job.get("id") or ""),
        "action": str(job.get("action") or ""),
        "status": str(job.get("status") or "unknown"),
        "stage": str(job.get("stage") or ""),
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "cancel_requested_at": job.get("cancel_requested_at"),
        "cancel_context": dict(job.get("cancel_context") or {}) if isinstance(job.get("cancel_context"), dict) else None,
        "context": dict(job.get("context") or {}),
        "parameters": dict(job.get("public_parameters") or {}),
        "lock": dict(job.get("lock") or {}),
        "exit_result": dict(job.get("exit_result") or {}) if isinstance(job.get("exit_result"), dict) else None,
        "failure": dict(job.get("failure") or {}) if isinstance(job.get("failure"), dict) else None,
    }
    if include_output:
        jid = result["id"]
        secrets = _sensitive_values(job)
        result["stdout"] = _read_output(_logs_root() / f"{jid}.stdout.log", redact_values=secrets)
        result["stderr"] = _read_output(_logs_root() / f"{jid}.stderr.log", redact_values=secrets)
        result["logs"] = _read_output(_logs_root() / f"{jid}.log", redact_values=secrets)
    return result


def _dispatch(command: str, job_id: str) -> None:
    if not HELPER.is_file():
        raise ServerMaintenanceError(f"Core server-maintenance helper is not installed at {HELPER}.", job_id=job_id, classification="dispatch_failed")
    try:
        subprocess.run(
            ["sudo", "-n", str(HELPER), command, job_id],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = str(getattr(exc, "stderr", "") or exc).strip()
        raise ServerMaintenanceError(f"Unable to dispatch privileged server-maintenance operation: {detail}", job_id=job_id, classification="dispatch_failed") from exc


class ServerMaintenanceProvider:
    """Public provider contract for ``core.server_maintenance`` 1.x."""

    def start(self, *, action: str, parameters: dict | None = None, context: dict) -> dict:
        action_def = _read_action(action)
        normalized, public_parameters = _normalize_parameters(action_def, parameters)
        operation_context = _validate_context(context)
        job_id = str(uuid.uuid4())
        payload = {
            "schema": 1,
            "id": job_id,
            "action": str(action_def["id"]),
            "action_revision": str(action_def.get("revision") or "1"),
            "status": "queued",
            "stage": "queued",
            "created_at": _utcnow(),
            "started_at": None,
            "finished_at": None,
            "cancel_requested_at": None,
            "context": operation_context,
            "parameters": normalized,
            "public_parameters": public_parameters,
            "lock": {"scope": "global", "state": "pending", "acquired_at": None},
            "exit_result": None,
            "failure": None,
        }
        _atomic_job(_jobs_root() / f"{job_id}.json", payload)
        try:
            _dispatch("--dispatch", job_id)
        except Exception as exc:
            # The root helper may already have persisted a more specific
            # validation/action failure. Preserve that durable classification
            # instead of flattening every helper rejection into dispatch_failed.
            try:
                current = _read_job(job_id)
            except ServerMaintenanceError:
                current = payload
            failure = current.get("failure") if isinstance(current.get("failure"), dict) else None
            if current.get("status") in TERMINAL_STATES and failure:
                raise ServerMaintenanceError(
                    str(failure.get("message") or exc),
                    job_id=job_id,
                    classification=str(failure.get("classification") or "dispatch_failed"),
                ) from exc
            payload["status"] = "dispatch_failed"
            payload["stage"] = "dispatch"
            payload["finished_at"] = _utcnow()
            payload["failure"] = {
                "classification": getattr(exc, "classification", None) or "dispatch_failed",
                "message": str(exc),
                "error_type": exc.__class__.__name__,
            }
            _atomic_job(_jobs_root() / f"{job_id}.json", payload)
            raise
        return self.get_job(job_id=job_id, context=operation_context)

    def get_job(self, *, job_id: str, context: dict) -> dict:
        _validate_context(context)
        return _public_job(_read_job(job_id), include_output=True)

    def cancel(self, *, job_id: str, context: dict) -> dict:
        operation_context = _validate_context(context)
        safe_id = _safe_job_id(job_id)
        job = _read_job(safe_id)
        if str(job.get("status")) in TERMINAL_STATES:
            return _public_job(job, include_output=True)
        cancel_path = _cancel_root() / f"{safe_id}.json"
        _atomic_job(cancel_path, {"job_id": safe_id, "requested_at": _utcnow(), "context": operation_context})
        try:
            _dispatch("--cancel", safe_id)
        except Exception:
            cancel_path.unlink(missing_ok=True)
            raise
        return self.get_job(job_id=safe_id, context=operation_context)

    def list_jobs(
        self,
        *,
        status: str | None = None,
        action: str | None = None,
        limit: int = 100,
        include_output: bool = False,
        context: dict | None = None,
    ) -> list[dict]:
        _validate_context(context)
        limit = max(1, min(int(limit), 500))
        status_filter = str(status or "").strip() or None
        action_filter = str(action or "").strip() or None
        rows = []
        root = _jobs_root()
        if root.is_dir():
            for path in root.glob("*.json"):
                try:
                    job = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not isinstance(job, dict):
                    continue
                if status_filter and str(job.get("status")) != status_filter:
                    continue
                if action_filter and str(job.get("action")) != action_filter:
                    continue
                rows.append(job)
        rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)
        return [_public_job(row, include_output=bool(include_output)) for row in rows[:limit]]

    def list_actions(self, *, context: dict) -> list[dict]:
        _validate_context(context)
        rows = []
        root = _registry_root()
        if not root.is_dir():
            return rows
        for path in sorted(root.glob("*.json")):
            try:
                action = _read_json(path, f"Registered server-maintenance action {path.name}")
            except ServerMaintenanceError:
                continue
            action_id = str(action.get("id") or "")
            if not ACTION_ID_RE.fullmatch(action_id):
                continue
            parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
            rows.append({
                "id": action_id,
                "description": str(action.get("description") or ""),
                "revision": str(action.get("revision") or "1"),
                "enabled": action.get("enabled", True) is True,
                "timeout_seconds": int(action.get("timeout_seconds") or 3600),
                "parameters": {
                    name: {k: v for k, v in spec.items() if k != "default" or not bool(spec.get("sensitive", False))}
                    for name, spec in parameters.items() if isinstance(spec, dict)
                },
            })
        return rows

    def health(self) -> dict:
        return {
            "healthy": HELPER.is_file(),
            "helper_installed": HELPER.is_file(),
            "state_root": str(_state_root()),
            "registered_actions": sum(1 for path in _registry_root().glob("*.json")) if _registry_root().is_dir() else 0,
            "global_lock": str(_state_root() / "server-maintenance.lock"),
            "execution_model": "systemd-detached-root-helper",
        }


_PROVIDER = ServerMaintenanceProvider()


def register_core_server_maintenance_capability():
    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Durable registered privileged server-maintenance job orchestration.",
        health=_PROVIDER.health,
        operations=("start", "get_job", "cancel", "list_jobs", "list_actions"),
        metadata={
            "durable": True,
            "global_lock": True,
            "execution": "registered-actions-only",
            "arbitrary_shell": False,
            "terminal_states": sorted(TERMINAL_STATES),
        },
    )


def get_server_maintenance_provider() -> ServerMaintenanceProvider:
    return _PROVIDER
