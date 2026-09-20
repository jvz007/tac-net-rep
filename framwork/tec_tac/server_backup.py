"""Core-owned privileged Tactical/Tec-Tac server backup capability.

The public capability is intentionally narrow. Modules submit typed backup,
restore, retention and secret-store requests. A root-owned helper validates and
executes those requests outside Django/Celery; modules never receive arbitrary
shell or sudo access.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .capabilities import register_capability
from .config import load_layout

CAPABILITY_ID = "core.server_backup"
CAPABILITY_VERSION = "1.5.2"
HELPER = Path("/usr/local/sbin/tec-tac-server-backup")
DEFAULT_STATE_ROOT = Path("/var/lib/tec-tac/server-backup")
TERMINAL_STATES = {"succeeded", "failed", "dispatch_failed"}
BACKUP_CLASSES = frozenset({"daily", "weekly", "monthly", "manual"})
DESTINATION_TYPES = frozenset({"local", "sftp", "ftp", "scp", "webdav", "s3"})


class ServerBackupError(RuntimeError):
    """Base exception for the Core server-backup capability."""

    def __init__(self, message: str, *, job_id: str | None = None, result: dict | None = None):
        super().__init__(message)
        self.job_id = job_id
        self.result = result or {}


class ServerBackupTimeout(ServerBackupError):
    pass


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _state_root() -> Path:
    layout = load_layout()
    return Path(layout.get("TEC_TAC_SERVER_BACKUP_ROOT") or DEFAULT_STATE_ROOT)


def _jobs_root() -> Path:
    return _state_root() / "jobs"


def _atomic_job(path: Path, payload: dict, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _normalize_context(context: dict | None) -> dict:
    raw = dict(context or {})
    return {
        "source_module": str(raw.get("source_module") or "").strip(),
        "source_action": str(raw.get("source_action") or "").strip(),
        "source_run_id": str(raw.get("source_run_id")) if raw.get("source_run_id") not in (None, "") else None,
        "requested_by": str(raw.get("requested_by")) if raw.get("requested_by") not in (None, "") else None,
    }


def _validate_destinations(destinations) -> list[dict]:
    if destinations is None:
        return []
    if not isinstance(destinations, list):
        raise ServerBackupError("destinations must be a list of typed destination objects.")
    result = []
    seen = set()
    for raw in destinations:
        if not isinstance(raw, dict):
            raise ServerBackupError("Each backup destination must be an object.")
        item = dict(raw)
        dtype = str(item.get("type") or "").strip().lower()
        if dtype not in DESTINATION_TYPES:
            raise ServerBackupError(f"Unsupported backup destination type: {dtype or '<blank>'}.")
        dest_id = str(item.get("id") if item.get("id") is not None else "").strip()
        if not dest_id or not __import__("re").fullmatch(r"[A-Za-z0-9_.-]{1,128}", dest_id):
            raise ServerBackupError("Each backup destination requires a safe stable id (letters, numbers, dot, underscore or dash).")
        if dest_id in seen:
            raise ServerBackupError(f"Duplicate backup destination id: {dest_id}.")
        seen.add(dest_id)
        item["id"] = dest_id
        item["type"] = dtype
        result.append(item)
    return result


def _timeout_for(action: str) -> int:
    defaults = {
        "create_backup": 6 * 60 * 60,
        "list_backups": 20 * 60,
        "restore_backup": 12 * 60 * 60,
        "apply_retention": 2 * 60 * 60,
        "validate_destination": 10 * 60,
        "validate_restore": 45 * 60,
        "store_secret": 120,
        "delete_secret": 120,
    }
    env_key = "TEC_TAC_SERVER_BACKUP_TIMEOUT_" + action.upper()
    try:
        return max(30, int(os.environ.get(env_key, defaults[action])))
    except (TypeError, ValueError):
        return defaults[action]


def _read_job(job_id: str) -> dict:
    try:
        uuid.UUID(str(job_id))
    except ValueError as exc:
        raise ServerBackupError("Invalid server-backup job id.", job_id=str(job_id)) from exc
    path = _jobs_root() / f"{job_id}.json"
    if not path.is_file():
        raise ServerBackupError("Server-backup job status is unavailable.", job_id=str(job_id))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServerBackupError("Server-backup job status is unreadable.", job_id=str(job_id)) from exc
    return payload


def _dispatch(job_id: str) -> None:
    if not HELPER.is_file():
        raise ServerBackupError(f"Core server-backup helper is not installed at {HELPER}.", job_id=job_id)
    try:
        subprocess.run(
            ["sudo", "-n", str(HELPER), "--dispatch", job_id],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = str(getattr(exc, "stderr", "") or exc).strip()
        raise ServerBackupError(f"Unable to dispatch Core server-backup job: {detail}", job_id=job_id) from exc


def _run(action: str, request: dict, *, context: dict | None, timeout: int | None = None) -> dict:
    job_id = str(uuid.uuid4())
    payload = {
        "id": job_id,
        "action": action,
        "status": "queued",
        "stage": "queued",
        "created_at": _utc_now(),
        "started_at": None,
        "finished_at": None,
        "error": None,
        "error_type": None,
        "context": _normalize_context(context),
        "request": request,
        "result": None,
    }
    _atomic_job(_jobs_root() / f"{job_id}.json", payload)
    try:
        _dispatch(job_id)
    except Exception as exc:
        payload["status"] = "dispatch_failed"
        payload["stage"] = "dispatch"
        payload["finished_at"] = _utc_now()
        payload["error"] = str(exc)
        payload["error_type"] = exc.__class__.__name__
        if action == "store_secret":
            payload["request"] = {"redacted": True}
        _atomic_job(_jobs_root() / f"{job_id}.json", payload)
        raise

    deadline = time.monotonic() + int(timeout or _timeout_for(action))
    while time.monotonic() < deadline:
        job = _read_job(job_id)
        if job.get("status") in TERMINAL_STATES:
            result = job.get("result") if isinstance(job.get("result"), dict) else {}
            result.setdefault("job_id", job_id)
            if job.get("status") == "succeeded":
                return result
            raise ServerBackupError(
                str(job.get("error") or "Core server-backup operation failed."),
                job_id=job_id,
                result=result,
            )
        time.sleep(1.0)
    raise ServerBackupTimeout(
        "Timed out waiting for the privileged server-backup operation to complete. The root-owned job may still be running; inspect its job id rather than dispatching a duplicate operation.",
        job_id=job_id,
    )


def _normalize_validation_overrides(overrides) -> list[str]:
    if overrides in (None, []):
        return []
    if not isinstance(overrides, list) or any(not isinstance(item, str) for item in overrides):
        raise ServerBackupError("validate_restore overrides must be an array of check IDs.")
    result = []
    seen = set()
    for raw in overrides:
        check_id = raw.strip()
        if not check_id or check_id in seen:
            raise ServerBackupError("validate_restore overrides contain a blank or duplicate check ID.")
        seen.add(check_id)
        result.append(check_id)
    return result


def _normalize_restore_overrides(overrides) -> dict[str, str]:
    if overrides in (None, {}):
        return {}
    if not isinstance(overrides, dict):
        raise ServerBackupError("restore_backup overrides must be an object mapping check IDs to audit IDs.")
    result = {}
    for raw_check, raw_audit in overrides.items():
        check_id = str(raw_check or "").strip()
        audit_id = str(raw_audit or "").strip()
        if not check_id or not audit_id:
            raise ServerBackupError("restore_backup overrides contain a blank check ID or audit ID.")
        result[check_id] = audit_id
    return result


_JOB_STAGE_LABELS = {
    "queued": "Queued",
    "dispatched": "Dispatched",
    "running": "Running",
    "prepare": "Preparing backup",
    "tactical.backup": "Creating Tactical native backup",
    "tactical.collect.nginx": "Collecting nginx configuration",
    "tactical.collect.systemd": "Collecting systemd services",
    "tactical.collect.confd": "Collecting Tactical conf.d configuration",
    "tactical.collect.letsencrypt": "Collecting Let's Encrypt certificates",
    "tactical.collect.opt_tactical": "Collecting Tactical reporting assets",
    "tactical.validate": "Validating Tactical native backup",
    "tec_tac.backup": "Creating Tec-Tac recovery component",
    "bundle.create": "Creating recovery bundle",
    "bundle.validate": "Validating recovery bundle",
    "destination.upload": "Uploading recovery bundle",
    "destination.verify": "Verifying destination copy",
    "restore-prepared": "Restore prepared",
    "complete": "Complete",
    "failed": "Failed",
    "dispatch": "Dispatch failed",
}

_SENSITIVE_LINE_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/=]+"),
    re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]+"),
    re.compile(r"(?i)(https?://[^:/\s]+:)([^@/\s]+)(@)"),
    re.compile(r"(?i)(password|passwd|pass|secret|token|access[_-]?key(?:_id)?|secret[_-]?access[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"),
)

def _sanitize_log_line(value: str) -> str:
    line = str(value).replace("\x00", "")[:4096]
    if "-----BEGIN " in line or "PRIVATE KEY" in line:
        return "[redacted private key material]"
    for pattern in _SENSITIVE_LINE_PATTERNS:
        if pattern.pattern.startswith("(?i)(https?"):
            line = pattern.sub(r"\1<redacted>\3", line)
        elif "bearer" in pattern.pattern.lower() or "basic" in pattern.pattern.lower():
            line = pattern.sub(r"\1<redacted>", line)
        else:
            line = pattern.sub(r"\1=<redacted>", line)
    return line

def _safe_log_tail(job_id: str, *, lines: int = 80) -> list[str]:
    path = _state_root() / "logs" / f"{job_id}.log"
    if not path.is_file() or path.is_symlink():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(int(lines), 200)):]
    except (OSError, ValueError):
        return []
    return [_sanitize_log_line(line) for line in raw]

def _find_job_by_source_run_id(source_run_id: str) -> dict:
    needle = str(source_run_id or "").strip()
    if not needle:
        raise ServerBackupError("source_run_id must not be blank.")
    matches = []
    root = _jobs_root()
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if str((payload.get("context") or {}).get("source_run_id") or "") == needle:
                matches.append(payload)
    if not matches:
        raise ServerBackupError(f"No Core server-backup job was found for source_run_id {needle!r}.")
    matches.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return matches[0]

def _public_job_status(job: dict) -> dict:
    progress = job.get("progress") if isinstance(job.get("progress"), dict) else {}
    stage = str(job.get("stage") or "")
    result = {
        "job_id": str(job.get("id") or ""),
        "source_run_id": (job.get("context") or {}).get("source_run_id"),
        "status": str(job.get("status") or "unknown"),
        "action": str(job.get("action") or ""),
        "stage": stage,
        "stage_label": str(job.get("stage_label") or _JOB_STAGE_LABELS.get(stage) or stage.replace(".", " ").replace("-", " ").title()),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "error": _sanitize_log_line(str(job.get("error"))) if job.get("error") else None,
        "progress": {
            "current": int(progress.get("current") or 0),
            "total": int(progress.get("total") or 0),
        },
        "log_tail": _safe_log_tail(str(job.get("id") or "")),
    }
    return result


class ServerBackupProvider:
    """Stable public provider contract for ``core.server_backup`` version 1.x."""


    def get_job_status(self, *, job_id: str | None = None, source_run_id: str | None = None, context: dict | None = None) -> dict:
        """Return sanitized read-only status for a Core backup/restore job.

        At least one lookup key is required. When both are provided they must
        resolve to the same job. No privileged helper is dispatched.
        """
        if not job_id and not source_run_id:
            raise ServerBackupError("get_job_status requires job_id or source_run_id.")
        if job_id:
            job = _read_job(str(job_id))
            if source_run_id is not None and str((job.get("context") or {}).get("source_run_id") or "") != str(source_run_id):
                raise ServerBackupError("job_id and source_run_id do not identify the same Core server-backup job.")
        else:
            job = _find_job_by_source_run_id(str(source_run_id))
        return _public_job_status(job)

    def create_backup(self, *, backup_class: str, destinations: list[dict], include_tactical: bool = True, include_tec_tac: bool = True, context: dict) -> dict:
        backup_class = str(backup_class or "").strip().lower()
        if backup_class not in BACKUP_CLASSES:
            raise ServerBackupError("backup_class must be daily, weekly, monthly, or manual.")
        if not isinstance(include_tactical, bool):
            raise ServerBackupError("include_tactical must be true or false.")
        if not isinstance(include_tec_tac, bool):
            raise ServerBackupError("include_tec_tac must be true or false.")
        if not include_tactical and not include_tec_tac:
            raise ServerBackupError("At least one recovery component must be included.")
        return _run(
            "create_backup",
            {
                "backup_class": backup_class,
                "destinations": _validate_destinations(destinations),
                "include_tactical": include_tactical,
                "include_tec_tac": include_tec_tac,
            },
            context=context,
        )

    def list_backups(self, *, destinations: list[dict], context: dict) -> list[dict]:
        result = _run(
            "list_backups",
            {"destinations": _validate_destinations(destinations)},
            context=context,
        )
        rows = result.get("backups") or []
        if not isinstance(rows, list):
            raise ServerBackupError("Core server-backup provider returned an invalid backup list.", result=result)
        return rows

    def restore_backup(self, *, backup_ref: str, destination: dict | None, restore_mode: str | None = None, context: dict, restore_tec_tac: bool | None = None, overrides: dict | None = None) -> dict:
        # Compatibility bridge for 1.0/1.1 consumers. New modules must send
        # restore_mode explicitly; legacy bool maps to full/tactical only.
        if restore_mode in (None, "") and isinstance(restore_tec_tac, bool):
            restore_mode = "full" if restore_tec_tac else "tactical"
        mode = str(restore_mode or "").strip().lower()
        if mode not in {"full", "tactical", "tec_tac"}:
            raise ServerBackupError("restore_mode must be full, tactical, or tec_tac.")
        destinations = _validate_destinations([destination]) if destination is not None else []
        return _run(
            "restore_backup",
            {
                "backup_ref": str(backup_ref or "").strip(),
                "destination": destinations[0] if destinations else None,
                "restore_mode": mode,
                "overrides": _normalize_restore_overrides(overrides),
            },
            context=context,
        )

    def validate_destination(self, *, destination: dict, context: dict) -> dict:
        destinations = _validate_destinations([destination])
        return _run(
            "validate_destination",
            {"destination": destinations[0]},
            context=context,
        )

    def validate_restore(self, *, backup_ref: str, destination: dict | None, restore_mode: str, context: dict, overrides: list[str] | None = None) -> dict:
        mode = str(restore_mode or "").strip().lower()
        if mode not in {"full", "tactical", "tec_tac"}:
            raise ServerBackupError("restore_mode must be full, tactical, or tec_tac.")
        destinations = _validate_destinations([destination]) if destination is not None else []
        return _run(
            "validate_restore",
            {
                "backup_ref": str(backup_ref or "").strip(),
                "destination": destinations[0] if destinations else None,
                "restore_mode": mode,
                "overrides": _normalize_validation_overrides(overrides),
            },
            context=context,
        )

    def apply_retention(self, *, policies: list[dict], context: dict) -> dict:
        if not isinstance(policies, list):
            raise ServerBackupError("policies must be a list.")
        normalized = []
        for raw in policies:
            if not isinstance(raw, dict):
                raise ServerBackupError("Each retention policy must be an object.")
            destination = raw.get("destination")
            if not isinstance(destination, dict):
                raise ServerBackupError("Each retention policy requires a destination object.")
            policy = {"destination": _validate_destinations([destination])[0]}
            for key in ("keep_daily", "keep_weekly", "keep_monthly", "keep_unclassified"):
                try:
                    value = int(raw.get(key, 0))
                except (TypeError, ValueError) as exc:
                    raise ServerBackupError(f"{key} must be an integer.") from exc
                if value < 0 or value > 10000:
                    raise ServerBackupError(f"{key} must be between 0 and 10000.")
                policy[key] = value
            normalized.append(policy)
        return _run("apply_retention", {"policies": normalized}, context=context)

    def store_secret(self, *, secret: dict, context: dict) -> str:
        if not isinstance(secret, dict) or not secret:
            raise ServerBackupError("secret must be a non-empty object.")
        # The transient job is mode 0600. The privileged helper moves the raw
        # value into a root-only secret file and redacts the job before worker
        # execution so credentials never appear in history/log responses.
        result = _run("store_secret", {"secret": dict(secret)}, context=context)
        secret_ref = str(result.get("secret_ref") or "")
        if not secret_ref:
            raise ServerBackupError("Core did not return a secret reference.", result=result)
        return secret_ref

    def delete_secret(self, *, secret_ref: str, context: dict) -> dict:
        return _run("delete_secret", {"secret_ref": str(secret_ref or "").strip()}, context=context)

    def health(self) -> dict:
        layout = load_layout()
        tactical_root = Path(layout.get("TACTICAL_ROOT") or "/rmm")
        helper_ok = HELPER.is_file()
        backup_script = tactical_root / "backup.sh"
        restore_script = tactical_root / "restore.sh"
        return {
            "healthy": bool(helper_ok and backup_script.is_file() and restore_script.is_file()),
            "helper": str(HELPER),
            "helper_available": helper_ok,
            "backup_script": str(backup_script),
            "backup_script_available": backup_script.is_file(),
            "restore_script": str(restore_script),
            "restore_script_available": restore_script.is_file(),
            "transports": sorted(DESTINATION_TYPES),
        }


_PROVIDER = ServerBackupProvider()


def register_core_server_backup_capability():
    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Privileged Tactical/Tec-Tac recovery-bundle backup, restore, remote transfer and retention operations.",
        health=_PROVIDER.health,
        operations=(
            "create_backup",
            "get_job_status",
            "list_backups",
            "restore_backup",
            "apply_retention",
            "validate_destination",
            "validate_restore",
            "store_secret",
            "delete_secret",
        ),
        metadata={
            "dangerous_operations": ["restore_backup"],
            "destination_types": sorted(DESTINATION_TYPES),
            "backup_classes": sorted(BACKUP_CLASSES),
            "recovery_modes": ["full", "tactical", "tec_tac"],
            "format_version": 2,
            "overrideable_restore_checks": ["target.os"],
        },
    )


def get_server_backup_provider() -> ServerBackupProvider:
    return _PROVIDER
