"""Core-owned Tec-Tac troubleshooting and diagnostics service.

The diagnostics surface is intentionally read-only. It gathers framework,
Django, service, scheduler, module, capability, contract, audit and filesystem
state without repairing or mutating production state.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from django.apps import apps
from django.core import checks
from django.db import connection
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState

from .capabilities import list_capabilities
from .contracts import build_contract_catalog, framework_version
from .module_manager_v2 import installed_catalog_v2
from .scheduler import scheduler_health

STATUS_ORDER = {"pass": 0, "warning": 1, "fail": 2, "unknown": 1}


def _check(check_id: str, label: str, status: str, summary: str, *, details: Any = None, help_id: str | None = None, metadata: dict | None = None) -> dict:
    return {
        "id": check_id,
        "label": label,
        "status": status if status in STATUS_ORDER else "unknown",
        "summary": str(summary or ""),
        "details": details,
        "help_id": help_id,
        "metadata": dict(metadata or {}),
    }


def _section(section_id: str, label: str, checks_: list[dict]) -> dict:
    worst = "pass"
    for item in checks_:
        if STATUS_ORDER.get(item.get("status"), 1) > STATUS_ORDER.get(worst, 0):
            worst = item.get("status") or "unknown"
    return {"id": section_id, "label": label, "status": worst, "checks": checks_}


def _safe_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def _version_checks() -> list[dict]:
    framework = framework_version()
    ui_candidates = [
        Path(os.environ.get("TEC_TAC_UI_ROOT", "")) / "VERSION" if os.environ.get("TEC_TAC_UI_ROOT") else None,
        Path("/var/lib/tec-tac/ui/tec-tac/VERSION"),
        Path("/opt/tec-tac-ui/VERSION"),
    ]
    ui_version = None
    ui_path = None
    for candidate in ui_candidates:
        if candidate and candidate.is_file():
            ui_version = _safe_text(candidate)
            ui_path = str(candidate)
            if ui_version:
                break
    return [
        _check("core.version.framework", "Framework version", "pass" if framework != "unknown" else "warning", framework, metadata={"version": framework}),
        _check("core.version.ui", "UI version", "pass" if ui_version else "warning", ui_version or "UI VERSION file was not found from the backend runtime.", metadata={"version": ui_version, "path": ui_path}),
    ]


def _django_check() -> dict:
    messages = list(checks.run_checks())
    rows = []
    has_error = False
    has_warning = False
    for item in messages:
        level = int(getattr(item, "level", checks.INFO))
        has_error = has_error or level >= checks.ERROR
        has_warning = has_warning or level >= checks.WARNING
        rows.append({
            "id": getattr(item, "id", None),
            "level": level,
            "message": str(getattr(item, "msg", item)),
            "hint": getattr(item, "hint", None),
            "object": str(getattr(item, "obj", "") or ""),
        })
    status = "fail" if has_error else ("warning" if has_warning else "pass")
    summary = "System check identified no issues." if not rows else f"Django reported {len(rows)} system check item(s)."
    return _check("core.django.system-check", "Django system check", status, summary, details=rows, help_id="core.troubleshooting-diagnostics")


def _migration_changes() -> dict[str, list[dict]]:
    loader = MigrationLoader(connection, ignore_no_migrations=True)
    from_state = loader.project_state()
    to_state = ProjectState.from_apps(apps)
    changes = MigrationAutodetector(from_state, to_state).changes(graph=loader.graph)
    result: dict[str, list[dict]] = {}
    for app_label, migrations in changes.items():
        if app_label != "tec_tac" and not app_label.startswith("tec_tac_"):
            continue
        serialized = []
        for migration in migrations:
            ops = []
            for operation in migration.operations:
                try:
                    description = operation.describe()
                except Exception:
                    description = operation.__class__.__name__
                ops.append({"type": operation.__class__.__name__, "description": str(description)})
            serialized.append({"name": migration.name, "operations": ops})
        result[app_label] = serialized
    return result


def _migration_checks() -> list[dict]:
    try:
        changes = _migration_changes()
    except Exception as exc:
        return [_check("core.migrations.scan", "Migration drift scan", "fail", f"Migration drift detection failed: {exc.__class__.__name__}: {exc}")]

    core = changes.get("tec_tac", [])
    installed_module_apps = sorted(
        config.label for config in apps.get_app_configs()
        if config.label.startswith("tec_tac_")
    )
    module_drift = {name: changes[name] for name in installed_module_apps if name in changes}
    core_check = _check(
        "core.migrations.framework",
        "Core migrations",
        "fail" if core else "pass",
        f"{len(core)} migration(s) need to be committed for tec_tac." if core else "Core model state matches committed migrations.",
        details={"app": "tec_tac", "migrations": core},
        help_id="core.troubleshooting-migrations",
    )
    module_check = _check(
        "core.migrations.modules",
        "Module migrations",
        "warning" if module_drift else "pass",
        f"{len(module_drift)} installed module app(s) have migration drift." if module_drift else "Installed Tec-Tac module model state matches committed migrations.",
        details={"apps_checked": installed_module_apps, "drift": module_drift},
        help_id="core.troubleshooting-migrations",
    )
    return [core_check, module_check]


def _systemd_state(unit: str) -> dict:
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
        value = (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0] if (proc.stdout or proc.stderr) else "unknown"
        return {"unit": unit, "state": value, "returncode": proc.returncode}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"unit": unit, "state": "unknown", "error": f"{exc.__class__.__name__}: {exc}"}


def _service_check() -> dict:
    units = ["rmm", "daphne", "celery", "celerybeat", "tec-tac-scheduler.timer"]
    rows = [_systemd_state(unit) for unit in units]
    failed = [row for row in rows if row.get("state") not in {"active", "activating"}]
    unknown = [row for row in failed if row.get("state") == "unknown"]
    status = "pass" if not failed else ("warning" if len(unknown) == len(failed) else "fail")
    summary = f"{len(rows) - len(failed)} of {len(rows)} expected services/timers are active."
    return _check("core.services.runtime", "Runtime services", status, summary, details=rows, help_id="core.troubleshooting-diagnostics")


def _scheduler_check() -> dict:
    try:
        health = scheduler_health()
        tick = str(health.get("tick_health") or "unknown")
        status = "pass" if tick == "healthy" else ("fail" if tick == "degraded" else "warning")
        return _check("core.scheduler.health", "Scheduler health", status, f"Scheduler tick health is {tick}.", details=health, help_id="core.scheduler-configuration")
    except Exception as exc:
        return _check("core.scheduler.health", "Scheduler health", "fail", f"Scheduler diagnostics failed: {exc.__class__.__name__}: {exc}")


def _module_check() -> dict:
    try:
        modules = installed_catalog_v2()
    except Exception as exc:
        return _check("core.modules.runtime", "Module runtime", "fail", f"Module catalogue failed: {exc.__class__.__name__}: {exc}")
    problems = []
    rows = []
    for module in modules:
        if module.get("legacy"):
            continue
        dependency_problems = [item for item in module.get("dependency_status", []) if not (item.get("installed") and item.get("enabled") and item.get("satisfied"))]
        runtime_problems = [item for item in module.get("runtime_requirements", []) if not item.get("satisfied")]
        issue = bool(module.get("metadata_error") or dependency_problems or runtime_problems)
        if issue:
            problems.append(module.get("id"))
        rows.append({
            "id": module.get("id"),
            "version": module.get("extension_version"),
            "enabled": bool(module.get("enabled")),
            "visible": bool(module.get("visible")),
            "metadata_error": module.get("metadata_error"),
            "dependency_problems": dependency_problems,
            "runtime_problems": runtime_problems,
        })
    return _check(
        "core.modules.runtime",
        "Module runtime",
        "warning" if problems else "pass",
        f"{len(problems)} module(s) have dependency/runtime problems." if problems else f"{len(rows)} managed module(s) inspected without dependency/runtime problems.",
        details=rows,
        help_id="core.modules",
    )


def _capability_check(*, live: bool) -> dict:
    try:
        rows = list_capabilities(check_health=live)
    except Exception as exc:
        return _check("core.capabilities.registry", "Capabilities", "fail", f"Capability discovery failed: {exc.__class__.__name__}: {exc}")
    unavailable = [row for row in rows if not row.get("available")]
    unhealthy = [row for row in unavailable if row.get("state") == "unhealthy"]
    status = "warning" if unavailable else "pass"
    suffix = "live provider health included" if live else "metadata-only; provider health not probed"
    summary = f"{len(rows)} capabilities registered; {len(unavailable)} unavailable ({suffix})."
    return _check(
        "core.capabilities.registry",
        "Capabilities",
        status,
        summary,
        details=rows,
        metadata={"live_health": live, "unavailable": len(unavailable), "unhealthy": len(unhealthy)},
        help_id="core.public-contracts",
    )


def _contract_check() -> dict:
    try:
        catalog = build_contract_catalog()
        return _check(
            "core.contracts.catalog",
            "Public Contracts",
            "pass",
            f"Contract catalogue generated for Framework {catalog.get('framework_version')}; {catalog.get('counts', {}).get('http', 0)} HTTP routes published.",
            details={"framework_version": catalog.get("framework_version"), "counts": catalog.get("counts")},
            help_id="core.public-contracts",
        )
    except Exception as exc:
        return _check("core.contracts.catalog", "Public Contracts", "fail", f"Contract catalogue generation failed: {exc.__class__.__name__}: {exc}")


def _audit_check() -> dict:
    try:
        from logs.models import AuditLog
        from .audit import record
        fields = {field.name for field in AuditLog._meta.get_fields()}
        required = {"username", "action", "object_type", "before_value", "after_value", "message", "debug_info"}
        missing = sorted(required - fields)
        if missing:
            return _check("core.audit.contract", "Audit write contract", "fail", "Tactical AuditLog is missing fields required by the Tec-Tac audit contract.", details={"missing_fields": missing})
        return _check("core.audit.contract", "Audit write contract", "pass", "Core audit writer and Tactical AuditLog compatibility are available.", details={"writer": f"{record.__module__}.{record.__name__}", "required_fields": sorted(required)}, help_id="core.public-contracts")
    except Exception as exc:
        return _check("core.audit.contract", "Audit write contract", "fail", f"Audit contract inspection failed: {exc.__class__.__name__}: {exc}")


def _helper_check() -> dict:
    paths = [
        "/usr/local/sbin/tec-tac-module-job",
        "/usr/local/sbin/tec-tac-module-v2-job",
        "/usr/local/sbin/tec-tac-module-hotfix",
        "/usr/local/sbin/tec-tac-system-update",
        "/usr/local/sbin/tec-tac-server-backup",
        "/usr/local/sbin/tec-tac-server-maintenance",
        "/usr/local/sbin/tec-tac-housekeeping",
    ]
    rows = []
    for raw in paths:
        path = Path(raw)
        rows.append({"path": raw, "exists": path.is_file(), "executable": os.access(path, os.X_OK) if path.exists() else False})
    bad = [row for row in rows if not row["exists"] or not row["executable"]]
    return _check("core.helpers.privileged", "Privileged helpers", "fail" if bad else "pass", f"{len(rows) - len(bad)} of {len(rows)} Core helper entrypoints are present and executable.", details=rows, help_id="core.troubleshooting-diagnostics")


def _storage_check() -> dict:
    path = Path("/opt/tec-tac")
    try:
        usage = shutil.disk_usage(path if path.exists() else "/")
        free_pct = (usage.free / usage.total * 100) if usage.total else 0.0
        status = "fail" if free_pct < 5 else ("warning" if free_pct < 15 else "pass")
        roots = [Path("/var/lib/tec-tac/module-manager"), Path("/var/lib/tec-tac/system-updates")]
        writable = [{"path": str(root), "exists": root.exists(), "writable": os.access(root, os.W_OK) if root.exists() else False} for root in roots]
        if any(row["exists"] and not row["writable"] for row in writable):
            status = "fail"
        return _check(
            "core.storage.runtime",
            "Runtime storage",
            status,
            f"{free_pct:.1f}% disk space free on the Tec-Tac filesystem.",
            details={"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free, "free_percent": round(free_pct, 1), "paths": writable},
            help_id="core.storage",
        )
    except Exception as exc:
        return _check("core.storage.runtime", "Runtime storage", "fail", f"Storage diagnostics failed: {exc.__class__.__name__}: {exc}")


def diagnostic_report(*, live_capabilities: bool = False) -> dict:
    """Return a read-only Core troubleshooting report.

    Capability provider health is metadata-only by default so a slow external
    provider cannot block the diagnostics page. Live provider health runs only
    when explicitly requested by an authorized operator.
    """
    sections = [
        _section("versions", "Framework & UI", _version_checks()),
        _section("django", "Django & database", [_django_check(), *_migration_checks()]),
        _section("runtime", "Runtime services", [_service_check(), _scheduler_check(), _helper_check()]),
        _section("modules", "Modules & capabilities", [_module_check(), _capability_check(live=live_capabilities)]),
        _section("contracts", "Contracts & audit", [_contract_check(), _audit_check()]),
        _section("storage", "Storage", [_storage_check()]),
    ]
    checks_flat = [item for section in sections for item in section["checks"]]
    counts = {key: sum(1 for item in checks_flat if item.get("status") == key) for key in ("pass", "warning", "fail", "unknown")}
    overall = "fail" if counts["fail"] else ("warning" if counts["warning"] or counts["unknown"] else "pass")
    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "live_capabilities": bool(live_capabilities),
        "counts": counts,
        "sections": sections,
    }
