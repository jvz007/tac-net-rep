"""Live Tec-Tac public contract catalog and agent-friendly exports.

The catalog intentionally combines stable framework Python surfaces with
runtime-registered module capabilities, scheduler actions, extension
permissions and the authenticated /api/tfd/ HTTP boundary.
"""
from __future__ import annotations

from importlib import import_module
from inspect import signature
from pathlib import Path
from typing import Iterable

from django.utils import timezone

from .capabilities import list_capabilities
from .rbac import permission_catalog
from .registry import TEC_TAC_ROOT
from .scheduler import scheduled_actions, serialize_action


CORE_CONTRACTS = (
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "SchedulerPermanentError",
        "kind": "python",
        "purpose": "Signal a scheduled-action failure that should not consume configured retries.",
        "audience": "provider",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "SchedulerTransientError",
        "kind": "python",
        "purpose": "Signal a scheduled-action failure that may use configured retries.",
        "audience": "provider",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "register_scheduled_action",
        "kind": "python",
        "purpose": "Register a stable business action with the shared Tec-Tac Scheduler.",
        "audience": "provider",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "reconcile_schedule",
        "kind": "python",
        "purpose": "Idempotently create/update a backend-module-owned schedule using owner_module + owner_key.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "disable_owned_schedule",
        "kind": "python",
        "purpose": "Disable a backend-module-owned schedule without direct model access.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "remove_owned_schedule",
        "kind": "python",
        "purpose": "Remove an idle backend-module-owned schedule without direct model access.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "get_scheduled_action",
        "kind": "python",
        "purpose": "Resolve one registered scheduler action in the current backend process.",
        "audience": "framework/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "scheduled_actions",
        "kind": "python",
        "purpose": "Enumerate registered scheduler actions in the current backend process.",
        "audience": "framework/backend",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "register_capability",
        "kind": "python",
        "purpose": "Register a stable, versioned public cross-module backend contract.",
        "audience": "provider",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "get_capability",
        "kind": "python",
        "purpose": "Resolve another module's public backend contract without importing provider internals.",
        "audience": "consumer",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "has_capability",
        "kind": "python",
        "purpose": "Boolean runtime availability check for a public capability.",
        "audience": "consumer",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "capability_status",
        "kind": "python",
        "purpose": "Return structured missing/disabled/unhealthy/version-incompatible capability state.",
        "audience": "consumer/diagnostics",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "list_capabilities",
        "kind": "python",
        "purpose": "Enumerate registered capability metadata with live runtime state.",
        "audience": "diagnostics",
    },
    {
        "area": "capabilities",
        "import_path": "tec_tac.capabilities",
        "name": "build_operation_context",
        "kind": "python",
        "purpose": "Build common cross-module audit/source context for provider calls.",
        "audience": "consumer",
    },
    {
        "area": "registry",
        "import_path": "tec_tac.registry",
        "name": "get_plugin",
        "kind": "python",
        "purpose": "Inspect installed plugin identity and package version metadata.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "registry",
        "import_path": "tec_tac.registry",
        "name": "get_plugins",
        "kind": "python",
        "purpose": "Enumerate registered extensions/reportsets and compatibility plugins.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "module-state",
        "import_path": "tec_tac.module_state",
        "name": "is_enabled",
        "kind": "python",
        "purpose": "Check persisted module runtime enablement.",
        "audience": "backend",
    },
    {
        "area": "module-state",
        "import_path": "tec_tac.module_state",
        "name": "is_visible",
        "kind": "python",
        "purpose": "Check module navigation visibility; visibility is not service health.",
        "audience": "backend/UI plumbing",
    },
    {
        "area": "module-state",
        "import_path": "tec_tac.module_state",
        "name": "module_record",
        "kind": "python",
        "purpose": "Read persisted module state metadata.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "module-state",
        "import_path": "tec_tac.module_state",
        "name": "version_satisfies",
        "kind": "python",
        "purpose": "Evaluate Tec-Tac semantic-version constraints.",
        "audience": "backend",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "has_extension_permission",
        "kind": "python",
        "purpose": "Authoritative backend check for a declared Tec-Tac extension permission.",
        "audience": "backend",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "effective_permissions",
        "kind": "python",
        "purpose": "Return the authenticated user's effective Tec-Tac extension permissions.",
        "audience": "backend",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "registered_permissions",
        "kind": "python",
        "purpose": "Enumerate extension permission codenames registered by loaded modules.",
        "audience": "diagnostics",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "permission_groups",
        "kind": "python",
        "purpose": "Return declared permission groups for one extension.",
        "audience": "backend/administration",
    },
)

RULES = (
    "Use Python tec_tac.* contracts inside the Tec-Tac/Tactical backend; use HTTP only at browser/external process boundaries.",
    "Do not import another module's private models, helpers, services, filesystem layout or database tables.",
    "Resolve cross-module business operations through the capability registry and re-check runtime availability at execution time.",
    "Optional integrations must soft-fail only the dependent feature when a provider is missing, disabled, unhealthy or incompatible.",
    "Modules define WHAT can run; the shared Scheduler owns WHEN it runs, recurrence, retry, concurrency and history.",
    "Backend authorization is authoritative; frontend visibility is never a substitute for permission checks.",
    "One-off schedule definitions are operational state, not permanent history; the Scheduler may remove completed one-off definitions after the configured retention period while preserving run history.",
    "Scheduler handlers must distinguish permanent from transient failures so retries are not wasted on invalid parameters, unavailable contracts, or incompatible dependencies.",
    "Treat transport acknowledgement as transport state, not operation success; providers must verify downstream execution outcome before returning success.",
    "Scheduled handlers must propagate downstream execution failures so Scheduler history and retry semantics reflect the real result.",
    "When dispatching raw OS commands, build and test the command for the exact shell used by the agent; Windows cmd.exe quoting, especially Program Files paths, must be deliberate.",
)


def framework_version() -> str:
    try:
        return (TEC_TAC_ROOT / "VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _http_contracts() -> list[dict]:
    # Import lazily to avoid a module-import cycle while tec_tac.urls itself is
    # importing the contract views.
    from . import urls as tec_tac_urls

    rows = []
    for entry in tec_tac_urls.urlpatterns:
        route = str(getattr(entry, "pattern", ""))
        if not route:
            continue
        callback = getattr(entry, "callback", None)
        view_class = getattr(callback, "view_class", None)
        methods = []
        if view_class is not None:
            for method in ("get", "post", "put", "patch", "delete"):
                if method in view_class.__dict__:
                    methods.append(method.upper())
        rows.append(
            {
                "route": f"/api/tfd/{route}",
                "name": getattr(entry, "name", None),
                "methods": methods or ["GET"],
                "kind": "http",
                "audience": "browser/external",
            }
        )
    return sorted(rows, key=lambda row: row["route"])


def build_contract_catalog() -> dict:
    capabilities = list_capabilities()
    actions = [serialize_action(action) for action in scheduled_actions()]
    permissions = permission_catalog()
    http = _http_contracts()
    core = []
    for source in CORE_CONTRACTS:
        row = dict(source)
        try:
            obj = getattr(import_module(row["import_path"]), row["name"])
            row["signature"] = str(signature(obj)) if callable(obj) else ""
        except Exception as exc:
            row["signature"] = ""
            row["signature_error"] = f"{exc.__class__.__name__}: {exc}"
        core.append(row)
    return {
        "schema": 1,
        "framework_version": framework_version(),
        "generated_at": timezone.now().isoformat(),
        "rules": list(RULES),
        "core": core,
        "capabilities": capabilities,
        "scheduler_actions": actions,
        "permissions": permissions,
        "http": http,
        "counts": {
            "core": len(core),
            "capabilities": len(capabilities),
            "scheduler_actions": len(actions),
            "permission_modules": len(permissions),
            "http": len(http),
        },
    }


def _lines_table(rows: Iterable[tuple[str, ...]], widths: tuple[int, ...]) -> list[str]:
    rendered = []
    for row in rows:
        rendered.append("  ".join(str(value).ljust(width) for value, width in zip(row, widths)).rstrip())
    return rendered


def render_markdown(catalog: dict | None = None) -> str:
    data = catalog or build_contract_catalog()
    out = [
        "# Tec-Tac Public Contracts",
        "",
        f"Framework: **{data['framework_version']}**  ",
        f"Generated: `{data['generated_at']}`",
        "",
        "This document is generated from the live Tec-Tac framework and registered module contracts.",
        "",
        "## Development rules",
        "",
    ]
    out.extend(f"- {rule}" for rule in data["rules"])
    out.extend(["", "## Core Python contracts", "", "| Import | Function / signature | Audience | Purpose |", "| --- | --- | --- | --- |"])
    for row in data["core"]:
        out.append(f"| `{row['import_path']}` | `{row['name']}{row.get('signature') or '()'}` | {row['audience']} | {row['purpose']} |")

    out.extend(["", "## Registered capabilities", ""])
    if not data["capabilities"]:
        out.append("_No module capabilities are currently registered._")
    for row in data["capabilities"]:
        out.extend([
            f"### `{row['id']}`",
            "",
            f"- Provider module: `{row['module_id']}`",
            f"- Capability version: `{row.get('capability_version') or 'unknown'}`",
            f"- Installed module version: `{row.get('installed_version') or 'n/a'}`",
            f"- Runtime state: `{row.get('state')}`",
            f"- Available: `{str(bool(row.get('available'))).lower()}`",
            f"- Operations: {', '.join(f'`{op}`' for op in row.get('operations', [])) or '_not declared_'}",
            f"- Description: {row.get('description') or '_none_'}",
        ])
        if row.get("reason"):
            out.append(f"- Diagnostic: {row['reason']}")
        if row.get("metadata"):
            import json
            out.extend(["- Published metadata:", "", "```json", json.dumps(row["metadata"], indent=2, sort_keys=True, default=str), "```"])
        out.append("")

    out.extend(["## Schedulable actions", ""])
    if not data["scheduler_actions"]:
        out.append("_No scheduler actions are currently registered._")
    else:
        out.extend(["| Action | Module | Targets | Permission | Dangerous |", "| --- | --- | --- | --- | --- |"])
        for row in data["scheduler_actions"]:
            out.append(
                f"| `{row['id']}` | `{row['module_id']}` | "
                f"{', '.join(f'`{v}`' for v in row.get('target_types', []))} | "
                f"`{row.get('permission') or ''}` | `{str(bool(row.get('dangerous'))).lower()}` |"
            )

    out.extend(["", "## Extension permissions", ""])
    if not data["permissions"]:
        out.append("_No extension permission groups are registered._")
    for module in data["permissions"]:
        out.append(f"### `{module['id']}` package `{module['version']}`")
        out.append("")
        for group in module.get("groups", []):
            out.append(f"- **{group['name']}**: " + ", ".join(f"`{code}`" for code in group.get("permissions", [])))
        out.append("")

    out.extend(["## HTTP boundary", "", "Use these endpoints from the browser or an external process. Backend Tec-Tac modules should prefer the Python contracts above.", "", "| Methods | Endpoint | Route name |", "| --- | --- | --- |"])
    for row in data["http"]:
        out.append(f"| `{'/'.join(row['methods'])}` | `{row['route']}` | `{row.get('name') or ''}` |")

    out.extend([
        "",
        "## Capability consumer pattern",
        "",
        "```python",
        "from tec_tac.capabilities import get_capability, build_operation_context",
        "",
        "provider = get_capability(",
        '    "provider.capability",',
        '    version=">=1.0.0,<2.0.0",',
        "    required=False,",
        ")",
        "",
        "if provider is None:",
        "    # soft-fail only the optional integration feature",
        "    ...",
        "```",
        "",
        "## Scheduler provider pattern",
        "",
        "```python",
        "from tec_tac.scheduler import register_scheduled_action",
        "",
        "register_scheduled_action(",
        '    id="module.business-action",',
        '    module_id="module",',
        '    label="Business action",',
        "    handler=handler,",
        ")",
        "```",
        "",
        "Backend-owned recurring definitions should use `reconcile_schedule(...)` rather than importing TecTacSchedule directly.",
        "",
    ])
    return "\n".join(out)


def render_text(catalog: dict | None = None) -> str:
    data = catalog or build_contract_catalog()
    out = [
        "TEC-TAC PUBLIC CONTRACTS",
        f"Framework: {data['framework_version']}",
        f"Generated: {data['generated_at']}",
        "",
        "DEVELOPMENT RULES",
    ]
    out.extend(f"- {rule}" for rule in data["rules"])
    out.extend(["", "CORE PYTHON CONTRACTS"])
    for row in data["core"]:
        out.append(f"- {row['import_path']}.{row['name']}{row.get('signature') or '()'} [{row['audience']}] - {row['purpose']}")

    out.extend(["", "REGISTERED CAPABILITIES"])
    if not data["capabilities"]:
        out.append("- none")
    for row in data["capabilities"]:
        ops = ", ".join(row.get("operations", [])) or "not declared"
        out.append(
            f"- {row['id']} | module={row['module_id']} | capability={row.get('capability_version') or 'unknown'} | "
            f"package={row.get('installed_version') or 'n/a'} | state={row.get('state')} | operations={ops}"
        )
        if row.get("description"):
            out.append(f"  {row['description']}")
        if row.get("reason"):
            out.append(f"  diagnostic: {row['reason']}")
        if row.get("metadata"):
            import json
            out.append(f"  metadata: {json.dumps(row['metadata'], sort_keys=True, default=str)}")

    out.extend(["", "SCHEDULABLE ACTIONS"])
    if not data["scheduler_actions"]:
        out.append("- none")
    for row in data["scheduler_actions"]:
        out.append(
            f"- {row['id']} | module={row['module_id']} | targets={','.join(row.get('target_types', []))} | "
            f"permission={row.get('permission') or 'none'} | dangerous={str(bool(row.get('dangerous'))).lower()}"
        )

    out.extend(["", "EXTENSION PERMISSIONS"])
    if not data["permissions"]:
        out.append("- none")
    for module in data["permissions"]:
        out.append(f"- {module['id']} package {module['version']}")
        for group in module.get("groups", []):
            out.append(f"  {group['name']}: {', '.join(group.get('permissions', []))}")

    out.extend(["", "HTTP BOUNDARY"])
    for row in data["http"]:
        out.append(f"- {'/'.join(row['methods'])} {row['route']} ({row.get('name') or 'unnamed'})")

    out.extend([
        "",
        "RULE OF THUMB",
        "Python inside the Tec-Tac backend; HTTP at browser/external process boundaries.",
        "Capabilities are public cross-module business contracts. Scheduler actions expose WHAT can run; the Scheduler owns WHEN.",
        "",
    ])
    return "\n".join(out)
