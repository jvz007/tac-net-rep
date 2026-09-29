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
from .reporting import list_reporting_models
from .registry import TEC_TAC_ROOT
from .scheduler import scheduled_actions, serialize_action
from .resources import resource_contract_metadata


CORE_RESOURCE_CONTRACTS = (
    {"area":"resources","import_path":"tec_tac.resources","name":"user_context","kind":"python","purpose":"Create a Resource Directory authority context from an authenticated Tactical user.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"trusted_service_context","kind":"python","purpose":"Create an explicit trusted non-interactive Resource Directory context; global access is never implicit.","audience":"trusted backend/service"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_clients","kind":"python","purpose":"List Tactical clients through the stable scoped Core Resource Directory.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_client","kind":"python","purpose":"Resolve one scoped Tactical client as a stable Core record.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"create_client","kind":"python","purpose":"Create a Tactical client through the Core resource write boundary.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_client","kind":"python","purpose":"Update a scoped Tactical client through the Core resource write boundary.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"delete_client","kind":"python","purpose":"Delete a scoped Tactical client after atomically relocating its agents when required.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_sites","kind":"python","purpose":"List Tactical sites globally or by client through the stable scoped Core Resource Directory.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_site","kind":"python","purpose":"Resolve one scoped Tactical site as a stable Core record.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"create_site","kind":"python","purpose":"Create a Tactical site inside the caller's client scope through Core.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_site","kind":"python","purpose":"Update a scoped Tactical site through the Core resource write boundary.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"delete_site","kind":"python","purpose":"Delete a scoped Tactical site after atomically relocating its agents within the same client when required.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_custom_fields","kind":"python","purpose":"List editable Tactical custom-field definitions and values for a scoped client or site.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_custom_fields","kind":"python","purpose":"Update scoped client/site Tactical custom-field values through Core validation and audit.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_agents","kind":"python","purpose":"List Tactical agents globally or by client/site through the stable scoped Core Resource Directory.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_agent","kind":"python","purpose":"Resolve one scoped Tactical agent using its stable agent_id.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"resolve_resource","kind":"python","purpose":"Resolve a client, site or agent through one generic Core operation.","audience":"consumer/backend"},
)

CORE_CONTRACTS = (
    {
        "area": "publisher-trust",
        "import_path": "tec_tac.trusted_publishers",
        "name": "list_trusted_publishers",
        "kind": "python",
        "purpose": "List root-managed trusted publisher policy metadata without exposing private signing material.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "publisher-trust",
        "import_path": "tec_tac.trusted_publishers",
        "name": "verify_release_files",
        "kind": "python",
        "purpose": "Verify exact package bytes, detached Ed25519 signature and local publisher policy before installation.",
        "audience": "framework/internal",
    },
    {
        "area": "audit",
        "import_path": "tec_tac.audit",
        "name": "record",
        "kind": "python",
        "purpose": "Record a Tec-Tac module event through Core into Tactical's unified AuditLog trail.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "register_reporting_model",
        "kind": "python",
        "purpose": "Register a module-owned Django model with Tactical Report Manager through Core.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "unregister_reporting_model",
        "kind": "python",
        "purpose": "Remove a module reporting-model registration and resynchronize Tactical runtime state.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "list_reporting_models",
        "kind": "python",
        "purpose": "List registered report-facing models with provider and availability metadata.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "reporting_model_status",
        "kind": "python",
        "purpose": "Return live availability for one public reporting-model registration.",
        "audience": "backend/diagnostics",
    },
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
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "get_effective_policy",
        "kind": "python",
        "purpose": "Return the Core-owned effective Tec-Tac session security policy.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "list_sessions",
        "kind": "python",
        "purpose": "List safe server-side Tec-Tac session records without exposing token fingerprints.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "list_audit_events",
        "kind": "python",
        "purpose": "Read sanitized Core session-security audit events for administration/reporting modules.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "page_audit_events",
        "kind": "python",
        "purpose": "Read one bounded page of sanitized Core session-security audit events with total-count metadata.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "revoke_session",
        "kind": "python",
        "purpose": "Revoke one Core Tec-Tac session independently of Tactical token validity.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "revoke_user_sessions",
        "kind": "python",
        "purpose": "Revoke a user's Core sessions, optionally preserving one current session.",
        "audience": "provider/backend",
    },
    {
        "area": "session-security",
        "import_path": "tec_tac.session_security",
        "name": "SessionAuthenticated",
        "kind": "python",
        "purpose": "DRF permission enforcing Tactical authentication plus Core Tec-Tac session trust.",
        "audience": "provider/backend",
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

HTTP_CONTRACT_DETAILS = {
    "/api/tfd/account/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; self only",
            "response": {
                "account": "current Tactical user identity and SSO/TOTP state",
                "mfa": "current Tec-Tac backup-code status",
                "tactical_ui": "current Tactical agent double-click/default URL Action preferences plus allowed choices",
            },
        },
    },
    "/api/tfd/account/password/": {
        "PUT": {
            "authorization": "authenticated local Tec-Tac session; self only; current-password proof required",
            "request": {"current_password": "current local password", "new_password": "new password accepted by Django password validators"},
            "response": {"changed": True, "other_sessions_revoked": "integer"},
            "errors": {"400": "SSO-managed account, rejected current password, or invalid new password"},
        },
    },
    "/api/tfd/account/totp/reset/": {
        "POST": {
            "authorization": "authenticated local Tec-Tac session; self only; current password + current TOTP proof required",
            "request": {"current_password": "current local password", "current_totp": "current authenticator code"},
            "response": {"reset": True, "reauthentication_required": True, "sessions_revoked": "integer"},
            "semantics": "clears Tactical TOTP secret, invalidates Tec-Tac backup codes, revokes every active session; normal sign-in performs fresh enrollment",
            "errors": {"400": "SSO-managed account, TOTP not configured, or proof rejected"},
        },
    },
    "/api/tfd/account/tactical-ui/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; self only",
            "response": {"preferences": "Tactical agent_dblclick_action/url_action plus current valid choices"},
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session; self only",
            "request": {"agent_dblclick_action": "one of Tactical's current model choices", "url_action_id": "integer|null"},
            "response": {"preferences": "updated Tactical UI preferences"},
            "errors": {"400": "unknown field, unsupported action, missing URL Action, or URL Action permission denied"},
        },
    },
    "/api/tfd/modules/v2/jobs/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "status": "optional string", "action": "optional string", "search": "optional string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/session/audit/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "username": "optional string", "event_type": "optional string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/access/sessions/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "search": "optional username/IP string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/scheduler/runs/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "status": "optional string", "search": "optional string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/access/security-policy/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with account-security administration permission",
            "response": {
                "policy": {
                    "schema": "integer policy schema version",
                    "protect_superuser_accounts": "boolean",
                    "updated_at": "UTC timestamp",
                    "updated_by": "actor username",
                },
                "can_change": "boolean; true only for an effective superuser",
            },
            "errors": {
                "403": "account-security administration permission denied",
                "500": "root-owned policy could not be read",
            },
        },
        "PUT": {
            "authorization": "effective Tactical superuser",
            "request": {"protect_superuser_accounts": "boolean"},
            "response": {
                "policy": {
                    "schema": "integer policy schema version",
                    "protect_superuser_accounts": "boolean",
                    "updated_at": "UTC timestamp",
                    "updated_by": "actor username",
                },
                "can_change": True,
            },
            "errors": {
                "400": "missing/invalid boolean or privileged policy helper validation failure",
                "403": "effective-superuser authority required",
                "500": "strict Core audit failed and the requested policy change was rolled back/fail-closed",
            },
        },
    },
    "/api/tfd/system/backups/restore/": {
        "GET": {
            "authorization": "effective Tactical superuser with a valid Tec-Tac session",
            "response": {"destinations": "array of server-registered backup destinations; browser cannot supply arbitrary destination configuration"},
            "errors": {"403": "effective-superuser authority required"},
        },
        "POST": {
            "authorization": "effective Tactical superuser with a valid Tec-Tac session",
            "request": {
                "action": "list|validate|restore",
                "destination_ids": "list action: array of registered destination ids",
                "backup_ref": "validate/restore: selected backup reference",
                "destination_id": "validate/restore: registered destination id",
                "restore_mode": "full|tactical|tec_tac",
                "validation_job_id": "restore only: successful matching validation job id",
                "overrides": "validate: array of check ids; restore: object mapping check ids to audit ids",
                "confirmed": "restore only: literal true",
            },
            "response": {"job_id": "UUID", "status": "queued/dispatched job state"},
            "errors": {
                "400": "invalid action/input, missing explicit confirmation, or validation mismatch",
                "403": "effective-superuser authority required",
            },
        },
    },
    "/api/tfd/system/backups/restore/jobs/<uuid:job_id>/": {
        "GET": {
            "authorization": "effective Tactical superuser with a valid Tec-Tac session",
            "response": {
                "job": {
                    "job_id": "UUID",
                    "action": "list_registered_backups|validate_registered_restore|restore_registered_backup",
                    "status": "queued|dispatched|running|succeeded|failed",
                    "request": "sanitized job request metadata",
                    "result": "operation result; validation includes recovery signer/source identity and version_transition",
                    "error": "sanitized error text when failed",
                }
            },
            "errors": {"403": "effective-superuser authority required or job is not a native Backup & Restore UI job"},
        },
    },
    "/api/tfd/system/updates/trust-policy/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session",
            "response": {
                "minimum_level": "unsigned|signed_development|signed_production|secure_signed",
                "minimum_label": "display label for the current floor",
                "levels": "ordered trust-level metadata",
                "environment": "production|development",
                "help_article": "core.trust-policy",
                "help_url": "compatible help URL",
            },
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session with trust-policy authority",
            "request": {"minimum_level": "unsigned|signed_development|signed_production|secure_signed"},
            "responses": {
                "applied": {
                    "shape": "effective trust-policy object",
                    "meaning": "requested level was applied through the privileged helper",
                },
                "console_required": {
                    "status": "console_required",
                    "requested_level": "requested lower trust level",
                    "environment": "production|development",
                    "command": "root-console command that must be run explicitly",
                    "help_article": "core.trust-policy",
                    "help_url": "compatible help URL",
                },
            },
        },
    },
    "/api/tfd/system/recovery/trust/": {
        "GET": {
            "authorization": "effective Tactical superuser",
            "query": {"job_id": "optional recovery-trust job UUID"},
            "response": {
                "identity": "installation/server recovery signer metadata when job_id is absent",
                "job": "sanitized asynchronous recovery-trust job status when job_id is present",
                "can_trust_signer": "boolean",
            },
        },
        "POST": {
            "authorization": "effective Tactical superuser",
            "request": {
                "backup_ref": "string",
                "destination_id": "previously validated Core destination id",
                "expected_key_id": "confirmed signer key id",
                "expected_fingerprint": "confirmed signer SHA-256 fingerprint",
                "expected_server_name": "confirmed source server name",
                "expected_installation_id": "confirmed source installation id",
            },
            "response": {"job_id": "UUID", "status": "queued", "action": "trust_recovery_signer"},
            "status": 202,
        },
    },
}


BROWSER_CONTRACTS = (
    {
        "id": "ui.authenticated.transport",
        "phase": "authenticated",
        "service": "api",
        "operations": ["api", "apiRaw", "apiBlob", "apiText"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Use Core-owned authenticated browser transport without reading Tactical tokens or authentication storage.",
    },
    {
        "id": "ui.authenticated.audit",
        "phase": "authenticated",
        "service": "audit",
        "operations": ["record"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-audit.md",
        "purpose": "Write module audit events through Core instead of Tactical AuditLog internals.",
    },
    {
        "id": "ui.authenticated.context-actions",
        "phase": "authenticated",
        "service": "contextActions",
        "operations": ["register", "list", "execute", "clear"],
        "placements": ["client.context-menu", "site.context-menu", "endpoint.context-menu", "alert.context-menu", "patch.context-menu"],
        "context": {
            "client.context-menu": ["resource_type", "resource", "client", "selection"],
            "site.context-menu": ["resource_type", "resource", "site", "client", "selection"],
        },
        "audience": "provider/consumer browser",
        "docs": "tec-tac-ui/docs/context-actions.md",
        "purpose": "Contribute and consume resource actions through stable shared placements without importing provider UI internals.",
    },
    {
        "id": "ui.authenticated.context-interactions",
        "phase": "authenticated",
        "service": "contextInteractions",
        "operations": ["register", "list", "execute", "clear"],
        "audience": "provider/consumer browser",
        "docs": "tec-tac-ui/docs/context-interactions.md",
        "purpose": "Contribute and consume cross-module drag/drop interactions through shared surfaces.",
    },
    {
        "id": "ui.authenticated.resource-views",
        "phase": "authenticated",
        "service": "resourceViews",
        "operations": ["register", "list", "clear"],
        "audience": "provider/consumer browser",
        "docs": "tec-tac-ui/docs/module-resource-views.md",
        "purpose": "Render optional module-owned visual contributions on consumer-owned resource placements.",
    },
    {
        "id": "ui.authenticated.code-editor",
        "phase": "authenticated",
        "service": "codeEditor",
        "operations": ["create", "createModel", "registerCompletionProvider", "registerHoverProvider", "registerDiagnosticsProvider", "clear"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-code-editor.md",
        "purpose": "Use Core-owned shared editor infrastructure without importing Monaco or Tactical editor internals.",
    },
    {
        "id": "ui.authenticated.dashboard-widgets",
        "phase": "authenticated",
        "service": "dashboardWidgets",
        "operations": ["register", "list", "clear"],
        "audience": "provider/browser",
        "docs": "tec-tac-ui/docs/module-dashboard-widgets.md",
        "purpose": "Contribute module widgets while Core owns dashboard layout, persistence and visibility.",
    },
    {
        "id": "ui.authenticated.quick-actions",
        "phase": "authenticated",
        "service": "quickActions",
        "operations": ["register", "pin", "pinAction", "listPins", "listCatalog", "clear"],
        "audience": "provider/browser",
        "docs": "tec-tac-ui/docs/module-quick-actions.md",
        "purpose": "Expose module-owned operator actions through Core-owned personal Quick Actions.",
    },
    {
        "id": "ui.authenticated.notifications",
        "phase": "authenticated",
        "service": "notifications",
        "operations": ["info", "success", "warning", "error", "show", "dismiss", "clear"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-notifications.md",
        "purpose": "Show bounded in-app operator notices without creating another notification surface.",
    },
    {
        "id": "ui.authenticated.help",
        "phase": "authenticated",
        "service": "help",
        "operations": ["register", "open", "clear"],
        "audience": "provider/browser",
        "docs": "tec-tac-ui/docs/module-help.md",
        "purpose": "Contribute module help articles to the Core Help and Knowledge Base surfaces.",
    },
    {
        "id": "ui.authenticated.header",
        "phase": "authenticated",
        "service": "header",
        "operations": ["register", "list", "clear"],
        "audience": "provider/browser",
        "docs": "tec-tac-ui/docs/module-header.md",
        "purpose": "Contribute compact module-owned components such as an Alerts bell to the Core top bar.",
    },
    {
        "id": "ui.authenticated.module-status",
        "phase": "authenticated",
        "service": "modules",
        "operations": ["list", "get", "isInstalled", "isEnabled"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-status.md",
        "purpose": "Inspect installed/enabled module state without additional HTTP calls; backend capability checks remain authoritative.",
    },
    {
        "id": "ui.authenticated.runtime-context",
        "phase": "authenticated",
        "service": "context / state.context",
        "operations": ["read", "tactical_ui.agent_dblclick_action", "tactical_ui.url_action_id", "tactical_ui.can_run_url_actions"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Read the Core-provided authenticated register(context).context object (also available as state.context), including permissions, preferences and Tactical UI preferences; treat it as read-only state.",
    },
    {
        "id": "ui.public.sso-providers",
        "phase": "public",
        "service": "ssoProviders",
        "operations": ["register", "list", "begin", "clear"],
        "audience": "provider/public-browser",
        "docs": "tec-tac-ui/docs/module-sso.md",
        "purpose": "Contribute sign-in providers from registerPublic(context) before Tactical authentication exists.",
    },
    {
        "id": "ui.public.module-runtime",
        "phase": "public",
        "service": "registerPublic(context)",
        "operations": ["publicApi", "addPublicRoute", "ssoProviders"],
        "audience": "module/public-browser",
        "docs": "tec-tac-ui/docs/module-sso.md",
        "purpose": "Expose bounded anonymous module routes and public API calls without Tactical credentials or authenticated runtime state.",
    },
)

RULES = (
    "Use Python tec_tac.* contracts inside the Tec-Tac/Tactical backend; use HTTP only at browser/external process boundaries.",
    "UI modules must use the documented browser contracts passed to register(context) or registerPublic(context); do not import Core UI internals or read Tactical authentication storage.",
    "Swagger grouping is Core-owned: installed extension endpoints are grouped from their registered Django app ownership even when the URL prefix differs from the module ID; unknown Tec-Tac prefixes fall back to the Framework group rather than being guessed as modules.",
    "Do not import another module's private models, helpers, services, filesystem layout or database tables.",
    "Feature modules must consume Tactical clients/sites/agents through tec_tac.resources; direct Tactical resource-model imports are a Core-only compatibility boundary.",
    "Resolve cross-module business operations through the capability registry and re-check runtime availability at execution time.",
    "Optional integrations must soft-fail only the dependent feature when a provider is missing, disabled, unhealthy or incompatible.",
    "Modules define WHAT can run; the shared Scheduler owns WHEN it runs, recurrence, retry, concurrency and history.",
    "Backend authorization is authoritative; frontend visibility is never a substitute for permission checks.",
    "Tec-Tac authenticated backend endpoints must use the Core session-security guard; Tactical token validity alone is not sufficient for Tec-Tac trust.",
    "Report-facing module models must register through tec_tac.reporting; modules must not import or mutate ee.reporting internals or Tactical schema files.",
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
        row = {
            "route": f"/api/tfd/{route}",
            "name": getattr(entry, "name", None),
            "methods": methods or ["GET"],
            "kind": "http",
            "audience": "browser/external",
        }
        detail = HTTP_CONTRACT_DETAILS.get(row["route"])
        if detail:
            row["contract"] = detail
        rows.append(row)
    return sorted(rows, key=lambda row: row["route"])


def build_contract_catalog() -> dict:
    # Contract discovery must be side-effect free and fast. Capability health
    # callbacks can perform provider/network I/O, so do not execute them while
    # rendering documentation or during framework install verification.
    capabilities = list_capabilities(check_health=False)
    actions = [serialize_action(action) for action in scheduled_actions()]
    permissions = permission_catalog()
    reporting_models = list_reporting_models()
    http = _http_contracts()
    browser = [dict(row) for row in BROWSER_CONTRACTS]
    core = []
    for source in (*CORE_RESOURCE_CONTRACTS, *CORE_CONTRACTS):
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
        "browser": browser,
        "capabilities": capabilities,
        "scheduler_actions": actions,
        "permissions": permissions,
        "reporting_models": reporting_models,
        "http": http,
        "resource_directory": resource_contract_metadata(),
        "counts": {
            "core": len(core),
            "browser": len(browser),
            "capabilities": len(capabilities),
            "scheduler_actions": len(actions),
            "permission_modules": len(permissions),
            "reporting_models": len(reporting_models),
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

    out.extend(["", "## Browser / UI module contracts", "", "These contracts are supplied by the Tec-Tac UI runtime. They are stable integration surfaces even when no provider modules are currently registered.", "", "| Contract | Phase | Service | Operations | Audience | Canonical docs | Purpose |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for row in data.get("browser", []):
        operations = ", ".join(f"`{op}`" for op in row.get("operations", [])) or "_none_"
        out.append(f"| `{row['id']}` | `{row['phase']}` | `{row['service']}` | {operations} | {row['audience']} | `{row['docs']}` | {row['purpose']} |")

    resource = data.get("resource_directory") or {}
    if resource:
        out.extend(["", "## Core Resource Directory", "", f"Contract: **`{resource.get('id')}`** version **`{resource.get('version')}`**  ", f"Namespace: **`{resource.get('namespace')}`**  ", f"Read-only: **`{str(bool(resource.get('read_only'))).lower()}`**", ""])
        out.append("Backend modules should import `tec_tac.resources` directly. Browser/external callers use the `/api/tfd/resources/...` HTTP representation. Raw Tactical ORM objects are never part of this contract.")
        out.extend(["", "### Resource shapes", "", "| Type | Public ID | Stable fields | Filters | Writes |", "| --- | --- | --- | --- | --- |"] )
        for rtype, spec in (resource.get("resource_types") or {}).items():
            writes = (resource.get("write_support") or {}).get(rtype) or []
            out.append(f"| `{rtype}` | `{spec.get('id_type')}` | {', '.join(f'`{v}`' for v in spec.get('fields', []))} | {', '.join(f'`{v}`' for v in spec.get('filters', []))} | {', '.join(f'`{v}`' for v in writes) or '_none_'} |")
        out.extend(["", "### Authorization", "", f"- Interactive reads: {resource.get('authorization', {}).get('interactive')}", f"- Service reads: {resource.get('authorization', {}).get('service')}", f"- Writes: {resource.get('authorization', {}).get('write')}"])
        pagination = resource.get("pagination") or {}
        if pagination:
            out.extend([
                "",
                "### Pagination",
                "",
                f"- Default page size: `{pagination.get('default_page_size')}`",
                f"- Maximum page size: `{pagination.get('maximum_page_size')}`",
                f"- Maximum page number: `{pagination.get('maximum_page_number')}`",
            ])
        list_contracts = resource.get("list_contracts") or {}
        if list_contracts:
            out.extend(["", "### List contracts", "", "| Resource | HTTP | Query | Response |", "| --- | --- | --- | --- |"] )
            for name, spec in list_contracts.items():
                query = ", ".join(f"`{key}`={value}" for key, value in (spec.get("query") or {}).items())
                response = ", ".join(f"`{key}`={value}" for key, value in (spec.get("response") or {}).items())
                out.append(f"| `{name}` | `{spec.get('http')}` | {query} | {response} |")
        mutation_contracts = resource.get("mutation_contracts") or {}
        if mutation_contracts:
            out.extend(["", "### Mutation contracts", "", "| Operation | HTTP | Semantics |", "| --- | --- | --- |"] )
            for name, spec in mutation_contracts.items():
                out.append(f"| `{name}` | `{spec.get('http')}` | {spec.get('semantics') or spec.get('response') or ''} |")
        if resource.get("rbac"):
            out.extend(["", "### Resource write RBAC", ""] )
            for name, codename in resource.get("rbac", {}).items():
                out.append(f"- `{name}`: `{codename}`")
        out.extend(["", "### Error semantics", ""] )
        for code, description in (resource.get("errors") or {}).items():
            out.append(f"- `{code}` — {description}")
        out.extend(["", f"Active-state semantics: {resource.get('active_semantics')}", "", f"Compatibility: {resource.get('compatibility')}", ""])

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

    out.extend(["## Registered reporting models", ""])
    if not data.get("reporting_models"):
        out.append("_No Tec-Tac reporting models are currently registered._")
    else:
        out.extend(["| Reporting ID | Provider | Django model | State | Fields | Description |", "| --- | --- | --- | --- | --- | --- |"])
        for row in data["reporting_models"]:
            fields = ", ".join(f"`{field}`" for field in row.get("queryable_fields", [])) or "_none_"
            out.append(
                f"| `{row['id']}` | `{row['module_id']}` | `{row['app_label']}.{row['model']}` | "
                f"`{row.get('state')}` | {fields} | {row.get('description') or ''} |"
            )

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

    out.extend(["", "BROWSER / UI MODULE CONTRACTS"])
    for row in data.get("browser", []):
        operations = ",".join(row.get("operations", [])) or "none"
        out.append(
            f"- {row['id']} | phase={row['phase']} | service={row['service']} | "
            f"operations={operations} | audience={row['audience']} | docs={row['docs']} - {row['purpose']}"
        )

    resource = data.get("resource_directory") or {}
    if resource:
        out.extend(["", "CORE RESOURCE DIRECTORY"])
        out.append(f"- contract={resource.get('id')} version={resource.get('version')} namespace={resource.get('namespace')} read_only={str(bool(resource.get('read_only'))).lower()}")
        for rtype, spec in (resource.get("resource_types") or {}).items():
            writes = ','.join((resource.get("write_support") or {}).get(rtype) or []) or 'none'
            out.append(f"  {rtype}: id={spec.get('id_type')} fields={','.join(spec.get('fields', []))} filters={','.join(spec.get('filters', []))} writes={writes}")
        out.append(f"  interactive_auth: {resource.get('authorization', {}).get('interactive')}")
        out.append(f"  service_auth: {resource.get('authorization', {}).get('service')}")
        out.append(f"  write_auth: {resource.get('authorization', {}).get('write')}")
        pagination = resource.get("pagination") or {}
        if pagination:
            out.append(
                f"  pagination: default={pagination.get('default_page_size')} max_size={pagination.get('maximum_page_size')} max_page={pagination.get('maximum_page_number')}"
            )
        for name, spec in (resource.get("list_contracts") or {}).items():
            query = ",".join(f"{key}={value}" for key, value in (spec.get("query") or {}).items())
            response = ",".join(f"{key}={value}" for key, value in (spec.get("response") or {}).items())
            out.append(f"  list.{name}: {spec.get('http')} query[{query}] response[{response}]")
        for name, codename in (resource.get("rbac") or {}).items():
            out.append(f"  rbac.{name}: {codename}")
        for code, description in (resource.get("errors") or {}).items():
            out.append(f"  error {code}: {description}")

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

    out.extend(["", "REGISTERED REPORTING MODELS"])
    if not data.get("reporting_models"):
        out.append("- none")
    for row in data.get("reporting_models", []):
        fields = ",".join(row.get("queryable_fields", [])) or "none"
        out.append(
            f"- {row['id']} | module={row['module_id']} | model={row['app_label']}.{row['model']} | "
            f"state={row.get('state')} | fields={fields}"
        )

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
