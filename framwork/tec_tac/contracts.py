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
        "purpose": "Record a Tec-Tac module event through Core into Tactical's unified AuditLog trail. Since 1.17.6 operation_context may not carry browser_provenance or core_refusal, and since 1.17.7 server_provenance: they are Core-owned and give a contract error. For a Tactical call use a registered Tactical operation (core.tactical_operations) so Core writes the row where the call happens. Core's own writers (record_browser_declared, record_core_refusal and, since 1.17.8, the private _record_tactical_operation) are Core-internal and not callable by modules.",
        "audience": "provider/backend",
    },
    {
        "area": "audit",
        "import_path": "tec_tac.audit",
        "name": "service_audit_actor",
        "kind": "python",
        "purpose": "Create Core-owned service/system provenance for scheduled and background audit events without fake Tactical users.",
        "audience": "provider/backend",
    },
    {
        "area": "audit",
        "import_path": "tec_tac.audit",
        "name": "device_audit_actor",
        "kind": "python",
        "purpose": "Create Core-owned device/probe provenance for callback audit events without fake Tactical users.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "register_reporting_model",
        "kind": "python",
        "purpose": "Register a module-owned Django model with Tactical Report Manager through Core. 1.17.4: new optional hidden_fields (list of field or property names that Report Manager hides and refuses; Core's own bridge cannot hide columns, so such a model is served only through Report Manager). Status rows gain hidden_fields, forwarded and row_scope. This is now a shim over reportmanager.registry (AD-15): when Report Manager 0.3.0 or later is enabled, the registration is held pending (available false, state pending-report-manager, no exception) and forwarded at once, or replayed in id order after start-up, when the capability is available. A Report Manager validation state (invalid, duplicate, not-owner, native-model-clash, unknown-provider, provider-disabled, model-unavailable) removes the registration and raises ReportingRegistrationError with that state. An availability state (row-scope-unavailable, bridge-unavailable, core-bridge-active, hidden-fields-unavailable) keeps the registration, logs a warning and returns the row without raising. To switch, resolve reportmanager.registry (has_capability) and call its register_model. The shim is removed after every module in modules/ has switched; no date is set.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "unregister_reporting_model",
        "kind": "python",
        "purpose": "Remove a module reporting-model registration and resynchronize Tactical runtime state. 1.17.4: a registration that was forwarded to Report Manager is removed there too.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "list_reporting_models",
        "kind": "python",
        "purpose": "List registered report-facing models with provider and availability metadata. 1.17.4: forwarded registrations return Report Manager's live row; pending ones return Core's row. Rows gain hidden_fields, forwarded and row_scope.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "reporting_model_status",
        "kind": "python",
        "purpose": "Return live availability for one public reporting-model registration. 1.17.4: the row gains hidden_fields, forwarded and row_scope.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "reporting_bridge_status",
        "kind": "python",
        "purpose": "Return the state of Core's Tactical reporting bridge. Keys: available, installed, error (Core's bridge error or the handover error), native_models, tec_tac_models, total_models, dynamic_schema (unchanged), plus 1.17.4 owner (core, reportmanager or pending), handover (Report Manager 0.3.0 or later was enabled at start-up, so Core did not patch Tactical), fallback (Core took its bridge back because reportmanager.registry is not the owner of the bridge), forwarded_models, pending_models, row_scope_enforced and row_scope_models {enforced, unscoped} (registration ids), plus 1.17.5 bridge_error (only Core's own bridge error, or null) and handover_error (only the handover error, for example Report Manager owns the bridge but reports unhealthy, or null); error is their combination (bridge_error or handover_error). Additive: error is unchanged. During handover installed stays false and no _tec_tac_reporting_bridge marker is set; Report Manager reads installed and the marker. row_scope_enforced true means Core offers the scope hook (scoped_report_manager), not that every registered model is scoped; the per-model truth is row_scope.enforced. It never calls Report Manager.",
        "audience": "backend/diagnostics",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "ReportingRegistrationError",
        "kind": "python",
        "purpose": "ValueError raised for a refused reporting-model registration. 1.17.4: carries state, one of invalid, duplicate, not-owner, native-model-clash, unknown-provider, provider-disabled or model-unavailable.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "scoped_report_manager",
        "kind": "python",
        "purpose": "Return a Django manager for a report-facing model: objects = scoped_report_manager(client='client_id', site='site_id', include_unassigned=False). Tactical's report engine calls Model.objects.filter_by_role(user) when the manager has it, before every operation, so rows are limited to the person's clients and sites: a superuser, or a role with neither can_view_clients nor can_view_sites, sees all rows; no role sees none; otherwise a row shows when its client path is in the granted client ids or its site path is in the visible site ids (granted sites plus the sites of granted clients). A row with no client or site is hidden unless include_unassigned. A model that declares neither path shows no rows to a scoped person. Paths are ORM lookup paths such as client_id or agent__site__client_id. A report run with no signed-in user (Tactical's scheduled report runner) is unscoped by Tactical itself, and Core cannot scope it. A visible row still exposes its own columns; hidden_fields is a separate control. It works whichever bridge serves the model.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "model_row_scope",
        "kind": "python",
        "purpose": "model_row_scope(app_label, model) returns {enforced, source, client_field, site_field, include_unassigned}. enforced is true only when Model.objects.filter_by_role is Core's scoped_report_manager implementation (not overridden) and the declared paths resolve on the model. source is core, model (a manager with its own filter_by_role, which Core cannot vouch for) or null. Every reporting status row carries it as row_scope.",
        "audience": "provider/backend",
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
        "area": "saved-views",
        "import_path": "tec_tac.saved_views",
        "name": "list_views",
        "kind": "python",
        "purpose": "List the saved views a user can read for one module (and optionally one view_key). Same rules as the HTTP contract.",
        "audience": "consumer/backend",
    },
    {
        "area": "saved-views",
        "import_path": "tec_tac.saved_views",
        "name": "get_view",
        "kind": "python",
        "purpose": "Read one saved view the user can read; a private view they cannot read raises SavedViewNotFound.",
        "audience": "consumer/backend",
    },
    {
        "area": "saved-views",
        "import_path": "tec_tac.saved_views",
        "name": "create_view",
        "kind": "python",
        "purpose": "Create a saved view owned by the user. Writes a strict Core audit row in the same transaction.",
        "audience": "consumer/backend",
    },
    {
        "area": "saved-views",
        "import_path": "tec_tac.saved_views",
        "name": "update_view",
        "kind": "python",
        "purpose": "Change the name, payload or readers of a saved view. Owner only.",
        "audience": "consumer/backend",
    },
    {
        "area": "saved-views",
        "import_path": "tec_tac.saved_views",
        "name": "delete_view",
        "kind": "python",
        "purpose": "Delete a saved view. Owner only. Failures raise a SavedViewError subclass (SavedViewValidationError, SavedViewNotFound, SavedViewPermissionDenied, SavedViewConflict, SavedViewAuditError).",
        "audience": "consumer/backend",
    },
    {
        "area": "runtime-settings",
        "import_path": "tec_tac.runtime_settings",
        "name": "get_module_register_timeout_seconds",
        "kind": "python",
        "purpose": "Return the configured module register() time limit in seconds (default 30, range 5 to 300). Never raises. Informational: the UI applies the limit, modules do not.",
        "audience": "diagnostics",
    },
    {
        "area": "runtime-settings",
        "import_path": "tec_tac.runtime_settings",
        "name": "get_update_source",
        "kind": "python",
        "purpose": "Return the remembered update source {type: release|branch, ref} for framework or ui (1.17.2). Default {type: release, ref: None}. A missing or invalid value reads as the default. Never raises. Informational: the System Updates page and the default stage use it.",
        "audience": "diagnostics",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "can_manage_runtime_settings",
        "kind": "python",
        "purpose": "True when the user may change Core runtime settings: an effective superuser, a holder of core.runtime_settings.manage (1.17.2) or a holder of core.privileged_operations. Never raises; any error reads as False.",
        "audience": "backend/administration",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "permission_groups",
        "kind": "python",
        "purpose": "Return declared permission groups for one extension.",
        "audience": "backend/administration",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "has_tactical_permission",
        "kind": "python",
        "purpose": "True when the user holds one Tactical Role flag, evaluated the way Tactical's own _has_perm does (1.17.6): a Django superuser or role superuser passes, a user with no role is denied, an installer user is denied, otherwise the role's boolean. The flag must be a boolean can_* field on Tactical's Role, or ValueError. A lookup failure fails closed (False). It adds no Tec-Tac permission and does not change has_extension_permission. Requires framework >=1.17.6.",
        "audience": "backend",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "tactical_permission_flags",
        "kind": "python",
        "purpose": "Evaluate several Tactical Role flags at once: returns {flag: bool}. Same rules as has_tactical_permission; every flag is validated first (ValueError), and a lookup failure returns every flag False (1.17.6).",
        "audience": "backend",
    },
    {
        "area": "rbac",
        "import_path": "tec_tac.rbac",
        "name": "tactical_permission_catalog",
        "kind": "python",
        "purpose": "Every boolean can_* field on Tactical's Role mapped to True or False for one user (1.17.7): tactical_permission_catalog(user) -> {flag: bool}. One role lookup, same rules as has_tactical_permission (a superuser or role superuser has every flag; an installer user, no role and any lookup failure have none). Non-boolean fields are excluded and the order follows the Role model. It adds no Tec-Tac permission. GET /api/tfd/ui/context/ publishes the same map as tactical_permissions. Requires framework >=1.17.7.",
        "audience": "backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "register_tactical_operation",
        "kind": "python",
        "purpose": "Declare one typed Tactical operation from the owning core module's AppConfig.ready() (1.17.7): (id, module_id, method, route, permissions, scope, body_fields, audit, module_permission=None, message=None). route is a Tactical route template such as agents/{agent_id}/reboot/. permissions are Tactical Role flags, all required. scope lists {type agent|client|site, source path:<name>|body:<field>}. body_fields is the whitelist of JSON body keys. audit is {action, object_type, audit_fields}. Since 1.17.8 only the core module that owns the route may declare it: Core's route owner table (docs/tactical-operations.md, Who may declare where) decides by the longest matching route prefix, so clients/ is Core's (AD-11), core/codesign/ is Licensing's alone (AD-16), agents/{id}/cmd/ is Remote Background's and agents/{id}/{port}/webvnc/ is Take Control's (AD-18), and Endpoints declares none. Refuses routes Core owns, a second caller for the same (method, route), an unknown flag, and a legacy, unknown or disabled module (TacticalOperationRegistrationError, a ValueError). The registry is empty until a module declares an operation. Requires framework >=1.17.7.",
        "audience": "core module/backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "run_tactical_operation",
        "kind": "python",
        "purpose": "Run a declared operation for the signed-in user of an authenticated request and audit it where the call happens (1.17.7): run_tactical_operation(request, module_id, operation_id, params=None, body=None) returns TacticalOperationResult(status, data, content_type, headers, audit, content). Core re-checks the Tactical flags, the optional module permission and the role's client and site limits, then dispatches in-process to Tactical's own view. Core's refusals raise TacticalOperationError(status, code, message, audit). It needs a request, so a Celery task cannot call it. Also available as capability core.tactical_operations 1.0.0 operation run.",
        "audience": "core module/backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "list_operations",
        "kind": "python",
        "purpose": "List the declared Tactical operations (optionally for one module) as plain metadata rows (1.17.7). Capability core.tactical_operations operation list_operations.",
        "audience": "consumer/backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "get_operation",
        "kind": "python",
        "purpose": "Return one declared Tactical operation's metadata row, or None (1.17.7). Capability core.tactical_operations operation get_operation.",
        "audience": "consumer/backend",
    },
)

HTTP_CONTRACT_DETAILS = {
    "/api/tfd/audit/record/": {
        "POST": {
            "deprecated": (
                "Deprecated since 1.17.7 for events a permissionless module declares in audit_events (path 2). The path still behaves exactly as in 1.17.6, "
                "keeps its browser_provenance marker, adds the response header Deprecation: true and logs one warning per module per process. "
                "Replacement: an event for a Tactical call moves to a registered Tactical operation (POST /api/tfd/tactical-operations/<module_id>/<operation_id>/); "
                "an event for the module's own backend action moves to tec_tac.audit.record from the backend route; a browser-only event with no server action has no replacement and stays declared until the module drops it. "
                "The end date is not set. The permissioned-module path (path 1) is not deprecated."
            ),
            "authorization": (
                "authenticated Tec-Tac session. Path 1: an explicitly permissioned module with one of its grants. "
                "Path 2 (1.16.0): a permissionless, enabled, non-legacy module that declares this exact object_type and action "
                "in its manifest audit_events. For client, site and agent objects Core also checks the caller's Tactical scope; "
                "since 1.17.0 any other lowercase object_type slug may be declared and has no scope check. "
                "Core provenance (module_id core) is never available"
            ),
            "request": {
                "module_id": "required string; module that owns the event",
                "action": "required; standard Tec-Tac audit action or custom:<slug>",
                "object_type": "required lowercase slug; path 2 accepts any object_type the module declared (client, site and agent are scope-checked)",
                "object_id": "optional on path 1; required on path 2 for client, site and agent (checked against the caller's scope); optional on path 2 for any other declared type (at most 255 characters)",
                "message": "optional string up to 4096 bytes",
                "before": "optional JSON value",
                "after": "optional JSON value",
                "metadata": "optional object; stored nested under debug_info.metadata",
            },
            "response": {
                "recorded": "true when Tactical's AuditLog row was written",
                "id": "AuditLog row id",
                "username": "signed-in user (Core-owned)",
                "module_id": "module id (Core-verified)",
                "module_version": "installed module version (Core-owned)",
                "correlation_id": "Core-owned correlation id",
            },
            "notes": [
                "Actor, module version, source and correlation id are Core-owned; supplying username, actor, user, module_version, source, correlation_id or request_id gives 400.",
                "Path 2 rows carry debug_info.operation_context.browser_provenance = module-declared-event. Core cannot prove the module's code sent the event, so the marker is set on every row on this path, including Core deny rows and rows whose metadata or operation_context was too large to store.",
                "Path 2 refusals (404 or 403 from the scope check) are not recorded as the module's event. Core writes one Core-owned deny row instead: action deny, one of two fixed Core messages (object missing or out of scope; role lacks Tactical's can_list_* permission) with no module text, metadata refused_action, reason and status, and debug_info.operation_context.core_refusal = true. Only Core sets core_refusal.",
                "Since 1.17.0 a module may declare 'deny' in audit_events (for example for a 403 Tactical itself returned). That row is recorded like any declared event, with the browser_provenance marker and without core_refusal, so it can be told apart from Core's own deny row.",
                "Other declared object types (1.17.0) have no scope check and no Core deny row. An event or object type the module did not declare gives 403 and writes nothing.",
                "Rate limit: 60/min and 1000/day per user and IP, counting accepted and refused requests (deny rows count too).",
                "A module that declares permission_groups and audit_events keeps path 1; audit_events is ignored for it.",
                "Deprecated since 1.17.7 (path 2 only): responses on path 2 carry Deprecation: true. See the deprecated key.",
                "operation_context.browser_provenance, server_provenance and core_refusal are Core-owned. A backend record() call that supplies any of them is a contract error (browser_provenance since 1.17.6, server_provenance since 1.17.7; before 1.17.6 only core_refusal).",
            ],
            "errors": {
                "400": "not a JSON object; actor/provenance field supplied; unknown field; invalid action or object_type; path 2 without object_id or with an invalid object_id",
                "403": "module_id core; module not permissioned for this account and event not declared (message contains 'not permitted'); module disabled, unknown or legacy; path 2: role lacks Tactical's can_list_* permission for the object type",
                "404": "path 2: object not found or outside the caller's client/site scope (same message, so existence is not leaked)",
                "429": "audit write rate limit reached",
            },
            "success": {"201": "recorded", "202": "accepted but Tactical's AuditLog write failed (recorded false)"},
        },
    },
    "/api/tfd/tactical-operations/<str:module_id>/<str:operation_id>/": {
        "POST": {
            "authorization": (
                "authenticated Tec-Tac session (SessionAuthenticated). Core then requires every Tactical Role flag the operation declares "
                "(a superuser and a role superuser pass; an installer user or a missing role is denied), the optional Tec-Tac module_permission, "
                "and every declared scope object inside the role's client and site limits. Tactical's own permission and scope classes run again on the call"
            ),
            "request": {
                "params": "object: one value for each {param} of the operation's route. Anything else gives 400",
                "body": "optional object: only the operation's body_fields. Any other key gives 400. At most 256 KiB",
            },
            "response": "Tactical's own status and body, relayed unchanged. A file answer keeps Content-Type and Content-Disposition (up to 25 MiB). Core's own refusals are JSON {detail, code}.",
            "notes": [
                "Added in 1.17.7. Additive. An operation exists only when an owning core module declares it with tec_tac.tactical_operations.register_tactical_operation; until then every call gives 404 tactical_operation_not_found.",
                "Core writes the audit row after the call, from Tactical's real answer, with the signed-in user as actor and the declaring module as module_id. Every row carries operation_context.server_provenance = tactical-operation, operation and tactical_status.",
                "2xx: the declared action. 401 or 403 from Tactical: a Core deny row (core_refusal, reason tactical_denied). Core's own refusals: the same deny row with a fixed Core text. 5xx, or an error after dispatch, on a call that is not GET: custom:outcome-unknown. Any other 4xx: no row.",
                "Response header X-Tec-Tac-Audit: recorded or not-recorded, present when a row was due. A failed audit write is logged and does not undo Tactical's change.",
                "A missing object and an object outside the caller's scope give the same 404 text. Tactical renaming a route gives 502 tactical_route_changed; Core never falls back to another path. A streaming answer is refused.",
                "Rate limit: 120/min and 5000/day per user and IP.",
            ],
            "errors": {
                "400": "unknown field, params or body invalid, body key not in the whitelist, scope field missing (code invalid_operation_request, invalid_params, invalid_body, body_field_not_allowed or scope_field_required)",
                "401": "not authenticated (authentication_required)",
                "403": "a Tactical flag or the module permission is missing (tactical_permission_denied or module_permission_denied), or Tactical itself answered 403",
                "404": "unknown operation or disabled module (tactical_operation_not_found), or object missing or outside scope (object_not_found)",
                "413": "body larger than 256 KiB",
                "429": "rate limit reached",
                "502": "tactical_route_changed, tactical_call_failed or tactical_response_refused",
            },
        },
    },
    "/api/tfd/saved-views/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the module must be core or an installed, enabled module the user may use",
            "query": {
                "module": "required module id",
                "view_key": "optional; narrow to one view_key",
            },
            "response": {
                "views": "views the caller can read: own views, shared views (readers empty) and private views that list the caller",
                "count": "number of views",
            },
            "notes": ["Each view: id, module_id, view_key, name, payload, shared, mine, can_edit, owner {id, username}, created_at, updated_at. readers (user ids) is returned to the owner only."],
            "errors": {"400": "module missing, unknown, disabled or invalid view_key", "403": "caller may not use the module"},
        },
        "POST": {
            "authorization": "authenticated Tec-Tac session; the module must be core or an installed, enabled module the user may use",
            "request": {
                "module_id": "required",
                "view_key": "required lowercase slug up to 64 characters",
                "name": "required, 1 to 160 characters, unique per owner, module and view_key",
                "payload": "required JSON object up to 64 KiB: filters and layout only, never data, secrets or tokens",
                "readers": "optional list of up to 100 active user ids. Empty (default) shares the view with everyone. Not empty makes it private to the owner and those ids. [own id] means only me",
            },
            "notes": [
                "At most 100 views per owner, module and view_key.",
                "Each create writes a Core audit row (module_id core, object_type saved_view, action add) without the payload, in the same transaction. A failed audit write rolls the create back.",
                "Write rate limit: 60/min and 2000/day per user and IP. Reads are not counted.",
            ],
            "errors": {"400": "invalid field, unknown field, payload too large, unknown reader, quota reached", "403": "caller may not use the module", "409": "name already used by this owner for this module and view_key", "429": "write rate limit reached", "500": "audit row could not be written; nothing was saved"},
            "success": {"201": "created"},
        },
    },
    "/api/tfd/saved-views/<uuid:view_id>/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the caller must be able to read the view",
            "errors": {"404": "no such view, or a private view the caller cannot read (same answer, so it does not leak)"},
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session; owner only",
            "request": {"name": "optional", "payload": "optional", "readers": "optional; omitted keeps the current readers", "module_id": "optional; must equal the current value", "view_key": "optional; must equal the current value"},
            "notes": ["Writes a Core audit row (action modify) without the payload; a failed audit write rolls the change back."],
            "errors": {"400": "invalid field", "403": "caller can read the view but is not the owner", "404": "view not found or not readable", "409": "name already used", "429": "write rate limit reached"},
        },
        "DELETE": {
            "authorization": "authenticated Tec-Tac session; owner only. The owner may delete a view whose module was removed",
            "notes": ["Writes a Core audit row (action delete). Deleting a user deletes their saved views."],
            "errors": {"403": "caller is not the owner", "404": "view not found or not readable", "429": "write rate limit reached"},
            "success": {"204": "deleted"},
        },
    },
    "/api/tfd/ui/context/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session",
            "response": {
                "module_register_timeout_seconds": "integer, added in 1.17.1. Seconds the UI lets a module's register() run before it marks the module failed and loads the next. Default 30, range 5 to 300. Additive: older UI builds ignore it.",
                "tactical_permissions": "object, added in 1.17.7: every boolean can_* field on Tactical's Role mapped to true or false for the signed-in user, for example {\"can_reboot_agents\": true}. A superuser or role superuser has every flag true. An installer user, a user with no role and any lookup failure have every flag false. It uses only the user's own role and adds no Tec-Tac permission. It is a hint for the UI: Tactical still decides every call. Additive: older UI builds ignore it.",
            },
            "notes": ["Only the fields added in 1.17.1 and 1.17.7 are listed here. The rest of the context (user, permissions, extensions, capabilities, module_status, preferences, locale, tactical_ui) is documented with the runtime-context browser contract."],
        },
    },
    "/api/tfd/system/update-source/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; any signed-in user",
            "response": {
                "update_sources": "object with framework and ui, each {type: release|branch, ref: branch name or null}. Default {type: release, ref: null}",
                "updated_at": "ISO time of the last change",
                "updated_by": "username of the last editor, or null",
            },
        },
        "PATCH": {
            "authorization": "authenticated Tec-Tac session; effective superuser only (Django is_superuser or a role with is_superuser). Tightened in 1.17.5: holders of core.runtime_settings.manage or core.privileged_operations who are not superusers were allowed in 1.17.2 to 1.17.4",
            "request": {
                "component": "required: framework or ui",
                "type": "required: release or branch",
                "ref": "branch name. Required for type branch: at most 200 characters, only letters, digits and . _ / -, no '..', no leading '-' or '/', no trailing '/', '.' or '.lock'. Ignored (stored as null) for type release",
            },
            "notes": [
                "Added in 1.17.2. Additive: no existing endpoint changes its meaning.",
                "The branch is not checked against GitHub on save, so saving works offline. A wrong name shows up as branch_error on the next online check.",
                "Writes a strict Core audit row (module_id core, object_type update_source, object_id the component, action modify) with the before and after {type, ref}, in the same transaction. A failed audit write rolls the change back. Setting the same value writes nothing.",
                "Changing the remembered source does not stage or install anything. Staging and installing still need core.privileged_operations and every signed-release and trust-policy check still applies.",
                "Write rate limit: 10/min and 200/day per user and IP (shared with runtime-settings). Reads are not counted.",
            ],
            "response": "same as GET",
            "errors": {"400": "unknown field, unknown component, invalid type or invalid branch name", "403": "caller is not an effective superuser: 'Only a Tec-Tac superuser may change the update source.' Checked before the body, so a non-superuser never sees 400", "429": "write rate limit reached"},
        },
    },
    "/api/tfd/system/updates/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with privileged lifecycle authority",
            "response": {
                "update_sources": "added in 1.17.2: {framework, ui}, each {type: release|branch, ref}. The remembered update source, so the UI needs no extra call. Additive: older UI builds ignore it.",
                "release_cache": "{framework, ui}, each the persisted stable-release row (read only, no GitHub call). Added in 1.17.4: when that component's saved update source is a branch, its row has latest_release null, stable_release (the cached stable release, same shape as latest_release, or null when none is cached) and source {type: branch, ref}. For a release source, or none, the row is unchanged and has no stable_release key.",
            },
            "notes": ["Only the keys added in 1.17.2 and 1.17.4 are listed here."],
        },
    },
    "/api/tfd/system/updates/online/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with privileged lifecycle authority",
            "query": {"component": "framework or ui", "force": "1 bypasses the caches"},
            "response": {
                "latest_release": "null for a branch source (1.17.3). A release source, or none, is unchanged. 1.17.4: the stable release for a branch source is in stable_release, never here",
                "stable_release": "added in 1.17.4, only for a branch source: the latest stable GitHub release as secondary information, {tag, name, published_at, html_url, commit, release_trust, operation}, the same shape as latest_release, or null when it could not be fetched and none is cached. Fetched with the same 24-hour release cache and stale-on-error behaviour as the release answer; force=1 bypasses the cache. A release source, or none, has no stable_release key",
                "checked_at": "for a branch source (1.17.4) the time of the stable-release check; null when there is none",
                "cache": "for a branch source (1.17.4) the stable-release cache state {hit, stale, ttl_hours}",
                "release_error": "text when the stable release could not be fetched (1.17.4: this can now be non-null for a branch source; before 1.17.4 it was always null there), else null. It never sets branch_error",
                "source": "added in 1.17.2, only when the remembered source is a branch: {type: branch, ref}. For a release source the response is unchanged",
                "branch": "added in 1.17.2, only for a branch source: {ref, head_commit, head_short, head_date, installed_commit, installed_short, installed_source {type, ref}, state same|differs|unknown, differs true|false|null, basis commit|version|null, head_version, installed_version}. basis, head_version and installed_version were added in 1.17.3. basis commit: the installed commit is the GitHub commit recorded when the component was last installed, and it wins when present. basis version: no install recorded a commit (offline upload, another repository, or an install before 1.17.2), so the VERSION file at the branch head is compared with the installed VERSION. A version match is weaker than a commit match: a branch can gain commits without a VERSION bump, so basis version can read same while commits differ. State stays unknown (differs null, basis null) when either VERSION cannot be read or is not a plausible version",
                "branch_error": "added in 1.17.2, only for a branch source: text when the branch could not be read, else null. Failing to read the branch VERSION never sets it. A branch failure never hides stable_release",
            },
            "notes": ["The branch head and its VERSION are cached for 5 minutes in the release cache file; force=1 bypasses them. Every earlier key stays present. 1.17.3: the value of latest_release is null for a branch source. 1.17.4: stable_release carries the stable release for a branch source."],
        },
    },
    "/api/tfd/system/updates/online/stage/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations",
            "request": {
                "component": "required: framework or ui",
                "source_type": "optional: release or branch. The default is the remembered source from /api/tfd/system/update-source/, release when none is saved; an explicit value wins (default changed in 1.17.2)",
                "ref": "branch name. With source_type branch and no ref, the saved branch ref is used only when source_type was omitted; an explicit branch with no ref returns 400 'A branch name is required'",
            },
            "response": {"201": "the staged package inspection, unchanged"},
            "errors": {
                "400": "unknown component, invalid source_type, or a branch or release that cannot be resolved",
                "403": "caller does not hold core.privileged_operations",
                "500": "unexpected staging failure",
            },
            "notes": [
                "1.17.2 default change, additive. The saved source only supplies the default. Trust-policy and signed-release checks and the root helper's re-verification still apply.",
                "Changing the saved source does not stage anything. Since 1.17.5 only a superuser can set the saved source.",
            ],
        },
    },
    "/api/tfd/system/runtime-settings/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; any signed-in user",
            "response": {
                "module_register_timeout_seconds": "object: value, minimum, maximum, default (seconds)",
                "updated_at": "ISO time of the last change",
                "updated_by": "username of the last editor, or null",
            },
        },
        "PATCH": {
            "authorization": "authenticated Tec-Tac session; effective superuser, a role holding core.runtime_settings.manage (1.17.2, grantable in the role editor by any role manager) or a role holding core.privileged_operations",
            "request": {"module_register_timeout_seconds": "required whole number of seconds from 5 to 300. A boolean, float, string or null is refused"},
            "notes": [
                "Writes a strict Core audit row (module_id core, object_type runtime_settings, action modify) with the before and after value, in the same transaction. A failed audit write rolls the change back.",
                "Write rate limit: 10/min and 200/day per user and IP. Reads are not counted.",
            ],
            "response": "same as GET",
            "errors": {"400": "unknown field, missing field or invalid value", "403": "caller is not an effective superuser and holds neither core.runtime_settings.manage nor core.privileged_operations: 'Tec-Tac core.runtime_settings.manage or core.privileged_operations permission is required to change runtime settings.' Checked before the body, so a caller without the right never sees 400", "429": "write rate limit reached"},
        },
    },
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
        "details": [
            "Error shape: every error thrown by api, apiRaw, apiBlob, apiText and publicApi carries status, payload and code.",
            "status is 0 when no response arrived, 401 when there is no token, otherwise the HTTP status. For the error-key rejection it is the 2xx status of the response.",
            "payload is the parsed response body. It is null for a 204, for an empty or unparseable body, and when status is 0. The field is payload; there is no body alias.",
            "code is payload.code when that is a string, otherwise null.",
            "api() also throws on any 2xx JSON object with a truthy error or detail key, unless rejectErrorPayload: false is passed. apiRaw, apiBlob and apiText never do.",
        ],
    },
    {
        "id": "ui.authenticated.audit",
        "phase": "authenticated",
        "service": "audit",
        "operations": ["record"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-audit.md",
        "purpose": (
            "Write module audit events through Core instead of Tactical AuditLog internals. Permissioned modules need one of their grants. "
            "Since Core 1.16.0 a permissionless module may also post events it declares in its manifest audit_events; "
            "since 1.17.0 the object type may be any lowercase slug. Client, site and agent objects must be inside the signed-in user's scope. "
            "Those rows carry a browser_provenance marker. "
            "Deprecated since Core 1.17.7 for declared events: the path still works and answers with a Deprecation: true header. "
            "An event for a Tactical call moves to a registered Tactical operation, so Core writes the row server-side; "
            "an event for the module's own backend action is written by the module's backend with tec_tac.audit.record; "
            "a browser-only event with no server action has no replacement yet. The permissioned-module path is not deprecated."
        ),
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
        "operations": ["create", "createModel", "registerCompletionProvider", "registerHoverProvider", "registerDiagnosticsProvider", "languages", "clear"],
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
        "operations": ["register", "open", "openContext", "list", "clear"],
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
        "operations": ["list", "get", "has", "isInstalled", "isEnabled", "isActive", "version", "satisfies"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-status.md",
        "purpose": "Inspect installed/enabled module state without additional HTTP calls; backend capability checks remain authoritative.",
    },
    {
        "id": "ui.authenticated.runtime-context",
        "phase": "authenticated",
        "service": "context / state.context",
        "operations": ["read", "locale", "timeZone", "dateTimeFormat", "tactical_ui.agent_dblclick_action", "tactical_ui.url_action_id", "tactical_ui.can_run_url_actions", "tactical_web_ui.installed", "tactical_web_ui.url", "server_url", "module_register_timeout_seconds", "tactical_permissions.<flag>"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Read the Core-provided authenticated register(context).context object (also available as state.context), including permissions, preferences, authoritative locale/time-zone/date-format fields, Tactical UI preferences, and whether the standard Tactical web UI is installed; treat it as read-only state.",
        "details": [
            "server_url: the Tactical API base without a trailing slash. It is an empty string when unset or not http(s). Read-only.",
            "module_register_timeout_seconds: whole seconds from 5 to 300, default 30. The UI applies it. It covers loading the module's entry file plus its register() call. A module that takes longer is marked failed and the UI carries on.",
        ],
    },
    {
        "id": "ui.authenticated.navigation",
        "phase": "authenticated",
        "service": "addNavigation",
        "operations": ["addNavigation"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Add a left-navigation item with addNavigation(item) from register(context). The item may be gated by permission.",
        "details": [
            "The item may carry one optional permission (a single code) or permissions (a list of codes).",
            "The item is hidden when the user lacks any listed code. Superusers always see it. An item with neither field is shown.",
            "When the backend supplied no context, a gated item is hidden.",
            "This is a display rule only. The backend still refuses what the user may not do.",
            "addNavigation is refused after the module was abandoned by a failed or timed-out register().",
        ],
    },
    {
        "id": "ui.authenticated.router",
        "phase": "authenticated",
        "service": "router",
        "operations": ["addRoute"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Add module routes through the guarded module router passed to register(context). Other vue-router members pass through unchanged.",
        "details": [
            "addRoute(route) and addRoute(parentName, route) are both guarded.",
            "A route whose path or name another owner already holds is refused.",
            "meta.dynamicModule is set on every route the module adds.",
            "addRoute returns the remover. Core runs the removers when the module is abandoned.",
            "addRoute is refused after the module was abandoned by a failed or timed-out register().",
            "Every other vue-router member (for example push, resolve and currentRoute) passes through unchanged.",
        ],
    },
    {
        "id": "ui.authenticated.permissions",
        "phase": "authenticated",
        "service": "hasPermission",
        "operations": ["hasPermission"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Ask whether the signed-in user holds a permission code with hasPermission(code), to show or hide a control.",
        "details": [
            "Returns true for a superuser, or when the code is in the user's effective permission set.",
            "Display only. The backend refuses what the user may not do.",
        ],
    },
    {
        "id": "ui.public.sso-providers",
        "phase": "public",
        "service": "ssoProviders",
        "operations": ["register", "list", "begin", "clear"],
        "audience": "provider/public-browser",
        "docs": "tec-tac-ui/docs/module-sso.md",
        "purpose": "Contribute sign-in providers from registerPublic(context) before Tactical authentication exists. Core owns the browser callback and token-completion boundary; public modules only initiate the provider redirect and never receive Tactical credentials or access tokens.",
    },
    {
        "id": "ui.public.module-runtime",
        "phase": "public",
        "service": "registerPublic(context)",
        "operations": ["publicApi", "addPublicRoute", "ssoProviders"],
        "audience": "module/public-browser",
        "docs": "tec-tac-ui/docs/module-sso.md",
        "purpose": "Expose bounded anonymous module routes and public API calls without Tactical credentials or authenticated runtime state. SSO callbacks and Tactical token exchange are reserved to Core and are not exposed through registerPublic(context).",
    },
)

RULES = (
    "A permissionless extension that needs a browser audit trail declares audit_events in tec_tac.json: [{\"object_type\": \"agent\", \"actions\": [\"view\", \"run\"]}]. object_type is a lowercase slug; each action is a standard Tec-Tac audit action or custom:<slug>. For client, site and agent Core checks the signed-in user's scope; other types have no scope check. Core sets the actor and marks the row browser_provenance. A module that declares audit_events must require framework >=1.16.0, and >=1.17.0 when it declares an object type other than client, site or agent.",
    "The UI, not modules, applies the module register() time limit. A module does not read or enforce module_register_timeout_seconds, and its register() must not assume more than the configured time. Core only stores and publishes the value (GET /api/tfd/ui/context/).",
    "Saved views belong to the Core saved views service (tec_tac.saved_views, /api/tfd/saved-views/). Modules must not keep saved views in browser storage, cookies or their own tables. A payload holds filters and layout only, never data, secrets or tokens. A module that uses the service must require framework >=1.17.0.",
    "A Tactical call that must be audited (reboot, Wake-on-LAN, report changes, code signing) is declared once by the owning core module with tec_tac.tactical_operations.register_tactical_operation and run through core.tactical_operations (POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ or the capability's run). Core writes the audit row where the call happens, so the browser cannot misreport it. The browser-declared audit_events path is deprecated since 1.17.7 for declared events (see docs/module-audit.md for the replacement of each event).",
    "Use Python tec_tac.* contracts inside the Tec-Tac/Tactical backend; use HTTP only at browser/external process boundaries.",
    "UI modules must use the documented browser contracts passed to register(context) or registerPublic(context); do not import Core UI internals or read Tactical authentication storage.",
    "Swagger grouping is Core-owned: installed extension endpoints are grouped from their registered Django app ownership even when the URL prefix differs from the module ID. Module manifests may declare a readable name and category=core; groups are named Core module · <name> or Module · <name>. Core HTTP surfaces use explicit subsystem groups, module callback ownership wins over path prefixes, and there is no generic Framework catch-all.",
    "Do not import another module's private models, helpers, services, filesystem layout or database tables.",
    "Feature modules must consume Tactical clients/sites/agents through tec_tac.resources; direct Tactical resource-model imports are a Core-only compatibility boundary.",
    "Resolve cross-module business operations through the capability registry and re-check runtime availability at execution time.",
    "Optional integrations must soft-fail only the dependent feature when a provider is missing, disabled, unhealthy or incompatible.",
    "Modules define WHAT can run; the shared Scheduler owns WHEN it runs, recurrence, retry, concurrency and history.",
    "Backend authorization is authoritative; frontend visibility is never a substitute for permission checks.",
    "Tec-Tac authenticated backend endpoints must use the Core session-security guard; Tactical token validity alone is not sufficient for Tec-Tac trust.",
    "SSO provider modules may initiate sign-in only. Core owns /account/provider/callback, exchanges the Tactical SSO session for a Knox token, and establishes the normal Tec-Tac session-security boundary before the operational shell loads.",
    "Report-facing module models register through the reportmanager.registry capability (Report Manager owns the report-model registry, AD-15); tec_tac.reporting remains a forwarding shim until every module has switched; modules must not import or mutate ee.reporting internals or Tactical schema files.",
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
    for row in data.get("browser", []):
        if row.get("details"):
            out.extend(["", f"### `{row['id']}` details", ""])
            out.extend(f"- {line}" for line in row["details"])

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
        events = module.get("audit_events") or []
        if events:
            out.append("- **Declared browser audit events**: " + ", ".join(
                f"`{event['object_type']}`: " + "/".join(f"`{action}`" for action in event.get("actions", []))
                for event in events
            ))
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
        for line in row.get("details") or []:
            out.append(f"    * {line}")

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
        for event in module.get("audit_events") or []:
            out.append(f"  audit_events {event['object_type']}: {', '.join(event.get('actions', []))}")

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
