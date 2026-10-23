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
    {"area":"resources","import_path":"tec_tac.resources","name":"trusted_service_context","kind":"python","purpose":"Create an explicit trusted non-interactive Resource Directory context; global access is never implicit. Since core.resources 1.9.0 (framework >=1.17.30, AD-34 condition 1) global_access=False is available to the module userinvite only, when the actor names that module and Core verifies the caller from the call stack: the context has no resource visibility and writes no audit row; every other caller is refused.","audience":"trusted backend/service"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_clients","kind":"python","purpose":"List Tactical clients through the stable scoped Core Resource Directory. Since core.resources 1.5.0 (framework >=1.17.22) each client record carries sites: that client's site records inside the caller's scope (same shape as list_sites records, one query per page), so List clients alone is enough to build a client and site tree, as Tactical's GET /clients/ does. The sites read still needs List sites. Since 1.7.0 (framework >=1.17.24) each record also carries workstation_policy_id, server_policy_id and block_policy_inheritance, and list_clients takes the optional filters alert_template_id and policy_id (the workstation or the server policy), each a positive integer or ResourceValidationError. Since core.resources 1.10.0 (framework >=1.17.40) each client record also carries failing_checks ({error, warning} booleans, Tactical's stored value, as of its last periodic refresh), agent_count (integer) and maintenance_mode (boolean), appended last: a client is computed only from the sites the caller may see (agent_count is the sum, maintenance_mode true when any of them is, failing_checks Tactical's stored client value only when every site is visible, otherwise the OR of the visible sites), so a role never learns of a hidden site; a client with no visible site reads 0, false and both false. Nested sites carry the keys too. They are read only, need no List agents flag (as Tactical's GET /clients/), and agent records never carry them.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_client","kind":"python","purpose":"Resolve one scoped Tactical client as a stable Core record. Since core.resources 1.5.0 it carries sites (the client's site records inside the caller's scope). Since core.resources 1.10.0 (framework >=1.17.40) each client record also carries failing_checks ({error, warning} booleans, Tactical's stored value, as of its last periodic refresh), agent_count (integer) and maintenance_mode (boolean), appended last: a client is computed only from the sites the caller may see (agent_count is the sum, maintenance_mode true when any of them is, failing_checks Tactical's stored client value only when every site is visible, otherwise the OR of the visible sites), so a role never learns of a hidden site; a client with no visible site reads 0, false and both false. Nested sites carry the keys too. They are read only, need no List agents flag (as Tactical's GET /clients/), and agent records never carry them.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"create_client","kind":"python","purpose":"Create a Tactical client and its first site through the Core resource write boundary. create_client(*, name, context, site_name=None, custom_fields=None) (core.resources 1.5.0, framework >=1.17.22): site_name is the first site's name (omitted, the site is named Default Site; deprecated), custom_fields is an optional list of {field_id, value} saved in the same transaction. As Tactical does, the client joins the creator's can_view_clients only when that list is not empty. Names may not contain the | character. The record returned carries sites with the first site and the 1.10.0 live keys (failing_checks, agent_count, maintenance_mode).","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_client","kind":"python","purpose":"Update a scoped Tactical client through the Core resource write boundary. update_client(client_id, *, name=None, alert_template_id=UNSET, context): at least one of name or alert_template_id (core.resources 1.4.0, framework >=1.17.17). alert_template_id is a positive integer to set the client's alert template or None to clear it; booleans, zero, negatives and text that is not a whole number raise ResourceValidationError, and so does an id that names no template (Tactical's own foreign key decides, Core imports no Alerts model). Core holds only the id: the template list belongs to Alerts. Same write rule as a rename (Tactical can_manage_clients, the Core resources permission, a whole-client grant); can_manage_alerts is not required, matching Tactical's client PUT. The write goes through Tactical's model save, so its own agent alert cache refresh still runs. The audit row carries before and after records (with alert_template_id) and metadata alert_template_changed. Existing calls with name only are unchanged. Since core.resources 1.7.0 (framework >=1.17.24) it also takes workstation_policy_id and server_policy_id (a positive integer to set, None to clear, UNSET to leave alone; an id that names no policy raises ResourceValidationError, Tactical's foreign key decides) and block_policy_inheritance (a real True or False only). Core holds only the ids: Automation owns the policy list. Same write rule as a rename (can_manage_automation_policies is not required, as Tactical's own PUT). The audit row carries metadata policy_changed (names of the changed fields, ids only), and a call that changes nothing writes no row. The record returned carries the 1.10.0 live keys; the audit rows never do. Since core.resources 1.11.0 (framework >=1.17.51) the optional keywords expected_workstation_policy_id, expected_server_policy_id (a positive integer, or None for 'must be unset') and expected_block_policy_inheritance (a real bool) are a compare-and-set guard, all UNSET by default: the compare runs inside the write transaction against the locked record; when a guard is given and the record holds another value nothing is written, no audit row is written and the call raises ResourceConflict whose code is record_changed (HTTP 409 {code: record_changed}), with a plain sentence that names the field and no value. A guard alone is not a change (the 'at least one of' rule stays), a bad guard value is a ResourceValidationError, a call with no guard behaves exactly as before, and there is no guard for the name or the alert template. PATCH accepts the same three keys in the body.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"delete_client","kind":"python","purpose":"Delete a scoped Tactical client after atomically relocating its agents when required.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_sites","kind":"python","purpose":"List Tactical sites globally or by client through the stable scoped Core Resource Directory. Since core.resources 1.5.0 (framework >=1.17.22) every site record carries client_name, the owning client's name, so a role with only List sites can group sites by client. Since 1.7.0 (framework >=1.17.24) each record also carries workstation_policy_id, server_policy_id and block_policy_inheritance, and list_sites takes the optional filters alert_template_id and policy_id, as list_clients does. Since core.resources 1.10.0 (framework >=1.17.40) each site record also carries failing_checks ({error, warning} booleans, Tactical's stored value, as of its last periodic refresh), agent_count (integer) and maintenance_mode (boolean), appended last: a site is computed from its own agents only. They are read only, need no List agents flag (as Tactical's GET /clients/), and agent records never carry them.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_site","kind":"python","purpose":"Resolve one scoped Tactical site as a stable Core record. Since core.resources 1.10.0 (framework >=1.17.40) it carries failing_checks, agent_count and maintenance_mode, computed from the site's own agents only.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"create_site","kind":"python","purpose":"Create a Tactical site inside the caller's client scope through Core. create_site(*, client_id, name, context, custom_fields=None) (core.resources 1.5.0, framework >=1.17.22): custom_fields is an optional list of {field_id, value} saved in the same transaction. As Tactical does, the site joins the creator's can_view_sites only when that list is not empty. Names may not contain the | character. The record returned carries the 1.10.0 live keys (failing_checks, agent_count, maintenance_mode).","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_site","kind":"python","purpose":"Update a scoped Tactical site through the Core resource write boundary. update_site(site_id, *, name=None, client_id=None, alert_template_id=UNSET, context) takes alert_template_id since core.resources 1.4.0 (framework >=1.17.17): a positive integer to set or None to clear, with the same checks, scope rule (a site grant or a grant of the site's client), audit metadata alert_template_changed and Tactical hook as update_client. Since 1.7.0 (framework >=1.17.24) it takes the three policy fields as update_client does. Moving a site (client_id other than the current one) is documented and tested. Since core.resources 1.8.0 (framework >=1.17.25, CQ79) it follows Tactical's Edit site: the agents follow the site, the source site needs its write scope, the destination client needs no grant (a limited role may move a site into a client it holds no grant on), a missing destination client is a 400, the last site of a client is refused, a name clash in the destination is a conflict, the same client is a no-op after the write-scope check, and the audit row carries client_changed, from_client_id, to_client_id and agents_moved (ids and a count only). The record returned carries the 1.10.0 live keys; the audit rows never do. Since core.resources 1.11.0 (framework >=1.17.51) the optional keywords expected_workstation_policy_id, expected_server_policy_id (a positive integer, or None for 'must be unset') and expected_block_policy_inheritance (a real bool) are a compare-and-set guard, all UNSET by default: the compare runs inside the write transaction against the locked record, before a move or any other change, so a stale guard moves nothing; when a guard is given and the record holds another value nothing is written, no audit row is written and the call raises ResourceConflict whose code is record_changed (HTTP 409 {code: record_changed}), with a plain sentence that names the field and no value. A guard alone is not a change (the 'at least one of' rule stays), a bad guard value is a ResourceValidationError, a call with no guard behaves exactly as before, and there is no guard for the name or the alert template. PATCH accepts the same three keys in the body.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"delete_site","kind":"python","purpose":"Delete a scoped Tactical site after atomically relocating its agents within the same client when required.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_custom_fields","kind":"python","purpose":"List editable Tactical custom-field definitions and values for a scoped client or site.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_custom_field_definitions","kind":"python","purpose":"List the non-hidden Tactical custom-field definitions for a new client or site, each with its default as value, before the object exists (core.resources 1.6.0, Core 1.17.23). list_custom_field_definitions(resource_type, *, context) returns {resource_type, fields: [{field_id, name, type, options, required, value}]} in the same order and shape as list_custom_fields. No per-client data is read, so nothing is scoped. Gate: the create's own (Tactical can_manage_clients or can_manage_sites plus the Core permission; a superuser passes; a service context is refused). resource_type must be exactly client or site, else a validation error. HTTP: GET /api/tfd/resources/custom-fields/?resource_type=client|site. Needs framework >=1.17.23.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"update_custom_fields","kind":"python","purpose":"Update scoped client/site Tactical custom-field values through Core validation and audit.","audience":"authorized backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"list_agents","kind":"python","purpose":"List Tactical agents globally or by client/site through the stable scoped Core Resource Directory. Since core.resources 1.12.0 (framework >=1.17.58) it takes the keyword-only sort_by (hostname, client, site, platform or last_seen) and sort_dir (asc, the default, or desc): lowercase and case-sensitive, anything else (an unknown key, an unknown direction, an empty value, a value that is not text) raises ResourceValidationError (HTTP 400 invalid_resource_request). The order is applied inside the caller scope and before the page is cut, always followed by the old order (client, site, host name, agent id) so paging is stable; last_seen puts an agent that never reported last in both directions. A valid sort_dir without sort_by is accepted and ignored. Without sort_by the order is exactly the 1.11.0 order. GET /api/tfd/resources/agents/ takes the same two query parameters.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"get_agent","kind":"python","purpose":"Resolve one scoped Tactical agent using its stable agent_id.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"scope_descriptor","kind":"python","purpose":"Describe the caller's Tactical client and site scope once (core.resources 1.4.0, framework >=1.17.17): scope_descriptor(*, context) returns {mode, unrestricted, whole_client_ids, site_ids, whole_client_count, site_count}. mode is unrestricted, clients (only whole-client grants), sites (only explicit site grants), mixed or none. unrestricted is a superuser, a role superuser or a role with both can_view_clients and can_view_sites empty (Tactical's own rule). whole_client_ids are the explicit can_view_clients grants. site_ids are the explicit can_view_sites grants only, not the sites of a granted client. No role, a Tactical installer user and any lookup failure give mode none (fail closed). A trusted global service context is unrestricted; a service context that is not global is refused. A scope question only: no can_list_* flag is needed. Modules use this instead of reading Tactical's Role.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"scope_unrestricted","kind":"python","purpose":"True when the caller sees every client and site (core.resources 1.4.0, framework >=1.17.17): scope_unrestricted(context). The unrestricted flag of scope_descriptor.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"has_whole_client_access","kind":"python","purpose":"May the caller act on a whole client (core.resources 1.4.0, framework >=1.17.17): has_whole_client_access(client_id, *, context) is true only for an unrestricted caller or a role that lists the client in can_view_clients, and only when the client exists. A site-only role never holds the whole client, not even the client that owns its site. No can_list_clients is needed (a scope question only). No role, an installer user and any lookup failure give False. A malformed client_id raises ResourceValidationError. A trusted global service context has whole access to every existing client.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"ResourceAccessContext","kind":"python","purpose":"The authority context every Resource Directory call takes. Since core.resources 1.4.0 it has a read-only property scope that returns scope_descriptor(context=self), computed when read and never cached on the context.","audience":"consumer/backend"},
    {"area":"resources","import_path":"tec_tac.resources","name":"resolve_resource","kind":"python","purpose":"Resolve a client, site or agent through one generic Core operation. A client or site record carries the 1.10.0 live keys (failing_checks, agent_count, maintenance_mode); an agent record never does.","audience":"consumer/backend"},
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
        "purpose": "Record a Tec-Tac module event through Core into Tactical's unified AuditLog trail. Since 1.17.20 the action custom:operation-failed is Core-only (Core writes it when Tactical refuses a change) and gives AuditContractError. Since 1.17.20 (additive; needs framework >=1.17.20) a signed-in person who holds none of the module's own permissions is accepted as the actor when Core finds the module is the declaring owner of the action, meaning it registered at least one Tactical operation: action deny is accepted for any such module, and any other action only when it is the audit action of one of the module's operations that has no module_permission and the person holds every Tactical flag of that operation (an installer user, an unauthenticated actor, module core, a legacy or disabled module, a module with no operation, an undeclared action and an operation that needs a module permission stay refused with AuditContractError). Core marks the row debug_info.actor_authority = declared-operation-owner; a caller cannot supply it. Since 1.17.30 (AD-34 conditions 1 and 2, additive; needs framework >=1.17.30) a module whose manifest category is server may also write a deny row for a signed-in person who holds none of its permissions, only for the action deny and only when Core verifies from the call stack that the caller is that same module (a missing or different caller, a Core frame, any other action, any other category, an installer user and a legacy or disabled module stay refused with AuditContractError). Core marks the row debug_info.actor_authority = server-module-deny; a caller cannot supply it. The verifying helper is Core-private and no module may import it. Backend record() only: the browser audit path is unchanged. Since 1.17.6 operation_context may not carry browser_provenance or core_refusal, and since 1.17.7 server_provenance: they are Core-owned and give a contract error. For a Tactical call use a registered Tactical operation (core.tactical_operations) so Core writes the row where the call happens. Core's own writers (record_browser_declared, record_core_refusal and, since 1.17.8, the private _record_tactical_operation) are Core-internal and not callable by modules. Worked example (1.17.51, no behaviour change): Checks lets a person who holds only can_list_checks export an event log by declaring the read as a Tactical operation (method GET, permissions ['can_list_checks'], no module_permission, audit action export) and writing its export row from its backend with record(action='export', ...); Core accepts it as declared-operation-owner. The same row is refused for a person without the flag, for a module with no export operation, for an operation that sets module_permission, for an installer user and for any other action. A module that adopts it needs requires.framework >=1.17.51 (see docs/module-audit.md).",
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
        "purpose": "Return a Django manager for a report-facing model: objects = scoped_report_manager(client='client_id', site='site_id', include_unassigned=False). Tactical's report engine calls Model.objects.filter_by_role(user) when the manager has it, before every operation, so rows are limited to the person's clients and sites: a superuser, or a role with neither can_view_clients nor can_view_sites, sees all rows; no role sees none; otherwise a row shows when its client path is in the granted client ids or its site path is in the visible site ids (granted sites plus the sites of granted clients). A row with no client or site is hidden unless include_unassigned. A model that declares neither path shows no rows to a scoped person. Since 1.17.29 (additive, opt-in, framework >=1.17.29) the keyword server_wide=True declares rows that belong to the server and carry no client or site (an invitation history, a certificate observation): it must be a bool, it is refused with client, site or include_unassigned (ReportingRegistrationError), and since 1.17.30 (AD-34 condition 3) filter_by_role shows its rows to effective superusers only (a Django superuser or a role superuser; a role with no client or site limits, a scoped role, no role, no user and any error see none; server modules will get their own role system later, AD-34 condition 4; a report run with no signed-in user stays unscoped, so scheduling such a report is limited by Report Manager's own permission), so model_row_scope reports it enforced; a pathless manager without the flag is still not enforced. Paths are ORM lookup paths such as client_id or agent__site__client_id. A report run with no signed-in user (Tactical's scheduled report runner) is unscoped by Tactical itself, and Core cannot scope it. A visible row still exposes its own columns; hidden_fields is a separate control. It works whichever bridge serves the model.",
        "audience": "provider/backend",
    },
    {
        "area": "reporting",
        "import_path": "tec_tac.reporting",
        "name": "model_row_scope",
        "kind": "python",
        "purpose": "model_row_scope(app_label, model) returns {enforced, source, client_field, site_field, include_unassigned, server_wide} (server_wide added in 1.17.29, additive: true when the model declared scoped_report_manager(server_wide=True), false otherwise). enforced is true only when Model.objects.filter_by_role is Core's scoped_report_manager implementation (not overridden) and the declared paths resolve on the model, or the model declared server_wide and no path (its rows are visible to effective superusers only since 1.17.30). source is core, model (a manager with its own filter_by_role, which Core cannot vouch for) or null. Every reporting status row carries it as row_scope.",
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
        "purpose": (
            "Register a stable business action with the shared Tec-Tac Scheduler. permission is a Tec-Tac permission code, None (managers only), "
            "a Tactical role flag written 'tactical:can_manage_winupdates', or a list or tuple of those (any-of, at most 8, no duplicates; "
            "since 1.17.17, requires framework >=1.17.17 for the tactical: form and the list). The shape is checked at registration and a bad "
            "shape raises SchedulerError. A flag or code that does not exist fails closed when used (nobody but a scheduler manager passes) "
            "and is logged. The same check is repeated just before a one-off run, so a run whose owner lost the flag is skipped. Since 1.17.65 a scheduled run of a user-owned schedule is not re-checked (see below). "
            "serialize_action and the exported scheduler_actions rows carry permission (the single entry, or the entries joined with ' | ') "
            "and permission_any (the list, empty for a single entry). "
            "Since 1.17.63 (requires framework >=1.17.63) an optional last keyword unattended=False is accepted (CQ179 b). Module-facing change in 1.17.65 (signed by Johan on 20 October 2026, AD-13 condition 2 amended, CQ184 b, CQ186, CQ189): every SCHEDULED run of a user-owned schedule is not re-checked against its creator's current rights, for every registered action, flagged or not, because the right was checked when the person created or edited the schedule and Core stores and audits who that was. "
            "A manual or one-off run is always re-checked. unattended= is still accepted, keeps its validation (a bool; True only for an action id listed in the module's signed manifest system_actions, else SchedulerError) and has no effect (CQ188). A module-owned schedule with a stored creator name is exempt only for an action still listed in the signed manifest system_actions and registered with core.system_actions. "
            "Core still checks the caller, that the module is enabled and honoured, that the action is declared in the signed manifest, the snapshotted targets, the 2000 cap, at-most-once and the audit row. "
            "Cost, stated plainly: a person who is demoted or deactivated later keeps their unattended schedules running until someone removes or edits them, as in Tactical. "
            "ScheduledAction gains the last field unattended (default False); serialize_action is unchanged."
        ),
        "audience": "provider",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "reconcile_schedule",
        "kind": "python",
        "purpose": "Idempotently create/update a backend-module-owned schedule using owner_module + owner_key. Since 1.17.17 an owner_key that starts with one-off: raises SchedulerError: that prefix is reserved to Core, and only start_one_off_run makes such a schedule. Since 1.17.63 (CQ176, requires framework >=1.17.63) an optional keyword-only confirmed_by_request=None names the person behind the schedule: it must be a real Django or DRF request that passed Core's session check (the proof run_tactical_operation asks for), never a user id or a stand-in object (SchedulerNotAllowed). Core checks that person's permission for the action and Tactical scope of the targets, stores the creator and the confirmer by name, writes one audit row for the creation and one for every change, and the module stays the owner and the executor. WITHOUT a request, a schedule that has a stored creator can only be switched off or left as it is: any change to its action, targets, parameters, timing or policies, and switching it back on, raises SchedulerError. A call without the keyword on a schedule with no stored creator behaves as in 1.17.62. Since 1.17.66 (framework >=1.17.66) an optional keyword-only confirmation_id=None: for a declared system action (listed in the signed manifest system_actions and registered with core.system_actions), an enabled schedule and a confirmed_by_request, Core checks at this creation or edit the owning module's permission, the Tactical flags of the table row, the person's Tactical scope over every target, that the targets read as endpoints within the ceiling, the parameters, the module enabled and a replacement honoured, and refuses without a valid id issued for that person, action, targets, parameters and timing (SystemActionCreationRefused, a SchedulerNotAllowed; one deny row). An allowed creation or change writes its strict audit row with total_agents, groups and when. Any other action behaves exactly as before. Since 1.17.68 (module-facing, framework >=1.17.68; Johan, 21 October 2026, Q-APM12 option b): a call with confirmed_by_request IS an edit by that person. Core stores that person's Tactical client and site scope and role flags at that moment on the schedule (creation_scope), so an unattended run reads what the person could reach when they saved it and never their live row (see VerifiedSchedulerRun). When the person is not the stored owner, Core moves the ownership to them (created_by, created_by_username, confirmed_by_username, updated_by) after the unchanged permission and scope checks, stores their scope, and writes one strict modify audit row with owner_changed_from, owner_changed_to and previous_confirmed_by. Ownership never widens a schedule: the person's own Tactical scope must cover every target, with no bypass for a scheduler manager, or the call raises TakeoverRefused (a SchedulerNotAllowed, reason takeover_out_of_scope, the plain text 'You cannot take over this schedule: some of its targets are outside your Tactical scope.') and nothing changes; one deny row is written after the rollback. A call that only switches the schedule off moves nothing. A module-owned target type that the module registered a resolver for (register_target_resolver) is judged by the endpoints that resolver names. The signature is unchanged, and a module call with no request still cannot change a person's schedule.",
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
        "purpose": "Register a stable, versioned public cross-module backend contract. Since 1.17.9 (AD-20) the id must still begin with the provider module id and a dot, except that the honoured replacement of a core or server module may register that module's capability ids, and only the ids it declares in its manifest capabilities. Since 1.17.11 a refused registration also removes an earlier registration of the same id by the same module, so the name stays capability-unavailable.",
        "audience": "provider",
    },
    {
        "area": "module-replacement",
        "import_path": "tec_tac.module_replacement",
        "name": "honoured_replacement",
        "kind": "python",
        "purpose": "honoured_replacement(module_id) -> the core or server module id that module replaces right now, or None (1.17.9, AD-20; server modules since 1.17.11). Worked out from manifests and module state on every call, so disabling the replacement ends it at once. Never raises.",
        "audience": "core module/backend",
    },
    {
        "area": "module-replacement",
        "import_path": "tec_tac.module_replacement",
        "name": "replaced_by",
        "kind": "python",
        "purpose": "replaced_by(module_id) -> the module that honourably replaces that core or server module right now, or None (1.17.9, AD-20).",
        "audience": "core module/backend",
    },
    {
        "area": "module-replacement",
        "import_path": "tec_tac.module_replacement",
        "name": "replacement_status",
        "kind": "python",
        "purpose": "replacement_status(module_id=None) -> {module_id, replaces, enabled, honoured, reason, message, capabilities, conflict, degraded, unregistered, registered_mismatch} for one module that declares replaces (None when it declares none), or a list for every such module (1.17.9, AD-20). reason is one of replacement-disabled, target-missing, target-not-core (the module it names is not a core or server module), target-enabled, competing-replacement, capabilities-undeclared, capability-missing, capability-major-mismatch, capability-version-lower. conflict (1.17.11) is true when the replacement and the module it replaces are both enabled: Core does not load the replacement and queues a job that disables it. degraded is informational: it is true when a declared capability is not registered at run time, and also when registered_mismatch is not empty. registered_mismatch (1.17.10) lists {capability, declared, registered, reason} for each capability the replacement tried to register outside its declared major version or below its declared minor.patch; Core refused it, so the name stays unavailable. It lives in the running process and clears on restart or when a correct registration follows. A core module's undeclared-id refusal is logged once and is not listed here.",
        "audience": "core module/backend/browser",
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
        "purpose": "Return structured missing/disabled/unhealthy/version-incompatible capability state. Since Core 1.17.58 a state can also be health-reentrant (additive): a provider health callback that, directly or through another capability, asked for the status of a capability whose health check was already running on the same thread (A -> B -> A), or nested more than 8 deep. Core answers available false at once, with a reason that names only the capability ids in the chain, instead of recursing. get_capability raises CapabilityUnhealthy for it (its state attribute stays unhealthy), so callers that handle unhealthy need no change; a caller that compares the status dict state against a list of names should treat any state other than available as not available. check_health=False is unchanged.",
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
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "operators_for",
        "kind": "python",
        "purpose": "The operators a field of one kind offers, each {id, label} (core.filter_sets 1.1.0, framework >=1.17.50; date and number since 1.17.52). The six ids and labels are Core's one vocabulary (equals, not_equals, contains, not_contains, starts_with, ends_with; the same as Groups' STRING_OPERATORS). kind 'text' gets all six, 'bool' equals only, 'id' (client, site) equals and not_equals on the ID plus the four text operators matched on the display name when the field declares a name (has_name=True). Since 1.17.52 (additive) kind 'date' gets equals ('Is'), not_equals ('Is not'), before, after, on_or_before, on_or_after, between, in_the_last and not_in_the_last, and kind 'number' gets equals, not_equals ('Does not equal'), greater_than, less_than, at_least, at_most and between. The new ids live in their own tables, so the six-id OPERATORS table and the 'operators' key of the fields route and of the capability metadata stay the six; the full vocabulary is in the metadata keys all_operators, date_operators and number_operators. An unknown kind still raises FilterSetValidationError.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "validate_filter_set",
        "kind": "python",
        "purpose": "Check a filter {version, match 'all'|'any', rules [{kind 'rule', field, operator, value} | {kind 'group', match, rules}]} against the fields a person may use; return the normalized tree. Refuses, never drops: a field not in the list (FilterSetFieldUnavailable), an operator the field's kind does not offer, a value of the wrong type, a control character, a value over 200 characters, more than 50 rules or 20 groups, groups nested more than 3 deep. Empty rules match nothing, as in Groups. Fields are the declarations {id, label, kind text|id|bool, lookup or row_key, name_lookup or name_key for kind id, scope_kind 'client'|'site' for kind id (optional, since 1.17.51, never shown to the browser; Core uses it to keep an out-of-scope id out of a shared set), values {source distinct|static|none, options}} a module returns; Core validates each and drops a bad one with a log line. Since 1.17.52 (additive, core.filter_sets 1.1.0) a field of kind 'date' or 'number' is accepted. A date value is a strict ASCII YYYY-MM-DD string, a real date from 1970-01-01 to 2100-12-31 (whole days only, UTC days); between is {from, to} with both ends inclusive and from <= to; in_the_last and not_in_the_last are {amount, unit} with unit minutes, hours or days and amount a whole number from 1 to 525600 minutes, 8760 hours or 3650 days (a bool, decimal, text or other unit is refused). A number is a JSON int or a finite float (a bool, NaN, infinity, numeric text and a magnitude above 10**15 are refused); number between is {from, to} with from <= to; a number outside the field's minimum or maximum, or a decimal on an integer field, is refused. A dict with any other key is refused, and so is an operator the kind does not offer. The tree keeps the relative form, so a saved 'last 7 days' stays live. No new rule keys: the value is held in the rule's single value.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "build_q",
        "kind": "python",
        "purpose": "A Django Q for a filter, built from the module's declared lookups only. The tree is validated again first. Values go to Django as data (iexact, icontains, istartswith, iendswith escape %, _ and backslash): no raw SQL, no regular expression and no field name from the browser. not_* operators negate with ~Q, so an empty value still matches not_equals, as Groups does. The module ANDs it onto its own role-scoped list, so a filter can only narrow. Since 1.17.52: build_q(normalized, fields, *, now=None). now (keyword only, default the real clock, a naive value counts as UTC) is read once per call. A date or number rule emits only plain equality, __gte, __lt, __lte and __gt on the declared lookup, so a module may point lookup at an annotation it added to its queryset (Agents' count of pending actions) as long as it applies the annotation before it filters. Days are UTC days: equals is [D, D+1), before is < D 00:00, on_or_before is < D+1, after is >= D+1, on_or_after is >= D, between is [from, to+1), in_the_last is now-N .. now inclusive and not_in_the_last is its exact negation. A date on a datetime column uses aware UTC datetimes; with stored_as 'date' it uses plain dates. A NULL never satisfies a positive operator and does satisfy not_equals and not_in_the_last (Django's ~Q keeps NULL rows).",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "matches",
        "kind": "python",
        "purpose": "The in-memory twin of build_q for lists that are not model-backed: matches(normalized, row, fields) -> bool on a plain dict, read through each field's declared row_key (and name_key for the text operators of an id field). Casefolded compare; None counts as empty text; an empty group matches nothing. Since 1.17.52: matches(normalized, row, fields, *, now=None) follows build_q exactly for date and number fields, including the NULL rule and the UTC day. A date row value may be a datetime (naive counts as UTC), a date (its UTC midnight), an ISO string, or an int, float or Decimal (Unix seconds); a number row value may be an int, float, Decimal or numeric text; a bool is no value.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "from_legacy_formula",
        "kind": "python",
        "purpose": "Convert Groups' membership formula {version 1, items [{kind condition|group, join and|or, field, operator, value, items}]} into the filter tree above with identical results. The formula is read strictly left to right with no precedence, and the tree nests the same way. Values are kept as they are for validate_filter_set to check. A formula too complex for a filter set (more than 50 rules, more than 3 levels of groups after conversion) raises FilterSetValidationError. Groups' own validator and resolver are not used or changed.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "list_filter_sets",
        "kind": "python",
        "purpose": "List the saved filter sets a person can read for one module and view key (list_filter_sets(user, module_id, view_key)). Stored on the saved views table under the reserved view key 'fs-' + key, so a module's saved views never list them. Same sharing rules as saved views. Since 1.17.51: list_filter_sets(user, module_id, view_key, *, fields=None) takes the module's own field declarations (Core calls no provider from Python); the owner gets the full definition and every other reader gets the withheld form. Since 1.17.51 (additive, core.filter_sets stays 1.0.0) a reader who is not the owner never sees a rule value outside their scope: the full definition is the owner's only, and for anyone else each value that is not proven visible comes back as the rule {kind, field, operator, value: null, withheld: true}, with a top-level values_withheld count (0 when none), so the definition keeps its shape. For a field of kind id with the optional declaration key scope_kind ('client' or 'site') Equals and Does not equal show the id only when the reader is unrestricted, or holds it in whole_client_ids (client) or site_ids (site), or the Resource Directory finds that client or site in their scope; the four name operators show the text only when a client or site the reader may see has a name that contains it; any failure withholds. An id field with no scope_kind is always withheld from non-owners. text and bool values are shown; a rule on an unknown field or a value that is not text, a whole number or a bool is withheld. At most 200 lookups a call; past that, values are withheld. The set's name is an owner-typed label and stays visible. A row under 'fs-' whose payload is not a filter set (a saved view from before 1.17.50) is not listed.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "get_filter_set",
        "kind": "python",
        "purpose": "Read one filter set the person can read; a private set they cannot read raises FilterSetNotFound. Reader ids are returned to the owner only. Since 1.17.51: get_filter_set(user, set_id, *, fields=None) withholds out-of-scope rule values from a reader who is not the owner, exactly as list_filter_sets does (value null, withheld true, values_withheld); without fields every value of a set the person does not own is withheld.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "create_filter_set",
        "kind": "python",
        "purpose": "create_filter_set(user, module_id, view_key, name, definition, readers=None, *, fields) saves a named set owned by the user. fields are the module's own declarations for this person; the definition is validated against them. readers empty shares the set with everyone who can use the module. Writes a strict Core audit row (module core, object_type filter_set, action add) in the same transaction, with counts and never a rule value or a reader id. At most 100 sets per owner, module and view key. Failures raise a FilterSetError subclass.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "update_filter_set",
        "kind": "python",
        "purpose": "Change the name, definition or readers of a filter set (update_filter_set(user, id, *, name, definition, readers, fields)). Owner only, no administrator override. fields is needed when a definition is given. Writes a modify row for a name or definition change and custom:filter-set-share when the sharing changes, in the same transaction.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "delete_filter_set",
        "kind": "python",
        "purpose": "Delete a filter set. Owner only. Writes a delete audit row in the same transaction. Failures raise a FilterSetError subclass (FilterSetValidationError, FilterSetFieldUnavailable, FilterSetNotFound, FilterSetPermissionDenied, FilterSetConflict, FilterSetAuditError).",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "resolve_filter_set",
        "kind": "python",
        "purpose": "resolve_filter_set(user, module_id, filter_set_id, fields) -> normalized tree, for a module's list endpoint to evaluate with build_q or matches. fields are the module's own declarations for this person. The stored definition is validated again against them: a rule on a field the person may no longer use, or one the module no longer declares, raises FilterSetFieldUnavailable ('This filter set uses a field you cannot use.'): fail closed, never dropped, never widened. Core calls no provider here.",
        "audience": "consumer/backend",
    },
    {
        "area": "filter-sets",
        "import_path": "tec_tac.filter_sets",
        "name": "PROVIDER_CAPABILITY_SUFFIX",
        "kind": "python",
        "purpose": "The provider shape a module implements to offer filters: register the capability '<module id>.filter_fields' 1.0.0 (a core or server module also lists it in its manifest capabilities; the module requires framework >=1.17.50) with describe_fields(*, context) -> list of field declarations the person may use (the provider decides per permission), and distinct_values(field_id, *, context, search, page, page_size) -> {values: [{value, label}], has_more} for a field whose values.source is 'distinct'. context is tec_tac.resources.user_context(user). The provider MUST filter at the source inside context.scope (never a value from a client or site the person cannot see) with one indexed, bounded query of at most page_size + 1 rows. Core calls a provider only from GET /api/tfd/filter-sets/fields/ and GET /api/tfd/filter-values/, for the signed-in person, and publishes no Python function that calls a provider for another module. Since 1.17.52 (additive; the provider capability stays 1.0.0, a module that declares these requires framework >=1.17.52) a declaration may use kind 'date' or 'number' and the optional keys stored_as (kind date only: 'datetime' default, or 'date'), integer (kind number only, a bool, refuses a decimal), and minimum and maximum (kind number only, finite numbers, minimum <= maximum). A date or number field takes values.source 'none' only and may not declare name_lookup, name_key or scope_kind; each new key is refused on the wrong kind. A provider on a Core older than 1.17.52 drops a date or number declaration with a log line. This row names the constant that holds the suffix 'filter_fields'.",
        "audience": "provider module/backend",
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
        "name": "get_tactical_upload_max_bytes",
        "kind": "python",
        "purpose": "Return the largest file one Tactical operation may forward, in bytes (1.17.14, CQ40): the system setting tactical_operation_upload_max_mib, 1 to 25 MiB, default 10 MiB. Never raises: any failure, or a stored value out of range, reads as 10 MiB. Informational: Core's executor and HTTP route apply it, modules do not.",
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
        "purpose": "Declare one typed Tactical operation from the owning core module's AppConfig.ready() (1.17.7): (id, module_id, method, route, permissions, scope, body_fields, audit, module_permission=None, message=None, query_params=None, upload=None, ...; the keywords added since are described in the notes of the HTTP route row, the newest being file_response in 1.17.41). route is a Tactical route template such as agents/{agent_id:agent}/reboot/. permissions are Tactical Role flags, all required. scope lists {type agent|client|site, source path:<name>|body:<field>}. body_fields is the whitelist of JSON body keys. audit is {action, object_type, audit_fields}. Since 1.17.8 only the core module that owns the route may declare it: Core's route owner table (docs/tactical-operations.md, Who may declare where) decides by the longest matching route prefix, so clients/ is Core's (AD-11), core/codesign/ is Licensing's alone (AD-16), agents/{id}/cmd/ is Remote Background's and agents/{id}/{port}/webvnc/ is Take Control's (AD-18), and Endpoints declares none. Refuses routes Core owns, a second caller for the same (method, route), an unknown flag, and a legacy, unknown or disabled module (TacticalOperationRegistrationError, a ValueError). The registry is empty until a module declares an operation. Requires framework >=1.17.7. Since 1.17.9: a route parameter whose kind is agent or int can never hold a route word, but an untyped (str) parameter can, so a route such as agents/{x}/{p}/create-key/ is judged by every route it can reach and is refused to a module that does not own them all (declare {agent_id:agent}). Core also re-checks route ownership at dispatch and answers 404 tactical_operation_not_found for an operation whose module no longer owns the concrete path. Since 1.17.9 (AD-20) a module that declares replaces and is honoured joins the owners of the replaced core module's rules and of no other; see module_replacement. Since 1.17.13 every addition below is optional, so an operation declared the 1.17.12 way registers and runs unchanged (capability core.tactical_operations 1.1.0). audit may also carry object_param (a path parameter of the route: its value is the audit row's object_id, also on deny and outcome-unknown rows) and before = {route, fields} (a Tactical GET route of the same module whose parameters are a subset of the operation's own, with the same names and kinds; Core runs it in-process through Tactical's own view as the signed-in user before the change and writes at most 16 whitelisted top-level scalar fields, strings cut to 256 characters, as the row's before value; a failed read never blocks the change and the row metadata says before unavailable). A scope entry may use a body-selected type (the before:<field> source of 1.17.13 was removed in 1.17.14, see below), {type: body:<field>, source, type_map: {value: client|site}}, with the resolved type written to the row metadata as scope_type. query_params is a whitelist of up to 16 query names (for a GET operation until 1.17.41; any method since). upload = {field, max_bytes, extensions} lets a POST, PUT or PATCH operation forward exactly one file part as multipart/form-data (non-empty extension allow-list; the ceiling is the system setting tactical_operation_upload_max_mib, 10 MiB by default and at most 25 MiB since 1.17.14, and max_bytes may not exceed 25 MiB; field may be the value {file_name} to name the part after the cleaned file name, which Tactical's report asset upload needs). A module that uses them requires framework >=1.17.13. Since 1.17.13 (AD-21) the declaring module's effective category decides: a missing category counts as test, and a premium, server (bar Licensing for core/codesign/) or test module is refused every route even where the owner table lists its id; an honoured AD-20 replacement keeps its rights. Since 1.17.14 (Johan CQ37, capability core.tactical_operations 1.2.0, still major 1): the scope source before:<field> and the fail-closed 404 that came from a before-read that did not answer 200 are gone, and registering a before: source is refused with a plain message. An operation that has only an object id (an Agents note edit or delete: route agents/notes/{pk:int}/, audit.object_param pk, scope []) registers and runs with Tactical's own check deciding, as cancel-pending-action already did; the audit row still names the pk. audit.before stays as a non-blocking audit before-value. Nothing in modules/ declared before: or audit.before when it was removed. Since 1.17.18 (capability core.tactical_operations 1.4.0, still major 1; every addition is optional, so an operation declared the 1.17.17 way registers and runs unchanged): (1) caller_scope='unrestricted' (default None): only a caller with no client or site limits (core.resources.scope_unrestricted, the unrestricted flag of tactical_scope in the UI context) may run the operation. A limited caller, a caller with no role, an installer user and a failed lookup are refused 403 scope_unrestricted_required with a deny row (reason scope_unrestricted_required) and Tactical is never called; it is checked after the Tactical flags and the module permission and before the body is cleaned. It applies to every call of the operation, including a call whose body names no agent (the CQ57 'no agent' rule belongs to a row_lookup scope entry, not to caller_scope). Any other value is refused at registration. (2) A scope entry may carry optional: true (a body source only): Core resolves it only when the body field is present and not null, an empty list is allowed and checks nothing, and an absent entry adds no object id. A scope entry may have the type agent_pk for Tactical agent numbers (whole positive integers, one or a list of at most 1000, from a body field or an int path parameter), checked against the role's client and site limits by a separate helper (agent canonical ids and pk aliases are not mixed). A client or site entry may be a list of ids. (3) A scope entry {type: 'agent', source: 'path:<int param>', row_lookup: '<lookup id>'} names a row lookup that the owning core module registers with register_tactical_row_lookup: for a route whose path id loads a row (a task, a policy check, a patch policy). Core calls the lookup in-process before dispatch. A missing lookup, a lookup that raises, answers None or answers the wrong shape is refused 404 object_not_found (no detail). A row that belongs to an agent is held to the caller's role scope; a row with no agent (agent_id None, a policy-level row) is allowed to anyone who holds the Tactical flag and Tactical decides the rest (CQ57). The row records object id from the path id and metadata scope_source row_lookup and agentless true or false. row_lookup is refused on a body source, on a non-int path parameter and together with a second row_lookup entry. Core never reads Tactical models itself; the small race between the lookup and Tactical's own load is accepted. (4) audit.before may carry count_fields (list fields whose length only is recorded as <field>_count) and select = {param, field='id'} for a list GET: Core reads the list in-process as the signed-in user and selects the row whose field equals the cleaned PATH parameter (never anything the browser sends), a bare list or a paginated {results: [...]} answer, first 1000 rows scanned; no match or a non-list answer records before unavailable and never blocks the call. A declared before field whose value is a list of whole numbers or short strings (256 characters each, control characters dropped) is now recorded as a list, capped at 1000 entries with <field>_count and <field>_truncated, and lists of objects are never recorded. At most 32 fields may be declared (16 before 1.17.18). A caller can still never supply a before over HTTP; the Python-only audit_before keyword is unchanged. (5) body_selector: a list of at most 3 conditions {field, present: true|false} or {field, equals: text|whole number|boolean} on body_fields, all of which must hold. A second operation on the same (method, route) is accepted only when both belong to the same module, every operation on the route declares a body_selector, and every pair is provably exclusive (one field with contradicting conditions: present true against false, two different equals values, or equals against present false); a second module stays refused (AD-6 reading of CQ60). At run time a body that does not satisfy the operation's own selector is refused 400 body_selector_mismatch with a refusal row and no Tactical call. (6) audit.params: a list of at most 8 path parameter names of the route; their cleaned values are copied into the row's after value next to the declared body and query fields. (7) Route owner table: agents/{id}/tasks/ belongs to tasks and agents/{id}/checks/ belongs to checks (Johan, 10 October 2026; the longest prefix beats Agents' agents/ rule). (8) Added in 1.17.19 (capability 1.5.0, additive): server_only (a strict true or false, default false) keeps the operation off Core's browser route: POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ refuses it 403 operation_server_only with one Core deny row (reason server_only, refused_action the declared action) before any body is parsed or file read, after the signed-in check and before the Tactical flag check, and never calls Tactical. A module backend calling run_tactical_operation runs it unchanged. It stops the browser path only and is not a verified caller identity; module code must never pass the private _via_http_route keyword (a call that carries it only makes Core stricter). (9) Added in 1.17.20 (capability core.tactical_operations 1.6.0, additive; AD-19 condition 4 as amended 11 October 2026, CQ63 b): when Tactical answers a call that is not GET with a 4xx other than 401 and 403 (400, 404, 409, 422, 429 ...), Core writes exactly one row with the Core-only action custom:operation-failed, the declared object type and object id, the correlation id, and metadata declared_action (the operation's own audit action), result failed, failure tactical_refused, tactical_status, operation, method and route. The text is fixed ('Tactical refused this change (HTTP <status>); nothing was changed.'). The row has no before or after value and none of Tactical's own text, so a filter on the declared action never matches it. A 4xx on a GET writes nothing; 401 and 403 still write deny; 5xx or an error after dispatch on a non-GET still writes custom:outcome-unknown. result.audit and X-Tec-Tac-Audit are now a verdict for these answers. A module that wrote its own failed row for a Tactical 4xx should stop, so one refused attempt gives one row. Needs framework >=1.17.20; feature-detect with capability version >= 1.6.0. (10) The 403 tactical_permission_denied detail names the missing Tactical flag. (11) A body_selector field must also be listed in body_fields; present false still lists the field. Audit actions written by Core only, refused at registration: deny, custom:outcome-unknown and (1.17.20) custom:operation-failed. Needs framework >=1.17.19 for server_only. Since 1.17.21 (additive, capability core.tactical_operations 1.7.0, framework >=1.17.21): audit may carry object_field, the name of a top-level scalar field of Tactical's JSON success answer (for example id or pk), and object_body_field, the name of a cleaned body field that must be one of body_fields (for example name). Either gives the success row's object id (metadata.object_source answer or body) when no audit.object_param and no scope object does; object_field is tried first, and a bool, float, list, object or null value is ignored. Registration refuses either key on a GET operation, a name that is not a plain field name, a name that looks like a secret, and an object_body_field that is not in body_fields. A deny row, a failed row (Tactical's or Core's own) and an outcome-unknown row never carry the id, because they must not carry request body values or Tactical's text. An operation declared the 1.17.20 way registers and runs unchanged. Statement (1.17.68, patchmanagement 0.11.0 and 0.11.2; no behaviour changed): while a replacement of a core module is honoured (the one source is _honoured_pairs, AD-20), the replacement registers under its OWN module id (for Advanced Patch Management, patchmanagement, on winupdate/ and automation/patchpolicy/), and so does its row lookup. Core re-reads the honoured state on every call and at every dispatch. Registration happens in each process's ready(), and enabling the replacement reloads the web workers and restarts Celery, so no extra restart by hand is needed. The moment it stops being honoured its operations answer 404 tactical_operation_not_found, before any restart. See docs/module-replacement.md, 'The statement for operations and row lookups'.",
        "audience": "core module/backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "register_tactical_row_lookup",
        "kind": "python",
        "purpose": "register_tactical_row_lookup(module_id, lookup_id, fn) (1.17.18, capability core.tactical_operations 1.4.0, CQ56 a): the owning core module registers, from AppConfig.ready(), a function fn(pk: str) that answers None when the row does not exist, or a dict {'agent_id': '<canonical agent id>' or None} (None for a row that belongs to no agent, such as a policy task, a policy check or a policy-level patch policy). An operation names it with a scope entry {type: 'agent', source: 'path:<int param>', row_lookup: '<lookup id>'}; see register_tactical_operation (3) for what Core does with the answer. The same module and category rules as register_tactical_operation apply (TacticalOperationRegistrationError, a ValueError, for a module that is not a core module, a slug-shaped id, or a different function under the same id); a module may name only its own lookups, so another module's lookup id is simply missing and the call is refused 404 object_not_found. The lookup reads the module's own data; Core never reads Tactical models itself. Registering the same function again is idempotent. Requires framework >=1.17.18. Statement (1.17.68; no behaviour changed): the honoured replacement of a core module registers its row lookup under its own module id, exactly as it registers its operations (decided by _honoured_pairs on every call); when it stops being honoured the operations that name the lookup answer 404 tactical_operation_not_found, so the lookup is no longer reached.",
        "audience": "core module/backend",
    },
    {
        "area": "tactical-operations",
        "import_path": "tec_tac.tactical_operations",
        "name": "run_tactical_operation",
        "kind": "python",
        "purpose": "Run a declared operation for the signed-in user of an authenticated request and audit it where the call happens (1.17.7): run_tactical_operation(request, module_id, operation_id, params=None, body=None, query=None, upload=None) returns TacticalOperationResult(status, data, content_type, headers, audit, content). Since 1.17.13 query is a flat object of the operation's whitelisted query names (each value a string or whole number of at most 512 characters, no control characters, no '..' path segment; a name outside the whitelist gives 400 query_field_not_allowed) and upload is {name, content_type, content} (bytes) for an operation that declares a file part (refusals upload_not_allowed, upload_too_large, upload_type_not_allowed, invalid_upload; the audit row records the file name, size and content type, never the content). Core re-checks the Tactical flags, the optional module permission and the role's client and site limits, then dispatches in-process to Tactical's own view. Core's refusals raise TacticalOperationError(status, code, message, audit). It needs a request, so a Celery task cannot call it. Also available as capability core.tactical_operations 1.1.0 (1.0.0 until 1.17.12; ask for >=1,<2) operation run. Since 1.17.16 (capability core.tactical_operations 1.3.0, still major 1, additive) run takes two server-set keywords and is stricter about the request. correlation_id=None: 1 to 128 characters of letters, digits and . _ : -, written on every Core row of the call (success, deny and outcome-unknown) as audit.record(correlation_id=) does; a bad value is refused 400 invalid_correlation_id. audit_before=None: a flat dict of at most 16 fields (text up to 256 characters, whole numbers, true/false, null, and since 1.17.23 a list of whole numbers or texts) the caller asserts as the row's before value, for a route with no single-row GET to read; a list is kept to its first 1000 entries and the row carries <field>_count (the full length) and, when cut, <field>_truncated: true; a caller field named <list>_count or <list>_truncated next to a list is refused; a field name that looks like a secret, a nested value, a list holding an object, float, boolean, null or another list, a float or an oversize value is refused 400 invalid_audit_before. It is used only when the operation declares no audit.before read (Tactical's own read wins when both exist), is written only on the success row, and the row metadata says before recorded and before_source caller (before_source tactical for a read), so a reviewer can tell an asserted value from a read one. Neither keyword is available over HTTP: the route still accepts only params, body and query, and a browser can never send a correlation id (the audit endpoints refuse one). The request must now be a real Django HttpRequest, or a DRF Request wrapping one, whose user is authenticated and which carries tec_tac_session (left by Core's SessionAuthenticated guard); any other object is refused 401 authenticated_request_required with no audit row, because there is no trustworthy actor to write. Real callers (views that use SessionAuthenticated) are unaffected; a module's own stub tests that pass a fake request must now pass one that carries tec_tac_session. Requires framework >=1.17.16 for any of these. Since 1.17.21 (additive, capability core.tactical_operations 1.7.0): when Core refuses a call that is not GET before Tactical is called, with body_field_not_allowed, invalid_body, invalid_params, scope_field_required, invalid_correlation_id or invalid_audit_before, it writes one Core-only custom:operation-failed row (failure core_refused, metadata code and declared_action, a fixed Core text, no before or after value, no body, query or upload value) and sets TacticalOperationError.audit to the verdict {recorded, id, action}; X-Tec-Tac-Audit says the same over HTTP. A GET refusal writes no row and keeps audit None. body_too_large, invalid_query, the upload codes and tactical_route_changed still write no row. correlation_id and audit_before are now cleaned at the validation step, after the operation lookup and the permission checks, so an unknown operation or a caller who fails the permission checks is refused for that reason first, and no deny row carries an invalid correlation id. A module writes its own failed row for these six codes only when error.audit is None.",
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
    {
        "area": "caller-identity",
        "import_path": "tec_tac.caller_identity",
        "name": "calling_module",
        "kind": "python",
        "purpose": (
            "calling_module(*, provider_module_id) -> CallerIdentity(module_id, kind, module_version) or None (1.17.21, Johan CQ65 a, AD-26, capability core.caller_identity 1.0.0, "
            "framework >=1.17.21). A provider module calls it inside a function to learn which module's code is calling it. Nothing is passed in by the caller. The identity "
            "names signed modules only: kind is always module, and Core is never a caller. Core walks the Python stack upward from the provider's frame and decides by each "
            "frame's code file (real path): the frame that called calling_module must be the provider's own, and the provider's frames that follow one another directly are "
            "skipped; the first frame after them is the caller, and only that frame. It gives that module only when it is inside an installed module that is an extension, not "
            "legacy and enabled right now (read on every call, never cached). Anything else in that position gives None and the walk stops: a disabled, legacy or unreadable "
            "module, any frame inside the tec_tac framework (the Scheduler, a row lookup, signal dispatch, send_p1_email), a frame with a generated file name (<...>), and the "
            "standard library, Django, DRF, Celery or other third-party code. No gap is skipped between the provider and the module. A provider must treat None as refuse. Any "
            "registry or state error gives None (fail closed). Limits, in plain words: Core is never seen as Core or as any caller; a module's callable that Core runs (a "
            "Scheduler handler, a row lookup, a signal receiver, a functools.partial of a provider function) is that module only when its own frame calls the provider directly, "
            "else None; a module that calls another module's code is seen as the module whose code makes the call, so an allow-list of modules is only as strong as every "
            "allowed module's callback surface; code that forges its own file name (compile() with another module's path) is hostile code, and signed-module review stays the "
            "defence; identity says which module's code is calling, not which person, so a provider still checks the person or the service purpose itself. Core's own Priority 1 "
            "notice email does not go through caller identity in this release. It changes nothing in ResourceAccessContext, trusted_service_context, build_operation_context or "
            "notices.publish. Feature-detect with has_capability('core.caller_identity') and requires.framework >=1.17.21. See docs/caller-identity.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "event-jobs",
        "import_path": "tec_tac.event_jobs",
        "name": "register_event_job",
        "kind": "python",
        "purpose": (
            "register_event_job(*, id, module_id, label, handler, soft_time_limit_seconds=None, max_attempts=None, backoff_seconds=None, max_backoff_seconds=None, "
            "expires_seconds=None, max_backlog=None, dedupe_seconds=None, audit_success=False) -> EventJobPublisher (1.17.45, capability core.event_jobs 1.1.0 since 1.17.47, framework >=1.17.47 for the caller check, "
            "Johan 16 October 2026). The one sanctioned way for a module to do small background work because something happened (a Tactical alert was saved, a webhook arrived): "
            "no private thread, timer or event-started Celery task. Call it from AppConfig.ready(); it touches memory only and returns the one handle that can publish this job. "
            "id is '<module_id>.<job>' (the module part is the module's own id, exactly as spelled, since 1.17.63; lowercase letters, digits, - _ and . in the job part) and must start with the module's own id. handler(context) gets an EventJobContext "
            "(a dict with job_id, module_id, key, payload, attempt, max_attempts, final_attempt, enqueued_at and run_id, and no user fields) and returns None or a small JSON-safe "
            "dict. Registration is bound to the module: module_id must be an installed, enabled extension read from the registry and handler's code file must lie inside that module's "
            "own folder (real-path check); a partial, a built-in or generated code is refused. Refusals raise EventJobRegistrationError, a ValueError; a module wraps the call and logs, so "
            "Tactical always starts. Registering the identical definition again returns the same handle; a different one under the same id is refused. Core owns every ceiling: "
            "soft_time_limit_seconds 5-600 (default 30; the hard limit is 15 seconds more), max_attempts 1-10 (3), backoff_seconds 5-3600 (60, doubling, capped by max_backoff_seconds "
            "up to 3600, plus up to 20 percent jitter), expires_seconds 60-86400 (1800: a job not started by then ends expired), max_backlog 1-5000 (500 pending rows per job), "
            "dedupe_seconds 0-3600 (0: a succeeded run with the same key inside the window counts as a duplicate) and audit_success (False). A handler runs at least once and must be "
            "safe to run twice. Failures: SchedulerPermanentError, ValueError and TypeError give up at once; SchedulerTransientError, SoftTimeLimitExceeded and any other exception retry "
            "with Core's back-off until the attempts are used up, then the row ends failed with one Core audit row. The job runs as the module, not as a person: a handler cannot call "
            "run_tactical_operation, so an event job cannot make a Tactical change (the AD-13 system-action contract is still open). Feature-detect with has_capability('core.event_jobs') "
            "and set requires.framework >=1.17.47 (1.17.47 verifies the caller of every publish, AD-36; see EventJobPublisher). Needs migration 0032_event_jobs. See docs/event-jobs.md."
        ),
        "audience": "module/backend",
    },
    {
        "area": "event-jobs",
        "import_path": "tec_tac.event_jobs",
        "name": "EventJobPublisher",
        "kind": "python",
        "purpose": (
            "EventJobPublisher.publish(key, payload=None) -> PublishResult(outcome, reason) and EventJobPublisher.status() -> dict (1.17.45, core.event_jobs 1.1.0 since 1.17.47). The handle "
            "register_event_job returns; it cannot be built, copied or pickled, and only the registering module holds it. Since 1.17.47 (AD-36) every publish verifies its caller: the first frame above publish must be the code of the enabled, non-legacy module that owns the job (Core's private caller check, 5 second snapshot), else the answer is error with 'the caller is not the module that owns this job' and nothing is stored; call publish from your own module code, not through a Core callback. Since 1.17.48 Core counts each such refusal of a foreign caller and writes one Core audit row (custom:event-job-refused, with the count) per module and job once the clock hour ends; since 1.17.49 the refusal is counted in memory and sent to Core's worker in bulk (at most one bounded broker message a minute per process, no Redis call in publish), and the worker keeps the count in the shared cache (the limits: counts wait in the web process's memory until that process's next publish or refusal sends them and are lost if it restarts first; a count that reaches the worker after its hour has already been reported is not reported; a cache flush or fault loses a count; an audit write that is not confirmed is retried by the next tick); when the module list or state cannot be read the answer is error with 'the caller could not be verified', nothing is stored (the publish is lost, nothing is kept to retry), no tally and no row, and the next publish after about 1 second is checked again. The outcomes list is unchanged. publish never raises and never touches the network but one bounded "
            "broker publish (2 second timeout, retry off, a 30 second circuit breaker after one failure). outcome is queued, duplicate, dropped, disabled or error. It answers from memory "
            "first (the registry, a 5 second module-enabled cache, a 3 second in-process (job, key) duplicate check, a per-process cap of 600 publishes a minute per job, a cached backlog gauge; "
            "an absent gauge means open) and drops without a database query when any says no. Otherwise, after the caller's transaction commits (at once when none is open), it stores one row "
            "(PostgreSQL: statement timeout 1000 ms) and sends one Celery message. A failed broker publish is logged and the row stays pending: the Scheduler tick enqueues it. key is "
            "1-128 characters of letters, digits and . _ : @ / - ; payload is a JSON object of at most 2 KiB with scalar, list and dict values only (ids, never secrets or text bodies), checked "
            "before anything is stored, never logged, audited, listed or returned. Idempotency: one key can be pending or running once per job (a second publish is duplicate). Inside an open "
            "transaction the answer is queued before the row exists, so a duplicate found at commit is counted in the stats and not reported to the caller. status() returns this job's counts, "
            "backlog, oldest pending age and last failure, never a key or a payload."
        ),
        "audience": "module/backend",
    },
    {
        "area": "event-jobs",
        "import_path": "tec_tac.event_jobs",
        "name": "verify_event_job_context",
        "kind": "python",
        "purpose": (
            "verify_event_job_context(context, *, expected_module_id, expected_job_id) -> VerifiedEventJob(run_id, module_id, job_id, key, attempt, final_attempt) (1.17.45, "
            "core.event_jobs 1.1.0 since 1.17.47). A handler passes its own module id and job id; Core refuses with EventJobContextInvalid a plain dict, a copy of the context, a context issued for "
            "another module's or job's run, a run that is no longer running and an expected id that is missing or not text. The same shape as scheduler.verify_run_context, with no owner "
            "because an event job has no person behind it."
        ),
        "audience": "module/backend",
    },
    {
        "area": "accounts",
        "import_path": "tec_tac.accounts",
        "name": "create_user",
        "kind": "python",
        "purpose": (
            "create_user(*, username, email, first_name, last_name, role_id, password, invited_by_id) -> CreatedUser(user_id, username, role_id) "
            "(1.17.27, binding entry accounts contracts for User Invite, capability core.accounts 1.0.0, framework >=1.17.27). Creates a Tactical user "
            "for an accepted invite the way Tactical's own add-user does, and never through the User model of a module. Callable only by a verified "
            "caller: Core identifies the calling module from the call stack (AD-26, CQ87), the allow-list is CALLERS (userinvite), and nothing is passed "
            "in for the caller, so there is no caller argument. The purpose is fixed to accept-invite. Core checks: the username is valid and free, "
            "ignoring case; the email is valid and free, ignoring case; the password passes Django's validators with Tactical's AUTH_PASSWORD_VALIDATORS "
            "(weak_password, with no password in the message); the role exists (role_not_found), is not a superuser role (role_not_grantable, while CQ86 "
            "is open) and bool or non-integer ids are refused (invalid_input). The inviter (invited_by_id) is re-read at acceptance: it must exist, be "
            "active, not be an installer user and still hold Tactical's can_manage_accounts (inviter_not_allowed, and nothing is created). Core never "
            "sets a TOTP key, so Core's first-sign-in two-factor set-up (1.17.22) applies. The user, the role lookup and one strict Core audit row are "
            "in one transaction; a failed audit write rolls the user back (audit_failed). Tactical's Mesh permission sync runs once, after the commit. "
            "Typed errors, all AccountsError subclasses with a stable code: invalid_input, username_taken, email_taken, weak_password, role_not_found, "
            "role_not_grantable, inviter_not_allowed, caller_not_allowed, audit_failed (check_available adds rate_limited and rate_check_unavailable since 1.17.30). The module still checks the invite token and the emailed code "
            "itself. See docs/accounts-contract.md."
        ),
        "audience": "authorized backend",
    },
    {
        "area": "accounts",
        "import_path": "tec_tac.accounts",
        "name": "check_available",
        "kind": "python",
        "purpose": (
            "check_available(username, email, invited_by_id) -> Availability(status, username_taken, email_taken) (1.17.29; invited_by_id required since "
            "1.17.30, capability core.accounts 1.2.0, framework >=1.17.30, AD-31 and AD-34 condition 4). Says whether a username or an email is already used, ignoring case, so the create step of an invitation can tell the "
            "inviter before the invite is sent. status is exactly username_taken, email_taken or free; when both clash it is username_taken (the order "
            "create_user uses) and both flags are true. Same verified caller rule as create_user (caller_not_allowed, no query runs for any other "
            "caller); inputs are cleaned as in create_user (invalid_input), and invited_by_id must be a whole number above zero (a bool or a non-positive "
            "number is invalid_input). Since 1.17.30 Core re-checks the inviter as create_user does (the person exists, is active, is not an installer user and "
            "still holds can_manage_accounts, else inviter_not_allowed, with no lookup run and nothing counted) and limits each inviter to 30 answered calls per "
            "10 minutes and 300 per day (rate_limited; rate_check_unavailable, failing closed, when the counter cannot be read). A limit hit logs a warning and "
            "writes no audit row. A read: no audit row, no write. It returns no user id, name or other field. "
            "Core cannot see whether a person is signed in, so the module still calls it only from the signed-in create step and keeps its own limit. "
            "The stricter form was chosen by the main session on 14 October 2026 (AD-34 condition 4); Johan may relax it. "
            "Core does not verify the invite token (AD-31 condition 5, an accepted limit). See docs/accounts-contract.md."
        ),
        "audience": "authorized backend",
    },
    {
        "area": "accounts",
        "import_path": "tec_tac.accounts",
        "name": "list_grantable_roles",
        "kind": "python",
        "purpose": (
            "list_grantable_roles(inviter) -> [{id, name, is_superuser}] ordered by name then id (1.17.27, capability core.accounts 1.0.0, framework "
            ">=1.17.27). The roles the signed-in inviter may grant: an effective superuser sees every role, anyone else sees the roles that are not "
            "superuser roles. Each row carries id, name and is_superuser only, never permission flags or scope lists. Denied with accounts_permission_required "
            "unless the inviter is authenticated, not an installer user and holds Tactical's can_manage_accounts (AD-12: nothing is returned). Same verified "
            "caller rule as create_user (caller_not_allowed). A server module uses this instead of Tactical's /accounts/roles/ (AD-6)."
        ),
        "audience": "consumer/backend",
    },
    {
        "area": "module-routes",
        "import_path": "tec_tac.route_mounting",
        "name": "mounted_routes",
        "kind": "python",
        "purpose": "mounted_routes() -> [{prefix, module, state, reason}] (1.17.16, read only): what Core did with each loaded module's manifest routes key. A module may declare \"routes\": {\"prefix\": \"windows-patching\", \"urlconf\": \"tec_tac_patching.urls\"} in tec_tac.json (extensions only). Core then serves the module's urlconf at /api/tfd/<prefix>/ and the module no longer appends to tacticalrmm.urls or tec_tac.urls from its AppConfig.ready(). prefix is one lowercase slug (a-z, 0-9, _ and -, up to 64 characters) and defaults to the module id; it may differ from the id. urlconf is required and must sit inside one of the module's own django_apps packages, never tacticalrmm, tec_tac or another module's. Core mounts after every AppConfig.ready() has run, only modules whose app is loaded (a disabled module, and an AD-20 replacement Core dropped, are not mounted), and appends after Core's own routes, so a Core route always wins on an overlap. Each module is mounted on its own: a urlconf that cannot be imported is logged and skipped and never stops Tactical starting. Two loaded modules asking for the same prefix: the first by sorted module id is mounted, the second is refused (state refused). Compatibility path, no end date: a module that still appends to tec_tac.urls or tacticalrmm.urls is untouched and shows state compat, so adding routes and forgetting to drop the append is harmless. state is mounted, compat or refused. A bad routes key is refused when the package is inspected for install, not at start-up. Requires framework >=1.17.16.",
        "audience": "framework/diagnostics",
    },
    {
        "area": "notices",
        "import_path": "tec_tac.notices",
        "name": "publish",
        "kind": "python",
        "purpose": "publish(user, client_id, level, message, action=None, *, module_id) -> {created, notice} (1.17.16, CQ49): store one notice for a user from a module backend route or a Scheduler handler (no request needed). user is a user object or a username of an active interactive user (active, not an installer user, no agent link, not blocked from the dashboard); anything else raises NoticeError. module_id must be an installed, enabled extension and never core or tec-tac; it becomes the notice source. It is a CLAIMED id: Core does not yet verify which module is calling, so a module can name another enabled module until the verified caller identity request ships. level is info, success, warning or error. message is up to 1000 characters. action is None or {label, route}; route must be an internal Tec-Tac route starting with '/' (never javascript: or a URL), and a label needs a route. client_id is required and is the dedupe key, stored as <module_id>:<client_id> (the pair must fit 64 characters of letters, digits and . _ : -). A notice is stored once per user and key and a notice the person has read is never reset. Not exposed over HTTP. Requires framework >=1.17.16.",
        "audience": "provider/backend",
    },
    {
        "area": "audit",
        "import_path": "tec_tac.audit",
        "name": "request_correlation_id",
        "kind": "python",
        "purpose": "request_correlation_id(request) -> str (1.17.16): the correlation id every Core audit row of this request carries. Core has no middleware entry of its own, so the first row written for a request (or the first call here) mints the id and keeps it on the underlying Django request as tec_tac_request_id; every later row of the same request shares it, so a module backend can stamp its own parent audit.record row with it (correlation_id=) and the Tactical operation rows it triggers carry the same id. The attribute is set by Core only and a browser header (X-Request-ID, X-Correlation-ID) is never read. An explicit correlation_id on audit.record or run_tactical_operation wins over the request id and does not replace it. Requires framework >=1.17.16.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "start_one_off_run",
        "kind": "python",
        "purpose": "start_one_off_run(*, user, owner_module, action_id, targets=None, parameters=None, name=None, retry_count=0, retry_delay_seconds=60, confirmation_id=None) -> TecTacScheduleRun (1.17.16, AD-13 condition 2, CQ50): start one run of a registered Scheduler action on behalf of a user and track it. A module starts only its own actions (action.module_id == owner_module). The user must be active and not an installer user, hold the action now (an action with no permission is startable only by native scheduler managers, as in the browser) and hold the targets' Tactical scope; otherwise SchedulerNotAllowed (a SchedulerError). Core creates one disabled ONCE schedule owned by the module with owner_key one-off:<uuid> and created_by the user, so the ticker never dispatches it, the Scheduler page shows it as managed by the module, and the existing once-retention cleanup removes it (48 hours by default); the run history stays. It then queues the run like a manual run and writes one best-effort Core audit row (action add, object_type scheduler_run). Just before the handler runs, Core re-checks that the user is still active and still holds the action and the scope; if not the run ends skipped with a plain reason and an audit row, and the handler never runs. The handler context gains owner_type, owner_module, owner_key, owner_user_id, owner_username (the user fields only for a one-off run and a user-owned schedule, otherwise None) and one_off (see the scheduler docs). This is the start-and-track call, not the system-action contract (registered Tactical actions run in-process as the owner, still open). Call it outside an uncommitted database transaction. Requires framework >=1.17.16. Since 1.17.17 the action's permission may be a Tactical role flag or an any-of list (see register_scheduled_action), the flag is read again just before the handler runs, and the run cannot be repeated from the browser: POST /api/tfd/scheduler/schedules/<id>/run/ refuses every one-off schedule with 403, for any caller, so a second user cannot queue a run under the first user's identity. Since 1.17.18 the keyword-only retry_count (whole number 0 to 10, default 0) and retry_delay_seconds (whole number 1 to 86400, default 60) are stored on the one-off schedule and snapshotted onto the run; when the handler raises SchedulerTransientError the worker re-queues the run with that countdown until the attempts are used up, and the owner re-check (AD-13 condition 2) runs again on every attempt, so a permission lost between attempts ends the run skipped. A bool, text or float, or a value out of range, raises SchedulerError before anything is created. The defaults equal the behaviour before 1.17.18, so a call without the keywords is unchanged. The keywords need framework >=1.17.18. Since 1.17.66 (framework >=1.17.66) the optional keyword-only confirmation_id=None: for a declared system action Core checks the user's permission, Tactical flags and scope now and refuses without a valid id (SystemActionCreationRefused, a SchedulerNotAllowed); ask for the id with timing {schedule_type: once, run_at: now}. For any other action the argument is ignored.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "get_one_off_run",
        "kind": "python",
        "purpose": "get_one_off_run(run_id, *, owner_module) -> dict (1.17.16): the state of a run start_one_off_run started, in the serialize_run shape (id, status, result, error, started_at, finished_at ...). A module reads only its own: an unknown run, a run of another module and a run that is not a one-off raise SchedulerError. The run stays readable after its one-off schedule is cleaned up. Requires framework >=1.17.16.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "get_owned_schedule",
        "kind": "python",
        "purpose": "get_owned_schedule(owner_module, owner_key) -> dict | None (1.17.16): read one module-owned schedule without the model: {enabled, schedule_type, next_run_at, last_run_at, last_run_status, last_run_finished_at}, or None when no schedule has that tuple. next_run_at is None for a disabled schedule. Read only, no permission input: a module reads only its own tuple, the same trust as reconcile_schedule. Requires framework >=1.17.16. Since 1.17.63 the answer also carries created_by_username (the stored creator name, or None; additive).",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "SchedulerNotAllowed",
        "kind": "python",
        "purpose": "SchedulerNotAllowed (1.17.16): raised by start_one_off_run when the user may not run the action or touch the targets. A subclass of SchedulerError.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "verify_run_context",
        "kind": "python",
        "purpose": "verify_run_context(context, *, expected_module_id, expected_action_id, require_owner=True) -> VerifiedSchedulerRun (1.17.19, CQ64 a; the two expected ids are required since 1.17.20): a Scheduler handler passes the context object it was given and its own module id and action id, and Core confirms it issued that exact object for a run that is still running, then reads the owner from the database (the schedule's created_by for a one-off or user-owned run), never from the dict, and checks again that the owner is active and still holds the action and the target scope. It raises SchedulerRunContextInvalid (a SchedulerError) for a plain dict, a copy ({**context}, dict(context), copy.copy), a JSON, pickle or Celery round-trip, a context a module builds, a finished or deleted run, a run with no person behind it (unless require_owner=False, which verifies with user None) and any lookup error. VerifiedSchedulerRun is frozen: run_id, schedule_id, module_id, action_id, owner_module, owner_key, one_off, user, owner_user_id, owner_username; has_tactical_permission(flag) reads the owner again on every call and answers False on any error or a name that is not a can_* flag; resource_context() gives the owner's Resource Directory context so a scope-bound read runs as the person. The handler context is a dict subclass with every key it had, so handlers that ignore it are unchanged. Modules run in the same Python process as Core: this stops a module naming a run or an owner Core did not issue, and cannot stop deliberately hostile signed module code (signed-module review stays the defence). There is no per-run signed token. Since 1.17.20 (module-facing, breaking only for a caller of the 1.17.19 form, of which modules/ has none) expected_module_id and expected_action_id are required keywords: Core compares them, exactly, with the module and action of the run it loaded and raises SchedulerRunContextInvalid ('This run belongs to another module or action.', no ids echoed) when either differs or is missing, empty or not a string, so a context issued for module A's action cannot verify inside module B's handler. Calling it without them raises TypeError. It is not the AD-13 system-action contract, which is still open. Needs framework >=1.17.19; the ids need >=1.17.20. Since 1.17.65 (module-facing, framework >=1.17.65; signed 20 October 2026) a SCHEDULED run of a user-owned schedule verifies without the owner re-check, for every action (the creator was checked when the schedule was made; a manual run and a one-off run keep every re-check); VerifiedSchedulerRun.unattended is True for such a run. A module that wants its own live check calls has_tactical_permission or resource_context, which still read the owner fresh. VerifiedSchedulerRun gains the last fields creator_username, confirmed_by_username (the stored names, which survive a deleted user row) and unattended. user may then be None when the creator's user row is gone and require_owner=False. has_tactical_permission and resource_context stay fresh reads. A manual run and a one-off run keep every re-check. Since 1.17.68 (module-facing, framework >=1.17.68) the answer also reads the scope the schedule was created with (has_creation_scope, creation_scope_info, held_at_creation, resolved_endpoints; see VerifiedSchedulerRun), and a one-off run that delegation.start made for a grant a person confirmed verifies as unattended while its signed marker holds and its grant is unchanged (see start_delegated_run). Every other one-off keeps every re-check.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "VerifiedSchedulerRun",
        "kind": "python",
        "purpose": (
            "VerifiedSchedulerRun (1.17.19): the frozen answer of verify_run_context. Fields run_id, schedule_id, module_id, action_id, owner_module, owner_key, one_off, user, owner_user_id, owner_username and, since 1.17.63, creator_username, confirmed_by_username, unattended (defaults None, None, False); methods has_tactical_permission(flag) and resource_context(). Built only by verify_run_context. "
            "Since 1.17.68 (module-facing, additive, framework >=1.17.68; Johan, 21 October 2026, Q-APM12 option b: 'the work that he has done shouldn't be undone'): two private appended fields hold the scope the schedule was created with and the run's targets, and four public reads use them. "
            "has_creation_scope (property): True when the schedule carries the Tactical client and site scope and the role flags its person had when they created or last edited it; False for a schedule made before Core 1.17.68 that nobody has edited since. "
            "creation_scope_info() -> {v, captured_for, captured_at, scope: {unrestricted, whole_client_ids, site_ids}, flags} or None: a copy; changing it changes nothing. "
            "held_at_creation(flag) -> bool: for an unattended run, whether the person held the Tactical role flag (a boolean can_* field of Tactical's Role) when they saved the schedule; the owner's live row is never read, so a disabled or demoted owner changes nothing. A run a person started answers has_tactical_permission(flag), as before. A name that is not a can_* flag answers False. "
            "resolved_endpoints(*, whole_scope=False, limit=MAX_AGENTS) -> list of {pk, agent_id, hostname, platform, client_id, site_id}: the endpoints of the run's targets that lie inside the stored scope (unattended) or the person's live scope (a person-started run). Native targets (client, site, endpoint, dynamic) resolve as Core reads them; a module-owned type resolves through the module's resolver (register_target_resolver); none returns [] unless whole_scope=True, which returns the whole scope. The result is never wider than the targets AND the scope. More than limit (at most 40000) raises SchedulerPermanentError and nothing is truncated; a target that cannot be read as endpoints raises SchedulerPermanentError; a read fault raises SchedulerTransientError. "
            "For an unattended run with no stored scope, held_at_creation and resolved_endpoints raise CreationScopeUnavailable (a SchedulerPermanentError; plain text: edit it and save it once). Core never invents a scope. has_tactical_permission and resource_context are unchanged and still read the owner fresh and fail closed, so a module that keeps calling them for an unattended run keeps the old behaviour until it adopts these reads."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "SchedulerRunContextInvalid",
        "kind": "python",
        "purpose": "SchedulerRunContextInvalid (1.17.19): raised by verify_run_context with a plain message when the context is not one Core issued for a run that is still going, or its owner may no longer run it. A subclass of SchedulerError.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "PendingCompletion",
        "kind": "python",
        "purpose": (
            "PendingCompletion(kind, external_job_id, note=None) (1.17.61, R-21): what a Scheduler handler returns for 'started, finished later'. A frozen Core class, not a dict with magic keys, so no existing handler "
            "can park a run by accident; only an exact PendingCompletion counts (a subclass, or a dict with the same keys, is an ordinary result). kind is 'module' (the module completes the run with complete_pending_run) or "
            "'server_maintenance_job' (Core settles the run when the job file is terminal; external_job_id is the job's lowercase UUID). external_job_id is 1 to 128 characters of letters, digits and . _ : -. note is optional "
            "printable text up to 200 characters. A bad value raises SchedulerError when the object is built. Core keeps the run 'running' (the status values do not change, so the concurrency skip, once-cleanup and "
            "remove_owned_schedule keep protecting it), stores completion_state 'pending' and the reference, does not set schedule.last_run_at and never retries it. A run that waits longer than its action's timeout_seconds "
            "(7 days at most) fails with error type CompletionTimeout. For kind server_maintenance_job Core reads the job when the handler returns and fails the run with PendingRefused unless the job exists and its "
            "context names this module (source_module) and this run (source_run_id); the binding stops mistakes and an honest module, not hostile signed code. Requires framework >=1.17.61."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "pending_completion",
        "kind": "python",
        "purpose": "pending_completion(kind, external_job_id, note=None) -> PendingCompletion (1.17.61, R-21): the way a handler builds the value above. Raises SchedulerError for a kind, id or note that is not valid. Requires framework >=1.17.61.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "complete_pending_run",
        "kind": "python",
        "purpose": (
            "complete_pending_run(run_id, *, external_job_id, outcome, result=None, error=None, warnings=None) -> {run_id, status, duplicate} (1.17.61, R-21): the only way a module finishes a run whose handler returned a "
            "PendingCompletion of kind 'module'. outcome is succeeded, failed, cancelled or timed_out (anything else raises SchedulerError). Every rule fails closed. (1) Core verifies the caller from the call stack "
            "(the verified calling-module identity of core.caller_identity, AD-26): it must be the enabled module that owns the run's action, called from that module's own code; Core, library, generated, disabled and legacy frames are refused. The function "
            "is a plain re-export with no wrapper frame, so do not wrap it in a decorator or call it through a library. (2) Under a row lock the run must still be running with completion_state 'pending' and external_job_id must "
            "equal the one the handler returned; call it after the handler has returned (an earlier call is refused as not_pending). (3) The same completion twice is an idempotent no-op (no second audit row, finished_at "
            "unchanged); a different second outcome (conflict), a completion after stale recovery (late), a wrong job id (wrong_job) and a completion by the wrong module (wrong_module, caller_unverified) are refused with "
            "SchedulerCompletionRefused (a SchedulerError with .reason and a plain message) and at most one best-effort audit row custom:scheduler-completion-refused (reason code only, throttled to one per run and reason "
            "per five minutes). (4) succeeded ends the run succeeded; failed, cancelled and timed_out end it failed with error type ExternalFailed, ExternalCancelled or ExternalTimedOut. A job created, or an "
            "acknowledgement, is never success. (5) result is JSON up to 16 KiB (a non-object value is wrapped as {'value': ...}); error is printable text up to 500 characters; warnings (succeeded only) are up to 10 "
            "printable texts of up to 200 characters, kept in result['warnings']. A bad payload raises SchedulerError and changes nothing. A completion writes one best-effort audit row custom:scheduler-completion (no result "
            "text). Requires framework >=1.17.61."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "SchedulerCompletionRefused",
        "kind": "python",
        "purpose": "SchedulerCompletionRefused (1.17.61): raised by complete_pending_run when it refuses a completion. A subclass of SchedulerError with .reason (caller_unverified, wrong_module, action_unavailable, unknown_run, not_pending, wrong_job, conflict, late, and since 1.17.62 wrong_kind: the run is parked as server_maintenance_job, which only Core settles, so a module cannot complete it and the run is left unchanged) and a plain message that names no ids.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "serialize_run",
        "kind": "python",
        "purpose": (
            "serialize_run(run) -> dict (1.17.61, additive): gains the key 'completion': null for a run that never returned a PendingCompletion, otherwise {state, kind, since} where state is 'pending' (the run is waiting for its "
            "result; status is still 'running'), 'completed' or 'expired' (failed with CompletionTimeout), kind is 'module' or 'server_maintenance_job' and since is the ISO time the wait began. Every earlier key and every "
            "status value is unchanged, so a module that reads only the keys it read before is unaffected. New run error types: CompletionTimeout, ExternalFailed, ExternalCancelled, ExternalTimedOut, PendingRefused and "
            "SystemActionRefused (plus OutcomeUnknown from a system action). The built-in diagnostic action tec-tac.scheduler-test-pending (managers only, harmless, timeout 120 s) parks a run that no module can complete, "
            "so the run stays Running with a waiting label and then fails with CompletionTimeout; it is listed with the other scheduler actions in this export. Requires framework >=1.17.61."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "register_system_action",
        "kind": "python",
        "purpose": (
            "register_system_action(id, module_id, label, function, permissions, scope_kind='agents', dangerous=False, username_param=None) -> SystemActionDefinition | None (1.17.61, R-20, AD-13, capability "
            "core.system_actions 1.1.0 since 1.17.66): declare a typed Tactical function that Core may run unattended for a named owner. Call it from AppConfig.ready(); it touches memory only. Deny by default. (1) function is a key of "
            "Core's fixed table SYSTEM_FUNCTIONS (winupdate.scan and winupdate.install; since 1.17.66 also scripts.run; since 1.17.70 also winupdate.set_action, a write), never a dotted path: a module cannot name its own callable. (2) Only the module the table names (patching; scriptexecution for scripts.run) or the premium module "
            "that is its honoured replacement right now (AD-20) may register it; the owner must be a core module. A replacement that is not honoured is logged and nothing is registered (returns None, no exception). (3) "
            "permissions must contain every minimum flag of the table row (for scan and install: can_manage_winupdates and can_run_bulk, stricter than either Tactical route alone; for scripts.run since 1.17.66: can_run_bulk and can_run_scripts, stricter than Tactical's bulk route, which needs only can_run_bulk); a module may add flags, never remove one. "
            "(4) id is '<module_id>.<name>' and must be listed in the module's signed manifest key system_actions (a list of at most 20 ids; requires.framework >=1.17.61, an older Core refuses the unknown manifest "
            "key). (5) Identical re-registration is idempotent; a different definition under the same id is refused. Since 1.17.66 (CQ173, Johan: yes) winupdate.install may also be registered by the honoured replacement: Tactical's bulk install task re-approves updates by patch policy, so Core shows the fixed warning 'Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere.' in the confirmation and in the audit row. Since 1.17.68 (Johan, 21 October 2026) Core's patch lockdown (capability core.patch_lockdown) makes Tactical's own approve inert while that replacement is honoured, so for the replacement's install the warning is dropped from the confirmation, the audit row (which then carries patch_lockdown: active) and list_actions only while the guard is installed in the process; Windows Patching's own install and every other case keep it. Since 1.17.68 an optional keyword delegable_to=() lists up to five other module ids that may start this action for someone else under a delegation grant (describe_delegation, register_delegation_grant, start_delegated_run). username_param is allowed only for a function that takes a username (scripts.run does; Core always passes the creator's stored name, never a name from the caller). A refusal raises SystemActionRegistrationError (a ValueError): "
            "wrap the call, log and go on. Requires framework >=1.17.61. "
            "Since 1.17.70 (module-facing, framework >=1.17.70; CQ203, AD-45) a row of the table has a kind, task (every row before) or write, and a flag replacement_only. The one write row, winupdate.set_action, is registered ONLY by the module that is the honoured replacement of patching right now: Windows Patching itself is refused (it uses a person's own request), a premium module that replaces nothing, replaces another group or is not honoured is refused or, for a replacement that is not honoured, not registered (None). It must be registered with dangerous=True and an empty delegable_to, with permissions that include can_manage_winupdates, and its parameters are {allowed_actions: a subset of approve, ignore, nothing}. A module names only the key, never a callable. "
            "See docs/system-actions.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "run_system_action",
        "kind": "python",
        "purpose": (
            "run_system_action(context, *, action_id, agent_ids, parameters=None) -> {outcome: 'queued', agents, message, groups: {total, sent, failed, not_started}, summary} (1.17.61, R-20, AD-13; groups and summary since 1.17.66): call it from the module's own Scheduler handler with the context object the "
            "handler received. The work is queued in Tactical, not done: the message says 'Queued in Tactical; the result shows in each endpoint's update list.' At every run Core checks, in order: the context is the object "
            "Core issued and a person is behind the run (a user-owned schedule or a one-off run; a module-owned run has no owner and is refused); the verified caller is the run's module and the action's module; the action is "
            "registered, its module is enabled right now and a replacement is honoured right now; the owner is re-read from the database (active, not an installer user) and holds every Tactical flag now; the count is 1 "
            "to 40000 (since 1.17.66, 2000 before; refused above, never truncated); every endpoint number exists and lies inside the owner's Tactical role scope (one endpoint outside refuses the whole call, nothing is narrowed, and a scheduler manager "
            "gets no bypass); since 1.17.62 every endpoint is also one of the run's snapshotted schedule targets (client, site, endpoint or the scope of a dynamic target; a run never widens the set: outside_targets, or targets_unresolved when Core cannot read the "
            "snapshot as endpoints, as for a module-owned target type; none names no endpoint and refuses as outside_targets; and a vanished target is counted in the refusal text); the Tactical function can be imported (else function_unavailable, so a Tactical upgrade can never make Core call something else). A refusal ends the run skipped with error type "
            "SystemActionRefused (not for caller_unverified and wrong_module, which fail the caller's own handler instead), writes one deny audit row (reason code, the owner as actor, requested_by scheduler, no ids) and "
            "raises SystemActionRefused (a SchedulerPermanentError, never retried) with .reason. Then Core commits an at-most-once mark on the run, writes one STRICT audit row (action run, object system_action, actor the owner, "
            "metadata requested_by scheduler, run_id, schedule_id, owner_module, function, agent_count, targets_digest; no endpoint ids or hostnames) and only then calls Tactical's own Celery task with .delay, the way "
            "Tactical's bulk view does. No HTTP, no API key, no service account, no model write. If the audit row cannot be written nothing is sent. A retry or duplicate delivery that finds a sent mark sends nothing "
            "again and returns the same result with duplicate true; a mark stuck at 'claiming', or a send that raised, fails the run with error type OutcomeUnknown and is never sent again (at most once: a missed scan is "
            "possible, a double install is not). Tactical's own tasks for the first two rows take no username, so only Core's audit row names the owner. Requires framework >=1.17.61. "
            "Since 1.17.65 (module-facing, framework >=1.17.65; AD-13 condition 2 amended and signed 20 October 2026): a SCHEDULED run of a user-owned schedule skips only owner_inactive, permission_lost and out_of_scope (the person's right was checked when they made the schedule); the unattended= flag is no longer needed and has no effect; "
            "every other check stays, and a manual or one-off run keeps all of them. The action id must still be listed in the module's signed manifest system_actions at run time (else action_not_declared). Every run, deny and unknown-outcome audit row carries run_kind (scheduled or person), creator and confirmed_by; "
            "the actor is the creator's user row when it still exists, otherwise a Core service actor with the stored name in the metadata. When some snapshotted targets no longer exist but the rest still run, the result gains vanished_targets (a count) and the run row carries it. Since 1.17.66 (module-facing, framework >=1.17.66; Johan CQ178, 20 October 2026): more than 2000 endpoints are split, not refused. The whole snapshotted set is judged first (shape, count against the ceiling of 20 groups, scope for a person-started run, outside_targets, targets_unresolved, parameters, declared, enabled, honoured) and one failure refuses the whole call with nothing sent. The sorted ids are cut into groups of at most 2000. Each group has its own mark, its own STRICT audit row written before its own send (metadata group, groups, total_agents, agent_count, targets_digest; counts only, no endpoint ids) and is sent at most once; a failed audit write sends nothing for that group (a retry sends it once, and a group already sent is skipped). A group whose mark is stuck at claiming, or whose send raised, ends the run failed as OutcomeUnknown, is never sent again, and every later group stays not started. The result keeps outcome, agents (the total) and message, and gains groups {total, sent, failed, not_started} and one plain summary line; the failure text carries the same summary. Parameters (since 1.17.66): a row with a parameter schema (scripts.run: script_pk, args, env_vars, timeout, run_as_user, collector_all_output, save_to_agent_note) reads them only from what the person confirmed at creation (the run's parameters under system_action_parameters). The parameters argument must be None, {} or equal to that record, else parameters_changed; a bad shape is bad_parameters. scripts.run passes the creator's stored name (first 50 characters) as the username, never a name from the caller, and its audit rows carry script_pk and counts only, never an argument or an environment value. Rows with no schema (scan, install) still refuse any parameter. "
            "Since 1.17.67 (module-facing, framework >=1.17.67; held Medium of the 1.17.66 review): the group plan is fixed on the first attempt of a call and kept in one plan mark on the run (a mark with kind plan: the endpoint numbers as ranges and the digest of every group; no audit row, no send). A call is identified by its full sorted id set. A retry with the same set cuts its groups from the stored plan, as before. A set with no endpoint in common with an earlier plan of the run is a new call (two disjoint calls in one handler stay legal). A different set that overlaps a plan after any group of that plan was claimed, sent or left unknown ends the run failed as OutcomeUnknown (plain text: the endpoint list changed after part of this run was sent, Core did not send again; one custom:outcome-unknown row, counts only) and sends nothing, so an endpoint is never sent twice. When nothing was sent yet the plan is replaced and the call goes on. MAX_MARKS_PER_RUN is 105 (five full calls of 20 groups and five plan marks). A caller that sends the same endpoint list on a retry sees no change; a handler that sends a changed, overlapping list in one run now gets OutcomeUnknown. No module calls run_system_action yet."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "run_system_write",
        "kind": "python",
        "purpose": (
            "run_system_write(context, *, action_id, changes) -> {outcome: 'written', changes, written, unchanged, changed_meanwhile, groups: {total, sent, failed, not_started}, message, summary} (1.17.70, CQ203, AD-45; capability core.system_actions 1.3.0, operation run_write; framework >=1.17.70). "
            "The second kind of Tactical work Core does for an honoured premium replacement: a fixed write of one column in Tactical's own table, made in Core's process through Tactical's own serializer, because Tactical has no task for it. The first and only row is winupdate.set_action (the approve, ignore or do-nothing decision of one Windows update, Tactical's PUT winupdate/<update_id>/). "
            "Call it from the honoured replacement's own Scheduler handler with the context object the handler received. changes is a list of {update_id: whole number, action: 'approve' | 'ignore' | 'nothing'}: exactly those two keys (a write can touch only the action column, never installed, kb or result), each update once, 1 to 40000 items, every action one of the allowed_actions the person confirmed (inherit is refused). "
            "Core applies the same checks as run_system_action in the same order: a context Core issued for a run that is still going, the verified caller is the run's module and owns the action, the action is declared in the signed manifest now, the module is enabled now, the replacement is honoured now, the parameters come from the confirmed record only, and the owner, count and scope checks. "
            "Core reads each update's endpoint itself (one fixed read of Tactical's WinUpdate id and agent) and requires every update to exist; the resulting endpoint set is judged exactly like agent_ids (inside the run's snapshotted targets, never widened; inside the owner's role scope for a person-started run; inside the stored creation-time scope for an unattended run on a module-owned target type). One miss refuses the whole call and nothing is written; no id is named in the message. "
            "Per group of at most 2000 updates (up to 20 groups): Core marks the group, reads the current decision of every update, writes one STRICT audit row per chunk of at most 500 changes BEFORE the write carrying [update_id, before, after] and the run, schedule, creator, confirmer, action and group digest, then writes inside one transaction with row locks through WinUpdateSerializer(partial=True) with {action: value}. "
            "A row whose decision changed after the before was read is not overwritten (a person's later decision wins) and is counted as changed_meanwhile; a change equal to the current decision is counted as unchanged and not written. One closing audit row per group carries the counts and the decisions actually saved. A failed audit row writes nothing and aborts the mark (retried); a failed write is outcome-unknown, the group is never written again (at most once). "
            "A task row refuses here as wrong_kind and a write row refuses in run_system_action the same way. Refusals are those of run_system_action plus bad_changes (shape, count, duplicate update), unknown_update, action_not_allowed and, since 1.17.71, decisions_changed (a retry of the same run brings the same updates with other decisions: nothing is written, the run ends skipped, and a retry after part was started ends outcome-unknown; the run key now covers the decisions). Delegation refuses a write row (not_delegable). Plain limit: Tactical's own audit log does not show this write, because Core writes it in-process and not through Tactical's route; Core's strict audit rows are the record. See docs/system-actions.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "run_system_command",
        "kind": "python",
        "purpose": (
            "run_system_command(context, *, action_id, command) -> {outcome: 'ran' | 'unreachable' | 'failed', agent_id, command_id, output, truncated, message} (1.17.75, AD-45, CQ175; capability core.system_actions 1.5.0, operation run_command; framework >=1.17.75). "
            "The third kind: one command on ONE endpoint through Tactical (Tactical's own send_raw_cmd view, POST agents/{agent_id}/cmd/ with the string agent id; Core copies none of its steps; since 1.17.76 the view runs in process as Core's least-privilege Tactical service user tectac-communicator (can_send_cmd only, no sign-in), Johan's signed call of 23 October 2026, AD-50: the person's Communicator rights are checked when the schedule is made and the command runs as the Communicator module; the service user and its role are made by Core migration 0038 at install or upgrade, never on the first send, and a missing or deviant one refuses function_unavailable; only endpoints in the owner's creation-time scope; at most 2000 commands per run, then too_many_commands; Tactical's can_send_cmd is NOT required of the owner, a known issue to fix next week), for the schedule owner. The row agent.command is registered by remote-background (the owner of that piece, dangerous=True, never delegated); only a verified Scheduler run of communicator may call it. "
            "command is exactly {agent_id: whole number, command_id: text of 1 to 128 letters, digits, . _ : -, template_id: text, params: dict} (AD-49, Johan, 23 October 2026: Core never accepts a command text; a free command field is bad_command). Core renders the command itself from a FIXED TEMPLATE that the signed code of communicator registered at AppConfig.ready() with tec_tac.system_actions.register_command_template(module_id, template_id, *, shell, text=None, file=None, slots=None, timeout=30) -> {id, hash} (module_id on the row's allow-list only and equal to the verified calling module; a file must lie inside that module's install directory, symlinks refused; template_id is '<module_id>.<name>'; text uses {slot} placeholders; a file is an absolute path whose content is the template and is read and hashed again at every run; slots are {type: int, min, max} | {type: text, max, chars, spaces?} (printable ASCII without quotes or shell metacharacters; one token: a space needs spaces: true, and a value never starts with - or /) | {type: enum, values}; a template is immutable: the same content again is accepted, different content under the same id is refused and logged). Core hashes each template (shell, fixed text or file content, slot schema, timeout); tec_tac.system_actions.command_template_hashes(ids) returns the current hashes. The person confirmed parameters {allowed_templates: [ids], template_hashes: {id: hash}, max_timeout: 1 to 60, rights: [communicator.send] plus communicator.reboot when an allowed template was registered with right='communicator.reboot'} when making the schedule (1.17.76, AD-50: Core cannot read a module permission, so Communicator attests the rights the person held when the schedule was made; register_command_template takes right='communicator.send' | 'communicator.reboot'; parameters without rights, or rights that do not cover every allowed template, are refused when the schedule is made, and a run whose rights do not hold a template's right is refused permission_lost); a template outside them is action_not_allowed, and a template whose current hash differs from the confirmed or the registered one (the module was updated, or the file changed) is template_changed: the person must confirm again. Params that do not fit the slots (a quote or shell metacharacter in a text slot, a number out of range, an unknown enum value) are bad_command. "
            "Core applies every check of run_system_action in the same order, then the Communicator rights attested at creation (permission_lost without them) and that the owner still exists and is active, the flags the registering module listed as held at creation, and the owner's stored scope (for an unattended run too). Tactical's can_send_cmd is not checked (AD-50). A repeated command_id for the same endpoint is refused (duplicate_command): the claim is an atomic cache.add of 24 hours, shared by the workers, backed since 1.17.76 by the durable strict audit row, and an unreachable cache or a failed lookup refuses the call. "
            "A refusal of this call does not end the run, because it is one endpoint of a batch. A strict audit row is written before the send and a closing row after; they hold the run, schedule, endpoint, command_id, shell, timeout and lengths, never the command or the output; since 1.17.75 they also hold the template id and hash. The output is cut at 1 MiB (truncated=true). A failed send is never repeated under the same command_id. See docs/system-actions.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "SystemActionRefused",
        "kind": "python",
        "purpose": "SystemActionRefused (1.17.61): raised by run_system_action for a refusal. A SchedulerPermanentError with .reason (context_invalid, owner_refused, no_owner, caller_unverified, wrong_module, unknown_action, module_disabled, replacement_not_honoured, function_unavailable, owner_inactive, permission_lost, bad_parameters, bad_agents, agent_count, out_of_scope, reapproves_by_policy (no longer returned since 1.17.66), mark_limit, since 1.17.66 parameters_changed (the parameters passed differ from what the person confirmed) and, at creation, not_permitted, confirmation_required, confirmation_invalid and, since 1.17.67, declaration_unreadable (raised as SystemActionCreationRefused), since 1.17.62 outside_targets and targets_unresolved, since 1.17.68 creation_scope_unavailable (an unattended run on a module-owned target type has no stored creation-time scope; the module's resolver answer is cut to that scope, and an endpoint outside it is out_of_scope): the endpoints must be among the run's snapshotted schedule targets, and since 1.17.63 action_not_declared: the action id is no longer listed in the module's signed manifest system_actions, and since 1.17.70 wrong_kind (a write row run by run_system_action, or a task row by run_system_write), bad_changes, unknown_update and action_not_allowed from run_system_write, and since 1.17.71 decisions_changed, and since 1.17.75 bad_command and duplicate_command, since 1.17.75 template_changed) and a plain message that names no agent. SystemActionRegistrationError (a ValueError) is raised by register_system_action.",
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_action_confirmation",
        "name": "describe_confirmation",
        "kind": "python",
        "purpose": (
            "describe_confirmation(user, action_id, targets, parameters=None, when=None) -> {required, text, confirmation_id, total, groups, expires_in} (1.17.66, AD-13 as amended by Johan on 20 October 2026; "
            "capability core.system_actions 1.1.0, operation describe_confirmation(request, *, action_id, targets, parameters=None, when=None), which takes the person's own signed-in request instead of a user). "
            "The one plain Yes or No for a schedule of a declared system action. It first runs every creation-time check (the owning module's permission, the Tactical flags of the table row and the definition with no bypass for a "
            "scheduler manager, the person's Tactical scope over every target, targets that read as endpoints within the ceiling, the parameters, the module enabled, a replacement honoured) and refuses with SystemActionCreationRefused "
            "(a SchedulerNotAllowed with .reason) and one deny audit row, so a person who may not create the schedule never gets a text. Otherwise it answers a plain text naming what will happen, the total, the number of groups, the timing and any fixed warning, "
            "and a confirmation id signed for that person, action, targets, parameters and timing, valid for 600 seconds. The id proves the text was produced for that request; it does not prove the person pressed Yes, because Core cannot see the button. "
            "For an action that is not a declared system action it answers required false and issues nothing. The id is read by POST /api/tfd/scheduler/system-actions/confirmation/ (the browser), reconcile_schedule(confirmation_id=) and start_one_off_run(confirmation_id=). "
            "Requires framework >=1.17.66. See docs/system-actions.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_action_confirmation",
        "name": "SystemActionCreationRefused",
        "kind": "python",
        "purpose": "SystemActionCreationRefused (1.17.66): raised when a creation, an edit or a one-off start of a declared system action is refused. A SchedulerNotAllowed (so a SchedulerError) with .reason, one of unknown_action, function_unavailable, owner_inactive, module_disabled, replacement_not_honoured, not_permitted, bad_parameters, targets_unresolved, out_of_scope, agent_count, confirmation_required, confirmation_invalid and, since 1.17.67, declaration_unreadable (Core could not read the signed manifest or the registry, so it cannot tell whether the action is a system action: nothing is saved, queued or issued; try again later; an action that either source already shows is not a system action is never refused for it), and a plain message that names no endpoint. Core writes one deny audit row per refusal. Requires framework >=1.17.66.",
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "describe_delegation",
        "kind": "python",
        "purpose": (
            "describe_delegation(request, *, owner_module, provider_module, action_id, targets, parameters=None) -> {required, text, confirmation_id, total, groups, expires_in} (1.17.68, S4; capability core.system_actions 1.2.0, operation of the same name; framework >=1.17.68). "
            "The one plain Yes or No for a delegation grant: the person who saves a Maintenance profile confirms once that Maintenance may later start Advanced Patch Management's scheduled install for them. The caller is verified from the call stack and must be owner_module; request must be the person's own real, session-checked request (a user, a stand-in or a user id is refused). "
            "The provider must have registered the system action with delegable_to naming owner_module, the action must be a scheduled action of the provider, still listed in its signed manifest, both modules enabled, and a replacement honoured. Core then runs every creation-time check for the person (the action's permission, every Tactical flag of the table row with no bypass for a scheduler manager, the person's scope over every resolved endpoint, targets that read as endpoints within the ceiling of 40000 (a module-owned type reads through the resolver of owner_module), the parameters) and refuses with SystemActionCreationRefused or DelegationRefused and one deny row, so a person who may not create the grant never gets a text. "
            "The text names the endpoints and groups, who will start it and that it runs with nobody signed in, what Core still checks at run time (the confirmation is unchanged, the modules are on, the replacement is still honoured, every endpoint is inside the confirmed targets and the person's stored scope), that Core does not look at the person's account again so the run goes on if the account is later disabled, and that editing or removing the profile stops it. It also carries the re-approve warning where it still applies. The confirmation id is signed with its own prefix (a schedule's confirmation id cannot be reused), binds the person, owner, provider, action, targets and parameters, is valid for 600 seconds, is not stored and does not prove a button was pressed. See docs/system-actions.md, Delegation."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "register_delegation_grant",
        "kind": "python",
        "purpose": (
            "register_delegation_grant(request, *, owner_module, grant_key, provider_module, action_id, targets, parameters=None, confirmation_id) -> {grant_key, created, owner_changed} (1.17.68, S4; framework >=1.17.68). "
            "Stores or replaces the grant a person confirmed, under (owner_module, grant_key). The caller must be owner_module and request the person's own real request. Core repeats every creation-time check, requires a valid confirmation id from describe_delegation for exactly these arguments, stores the grant (the provider, action, canonical targets, the confirmed parameters, the person by row and by stored name, and the person's scope and role flags at that moment) and writes one strict audit row. grant_key is 1 to 120 characters of lowercase letters, digits and : _ . -. At most 20 grants per owner module (DelegationRefused grant_limit). A second person who registers the same grant takes it over: it is refused (takeover_out_of_scope, nothing changes) unless that person's own Tactical scope covers every target, otherwise the owner, the names and the scope move to them and the strict audit row carries owner_changed_from, owner_changed_to and previous_confirmed_by. Every save changes the grant's digest, so every ticket made before it stops working."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "remove_delegation_grant",
        "kind": "python",
        "purpose": "remove_delegation_grant(*, owner_module, grant_key) -> bool (1.17.68, S4; framework >=1.17.68). Removes the grant and writes one strict audit row. The caller must be owner_module. Every ticket made for the grant stops working. Call it when the profile is deleted or no longer has the patch step. True when there was a grant.",
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "issue_delegation_ticket",
        "kind": "python",
        "purpose": "issue_delegation_ticket(context, *, grant_key) -> str (1.17.68, S4; framework >=1.17.68). Called by the owner module inside its own LIVE Scheduler run, with the context object the handler received (a context Core did not issue, a finished run and a caller that is not the run's module are refused). The grant must exist for that module and be enabled. The ticket is signed with the server's secret, bound to that run, the grant and the grant's digest as it is now, and valid for 24 hours. The owner module passes it to the provider's step; the provider presents it to start_delegated_run. Editing or removing the grant makes every ticket for it fail with grant_changed or grant_missing.",
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "start_delegated_run",
        "kind": "python",
        "purpose": (
            "start_delegated_run(ticket, *, action_id, agent_ids, name=None) -> TecTacScheduleRun, queued (1.17.68, S4; framework >=1.17.68). Called by the provider module named in the grant, from its own code. Core verifies the caller, the ticket (signature, expiry), the grant (still there, enabled, same digest, provider and action as the ticket says), that the action is still registered by the caller with delegable_to naming the grant's owner module, still listed in its signed manifest, both modules enabled and a replacement honoured. "
            "It resolves the grant's targets (a module-owned type through the owner module's resolver) and reads the endpoints inside the person's stored scope; agent_ids (endpoint numbers, 1 to 40000) must be inside both or the call is refused as outside_grant and nothing starts. "
            "Core then creates the provider's own one-off schedule and run (owner_key one-off:<uuid>, created_by the person who confirmed, or the stored name when the user row is gone; targets exactly the endpoints passed; parameters exactly what was confirmed plus a marker Core signed for that schedule) and queues it. The provider's handler runs and calls the unchanged run_system_action, which keeps its groups, its at-most-once marks and its strict audit row. The same ticket and the same endpoints always name the same run, so a retry returns that run and never starts a second install. "
            "The run is exempt from the owner re-check only while its marker verifies and its grant is unchanged; every other one-off keeps every re-check. Audit: one strict add row naming the owner module, provider, creator, confirmer, grant key, total and groups (no endpoint ids); one deny row for each refusal with a reason code. Refusals raise DelegationRefused (a SchedulerNotAllowed and SchedulerPermanentError) with reason: caller_unverified, wrong_module, ticket_invalid, ticket_expired, ticket_used, grant_missing, grant_disabled, grant_changed, unknown_action, not_delegable, action_not_declared, module_disabled, replacement_not_honoured, bad_agents, agent_count, creation_scope_unavailable, targets_unresolved, outside_grant. The provider reads the run with get_one_off_run(run_id, owner_module=provider)."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.system_actions",
        "name": "resolve_delegated_targets",
        "kind": "python",
        "purpose": (
            "resolve_delegated_targets(ticket, *, action_id, endpoint_ids) -> {agents: [{agent_id, pk}], covered, not_covered} (1.17.74, Q-APM21 b; capability core.system_actions 1.4.0, operation resolve_delegated_targets; framework >=1.17.74). "
            "Called by the provider module named in the grant, from its own code, BEFORE start_delegated_run, to learn which of the endpoints it holds are covered by the ticket. endpoint_ids is a list of 1 to 40000 whole endpoint numbers or agent id texts. "
            "Core opens the ticket and applies exactly the checks start_delegated_run applies before it makes a run (signature and expiry, grant present and enabled, grant unchanged, the caller is the grant's provider, the action matches, the provider's action may be delegated and is declared, "
            "the modules are enabled, the replacement is honoured), then reads the grant's targets and the person's stored creation-time scope and returns only the endpoints inside both. An endpoint the ticket does not cover is only counted in not_covered, never named. "
            "Any ticket problem gives one generic refusal, DelegationRefused with reason ticket_invalid and one deny audit row, so a module cannot probe the grant. The call creates no run and no schedule. The provider then passes the covered endpoint numbers to start_delegated_run. "
            "The caller is read from the call stack, never from an argument. A list that is not 1 to 40000 whole numbers or texts is refused as bad_agents or agent_count. "
        ),
        "audience": "provider/backend",
    },
    {
        "area": "system-actions",
        "import_path": "tec_tac.delegation",
        "name": "DelegationRefused",
        "kind": "python",
        "purpose": "DelegationRefused (1.17.68): raised by the five delegation functions when a call is refused. A SchedulerNotAllowed and a SchedulerPermanentError (never retried) with .reason (see start_delegated_run, and for describe and register also no_person, bad_grant_key, bad_module, confirmation_required, confirmation_invalid, grant_limit and takeover_out_of_scope) and a plain message that names no endpoint and no id. A refusal found by the shared creation-time checks is a SystemActionCreationRefused instead.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler_target_resolvers",
        "name": "register_target_resolver",
        "kind": "python",
        "purpose": (
            "register_target_resolver(module_id, target_type, resolver) -> None (1.17.68, the target-resolver contract; framework >=1.17.68). The module that owns a target type (a Maintenance or Advanced Patch Management profile) tells Core, from AppConfig.ready() and in memory only, how the type reads as Tactical endpoints: resolver(targets: dict) -> iterable of Tactical agent numbers (whole numbers) or agent ids (text), read-only, fast, run in the caller's process on a copy of the targets. "
            "The caller is verified from the call stack and must be module_id; the type may not be none, client, site, endpoint, agent or dynamic (or their plurals), must be a plain lowercase word, and must be listed in target_types of one of the module's registered scheduled actions (checked at registration once the module has one, and again at every use). A different resolver under the same key raises TargetResolverRegistrationError (a ValueError); the same one again is accepted. "
            "Core canonicalises every returned id to a Tactical agent number and checks it exists. A bad token, an id that names no endpoint, an ambiguous id, more than 40000 ids, a result that is not a list and any exception all mean unresolved (nothing is guessed, narrowed or truncated), and the caller refuses as before (targets_unresolved). "
            "What it changes: a system action on a schedule with such a type is no longer refused as targets_unresolved at creation or run; a scoped person may create a schedule with such a type when every resolved endpoint is inside their own Tactical scope (before, a module-owned type needed unrestricted scope); an unattended run reads the endpoints inside the stored creation-time scope. A type with no resolver keeps the old rule. The resolver decides no right: it only names endpoints, and the person's or the stored scope still bounds them."
        ),
        "audience": "core module/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "CreationScopeUnavailable",
        "kind": "python",
        "purpose": "CreationScopeUnavailable (1.17.68): raised by VerifiedSchedulerRun.held_at_creation and resolved_endpoints for an unattended run whose schedule has no stored creation-time scope (made before Core 1.17.68 and not edited since). A SchedulerPermanentError with .reason creation_scope_unavailable and the plain text 'This schedule was made before Core kept its scope. Edit it and save it once.' Core never invents a scope.",
        "audience": "provider/backend",
    },
    {
        "area": "scheduler",
        "import_path": "tec_tac.scheduler",
        "name": "TakeoverRefused",
        "kind": "python",
        "purpose": "TakeoverRefused (1.17.68): raised by reconcile_schedule (and answered as 403 with reason takeover_out_of_scope by PATCH /api/tfd/scheduler/schedules/<id>/) when a person other than the owner edits a schedule whose targets are wider than that person's own Tactical scope. A SchedulerNotAllowed with the plain text 'You cannot take over this schedule: some of its targets are outside your Tactical scope.' The owner, the stored scope and every field stay as they were. Johan, 21 October 2026: ownership never widens a schedule.",
        "audience": "provider/backend",
    },
    {
        "area": "patch-lockdown",
        "import_path": "tec_tac.patch_lockdown",
        "name": "status",
        "kind": "python",
        "purpose": (
            "status() -> {active, honoured_module, tasks_off, approve_guard_installed} (1.17.68; capability core.patch_lockdown 1.0.0, operation status; framework >=1.17.68; Johan, 21 October 2026, the former R-36: 'the tactical patch policy must be disabled when APM is installed'). "
            "active is True only while a replacement of the core module patching (Advanced Patch Management) is honoured right now (AD-20), read at most every 30 seconds; an unreadable module state answers False, so a read fault never switches Tactical's patching off. honoured_module is that module's id or None. "
            "While active, Core does three things and writes no Tactical data: it sets Tactical's own documented switches TRMM_DISABLE_APPROVE_UPDATES_TASK and TRMM_DISABLE_WINUPDATES_INSTALL_TASK to True at start-up in every process (never to False, never over a value the administrator set), it makes Agent.approve_updates return without approving (so an update the replacement set to Ignore is not flipped back by Tactical's install call), and it answers this status. tasks_off says both switches are True in this process; approve_guard_installed says the guard is installed in this process. "
            "The declared operations a replacement registers (scan, install, set-update-action, reset, add, edit and delete patch policy) and the system actions are not blocked and still send only what is already approved. When the replacement is no longer honoured, Tactical's own approve works again at once and the switches go back with the restart a module enable or disable already causes. A guard that cannot be installed fails open. The Scheduler tick writes one audit row custom:tactical-patch-lockdown (state on, held or off, honoured_module; on and held also say which parts are in effect, tasks_off and approve_guard) when the state changes. "
            "A premium replacement drops its own 'does not apply decisions' warning when active and approve_guard_installed are both True. Not built: refusing Tactical's own native winupdate/ and automation/patchpolicy/ mutating routes. See docs/patch-lockdown.md."
        ),
        "audience": "consumer/backend",
    },
    {
        "area": "module-dependants",
        "import_path": "tec_tac.module_dependants",
        "name": "dependants",
        "kind": "python",
        "purpose": (
            "dependants(*, context=None) -> {module, dependants: [{id, name, version, relation, constraint, enabled, capabilities: [{id, version}]}], complete} (1.17.71; capability core.module_dependants 1.0.0, operation dependants; framework >=1.17.71; Johan, 21 October 2026: Groups must not delete a group that is in use). "
            "It lists the installed, non-legacy modules whose signed manifest dependencies or optional_dependencies name the CALLING module (relation required or optional, with the constraint they declared), sorted by id, at most 200 (complete is False above that). enabled is the dependant's current state: a disabled module is still listed, because its saved configuration still points at the caller. capabilities are the {id, version} pairs its signed manifest declares, so the caller can then ask only those. Nothing else is returned: no routes, permissions, settings, paths, audit events or data of the dependant. "
            "Caller rule (rule 1.10, AD-26): the caller is the verified, enabled, non-legacy module whose code called the function. Core itself, an unverified caller, a disabled module or a legacy module is refused with DependantsRefused (plain text, no module ids). The answer is about the calling module's own id only, so a module cannot list the dependants of another. "
            "Fail closed: an unreadable module list or module state raises DependantsUnavailable and never answers an empty list; a caller that treats complete False or DependantsUnavailable as 'could not check, do not delete' is correct. Groups declares core.module_dependants under its manifest requires. Core calls no provider on behalf of a module: the dependant's own capability (for example <id>.groups_usage) is asked by the caller through get_capability. Also new in 1.17.71: PluginSpec.dependencies and PluginSpec.optional_dependencies (sorted (module id, constraint) pairs, empty when absent or malformed). See docs/module-dependants.md."
        ),
        "audience": "consumer/backend",
    },
    {
        "area": "server-maintenance",
        "import_path": "tec_tac.server_maintenance",
        "name": "get_server_maintenance_provider",
        "kind": "python",
        "purpose": (
            "The provider behind capability core.server_maintenance, now 1.1.0 (1.0.0 until 1.17.16; still major 1, additive; ask for >=1.1,<2 and framework >=1.17.17). "
            "start(*, action, parameters=None, context, user=None) and cancel(*, job_id, context, user=None) take a user. An action manifest may carry permission "
            "(a Tec-Tac extension permission code) and owner_module (the module that owns it). When an action declares a permission, start() needs a user who holds it "
            "(a superuser passes, AD-10); no user, a failed lookup, an unknown code or a missing grant raises ServerMaintenancePermissionDenied (classification "
            "permission_denied), writes a best-effort Core audit row (action deny, object_type server_maintenance_action; it never carries the parameters) and creates "
            "no job file. cancel() applies the same check against the permission the job's action had when it started (jobs written before 1.17.17 use the registry's "
            "permission now). A permissioned action whose owner_module is not enabled is refused with classification action_disabled. An action with no permission, and "
            "a caller that passes no user, behave as in 1.17.16. start(parameters=None) now means no parameters (before 1.17.17 it was refused as 'parameters must be "
            "an object'). list_actions rows add permission and owner_module (null when absent); job rows add permission. POST /api/tfd/system/maintenance/jobs/ and the "
            "cancel route keep requiring core.privileged_operations and, for a permissioned action, its permission as well (403 naming the permission); the action list "
            "and the job list and detail routes hide permissioned actions and their jobs from a caller who lacks it. "
            "A signed module registers its own actions from its manifest key server_maintenance_actions (see the manifest-key rule for 1.17.17). "
            "Requires framework >=1.17.17."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "server-maintenance",
        "import_path": "tec_tac.server_maintenance",
        "name": "ServerMaintenancePermissionDenied",
        "kind": "python",
        "purpose": "ServerMaintenancePermissionDenied (1.17.17): raised by start() and cancel() when the caller does not hold the permission the action declares. A subclass of ServerMaintenanceError with classification permission_denied and a permission attribute naming the code to ask an administrator for.",
        "audience": "consumer/backend",
    },
    {
        "area": "server-maintenance",
        "import_path": "tec_tac.server_maintenance",
        "name": "holds_action_permission",
        "kind": "python",
        "purpose": "holds_action_permission(user, permission) -> bool (1.17.17): may this user use an action that declares permission? No permission means yes; otherwise the user must hold it through the Tec-Tac role grants (a superuser passes). No user, a failed lookup and an unknown code are False. The same test start() and cancel() apply, for a module that wants to hide an action it lists.",
        "audience": "consumer/backend",
    },
    {
        "area": "server-maintenance",
        "import_path": "tec_tac.server_job_hooks",
        "name": "hook_job_id",
        "kind": "python",
        "purpose": (
            "hook_job_id(module_id) -> '<module_id>.server_job_finished' (1.17.62, R-22 part 2, requires framework >=1.17.62, needs migration 0035_server_job_hook): the id of the core.event_jobs job through which Core hands a FINISHED "
            "core.server_maintenance job to the module that owns it, with no page open. A module opts in by registering that event job from AppConfig.ready() with register_event_job(id=hook_job_id(<module id>), module_id=<module id>, "
            "label=..., handler=...); no new manifest key. Core ties a job to a module through the owner_module Core wrote in the job file when the job started (the action's owner_module, since 1.17.17). A module that registers no "
            "such job is left alone. The scheduler tick step deliver_finished_server_jobs() reads at most 50 job files a tick (only files changed in the last six hours), stores ONE event job per finished job through Core's own "
            "publish path (event_jobs.publish_for_core; no module code runs in the tick) and records a durable unique row per job id before it stores the event, so a job is handed over at most once per Core. The handler gets "
            "context['payload'] = {job_id, action_id, status (succeeded, failed, cancelled or dispatch_failed), exit_code (int or null), classification (only when the job file has one)}: never output text, never parameters. It "
            "runs as the module with no user and cannot make a Tactical change. The event job's own limits, retries, back-off and expiry apply, so the handler MUST be idempotent; it can also run for a job a browser poll of "
            "get_job already recorded. A job whose module is disabled, removed or not the honoured replacement when it finishes is marked skipped with one audit row (custom:server-job-hook-skipped), never retried for ever; an event "
            "that could not be stored after three ticks is abandoned with one audit row (custom:server-job-hook-abandoned). start, get_job, cancel and list_jobs are unchanged. Since 1.17.63 (CQ183, requires framework >=1.17.63) the module part of an event job id keeps the module id's own spelling, so a module with capital letters such as securityWAF "
            "registers securityWAF.server_job_finished; the job part after the dot stays lowercase, and Core never case-folds a module id. A tick reads at most 200 job files and hands over at most 50 finished jobs; a file read as not finished is not read again until its file changes. "
            "See docs/server-maintenance-capability.md and docs/event-jobs.md."
        ),
        "audience": "provider/backend",
    },
    {
        "area": "server-maintenance",
        "import_path": "tec_tac.server_job_hooks",
        "name": "deliver_finished_server_jobs",
        "kind": "python",
        "purpose": (
            "deliver_finished_server_jobs(now=None, limit=50) -> counts (1.17.62, R-22 part 2): Core's own step in the Scheduler tick (a module never calls it). Never raises, runs no module code, hands over at most 50 finished jobs and reads at most 200 job files a tick (1.17.63), "
            "and leaves the tick's own output line unchanged. See hook_job_id for what a module receives. Requires framework >=1.17.62."
        ),
        "audience": "framework/internal",
    },
    {
        "area": "tactical-websocket",
        "import_path": "tec_tac.tactical_websocket",
        "name": "issue_ticket",
        "kind": "python",
        "purpose": "Issue one single-use, 30 second ticket for a Tactical terminal socket (1.17.31, C4, capability core.tactical_websocket 1.0.0; 1.1.0 in Core 1.17.34 adds the kind server-terminal). issue_ticket(request, module_id, kind, agent_id) runs Core's checks for the signed-in user of the request: the module owns the kind (its route owner rule, agents/{agent_id}/terminal-defaults/ for kind agent-terminal), the Tactical flag can_use_terminal, and the agent inside the caller's role scope. For kind server-terminal (AD-35) agent_id is None, only the module globalsettings may ask, only an effective superuser may have it (403 superuser_required), and only where Tactical's server web terminal is on and the caller holds can_use_webterm (403 server_terminal_disabled). It answers {ticket, path, session_id, expires_in, kind} or raises TicketRefusal (status, code, message, audit). The capability's operation issue_ticket is the same, and accepts a call only from the module it names (verified caller). The browser route is POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/. The socket is /ws/tfd/agent-terminal/<ticket>/, or /ws/tfd/server-terminal/<ticket>/ for the server terminal. Since 1.17.34 terminal input and resize frames count as session activity (output does not), and the idle limit and absolute maximum close the socket 4401. See docs/tactical-websocket.md.",
        "audience": "backend/browser",
    },
    {
        "area": "module-preferences",
        "import_path": "tec_tac.module_preferences",
        "name": "get",
        "kind": "python",
        "purpose": "get(user, name, *, module_id, default=None) -> the stored value of one preference of the signed-in person for an installed, enabled module (1.17.35, capability core.module_preferences 1.2.0 from 1.17.38). Only that person's row is read; a missing row gives default. name matches [a-z0-9][a-z0-9._-]{0,63}. The calling module is verified by Core (1.17.37, AD-26): a module may use it only for its own id, and any other caller, Core included, gets ModulePreferenceError caller_not_allowed (403) before any read. Core refuses core and tec-tac, and an unknown or disabled module raises ModulePreferenceError module_not_found (404). Since 1.17.38 a person who may not use the module gets module_not_allowed (403) before any read. A read is not audited. Requires framework >=1.17.38. See docs/module-preferences.md.",
        "audience": "consumer/backend",
    },
    {
        "area": "module-preferences",
        "import_path": "tec_tac.module_preferences",
        "name": "set",
        "kind": "python",
        "purpose": "set(user, name, value, *, module_id) -> the stored value (1.17.35; capability core.module_preferences 1.2.0 from 1.17.38). The calling module is verified by Core (1.17.37): a module may use it only for its own id, and any other caller gets caller_not_allowed (403) before anything is read or written. Since 1.17.38 a person who may not use the module gets module_not_allowed (403). value is plain JSON (a scalar, a list or an object) of at most 4 KiB stored and 5 levels deep. A 51st name for one module raises preference_limit (400). invalid_name and invalid_value are raised before anything is written. Writes by one person are serialised. Since 1.17.38 each real add or modify writes one strict Core audit row (object_type module_preference, object_id <module_id>/<name>, the person as actor, the size of the value and never the value). A write that changes nothing writes no row. If that row cannot be written the change is rolled back and ModulePreferenceError audit_failed (503) is raised. No secret, token or personal data may be stored. Requires framework >=1.17.38.",
        "audience": "consumer/backend",
    },
    {
        "area": "module-preferences",
        "import_path": "tec_tac.module_preferences",
        "name": "delete",
        "kind": "python",
        "purpose": "delete(user, name, *, module_id) -> True when one of the signed-in person's rows was removed, else False (1.17.35; capability core.module_preferences 1.2.0 from 1.17.38). Only that person's row is touched. The calling module is verified by Core (1.17.37): a module may use it only for its own id; any other caller gets caller_not_allowed (403). Since 1.17.38 a person who may not use the module gets module_not_allowed (403). Since 1.17.38 a removal writes one strict Core audit row (action delete, object_id <module_id>/<name>, never the value); deleting a name that does not exist writes none. If that row cannot be written the removal is rolled back and ModulePreferenceError audit_failed (503) is raised. Requires framework >=1.17.38.",
        "audience": "consumer/backend",
    },
    {
        "area": "module-preferences",
        "import_path": "tec_tac.module_preferences",
        "name": "list_for",
        "kind": "python",
        "purpose": "list_for(user, *, module_id) -> {name: value} of every preference of the signed-in person for the module, sorted by name (1.17.35; capability core.module_preferences 1.2.0 from 1.17.38). The calling module is verified by Core (1.17.37): a module may use it only for its own id; any other caller gets caller_not_allowed (403). Since 1.17.38 a person who may not use the module gets module_not_allowed (403). A read is not audited. Requires framework >=1.17.38.",
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
    "/api/tfd/module-preferences/<str:module_id>/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session (SessionAuthenticated); self only, never another person's row (added 1.17.35)",
            "response": {"module_id": "the path id", "preferences": "{name: value} of every preference of this person for the module, sorted by name"},
            "module_id": "a claim: Core cannot prove that the request came from that module's page, so the path id is a claim. Core checks that it is an installed, enabled extension (core and tec-tac are refused) and that the person may use it (since 1.17.38). See What Core can and cannot prove about the module id in docs/module-preferences.md.",
            "errors": {
                "401": "not signed in",
                "403": "module_not_allowed (since 1.17.38): the person may not use this module (no permission it declares, and not a superuser)",
                "404": "module_not_found: an unknown or disabled module, or core or tec-tac",
            },
        },
    },
    "/api/tfd/module-preferences/<str:module_id>/<str:name>/": {
        "PUT": {
            "authorization": "authenticated Tec-Tac session; self only; changes are throttled at 120 a minute (reads are not throttled)",
            "request": {
                "body": "exactly {\"value\": ...}: a JSON scalar, list or object of at most 4 KiB stored and 5 levels deep",
                "name": "path: [a-z0-9][a-z0-9._-]{0,63}",
            },
            "response": {"module_id": "the path id", "name": "the path name", "value": "the stored value"},
            "errors": {
                "400": "invalid_name, or invalid_value (a body that is not exactly {value}, a value too large or too deep, or not plain JSON), or preference_limit (a 51st name for the module: at most 50)",
                "401": "not signed in",
                "403": "module_not_allowed (since 1.17.38): the person may not use this module",
                "404": "module_not_found",
                "429": "throttle: more than 120 changes a minute",
                "503": "audit_failed (since 1.17.38): the change could not be audited, so it was not saved (rolled back)",
            },
            "audit": "since 1.17.38, one strict Core audit row for a real add or modify (action add or modify, object_type module_preference, object_id <module_id>/<name>, source browser, module_verified false, and size_bytes, never the value). A write that changes nothing writes no row.",
        },
        "DELETE": {
            "authorization": "authenticated Tec-Tac session; self only; throttled as PUT",
            "response": {"module_id": "the path id", "name": "the path name", "deleted": "true when one row was removed, else false"},
            "errors": {
                "400": "invalid_name",
                "401": "not signed in",
                "403": "module_not_allowed (since 1.17.38)",
                "404": "module_not_found",
                "429": "throttle",
                "503": "audit_failed (since 1.17.38): the removal was rolled back",
            },
            "audit": "since 1.17.38, one strict Core audit row when a row is removed (action delete, source browser, never the value). Nothing is written when no row was there.",
        },
    },
    "/api/tfd/tactical-websocket/<str:module_id>/<str:kind>/tickets/": {
        "POST": {
            "authorization": (
                "authenticated Tec-Tac session (SessionAuthenticated). Core then requires the module to own the kind (its route owner rule; the terminal kind is owned by whoever owns agents/{agent_id}/terminal-defaults/, remote-background in 1.17.31), the Tactical flag can_use_terminal, and the agent inside the caller's client and site limits"
            ),
            "request": {
                "body": "kind agent-terminal: a JSON object with exactly one key, agent_id (the canonical Tactical agent id). Kind server-terminal (1.17.34): exactly {}. Any other key, or a missing agent_id, gives 400 invalid_ticket_request",
                "module_id": "path: the owning core module id (globalsettings for kind server-terminal; any other module gets 403 websocket_owner_required)",
                "kind": "path: the socket kind, agent-terminal or server-terminal (1.17.34, capability core.tactical_websocket 1.1.0). Another value gives 404 websocket_kind_not_found",
            },
            "response": "201 {ticket, path, session_id, expires_in, kind}. ticket is 43 URL-safe characters, single use, valid for 30 seconds. path is /ws/tfd/agent-terminal/<ticket>/, or /ws/tfd/server-terminal/<ticket>/ for the server terminal. session_id is a new uuid4 for the terminal session. Core's refusals are JSON {detail, code}.",
            "errors": {
                "400": "invalid_ticket_request (body keys) or invalid_agent_id",
                "401": "authenticated_request_required, or tactical_session_required (the session is not linked to a Tactical token; sign in again)",
                "403": "websocket_owner_required (the module does not own the kind), tactical_permission_denied (names can_use_terminal), superuser_required (server-terminal: the caller is not an effective superuser, 1.17.34), server_terminal_disabled (server-terminal: Tactical's server web terminal is off, or the caller lacks can_use_webterm, 1.17.34)",
                "404": "websocket_kind_not_found, or object_not_found (the agent is outside the caller's limits or does not exist; the same text for both)",
                "503": "websocket_unavailable: the ticket store (Django cache) did not hold the ticket, so nothing was issued. Fail closed",
            },
            "notes": [
                "Added in 1.17.31 (module-facing, additive, capability core.tactical_websocket 1.0.0). Needs framework >=1.17.31. Nothing existing changed.",
                "Kind server-terminal, added in 1.17.34 (module-facing, additive, capability core.tactical_websocket 1.1.0, AD-35): a shell on the server itself, run by Tactical's own consumer as the Tactical service user. The socket accepts the ticket once, checks Origin, the sign-in, superuser standing, Tactical's switch and can_use_webterm, then writes ONE strict row custom:server-terminal-start (object type server, module globalsettings) before the shell starts: no row means close 4502 and no shell. The watcher re-checks superuser standing every 30 seconds and kills the shell on loss (close 4003). Close codes: 4401, 4003, 4502, 4503. The agent-terminal body, codes and audit action are unchanged.",
                "A 403 and an out-of-scope 404 write one Core deny row (reason, status and kind; no body values). A successful mint writes no audit row: the audit row is written once per session start by the relayed socket (custom:terminal-start).",
                "Throttles: 30 requests per minute and 500 per day for each signed-in user and address.",
            ],
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
                "query": "optional object, added in 1.17.13: only the query names the operation declares (query_params; a GET operation until 1.17.41, any method since), each a string or whole number of at most 512 characters. Any other name gives 400 query_field_not_allowed",
                "multipart": "added in 1.17.13: multipart/form-data with the text parts params, body and query (each a JSON object) and exactly one file part named as the operation declares it (upload.field). The size is checked before the file is read: the operation's own cap, never more than 10 MiB. The JSON form is unchanged",
            },
            "response": "Tactical's own status and body, relayed unchanged. A file answer keeps Content-Type and Content-Disposition (up to 25 MiB). Core's own refusals are JSON {detail, code}.",
            "notes": [
                "Added in 1.17.7. Additive. An operation exists only when an owning core module declares it with tec_tac.tactical_operations.register_tactical_operation; until then every call gives 404 tactical_operation_not_found.",
                "Core writes the audit row after the call, from Tactical's real answer, with the signed-in user as actor and the declaring module as module_id. Every row carries operation_context.server_provenance = tactical-operation, operation and tactical_status.",
                "2xx: the declared action. 401 or 403 from Tactical: a Core deny row (core_refusal, reason tactical_denied). Core's own refusals: the same deny row with a fixed Core text. 5xx, or an error after dispatch, on a call that is not GET: custom:outcome-unknown. Since 1.17.20 any other 4xx on a call that is not GET: one custom:operation-failed row (declared_action in metadata, no before or after value). A 4xx on a GET: no row. Since 1.17.21 a refusal Core makes itself before Tactical is called (body_field_not_allowed, invalid_body, invalid_params, scope_field_required, invalid_correlation_id, invalid_audit_before) on a call that is not GET writes one custom:operation-failed row (failure core_refused).",
                "Response header X-Tec-Tac-Audit: recorded or not-recorded, present when a row was due. A failed audit write is logged and does not undo Tactical's change.",
                "A missing object and an object outside the caller's scope give the same 404 text. Tactical renaming a route gives 502 tactical_route_changed; Core never falls back to another path. A streaming answer is refused unless the operation declares file_response (1.17.41).",
                "Rate limit: 120/min and 5000/day per user and IP.",
                "Added in 1.17.21 (module-facing, additive, capability core.tactical_operations 1.7.0): Core's own refusal of a change before Tactical is called (body_field_not_allowed, invalid_body, invalid_params, scope_field_required, invalid_correlation_id, invalid_audit_before) writes one custom:operation-failed row (failure core_refused) and sets error.audit and X-Tec-Tac-Audit; audit.object_field and audit.object_body_field name the success row's object id for a create. Needs framework >=1.17.21. See docs/tactical-operations.md.",
                "Added in 1.17.23 (module-facing, additive, capability core.tactical_operations 1.8.0): the Python-only audit_before keyword also accepts a list of whole numbers or texts per field, recorded as <field> with <field>_count and, when cut at 1000 entries, <field>_truncated. Feature-detect with core.tactical_operations >= 1.8.0; needs framework >=1.17.23. Scalar-only callers are unchanged. See docs/tactical-operations.md.",
                "Added in 1.17.26 (module-facing, additive and opt-in, capability core.tactical_operations 1.9.0; a declaration that passes neither key behaves exactly as before): register_tactical_operation takes two optional keywords at the end. permissions_any is a list of Tactical role flags of which the caller needs at least one, on top of every flag of permissions (Tactical's report generation is view OR manage); permissions may be empty only when permissions_any is given; a flag may not be in both lists; the 403 tactical_permission_denied names the flags ('It needs one of can_view_reports, can_manage_reports.'); the deny row carries needs_one_of; list_operations and get_operation show permissions_any (an empty list for an old declaration). body_max_bytes is a whole number of bytes from the 256 KiB default (limits.body_bytes) up to the Core ceiling of 8 MiB (limits.body_bytes_max, a Core constant); body_too_large (413) names the cap that applied; list_operations and get_operation show the effective cap as body_max_bytes; a value below the default, above the ceiling, a bool or a non-integer is refused at registration. A web-server body limit (nginx) or Tactical's own limit still applies and was not verified. Feature-detect with core.tactical_operations >= 1.9.0; needs framework >=1.17.26. See docs/tactical-operations.md.",
                "Added in 1.17.41 (module-facing, additive and opt-in, capability core.tactical_operations 1.11.0; a declaration that uses none of the three behaves exactly as before; needs framework >=1.17.41, feature-detect with core.tactical_operations >= 1.11.0): (1) register_tactical_operation(file_response=True), a strict bool for a GET or POST operation, lets Core relay a streamed Tactical file answer (FileResponse): Core reads it chunk by chunk up to limits.response_bytes (25 MiB), closes it and carries on as for a normal answer, with the same status handling and audit rows (success, deny for 401 and 403, failed for another 4xx on a change, outcome-unknown for 5xx); Content-Type and Content-Disposition are relayed with the bytes; a stream over the cap is cut, closed and refused as tactical_response_refused; the row never carries the file name or bytes; without file_response a stream is refused as before; list_operations shows file_response. (2) query_params may be declared on any method (a DELETE reads request.query_params): the name whitelist, the flat 512-character values, the control-character and '..' rules and the secret-name refusal are unchanged. (3) The route parameter kind {name:service} takes a Windows service name (first character a letter, digit or underscore, then letters, digits, space and $ # ( ) . , _ -, at most 256 characters, no slash, no '..'), built into the path unquoted so Tactical's own <str:svcname> pattern resolves it; the owner table is unchanged (services/ is Remote Background's). See docs/tactical-operations.md.",
                "Added in 1.17.58 (module-facing, additive, capability core.tactical_operations 1.16.0; no new declaration key, an operation without audit_list_masks writes exactly the rows it wrote before; needs framework >=1.17.58, feature-detect with core.tactical_operations >= 1.16.0): (1) for each list named in audit_list_masks the success row records <list>_changed (for example actions_changed) on the after side, true or false, a bool and never a value. Core compares the canonical-JSON digest of the raw list in Tactical's before read with the digest of the body's raw list; the digests are held in memory for that comparison only and are never stored, logged or returned. true: the sent list differs in any way (a masked value, a command text, an item added, removed or reordered; key order inside an item does not count); false: identical. The marker is omitted when the before read did not return the list, when the caller supplied its own audit_before, or when the body sent no list, so a change is never claimed as unchanged on no evidence; it never appears on a failed, denied or outcome-unknown row. (2) metadata.object_count is counted over the scope entries that name the row's object, so a scope entry marked names_object false is no longer counted on the success, failed, tactical-denied and outcome-unknown rows; the scope's own refusal rows keep the full-scope count. See docs/tactical-operations.md.",
                "Added in 1.17.52 (module-facing, additive and opt-in, capability core.tactical_operations 1.15.0; a declaration that uses neither addition behaves exactly as before; needs framework >=1.17.52, feature-detect with core.tactical_operations >= 1.15.0): (1) register_tactical_operation(audit_list_masks={list: {key: 'names'|'mask'}}), a Python-only keyword for lists already named in audit_lists, keeps a key's value out of the row (AD-39: names first, *** second). names records only the name of each text item (KEY=VALUE gives KEY, --flag=value gives --flag, -Name value gives -Name; an item with no name, such as a positional argument, an empty value or base64 padding, and any non-text item is ***); mask records the name and *** for the value (KEY=***, -Name ***) and *** for a scalar text key such as a cmd action's command; names on a scalar key is ***; a masked key whose value is not text or a list of scalars is ***; null stays null. It covers the after side (cleaned body) and the before side (Tactical's own answer), and the audit_lists bounds apply after masking. Registration refuses a list not in audit_lists, more than 8 keys per list, a key that is not a field name, a mode other than names or mask and a non-dict mapping. audit_lists without it is still recorded in clear. list_operations and get_operation show audit.list_masks (an empty object when none). (2) A scope entry may carry names_object: false (a strict bool, default true): it is checked exactly as before and its deny rows are unchanged, but it does not name the object of the success, failed, tactical-denied and outcome-unknown rows, so audit.object_field or audit.object_body_field can name a created record. Registration refuses a non-bool and a scope whose entries are all names_object false unless the declaration has audit.object_param, audit.object_field, audit.object_body_field or audit.object_id. describe() shows names_object: false only when false. See docs/tactical-operations.md.",
                "Added in 1.17.45 (module-facing, additive and opt-in, capability core.tactical_operations 1.14.0; a declaration that uses none of it behaves exactly as before; needs framework >=1.17.45, feature-detect with core.tactical_operations >= 1.14.0): (1) audit.action_by_body = {field, map} chooses the success row's audit action from the cleaned value of one body field (for example {field: 'action', map: {approve: 'approve', ignore: 'modify'}}); a missing or unmatched value keeps audit.action; at most 8 entries, keys text of at most 40 characters, the field must be one of body_fields and not a secret field, and deny, custom:outcome-unknown and custom:operation-failed are refused because Core writes them only; failed and outcome-unknown rows carry the chosen action in metadata.declared_action. (2) A scope entry may name a nested body source, body:<field>.<key>, one level deep (for example body:dependencies.client): the field must be one of body_fields and hold an object (400 scope_field_required otherwise), optional entries, list values and the 1000 id cap behave as for a top-level source, and the nested path is refused with row_lookup, audit.object_body_field and audit.secret_fields; Core checks the scope before Tactical runs and forwards the body it checked. (3) A core_refused row for invalid_correlation_id, invalid_audit_before or invalid_params now carries the declared audit.object_id. list_operations and get_operation show audit.action_by_body. See docs/tactical-operations.md.",
                "Added in 1.17.44 (module-facing, additive and opt-in, capability core.tactical_operations 1.13.0; a declaration that does not use the key behaves exactly as before; needs framework >=1.17.44, feature-detect with core.tactical_operations >= 1.13.0): audit.object_id is a fixed text (letters, digits and . _ : -, 1 to 64 characters, not secret-looking) for an operation with no path parameter that names the object, such as a settings save. It is the last fallback after audit.object_param and the first scope object, and it is refused on a GET operation and together with audit.object_param, audit.object_field or audit.object_body_field. Because it is declared text and never caller or body input, it names the object on every row of that operation: success, deny, failed, outcome-unknown and core_refused. list_operations and get_operation now show audit.object_id and audit.secret_fields. audit.secret_fields may no longer name the same field as audit.object_field. See docs/tactical-operations.md.",
                "Added in 1.17.43 (module-facing, additive and opt-in, capability core.tactical_operations 1.12.0; a declaration that uses neither key behaves exactly as before; needs framework >=1.17.43, feature-detect with core.tactical_operations >= 1.12.0): audit.secret_fields names up to eight body fields whose value Core never records. The success row writes changed, or present before and changed or unchanged after when audit.before holds the field (an in-memory comparison). metadata.object_count gives the number of ids the first scope entry names, when it names more than one. See docs/tactical-operations.md.",
                "Added in 1.17.28 (module-facing, additive and opt-in, capability core.tactical_operations 1.10.0; a declaration without it behaves exactly as before): register_tactical_operation takes one optional keyword, audit_lists, a list of up to two body or before field names that hold a list of flat objects (such as a task's actions). Each is recorded IN CLEAR, with no masking (script arguments and environment values appear as Tactical stores them; this is the signed exception AD-32 to module standard section 3, for audit_lists only, and audit-view holders can read these values), in the success row: the after value from the cleaned body and, when the operation has a before read, the before value from Tactical's GET answer. Bounds (limits_added_in_1_10_0): 50 entries per list, 24 keys per entry, a text value cut at 4096 characters with control characters other than tab and newline removed, one level of up to 100 scalars, 64 KiB of text per list field, two list fields per operation. The row carries <field>_count (the full length) and <field>_truncated when anything was cut or dropped. A malformed list is recorded as its count only. Failed, denied and outcome-unknown rows carry no list. describe() shows audit.lists. Feature-detect with core.tactical_operations >= 1.10.0; needs framework >=1.17.28. See docs/tactical-operations.md.",
                "Added in 1.17.20 (module-facing, additive, capability core.tactical_operations 1.6.0): the Core-only audit action custom:operation-failed for a non-GET call that Tactical refuses with a 4xx other than 401 and 403 (metadata declared_action, result failed, no before or after value; result.audit and X-Tec-Tac-Audit are now a verdict, not {} and absent). tec_tac.audit.record also refuses that action with AuditContractError. Needs framework >=1.17.20.",
                "Added in 1.17.19 (module-facing, additive, capability core.tactical_operations 1.5.0): server_only (the browser route refuses the operation 403 operation_server_only with a Core deny row; a module backend runs it unchanged; it stops the browser path only and is not a verified caller identity), and a 403 detail that names the missing Tactical flag. Needs framework >=1.17.19 for server_only.",
                "Added in 1.17.18 (module-facing, additive, capability core.tactical_operations 1.4.0): caller_scope, optional and agent_pk scope entries, row_lookup scope entries and register_tactical_row_lookup, list-valued audit.before fields, count_fields and select, body_selector (several operations on one route inside the owning module) and audit.params. Two new refusal codes: 403 scope_unrestricted_required and 400 body_selector_mismatch. See docs/tactical-operations.md.",
                "Added in 1.17.13 (module-facing, additive): audit.object_param, audit.before, body-selected scope types, query for GET operations and one multipart file part. The browser helper sends query and the file part from UI 0.12.91. (The scope source before:<field>, also added in 1.17.13, was removed in 1.17.14.)",
                "Changed in 1.17.14 (module-facing): capability core.tactical_operations is 1.2.0. The scope source before:<field> is removed (CQ37): an operation with only an object id declares scope [] and Tactical's own check decides, and a failed audit.before read never refuses a call. The upload ceiling is a system setting, tactical_operation_upload_max_mib (whole MiB, 1 to 25, default 10, changed by a superuser through PATCH /api/tfd/system/runtime-settings/); an operation's declared max_bytes may be at most 25 MiB, and a file is held to the smaller of that and the setting at the time of the call (CQ40). The capability's limits report upload_bytes (the effective ceiling), upload_bytes_default and upload_bytes_max. A body-size limit in the web server (nginx) or Tactical still applies and was not verified.",
            ],
            "errors": {
                "400": "unknown field, params or body invalid, body key not in the whitelist, scope field missing (code invalid_operation_request, invalid_params, invalid_body, body_field_not_allowed or scope_field_required); since 1.17.18 also body_selector_mismatch (the body does not fit the operation that was named); since 1.17.13 also invalid_query, query_field_not_allowed, upload_not_allowed, upload_type_not_allowed and invalid_upload",
                "401": "not authenticated (authentication_required)",
                "403": "a Tactical flag or the module permission is missing (tactical_permission_denied or module_permission_denied), since 1.17.18 an operation declared for callers with no client or site limits was called by a limited caller (scope_unrestricted_required), since 1.17.19 the operation is server-only and was called from the browser route (operation_server_only), or Tactical itself answered 403",
                "404": "unknown operation or disabled module (tactical_operation_not_found), or object missing or outside scope (object_not_found)",
                "413": "body larger than 256 KiB (body_too_large), or an uploaded file larger than the operation's cap (upload_too_large, since 1.17.13)",
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
                "view_key": "required lowercase slug up to 64 characters; a key starting with fs- is reserved for Core filter sets (1.17.50) and is refused",
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
    "/api/tfd/filter-sets/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the module must be core or an installed, enabled module the user may use",
            "query": {"module": "required module id", "view_key": "required lowercase slug up to 61 characters (Core stores it as 'fs-' + view_key)"},
            "response": {"filter_sets": "sets the caller can read: own sets, shared sets (readers empty) and private sets that list the caller", "count": "number of sets"},
            "notes": ["Added in 1.17.50 (core.filter_sets 1.0.0; 1.1.0 since 1.17.52). Each set: id, module_id, view_key, name, definition {version, match, rules}, shared, mine, can_edit, owner {id, username}, created_at, updated_at. readers (user ids) is returned to the owner only. Since 1.17.51 a reader who is not the owner sees a rule value only when it is inside their scope: otherwise the rule comes back as {kind, field, operator, value: null, withheld: true} and the set carries values_withheld (a count, 0 for the owner). The module's fields are read for the signed-in person only when a readable set that person does not own has rules; if the provider is missing or fails the GET still answers with those values withheld. The set's name is a label its owner typed and stays visible. A set can only narrow the reader's own scoped list and reveals no rows."],
            "errors": {"400": "module missing, unknown or disabled, or invalid view_key", "403": "caller may not use the module"},
        },
        "POST": {
            "authorization": "authenticated Tec-Tac session; the module must be core or an installed, enabled module the user may use",
            "request": {
                "module_id": "required; the module must offer '<module id>.filter_fields'",
                "view_key": "required lowercase slug up to 61 characters",
                "name": "required, 1 to 160 characters, unique per owner, module and view_key",
                "definition": "required {match: 'all'|'any', rules: [{kind: 'rule', field, operator, value} | {kind: 'group', match, rules}]}. At most 50 rules and 20 groups, groups nested 3 deep, values up to 200 characters with no control characters. Every field must be one the caller may use in the module",
                "readers": "optional list of up to 100 active user ids. Empty (default) shares the set with everyone who can use the module. Not empty makes it private to the owner and those ids",
            },
            "notes": [
                "At most 100 sets per owner, module and view_key.",
                "Each create writes a Core audit row (module_id core, object_type filter_set, action add) with counts, never a rule value or a reader id, in the same transaction. A failed audit write rolls the create back.",
                "Write rate limit: 60/min and 2000/day per user and IP. Reads are not counted.",
            ],
            "errors": {"400": "invalid field, unknown field, invalid rule, too many rules or levels, unknown reader, quota reached", "403": "caller may not use the module", "404": "the module offers no filters", "409": "name already used by this owner for this module and view_key", "422": "a rule uses a field the caller may not use (code field_unavailable)", "429": "write rate limit reached", "500": "audit row could not be written; nothing was saved", "502": "the module's filter fields could not be read"},
            "success": {"201": "created"},
        },
    },
    "/api/tfd/filter-sets/<uuid:set_id>/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the caller must be able to read the set",
            "errors": {"404": "no such set, or a private set the caller cannot read (same answer, so it does not leak)"},
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session; owner only. There is no administrator override",
            "request": {"name": "optional", "definition": "optional; validated against the caller's fields", "readers": "optional; omitted keeps the current readers", "module_id": "optional; must equal the current value", "view_key": "optional; must equal the current value"},
            "notes": ["Writes a modify audit row for a name or definition change, and custom:filter-set-share when the sharing changes (counts only), in the same transaction; a failed audit write rolls the change back."],
            "errors": {"400": "invalid field", "403": "caller can read the set but is not the owner (answered before the module's provider is called, with or without a definition, since 1.17.51)", "404": "set not found or not readable", "409": "name already used", "422": "a rule uses a field the caller may not use", "429": "write rate limit reached", "502": "the module's filter fields could not be read"},
        },
        "DELETE": {
            "authorization": "authenticated Tec-Tac session; owner only. The owner may delete a set whose module was removed",
            "notes": ["Writes a Core audit row (action delete). Deleting a user deletes their filter sets."],
            "errors": {"403": "caller is not the owner", "404": "set not found or not readable", "429": "write rate limit reached"},
            "success": {"204": "deleted"},
        },
    },
    "/api/tfd/filter-sets/fields/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the module must be core or an installed, enabled module the user may use",
            "query": {"module": "required module id"},
            "response": {
                "module": "the module id",
                "available": "boolean; false when the module offers no filters (fields is then empty)",
                "fields": "the fields the caller may filter on: {id, label, kind text|id|bool|date|number, operators [{id, label}], values {source distinct|static|none, options (static only)}, constraints (date and number fields only, added in 1.17.52: {stored_as} for a date, {integer, minimum, maximum} for a number)}. Never a lookup, a row key or a name path",
                "operators": "the six base operators [{id, label}] (unchanged since 1.17.50; the date and number operators are in the keys below)",
                "date_operators": "[{id, label}], added in 1.17.52: the operators a date field offers",
                "number_operators": "[{id, label}], added in 1.17.52: the operators a number field offers",
                "relative_units": "[{id, max_amount}], added in 1.17.52: minutes 525600, hours 8760, days 3650, for in_the_last and not_in_the_last",
                "limits": "rules, groups, depth, value_length, page_size and the other limits",
            },
            "notes": ["Added in 1.17.50. Read limit 240/min per user and IP.", "Since 1.17.52 (core.filter_sets 1.1.0, additive) the answer also carries date_operators, number_operators and relative_units, and a date or number field carries constraints. A date value is a UTC day written YYYY-MM-DD; between is {from, to}; in_the_last and not_in_the_last are {amount, unit}; a number between is {from, to}. Labels come from this answer, so the browser hard-codes none."],
            "errors": {"400": "module missing, unknown or disabled", "403": "caller may not use the module", "429": "read rate limit reached", "502": "the module's filter fields could not be read"},
        },
    },
    "/api/tfd/filter-values/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; the module must be an installed, enabled module the user may use",
            "query": {
                "module": "required module id; only that module's own '<module id>.filter_fields' provider answers",
                "field": "required field id; it must be a field of that module with values.source 'distinct' that the caller was offered",
                "search": "optional text, at most 100 characters, no control characters",
                "page": "optional whole number 1 to 200 (default 1); the page size is fixed at 25",
            },
            "response": {"values": "[{value, label}]: value is text (up to 200 characters) or a whole number, label up to 300 characters; no repeats", "has_more": "boolean", "page": "the page", "page_size": "25"},
            "notes": [
                "Added in 1.17.50 for the Equals and Does not equal pickers. The module's provider filters at the source inside the caller's Tactical client and site scope (context.scope), so a value that exists only on a client the caller cannot see is never offered.",
                "Core answers an empty list without calling the provider when the caller's scope mode is none or cannot be read (fail closed).",
                "Core cuts the provider's answer to the page size, keeps only text or whole-number values, drops repeats and over-long values, and caches an answer for 30 seconds in the web process (at most 256 entries) keyed by the person, a hash of their scope, module, field, search and page. A role change takes effect at once.",
                "There is no fallback: when the provider fails Core answers 502 values_unavailable with no stack text and no value from any other source.",
                "Read limit 240/min per user and IP.",
            ],
            "errors": {"400": "module missing or unknown, search too long or with control characters, page out of range", "403": "caller may not use the module", "404": "the module offers no filters, or no such distinct-value field for the caller", "429": "read rate limit reached", "502": "values_unavailable: the module's provider failed"},
        },
    },
    "/api/tfd/ui/context/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session",
            "response": {
                "module_register_timeout_seconds": "integer, added in 1.17.1. Seconds the UI lets a module's register() run before it marks the module failed and loads the next. Default 30, range 5 to 300. Additive: older UI builds ignore it.",
                "session_theme": "string|null, added in 1.17.24 (CO9). The theme chosen in the dropdown for this sign-in only: null, dark, light or high-contrast. It is held on the session, never written to the saved preference, and dies with the session, so the next person to sign in on the same browser starts without it. The UI applies it at startup before the saved preference. Additive: older UI builds ignore it. Set it with PUT /api/tfd/session/theme/.",
                "system_name": "string, added in 1.17.23. The name an authenticator app shows for this system (Core setting, default Tec-Tac, 1 to 60 characters, no colon). Read only here. The authenticator set-up answer carries the same name as issuer. Additive: older UI builds ignore it.",
                "tactical_scope": "object, added in 1.17.17: the signed-in user's Tactical client and site scope as {mode, unrestricted, whole_client_count, site_count}. mode is unrestricted, clients, sites, mixed or none. It carries counts only, never id lists, so the startup payload stays small; the ids stay in the Python contract (core.resources scope_descriptor). It is built from the same descriptor as core.resources 1.4.0. An installer user, a user with no role and any lookup failure give mode none and unrestricted false. It is a hint for the UI: Tactical still decides every call. Additive: older UI builds ignore it. The UI exposes it in register(context).context in a later UI release.",
                "tactical_permissions": "object, added in 1.17.7: every boolean can_* field on Tactical's Role mapped to true or false for the signed-in user, for example {\"can_reboot_agents\": true}. A superuser or role superuser has every flag true. An installer user, a user with no role and any lookup failure have every flag false. It uses only the user's own role and adds no Tec-Tac permission. It is a hint for the UI: Tactical still decides every call. Additive: older UI builds ignore it.",
                "module_status[].replaces": "string|null, added in 1.17.11: the core or server module id the module's manifest declares it replaces (AD-20), null for a module that declares none and for a legacy plugin. The declared value, not the honoured one. A replacement enabled next to the module it replaces is reported with enabled false and active false. Additive: older UI builds ignore it.",
                "module_status[].description": "string|null, added in 1.17.16: the plain-text description the module's manifest declares (1 to 500 characters), null when it declares none and for a legacy plugin. Additive: older UI builds ignore it.",
                "module_status[].category": "string|null, added in 1.17.13 (AD-21): the category the manifest declares (core, server, premium or test), null when it states none and for a legacy plugin. Additive.",
                "module_status[].effective_category": "string|null, added in 1.17.13: the category Core acts on. A missing category is test. Null for a legacy plugin.",
                "module_status[].category_missing": "boolean, added in 1.17.13: true when the manifest states no category.",
                "module_status[].category_refused": "boolean, added in 1.17.13: true when the effective category is test and this server is not a development server (root config TEC_TAC_ENVIRONMENT). Core then refuses to install the module (install only since 1.17.14, Johan CQ38: a module that is already installed keeps loading and can be enabled).",
                "module_status[].category_warning": "string|null, added in 1.17.13: plain English for the badge or hint, null when there is nothing to say.",
            },
            "notes": ["Only the fields added in 1.17.1, 1.17.7, 1.17.11 and 1.17.13 are listed here. The rest of the context (user, permissions, extensions, capabilities, module_status, preferences, locale, tactical_ui) is documented with the runtime-context browser contract."],
        },
    },
    "/api/tfd/system/update-source/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; any signed-in user",
            "response": {
                "update_sources": "object with framework and ui, each {type: release|branch, ref: branch name or null}. Default {type: release, ref: null}",
                "licensing_enforcement_mode": "object (added 1.17.58, additive): value (off, log-only or enforce), source (default when no choice was made, set when a superuser chose a value), choices, default (log-only). The mode decides what the module stage and install licence gate does: enforce refuses a module whose licence check fails (as before 1.17.58), log-only lets it through and writes one audit row (custom:licence-would-block), off skips the check. Licensing never blocks sign-in, Tactical operations, module rollback or security updates, in any mode",
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
                "tactical_operation_upload_max_mib": "object: value, minimum, maximum, default, bytes. Added 1.17.14 (CQ40): the largest file one Tactical operation may forward, in whole MiB (1 to 25, default 10). Existing installs read 10",
                "system_name": "object: value, maximum_length, default. Added 1.17.23: the name an authenticator app shows for this system (1 to 60 characters, default Tec-Tac). Existing installs read Tec-Tac. Additive",
                "updated_at": "ISO time of the last change",
                "updated_by": "username of the last editor, or null",
            },
        },
        "PATCH": {
            "authorization": "authenticated Tec-Tac session; effective superuser, a role holding core.runtime_settings.manage (1.17.2, grantable in the role editor by any role manager) or a role holding core.privileged_operations",
            "request": {
                "module_register_timeout_seconds": "whole number of seconds from 5 to 300. A boolean, float, string or null is refused. Since 1.17.14 optional: send it, tactical_operation_upload_max_mib, or both",
                "tactical_operation_upload_max_mib": "whole number of MiB from 1 to 25 (added 1.17.14, CQ40). Same strictness as the timeout. Superuser only: a caller who holds core.runtime_settings.manage but is not an effective superuser gets 403 for this key, checked before the value",
                "licensing_enforcement_mode": "text (added 1.17.58): off, log-only or enforce, exactly (lowercase). Anything else, a bool, a number, an empty text or another case is a 400. JSON null resets it to Core's default (log-only; the stored value goes blank, so a later release can move the default without a data migration). Superuser only: a caller who holds core.runtime_settings.manage but is not an effective superuser gets 403, checked before the value, with one best-effort Core deny row (object_id licensing_enforcement_mode, no value), and a body that mixes it with another setting is refused whole. Each change writes its own strict audit row (object_id licensing_enforcement_mode, before and after the effective mode, metadata source_before and source_after: default or set)",
                "system_name": "text (added 1.17.23): the name an authenticator app shows for this system. 1 to 60 characters, trimmed and NFC-normalised. A boolean, number, list, empty text, a control or invisible character or a colon is refused with 400 (a colon is never altered or stored). JSON null resets it to Tec-Tac. Superuser only since 1.17.24 (before, core.runtime_settings.manage was enough): a caller who is not an effective superuser gets 403 for this key, checked before the value, and a body that mixes it with another setting is refused whole. A refusal writes one best-effort Core deny row (object_id system_name, no value). Each change writes its own strict audit row (object_id system_name, before and after the name)",
            },
            "notes": [
                "Writes a strict Core audit row (module_id core, object_type runtime_settings, action modify) with the before and after value, in the same transaction. A failed audit write rolls the change back. Since 1.17.14 each changed setting writes its own row, with object_id the setting name. A setting sent with its current value writes no row.",
                "A body with only module_register_timeout_seconds behaves exactly as before. An empty body or an unknown key is a 400 (since 1.17.14 the empty-body text names both settings).",
                "Write rate limit: 10/min and 200/day per user and IP. Reads are not counted.",
            ],
            "response": "same as GET",
            "errors": {"400": "unknown field, empty body or invalid value", "403": "for the upload key, system_name or licensing_enforcement_mode: the caller is not an effective superuser ('Only a Tec-Tac superuser may change the Tactical operation upload limit.', 'Only a Tec-Tac superuser may change the system name.' or 'Only a Tec-Tac superuser may change the licensing enforcement mode.'; each refusal writes one Core deny row since 1.17.24). Otherwise caller is not an effective superuser and holds neither core.runtime_settings.manage nor core.privileged_operations: 'Tec-Tac core.runtime_settings.manage or core.privileged_operations permission is required to change runtime settings.' Checked before the body, so a caller without the right never sees 400", "429": "write rate limit reached"},
        },
    },
    "/api/tfd/system/licensing/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; an effective superuser or a holder of core.runtime_settings.manage (the people who can set the mode). Anyone else gets 403. A read writes no audit row and makes no network call",
            "response": {
                "mode": "object: value (off, log-only or enforce), source (default or set), choices, default",
                "enforcing": "boolean, true only when the mode is enforce",
                "licence": "object {state, module_licensing, reason}. state is licensing_unavailable when the Licensing module is missing, disabled, unhealthy or provisional (nothing is shown as licensed while module licensing is provisional); otherwise the Licensing module's licence state when it is one of licensed, unlicensed, expired, revoked, unavailable, invalid or provisional, else unknown. module_licensing is provisional, enforced or unknown. reason is a plain sentence or null. Core reads only the public capability status of licensing.entitlements (health keys license_state and module_licensing, registered metadata module_licensing); no key, token, fingerprint or provider text is ever copied",
                "would_block": "object {count, modules, limit}: every installed module whose manifest has licensing.required, run through the same check the gate uses with the mode ignored (what enforce would do). modules is at most 50 rows of {module_id, version, state, reason}; count is the true number. state is Core's own code (for example unlicensed, capability-unavailable, disabled, unhealthy, provider-error, check-error) and reason is Core's own sentence, never the provider's text",
                "grace": "object {window_days, days_left, reason}: window_days is 7. days_left is null until the licensed catalogue and its signed refresh time exist; Core shows no days rather than guess",
                "never_blocked": "array: sign-in, Tactical operations, rollback and security updates are never blocked by licensing",
                "revoked_effect": "plain sentence: a revoked licence will disable new installs only when enforcement is on, and that is not active",
            },
            "errors": {"403": "the caller is neither an effective superuser nor a holder of core.runtime_settings.manage"},
            "notes": ["Added 1.17.58 (additive). The UI context answer (GET /api/tfd/ui/context/) is unchanged. See docs/module-licensing.md."],
        },
    },
    "/api/tfd/account/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; self only",
            "response": {
                "account": "current Tactical user identity and SSO/TOTP state",
                "mfa": "current Tec-Tac backup-code status",
                "tactical_ui": "current Tactical UI preferences plus allowed choices (the same object as GET /api/tfd/account/tactical-ui/; the fields beyond the double-click and URL Action ones were added in 1.17.35)",
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
            "response": {
                "preferences": "Tactical agent_dblclick_action/url_action, the UI scalars below, and the valid choices (agent_dblclick_choices, default_agent_tbl_choices, client_tree_sort_choices, url_actions when allowed)",
            },
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session; self only; partial update (only the fields sent change), all or nothing",
            "request": {
                "agent_dblclick_action": "one of Tactical's current model choices",
                "url_action_id": "integer|null",
                "dark_mode": "boolean (added 1.17.35)",
                "show_community_scripts": "boolean (added 1.17.35)",
                "clear_search_when_switching": "boolean (added 1.17.35)",
                "default_agent_tbl_tab": "server, workstation or mixed (added 1.17.35)",
                "client_tree_sort": "alphafail or alpha (added 1.17.35)",
                "client_tree_splitter": "whole number from 1 to 99 (added 1.17.35)",
                "loading_bar_color, dash_info_color, dash_positive_color, dash_negative_color, dash_warning_color": "a Quasar colour name such as red or deep-purple-3, or a # colour of 3, 4, 6 or 8 digits, at most 40 characters (added 1.17.35)",
                "date_format": "empty or null for the server default, else at most 30 letters, digits, spaces and : / - . , [ ] (added 1.17.35)",
            },
            "response": {"preferences": "updated Tactical UI preferences, as the GET returns them"},
            "errors": {
                "400": "unknown field (block_dashboard_login is not a UI preference and is refused), unsupported action, missing URL Action, URL Action permission denied, or a value outside the rules above (nothing is saved)",
            },
            "audit": "self_tactical_ui_preferences_changed, with the changed field names only, never the values",
        },
    },
    "/api/tfd/modules/repositories/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; a caller who cannot manage modules gets the redacted form (no address, generic skipped reasons)",
            "export_details": True,
            "response": {
                "schema": "whole number 1",
                "repositories": "the repository status rows. Each row is the public repository record (every stored field except auth_token) plus sync {status, synced_at, last_attempt_at, error, module_count, skipped_count, skipped}. sync.status is 'never' before a first sync. skipped holds at most 100 records {index, id, version, reason}. For a caller who cannot manage modules the address fields (url and every key ending in _url) are left out, sync.error is a generic sentence and each skipped reason is generic",
                "count": "whole number, len(repositories)",
                "manage": "true when the caller may manage modules",
                "sync_schedule": "object or null (added 1.17.42): the daily sync (action tec-tac.module-repository-sync). Null for the whole object when the schedule does not exist. Keys: enabled (true or false), time ('03:00', or null), timezone (the server's Django TIME_ZONE, or null), next_run_at (null when none is due), last_run_at and last_run_status (both null when it has never run). It holds no address.",
            },
            "notes": [
                "Added 1.17.42, additive: sync_schedule. The daily sync syncs the enabled repositories at 03:00 in the server's own time zone (Django TIME_ZONE, shown in sync_schedule.timezone; UTC on stock Tactical, so 05:00 in South Africa) through the Scheduler. The Sync actions and the catalog GET are unchanged: the catalog GET never calls a repository.",
                "Added 1.17.43, documentation only: the official seed's index path is the development channel (CQ125), seeded disabled. A 1.17.42 record that still holds the assumed path is corrected once. No route or field changed.",
            ],
        },
    },
    "/api/tfd/modules/repositories/sync/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session; module management only (a caller who cannot manage modules is refused)",
            "response": {"repositories": "one row per enabled repository: the public repository fields plus sync {status, synced_at, error, module_count, skipped_count, skipped}"},
            "notes": [
                "Added 1.17.39, additive, informational: sync.skipped_count is the real total of entries Core skipped in the last sync of that repository, and sync.skipped[] lists at most 100 of them, in index order. Each record is {index, id, version, reason}: index is the entry's position in the index; id and version are the entry's text cut to 100 characters with control characters removed (null when not text); reason is the plain-English reason, at most 300 characters. A duplicate id and version are both skipped with reason 'duplicate'.",
                "For a caller who cannot manage modules, each reason is replaced by a generic sentence (a reason can quote a URL or a host from the remote index). id, version, index and skipped_count stay.",
                "Status stays 'ok' when at least one entry was kept. An index whose entries are all invalid fails with status 'error' and the previous cache is kept. Whole-index failures (not schema 1, modules not an array, a fetch, size or address-guard refusal) fail as before.",
                "Added 1.17.39, additive, informational: the five release fields (channel, lifecycle, downgrade_policy, signing_environment, recommended) are shown with each release. Core never acts on them.",
            ],
        },
    },
    "/api/tfd/modules/repositories/<str:repository_id>/sync/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session; module management only",
            "response": {"sync": "{status, synced_at, error, module_count, skipped_count, skipped}, plus the public repository fields"},
            "notes": [
                "Added 1.17.39, additive, informational: sync.skipped_count and sync.skipped[] (at most 100 records, each {index, id, version, reason}), with the same rules and the same redaction for a caller who cannot manage modules as /api/tfd/modules/repositories/sync/. An all-invalid index answers 400 with the reason in detail, and the previous cache is kept.",
            ],
        },
    },
    "/api/tfd/modules/catalog/online/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; a caller who cannot manage modules gets the redacted form (generic skipped reasons)",
            "response": {
                "modules": "array of the online catalog items: the modules that at least one enabled repository's cache offers (since 1.17.41; before it, modules that were only installed also appeared here)",
                "count": "whole number, len(modules) (since 1.17.41)",
                "installed_only": "array of {id, name, installed_version, installed_source} (added 1.17.41): installed modules that no enabled repository offers. They are not presented as available",
                "availability": "object (added 1.17.41): state (no_repository, not_synced, sync_failed, empty or ready), enabled_repositories, synced_repositories, message (one plain sentence, empty when ready) and installed_only_count",
                "repositories": "the repository status rows, with sync.skipped_count and sync.skipped[]",
            },
            "notes": [
                "Changed 1.17.41 (module-facing: used by the browser only, no module calls this route): modules[] now holds only what an enabled repository offers, each item still carrying installed, installed_version, update_available, compatible, available_sources and releases. An installed module that no enabled repository offers moves to the additive installed_only[]. availability.state says why the list is empty: no_repository (no enabled repository), not_synced (enabled, none synced yet), sync_failed (every enabled repository's last sync failed and none has a cache), empty (synced, no modules) or ready. A cache kept after a failed sync still counts as synced, so its modules stay offered. A caller who cannot manage modules gets the same redaction as before and no repository URL. This GET never calls a repository: syncing stays the manual Sync action.",
                "Added 1.17.39, additive, informational: each modules[] item and each modules[].releases[] row carries channel, lifecycle, downgrade_policy and signing_environment (a string of at most 64 characters, or null) and recommended (true, false or null). A modules[] item takes them from the selected release, and is null when nothing is selected or the cache predates them. Core shows them and never acts on them: they are not used for selection, ordering, compatibility, staging or any refusal, and no value is checked against a list.",
                "Module download and staging are not gated on any entitlement or licence (added 1.17.39): Core does not check a licence on sync, listing or download.",
            ],
        },
    },
    "/api/tfd/modules/v2/": {
        "response": {
            "modules[].replaces": "string|null, the core or server module this module replaces (added 1.17.9)",
            "modules[].description": "string|null, the manifest description (added 1.17.16), null when the module declares none",
            "modules[].routes": "{prefix, urlconf}|null, the manifest routes key (added 1.17.16): Core serves the module's urlconf at /api/tfd/<prefix>/. null when the module declares none (see tec_tac.route_mounting.mounted_routes)",
            "modules[].replacement": "object|null, replacement status of a module that declares replaces (added 1.17.9). Carries registered_mismatch and a registration-caused degraded since 1.17.10, and conflict (boolean, true while it is enabled next to the module it replaces) since 1.17.11. See replacement_status",
            "modules[].replaced_by": "string|null, the module that honourably replaces this core or server module right now (added 1.17.9)",
            "modules[].will_disable": "array of module ids, added 1.17.11: the modules that enabling this module would disable in the same job (its replaced module, when that is enabled and every other rule passes). Empty when none. Show it, then send it back as disable_replaced. Since 1.17.12 (AD-20 hand-back, same field, new meaning for the replaced module) it also names the enabled replacement(s) that enabling a disabled core or server module would switch off. Enabling the module then needs a second confirmation: see second_confirmation_required",
            "modules[].category": "string|null, added 1.17.13 (AD-21, the declared manifest category: core, server, premium or test; the manifest is read first). The same release adds effective_category (a missing category is test), category_missing, category_refused (effective test on a server that is not a development server) and category_warning (plain English or null) to every extension row, and category_state and category_mismatch (what the install wrote to module state, and whether it differs from the manifest). An install plan that Core refuses for this reason returns the problem type category_refused (module, category, effective_category, message). Since 1.17.14 an enable is never refused for the category. Additive.",
            "modules[].second_confirmation_required": "boolean, added 1.17.12: true when enabling this module would switch off an enabled replacement of it (a disabled core or server module whose replacement is enabled), so the request needs confirm_replacement_switch: true after the disable_replaced list. False for a replacement, which keeps its single confirmation, and for every other module. Lets the UI ask before it sends",
            "modules[].will_enable": "array of module ids, added 1.17.12: for an enabled replacement, the replaced module that disabling it switches back on in the same job (it is installed, a core or server module, disabled, and no other enabled module replaces it). Empty when none, and in the reconcile case where the replaced module is enabled already. Since 1.17.14 (CQ34) it lists only the modules that CAN come back; one that cannot is in hand_back_unavailable. A replacement disabled as part of a deliberate cascade hands back its replaced module too (CQ36)",
            "modules[].hand_back_unavailable": "array of {module, reasons[], required_modules[]}, added 1.17.14 (CQ34): the replaced modules that disabling this replacement would switch back on but that cannot come back (a missing or disabled dependency, a version constraint, a runtime requirement, or a module that cannot be managed from the UI). reasons are plain English. required_modules are the modules named by the missing, disabled or out-of-range dependency rows, so the UI can say which module is needed. Empty when none. This is a warning, not a refusal",
            "modules[].hand_back_confirmation_required": "boolean, added 1.17.14 (CQ34): true when hand_back_unavailable is not empty, so disabling this replacement needs confirm_without_hand_back: true. The system loses the listed modules until they can be enabled",
            "modules[].replacement_dependants": "array of {replacement, modules[]}, added 1.17.14 (CQ35): on a disabled core or server module whose replacement is enabled, the enabled modules that name that replacement DIRECTLY in their dependencies. Modules that depend on this module are not listed: it is the one coming back, and the replacement's contract parity (AD-20 condition 3) keeps them satisfied. A warning shown in the second confirmation, never a refusal and never a cascade",
            "modules[].dependency_status[].satisfied_by": "string|null, added 1.17.11: the honoured replacement that stands in for this hard dependency while it is disabled. enabled stays truthful. The version constraint still applies to the dependency's own installed version",
        },
        "errors": {"400": "an enable or install that would run a replacement next to a module it replaces and that module cannot be handled (problem type replacement_conflict, for example a rival enabled replacement, or enabling a core or server module while its replacement is enabled) or does not cover every capability of the module it replaces (replacement_incomplete), added 1.17.9. Enabling or installing the replacement itself no longer fails because the replaced module is enabled (1.17.11): it names that module in will_disable and needs confirmation. Since 1.17.12 enabling the replaced module next to its enabled replacement no longer fails either (CQ32): it names the replacement in will_disable and needs two confirmations. Since 1.17.14 replacement_has_dependants and the hand_back_blocked refusal are gone: both are warnings (replacement_dependants and hand_back_unavailable on the catalogue row) that the two-step confirmation shows"},
    },
    "/api/tfd/modules/v2/<str:plugin_id>/state/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session with module management permission",
            "request": {
                "enabled": "required boolean",
                "cascade": "optional boolean (disable only)",
                "disable_replaced": "optional array of module ids, added 1.17.11: the list the operator was shown (modules[].will_disable). When enabling this module would disable other modules, the request must name exactly that list. A list that is missing or out of date is refused",
                "confirm_replacement_switch": "optional boolean, added 1.17.12: the second confirmation. Required (it must be exactly true) only when enabling this module would switch off an enabled replacement of it (modules[].second_confirmation_required), and only after disable_replaced is right. Any other type is a plain 400 refusal; false is the same as missing. Ignored when nothing needs it. Disabling needs neither field (except as below)",
                "confirm_without_hand_back": "optional boolean, added 1.17.14 (CQ34): the confirmation to disable a replacement whose replaced module cannot come back (modules[].hand_back_confirmation_required). Required (it must be exactly true) only then. Any other type is a plain 400 refusal; false is the same as missing. Ignored when nothing needs it. With it the job disables the replacement and hands back only the modules that can come back",
            },
            "response": {"202": "the queued job"},
            "errors": {
                "400": "invalid field, or a refusal. code replacement_confirmation_required (added 1.17.11) means the enable would disable the modules in will_disable and the request did not name exactly them; the answer carries detail (plain English), code and the fresh will_disable. Old callers that send no list see this refusal and nothing is changed. code replacement_second_confirmation_required (added 1.17.12) means the list was right but the request did not carry confirm_replacement_switch: true while enabling this module would switch off its replacement; the answer carries detail (plain English, naming the replacement and saying it will be switched off), code, will_disable and module (the id being enabled). Old callers that send no flag see this refusal and nothing is changed. Since 1.17.14 (CQ35) the replacement_second_confirmation_required answer also carries dependants, [{replacement, modules[]}]: the enabled modules that name the replacement directly. It is a warning in the same two-step confirmation. replacement_has_dependants no longer refuses, and nothing cascades. code replacement_hand_back_confirmation_required (added 1.17.14, CQ34) means disabling a replacement would leave a replaced module off because it cannot be enabled, and the request did not carry confirm_without_hand_back: true; the answer carries detail (plain English), code, module, will_enable (the modules that can come back) and hand_back_unavailable ([{module, reasons[], required_modules[]}]). Old callers that send no flag see this refusal and nothing is queued. Until 1.17.14 the same disable was refused with no code (hand_back_blocked)",
            },
            "notes": [
                "Added 1.17.11 (AD-20): enabling a module with replaces disables the module it replaces in the same job, after the root job helper re-checks the replacement rules from root-owned manifests. The helper refuses anything the operator did not confirm and restores the flags if the runtime sync fails.",
                "Changed 1.17.12: before this, Core wrote a custom:module-replacement-disabled row per disabled module when the job was queued, before anything had changed. The queue-time row is now custom:module-replacement-switch-queued (object the module being enabled or disabled, actor the requesting user, metadata job_id, disable, enable), a request that claims no change. The outcome rows are written by the scheduler tick once the job has finished, with the system service as actor and metadata job_id, requested_by, replacement and replaced: custom:module-replacement-disabled (a module the job disabled), custom:module-replacement-enabled (a replaced module handed back), custom:module-replacement-conflict-resolved (a replacement found enabled next to its replaced module and disabled by the helper) and custom:module-replacement-switch-failed (a failed job that had a planned list; the message says whether the flags were put back or nothing changed, with the stage and error). Each is written once per job, within about a minute of the job finishing, and only for jobs finished in the last 7 days. Nothing in modules/ reads these action names.",
                "Added 1.17.14 (module-facing, Johan CQ34 to CQ36, 9 October 2026): disabling a replacement whose replaced module cannot be enabled warns and continues. The first request is refused with replacement_hand_back_confirmation_required and queues nothing. With confirm_without_hand_back: true the job disables the replacement and hands back only the modules that can come back (the helper still re-checks every rule). The job records hand_back_skipped (the ids left off), the queue-time audit row names what was skipped, and the outcome row says the replaced module stayed off. A deliberate disable always hands back, including a replacement disabled in a cascade; a rollback, a failed job and a reconcile job never do. Core does not offer to install a missing module (the catalogue is not online). A failed module job raises one notice per recipient (source core, level error, client_id module-job-failed:<job id>, action route /modules) for every active superuser and the user who started the job; a failed switch says whether the flags were put back.",
                "Added 1.17.12 (AD-20 hand-back, Johan CQ32 and CQ33): enabling a disabled core or server module whose replacement is enabled switches the replacement off in the same job, after two confirmations in order (disable_replaced, then confirm_replacement_switch: true). The job carries disable_modules and replacement_confirmed. Since 1.17.14 an enabled module that depends on the replacement no longer refuses it: it is listed in the second confirmation (CQ35). Disabling an enabled replacement switches the replaced module back on in the same job (the job carries enable_modules, listed as modules[].will_enable); since 1.17.14 a replaced module that cannot come back is a warning that needs confirm_without_hand_back (CQ34). Dependants of the replaced module stay satisfied throughout and do not block it; dependants of the replacement still need cascade. The root job helper re-checks every rule and both confirmations from root-owned manifests and the root-owned job copy, makes both changes in one state write, and restores both flags (then resyncs) if the runtime sync fails. Old callers that send no list or no second flag get a refusal and nothing changes. The reconcile job (reason replacement_conflict) never hands back.",
            ],
        },
    },
    "/api/tfd/modules/v2/packages/<uuid:upload_id>/install/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session with module management permission",
            "request": {
                "kind": "optional: artifact (default) or batch",
                "licence_override_reason": "optional text (added 1.17.58): the same audited licence override as on the inspect route, as a JSON string. Superuser only; 403 licence_override_superuser_required for anyone else, 400 invalid_licence_override_reason when empty, over 500 characters, with a control character or not text. It does not carry over from the stage: the install runs the licence gate again and needs its own reason",
                "order": "optional array of module ids",
                "disable_replaced": "optional array of module ids, added 1.17.11: the list the operator was shown (plan.will_disable from the inspect answer). A fresh install of a module with replaces disables the module it replaces in the same job, so the request must name exactly that list",
            },
            "response": {"202": "the queued job"},
            "errors": {"400": "invalid field or an unsatisfiable plan, or code replacement_confirmation_required (added 1.17.11) with the fresh will_disable when the install would disable modules the request did not name"},
            "notes": ["A single local package that would disable a module is installed by the v2 worker (like a rename), because only the v2 worker disables in the same job. An upgrade of an installed replacement names nothing.", "Added 1.17.58: the licence gate follows the licensing mode as on the inspect route; the 403 licensing_requirement_failed payload gains licensing.enforcement_mode, and a candidate's licensing_status gains enforcement_mode, would_block, audited (log-only) and overridden (an audited override). Additive."],
        },
    },
    "/api/tfd/modules/catalog/online/stage/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session with module management permission",
            "request": {
                "repository_id": "required text",
                "module_id": "required text",
                "version": "optional text",
                "allow_source_change": "optional boolean",
                "licence_override_reason": "optional text (added 1.17.58): the same audited licence override as on the v2 inspect route, as a JSON string. Superuser only; 403 licence_override_superuser_required for anyone else (checked before the package is downloaded), 400 invalid_licence_override_reason when empty, over 500 characters, with a control character or not text. It does not carry over to the install",
            },
            "response": {"201": "the staged package, as the v2 inspect answer"},
            "errors": {"403": "licensing_requirement_failed in enforce when the licence check refuses the module and no valid override was sent (the licensing object names the mode), or an override from a caller who is not a superuser", "400": "invalid field or invalid override reason"},
            "notes": ["Added 1.17.58 (additive): the licence gate follows the licensing mode. In log-only (the default) and off a refused module is staged; the download itself was never gated on a licence (1.17.39) and still is not."],
        },
    },
    "/api/tfd/modules/v2/packages/inspect/": {
        "POST": {
            "request": {
                "licence_override_reason": "optional text (added 1.17.58): a form field on this multipart route. Plain text of 1 to 500 characters after trimming, no control or invisible characters. Only an effective superuser may send it, and it only matters while the licensing mode is enforce and the licence check refused a module: Core then writes one strict audit row (custom:licence-override, with the reason) and the stage continues. See the notes",
            },
            "notes": [
                "Added 1.17.58 (module-facing, additive): the licence gate follows the licensing mode (GET /api/tfd/system/licensing/). In log-only, the default, and in off, a module whose licence check fails is staged and the answer's licensing_status carries would_block true (log-only) or state not-checked (off); in enforce the stage is refused with 403 {code licensing_requirement_failed, licensing {..., enforcement_mode: enforce}} as before. licence_override_reason from a caller who is not an effective superuser is 403 {code licence_override_superuser_required} plus one Core deny row (object licence_override, no reason text), checked before any package work in every mode. From a superuser an empty, over-long, control-character or non-text value is 400 {code invalid_licence_override_reason}; it is never silently ignored. The override lets one refused module through the licence gate only: signature, trust, compatibility, dependency and replacement checks run exactly as before. If the strict audit row cannot be written the refusal stands. The override does not carry to the install: the install needs its own reason. In log-only and off nothing blocks, so no override row is written.",
                "Since 1.17.11 the install plan carries will_disable (array of module ids) at the top and on each action: the modules a fresh install of a replacement would disable. Show it and send it back as disable_replaced on the install call. The plan stays valid.",
                "Since 1.17.11 a plan problem disabled_dependency is not raised when an honoured replacement stands in for the dependency.",
                "Since 1.17.18 several packages may come with their detached signatures and release metadata. Send them as multipart form fields: packages (repeated), signatures (repeated) and metadata_files (repeated). The old single fields signature and metadata (or release_metadata) still work for one package. Core pairs from the release metadata, never by guessing: metadata.filename must equal an uploaded package name and metadata.signature must equal an uploaded signature name. A package with neither companion stays unsigned and follows the normal unsigned policy. Core refuses with a plain 400, naming the file, when a metadata file matches no uploaded package (a browser-renamed copy such as 'name (1).zip' will not match), a metadata file names a signature that was not uploaded, a signature belongs to no metadata file, or two metadata files are sent for one package. Nothing stays staged when a pairing fails. Trust is still verified for each package at stage time and again when the batch install is queued.",
            ],
        },
    },
    "/api/tfd/modules/v2/jobs/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "status": "optional string", "action": "optional string", "search": "optional string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
        "notes": ["Since 1.17.12 a job row carries disabled_modules, enabled_modules and reconciled_modules (arrays of module ids) once the root helper has run it: the modules the job disabled because of a replacement, the replaced modules it switched back on, and the replacements it found enabled next to their replaced module and disabled. Additive: absent on older jobs and on jobs that switched nothing. The request fields (disable_modules, enable_modules, replacement_confirmed) are not exposed."],
    },
    "/api/tfd/modules/v2/jobs/history/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations (the same check as the other module-management routes). 403 without it, no audit row",
            "query": {"page": "integer >=1 (400 when not a whole number or below 1)", "page_size": "integer 1..100, default 50 (a larger value is cut to 100; 400 when not a whole number or below 1)", "module": "optional exact module id; matches any module the job names", "action": "optional string", "status": "optional string", "kind": "optional module | hotfix"},
            "response": {"jobs": "array of rows, newest first", "count": "integer, rows in this page", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
            "row": {"id": "job id", "kind": "module | hotfix", "action": "as stored: install, replace, batch_install, bundle_install, enable, disable, remove, visibility, apply, rollback", "switch": "boolean, true for a replacement switch", "renamed_from": "module id | null", "module_ids": "array of module ids ('batch' is not listed)", "versions": "{module id: version} | null when the job carries none", "requested_by": "string | null", "created_at": "string | null", "started_at": "string | null", "finished_at": "string | null", "status": "string | null", "stage": "string | null", "error": "one short plain sentence, first line only, at most 200 characters, scrubbed | null", "has_log": "boolean", "log_bytes": "integer, size of the log file (0 when there is none)", "disabled_modules": "array", "enabled_modules": "array", "reconciled_modules": "array", "hand_back_skipped": "array"},
            "notes": [
                "Added in 1.17.60. The existing GET /api/tfd/modules/v2/jobs/ is unchanged and still puts log_tail on every row; this route is the one without log text.",
                "No row carries log text, a file path, a package path or hash, or publisher trust. Each row is built from a fixed list of fields.",
                "Rows come from module jobs and hotfix jobs together. A job record that cannot be read is skipped. Finished job records are removed after MODULE_JOB_RETENTION_DAYS (180) days; see docs/module-job-logs.md.",
            ],
        },
    },
    "/api/tfd/modules/v2/jobs/<uuid:job_id>/log/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations. 403 without it, no audit row",
            "query": {"download": "optional; 1 sends the log as a file (Content-Disposition: attachment; filename=module-job-<module>-<action>-<YYYY-MM-DD>.log). Anything else shows it inline"},
            "response": "text/plain; charset=utf-8, the scrubbed log. Headers: X-Content-Type-Options: nosniff, Cache-Control: no-store, X-Tec-Tac-Log-Truncated (true | false), X-Tec-Tac-Log-Bytes (size of the log file on disk), X-Tec-Tac-Log-Kept (all | head-and-tail), and since 1.17.66 on a 200 Access-Control-Expose-Headers: X-Tec-Tac-Log-Truncated, X-Tec-Tac-Log-Bytes, X-Tec-Tac-Log-Kept, Content-Disposition, so a browser on another origin can read them",
            "errors": {"400": "the id is not a canonical lowercase uuid", "403": "no module-management permission", "404": "unknown job, or 'No log was kept for this job.'", "503": "the audit row of this read could not be written, so no log text is sent (strict), or the log could not be read"},
            "audit": "one row per successful read: module core, action view, object type module_job_log, object id the job id, metadata job_id, kind, action, module, bytes, truncated, download. No log text.",
            "notes": [
                "Added in 1.17.60. A log over 5 MB comes back as its first and last 2.5 MB, each cut at a line boundary, with one marker line '[... N bytes were left out of the middle of this log ...]' between them. The headers say so as well.",
                "Secrets are redacted by pattern (private key blocks, Authorization and API-key headers, Bearer, Basic and Token values, URL passwords, password, secret, token and key fields, secret-named paths). A package sha256 after 'sha256=' is kept. Pattern scrubbing cannot be perfect, which is why every read is audited.",
                "The log is plain text. Show it as text, never as HTML.",
            ],
        },
    },
    "/api/tfd/system/updates/jobs/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations. 403 without it, no audit row",
            "query": {"page": "integer >=1 (400 when not a whole number or below 1)", "page_size": "integer 1..100, default 50 (a larger value is cut to 100; 400 when not a whole number or below 1)", "component": "optional framework | ui", "status": "optional string"},
            "response": {"jobs": "array of rows, newest first (finished_at, else created_at)", "count": "integer, rows in this page", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
            "row": {"id": "job id", "status": "queued | running | succeeded | failed", "created_at": "string|null", "started_at": "string|null", "finished_at": "string|null", "stage": "string", "error": "string|null", "error_type": "string|null", "rollback": "object|null", "action": "string", "component": "framework | ui", "version": "string|null", "installed_version": "string|null, the version that was installed before the update; absent on jobs run by a helper older than 1.17.67", "operation": "string|null", "package_sha256": "string|null", "package_filename": "string|null", "source": "object", "release_trust": "object|null", "requested_by": "string", "source_git": "object|null", "log_bytes": "integer | null, size of the kept log file", "has_log": "boolean"},
            "notes": [
                "Added in 1.17.67 (framework >=1.17.67). Reads the jobs folder and the history folder together, merged by job id (a history row wins). Only the newest 500 files by modification time are read.",
                "Whitelisted fields only. A row carries no log text (use the log route) and no file path: backup_path is left out of this list.",
                "Audit (1.17.67): when an update ends, the Scheduler tick writes one row within about a minute, from the job file: action install (or custom:system-update-failed), object type system_update, object id the component, message 'Update installed successfully 1.17.16 -> 1.17.17' (or 'Update installed successfully to 1.17.17' for a job the older helper ran; 'Update failed 1.17.16 -> 1.17.17. 1.17.16 was restored.'), metadata job_id, component, from_version, to_version, operation, result, requested_by, rollback_status. No error text and no path.",
            ],
        },
    },
    "/api/tfd/system/updates/jobs/<uuid:job_id>/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations. 403 without it",
            "response": "The row of the list above plus backup_path and log_tail (the last 80 log lines).",
            "notes": [
                "Since 1.17.67 a job that is no longer in the jobs folder is read from history instead of answering 404, and the answer carries the additive keys log_bytes (integer | null) and has_log (boolean). Every earlier key is unchanged.",
            ],
        },
    },
    "/api/tfd/system/updates/jobs/<uuid:job_id>/log/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations. 403 without it, no audit row",
            "query": {"download": "optional; 1 sends the log as a file (Content-Disposition: attachment; filename=system-update-<component>-<YYYY-MM-DD>.log). Anything else shows it inline"},
            "response": "text/plain; charset=utf-8, the scrubbed log. The same headers as GET /api/tfd/modules/v2/jobs/<uuid:job_id>/log/: X-Content-Type-Options: nosniff, Cache-Control: no-store, X-Tec-Tac-Log-Truncated, X-Tec-Tac-Log-Bytes, X-Tec-Tac-Log-Kept and, on a 200, Access-Control-Expose-Headers",
            "errors": {"400": "the id is not a canonical lowercase uuid", "403": "no module-management permission", "404": "job_not_found (unknown or unreadable job) or no_log", "503": "the audit row of this read could not be written, so no log text is sent (strict), or the log could not be read"},
            "audit": "one row per successful read: module core, action view, object type system_update_job_log, object id the job id, metadata job_id, component, bytes, truncated, download. No log text.",
            "notes": [
                "Added in 1.17.67 (framework >=1.17.67; UI 0.12.119 request). The job is found in the jobs folder, then in history. Same scrub, same 5 MB head-and-tail cap and same plain-text rule as the module job log.",
            ],
        },
    },
    "/api/tfd/system/maintenance/jobs/<uuid:job_id>/log/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with core.privileged_operations, and the permission of the job's action when it declares one. A job the caller may not see answers the same 404 as an unknown job",
            "query": {"download": "optional; 1 sends a file (Content-Disposition: attachment; filename=server-maintenance-<action>-<YYYY-MM-DD>.log)", "part": "optional all (default) | log | stdout | stderr. all is three headed sections ('== log ==', '== stdout ==', '== stderr ==') in one text; a file that does not exist is left out"},
            "response": "text/plain; charset=utf-8, scrubbed. The same headers as the module job log route. The 5 MB cap is shared between the non-empty parts.",
            "errors": {"400": "bad id (invalid_job_id) or bad part (invalid_part)", "403": "no core.privileged_operations", "404": "job_not_found (unknown, or hidden by the action's permission) or no_log", "503": "the audit row could not be written (strict), or the log could not be read"},
            "audit": "one row per successful read: module core, action view, object type server_maintenance_job_log, object id the job id, metadata job_id, action, part, bytes, truncated, download. No log text.",
            "notes": [
                "Added in 1.17.67 (framework >=1.17.67; UI 0.12.119 request). The job's own sensitive parameter values are removed before the usual scrub. The capability core.server_maintenance stays 1.1.0: this route adds no operation a module calls.",
            ],
        },
    },
    "/api/tfd/session/audit/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "username": "optional string", "event_type": "optional string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/access/sessions/": {
        "query": {"page": "integer >=1", "page_size": "integer 1..100", "search": "optional username/IP string"},
        "response": {"items": "array", "total": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
    },
    "/api/tfd/session/theme/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session; reads only the caller's own current session",
            "response": {"theme": "null | dark | light | high-contrast"},
        },
        "PUT": {
            "authorization": "authenticated Tec-Tac session; changes only the caller's own current session row",
            "request": {"theme": "required text, one of dark, light, high-contrast (the values of the saved preference's appearance.theme). A boolean, a number, null and any other text are refused with 400; so is any other body key"},
            "response": {"theme": "the theme now held"},
            "notes": [
                "Added in 1.17.24 (CO9). The theme is held for this sign-in only. It is never written to the saved preference (PUT /api/tfd/ui/preferences/ is unchanged, and a theme put there still works), and it dies with the session, so the next user starts clean: a new sign-in is a new session row.",
                "Not audited: a display choice, not a security event. GET /api/tfd/ui/context/ carries it as session_theme.",
            ],
            "errors": {"400": "body is not an object with only theme, or the theme is not one of the three", "401": "not signed in"},
        },
        "DELETE": {
            "authorization": "authenticated Tec-Tac session; the caller's own current session row",
            "response": {"theme": None},
            "notes": ["Clears the choice for this session. Idempotent."],
        },
    },
    "/api/tfd/access/sessions/revoke-all/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session; effective superuser only (Django is_superuser, the ROOT_USER or a role with is_superuser). An account administrator with only can_manage_accounts gets 403",
            "request": {
                "reason": "optional text, at most 255 characters (longer text is cut). Default administrator-request",
                "include_current": "optional boolean, default true (1.17.25, CQ76): the caller's own session and token end too. false keeps the caller's own session: its token is not deleted and its trust row is not revoked",
            },
            "response": {
                "revoked_tokens": "integer: Tactical Knox tokens deleted, all users, protected accounts included",
                "revoked_sessions": "integer: Tec-Tac session trust rows revoked",
                "users": "integer: distinct users whose tokens were deleted",
                "current_kept": "boolean: true only when the caller's own token and trust row were both spared (never just because include_current is false). False when the caller was signed out",
            },
            "notes": [
                "Added in 1.17.24 (CO17). Core takes no typed confirmation and no confirmation field: the UI asks one Yes or No (AD-27). Changed in 1.17.25 (CQ76): include_current defaults to true, so a caller who relied on the 1.17.24 default must now send include_current false.",
                "Runs in one transaction. It writes one session audit event (all_login_sessions_revoked, counts only, never a token or digest) and one strict Core audit row (action custom:revoke-all-sessions, object_type login_sessions, counts only). A failed audit write rolls everything back.",
                "A refusal writes one best-effort Core deny row. The per-user and per-token revoke routes are unchanged.",
            ],
            "errors": {"400": "include_current is not a boolean, or reason is not text", "401": "not signed in", "403": "the caller is not an effective superuser"},
        },
    },
    "/api/tfd/scheduler/event-jobs/": {
        "GET": {
            "authorization": "authenticated Tec-Tac session with server-maintenance authority (the same as scheduler/health/)",
            "response": {
                "jobs": "array of {module_id, job_id, label, registered, pending, running, oldest_pending_age_seconds, published, duplicate, dropped, succeeded, failed, expired, skipped, last_failure_at, last_error, max_backlog}",
                "totals": "sums of the counts",
                "limits": "Core's minimum, default and maximum of each registration limit",
            },
            "notes": [
                "Added in 1.17.45 (core.event_jobs 1.0.0). Counts, ages and the last error text only: never a payload, a key or a row id.",
                "registered is true when this process has the job registered; a job of a module that is disabled still lists its counts.",
            ],
            "errors": {"401": "not signed in", "403": "the caller lacks server-maintenance authority"},
        },
    },
    "/api/tfd/scheduler/system-actions/confirmation/": {
        "POST": {
            "authorization": "authenticated Tec-Tac session. The person is the signed-in user; every creation-time check runs for that person",
            "body": {
                "action_id": "a registered Scheduler action id that is also a declared system action",
                "targets": "the schedule's targets object, as sent to POST /api/tfd/scheduler/schedules/",
                "parameters": "the schedule's parameters object; the confirmed values of a system action sit under system_action_parameters",
                "when": "the timing fields (schedule_type, run_at, run_time, weekdays, day_of_month, interval_seconds, timezone); {schedule_type: once, run_at: now} for a one-off run",
            },
            "response": {"required": "boolean; false for an action that is not a declared system action (nothing else is set)", "text": "the plain Yes or No text", "confirmation_id": "signed id, valid for expires_in seconds", "total": "endpoints", "groups": "number of groups of at most 2000", "expires_in": "seconds"},
            "errors": {"400": "unknown action", "401": "not signed in", "403": "a creation-time check refused (reason: not_permitted, out_of_scope, targets_unresolved, agent_count, bad_parameters, module_disabled, replacement_not_honoured, owner_inactive, unknown_action, function_unavailable)"},
            "notes": [
                "Added in Core 1.17.66 (core.system_actions 1.1.0). The UI shows text in its plain Yes or No dialog and sends the id back as confirmation_id in the body of POST /api/tfd/scheduler/schedules/ or PATCH /api/tfd/scheduler/schedules/<id>/. A create or edit of a declared system action without a valid id is refused with 403 reason confirmation_required or confirmation_invalid.",
                "Since 1.17.68 (additive, no new route): POST /api/tfd/scheduler/schedules/ stores the creator's Tactical scope and role flags on the schedule, and PATCH stores the editor's when the owner edits. When a person other than the owner changes an edit field (the action, targets, parameters or timing) or switches the schedule on, ownership moves to that person if their own Tactical scope covers every target (no manager bypass); otherwise PATCH answers 403 reason takeover_out_of_scope with the plain text 'You cannot take over this schedule: some of its targets are outside your Tactical scope.' and changes nothing. A rename and switching a schedule off move nothing. A move writes the usual strict audit row (or one modify row) with owner_changed_from, owner_changed_to and previous_confirmed_by. A module-owned target type with a registered resolver is judged by the endpoints it names instead of 'unrestricted scope only'.",
                "The id binds the person, the action, the targets, the parameters and the timing. It is not stored and it does not prove that the button was pressed. A change to the name or to the policies of a schedule that is already on does not need one.",
                "A refusal writes one deny audit row (reason code, no endpoint ids). An allowed create or edit writes one strict audit row with creator, confirmer, schedule, total_agents, groups and when.",
            ],
        },
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
            "While signed out the shell refuses the call with status 401 and code signed_out, with no request.",
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
        "details": [
            "Since UI 0.12.99 client.context-menu and site.context-menu are also shown in a right-click menu on a client row and on a site row, with the same action context (the browser contextmenu event, so Shift+F10 and the menu key work too). A right-click on a client row selects it. The built-in entries stay first, then a divider, then the contributed actions.",
            "A contributed action runs as the Extensions button runs it. A disabled action shows its reason and does not run. A dangerous action asks the one Yes or No question first. An action the person may not use stays hidden (AD-12).",
        ],
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
        "operations": ["register", "list", "clear", "gridColumns", "loadGridColumns"],
        "audience": "provider/consumer browser",
        "docs": "tec-tac-ui/docs/module-resource-views.md",
        "purpose": "Render optional module-owned visual contributions on consumer-owned resource placements.",
        "details": [
            "Since UI 0.12.93 one placement takes data instead of a component: endpoint.grid-columns, a column of the Endpoints grid. See 'Grid columns' in tec-tac-ui/docs/module-resource-views.md. A module registers {id, resource: 'endpoint', placement: 'endpoint.grid-columns', label, order, permission, sortable, filterable, cell, load}. load is required at this placement and refused at every other one. cell is an optional badge component. sortable and filterable are strict booleans, default false.",
            "load(agentIds, {resource, placement, context, signal}) returns an object keyed by agent id. It runs once per page with string ids and no duplicates, and an id it was not given is dropped from the answer. The host pages at most 100 ids per call.",
            "A thrown error, a rejection or an answer that is not an object gives the status failed. Hitting the module register time limit (30 seconds by default) gives timeout and aborts signal. The host shows a quiet dash in both cases. Permission is checked when columns are listed and again just before load runs, so a column the user may not see is never called (AD-12).",
            "gridColumns({resource, ids, context}) and loadGridColumns({columns, agentIds, context, signal}) are for the host that draws the grid (Endpoints). gridColumns returns the visible columns, or those named by ids in that order. loadGridColumns returns an object keyed by column id, each value a promise that never rejects and resolves {id, status: 'ready' | 'failed' | 'timeout', values}. A saved view stores only the column id.",
            "Display only. The backend decides every call. Needs UI 0.12.93.",
        ],
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
        "details": [
            "Nothing shows and nothing is sent while the person is signed out; a module treats status 401 as signed out and stays silent.",
            "While signed out, show, info, success, warning and error return null: no toast and no stored notice (UI 0.12.103).",
        ],
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
        "details": [
            "popoverTarget (UI 0.12.101): header.popoverTarget is '#tec-tac-popover-layer'. Use it as the target of a Teleport for a pop-up opened from a header item. The layer is fixed above the top bar and page content, and below the help drawer, shell dialogs, quick actions, toasts and the confirm dialog. It is not rendered in a popup window, which has no header.",
        ],
    },
    {
        "id": "ui.authenticated.module-status",
        "phase": "authenticated",
        "service": "modules",
        "operations": ["list", "get", "has", "isInstalled", "isEnabled", "isActive", "version", "satisfies"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-status.md",
        "purpose": "Inspect installed/enabled module state without additional HTTP calls; backend capability checks remain authoritative.",
        "details": [
            "Each row is {id, version, installed, enabled, active, legacy, replaces}. replaces (needs Core 1.17.11) is the id of the core or server module the module declares it replaces in its manifest, or null.",
            "replaces is the declared value, not the honoured one. Core's executor still re-checks honouring on every call.",
            "A replacement that is enabled next to the module it replaces is reported with enabled false and active false (1.17.11): Core does not load its backend, so the UI must not load it either.",
        ],
    },
    {
        "id": "ui.authenticated.runtime-context",
        "phase": "authenticated",
        "service": "context / state.context",
        "operations": ["read", "locale", "timeZone", "dateTimeFormat", "tactical_ui.agent_dblclick_action", "tactical_ui.url_action_id", "tactical_ui.can_run_url_actions", "tactical_ui.dark_mode", "tactical_ui.show_community_scripts", "tactical_ui.clear_search_when_switching", "tactical_ui.default_agent_tbl_tab", "tactical_ui.client_tree_sort", "tactical_ui.client_tree_splitter", "tactical_ui.loading_bar_color", "tactical_ui.dash_info_color", "tactical_ui.dash_positive_color", "tactical_ui.dash_negative_color", "tactical_ui.dash_warning_color", "tactical_ui.date_format", "tactical_web_ui.installed", "tactical_web_ui.url", "server_url", "module_register_timeout_seconds", "system_name", "user.id", "user.superuser", "tactical_permissions.<flag>", "tactical_scope.mode", "tactical_scope.unrestricted", "tactical_scope.whole_client_count", "tactical_scope.site_count"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Read the Core-provided authenticated register(context).context object (also available as state.context), including permissions, preferences, authoritative locale/time-zone/date-format fields, Tactical UI preferences, and whether the standard Tactical web UI is installed; treat it as read-only state.",
        "details": [
            "tactical_ui (added 1.17.35): the scalars dark_mode, show_community_scripts, clear_search_when_switching (booleans), default_agent_tbl_tab (server, workstation or mixed), client_tree_sort (alphafail or alpha): alphafail is Tactical's 'Move failing clients to the top' and alpha is A to Z. Core publishes the person's setting and, on core.resources client and site records, the failing state (failing_checks, as of Tactical's last periodic refresh). Core never sorts: the ordering and any colour marking is the consumer's, client_tree_splitter (1 to 99), loading_bar_color and the four dash_*_color values (Quasar colour names or # colours), and date_format (a string, or null for the server default). Read-only and additive: the three keys from 1.15.178 are unchanged, and the choice lists are not in the context.",
            "server_url: the Tactical API base without a trailing slash. It is an empty string when unset or not http(s). Read-only.",
            "module_register_timeout_seconds: whole seconds from 5 to 300, default 30. The UI applies it. It covers loading the module's entry file plus its register() call. A module that takes longer is marked failed and the UI carries on.",
            "system_name: string, added in Core 1.17.23. The name an authenticator app shows for this system (default Tec-Tac). Read-only, display only. The set-up answer of POST /api/tfd/auth/totp/enrollment/ carries it as issuer; no unauthenticated read exists.",
            "module_status[].replaces: string or null, added in Core 1.17.11. The core or server module id that module's manifest declares it replaces (AD-20), null for a module that declares none and for a legacy plugin. It is the declared value, not the honoured one. UI 0.12.88 reads it to scope tacticalOperation to the AD-20 module the caller replaces and fails closed when it is absent. Additive: older UI builds ignore it.",
            "module_status[].category, effective_category, category_missing, category_refused and category_warning: added in Core 1.17.13 (AD-21), see docs/module-categories.md. category is the declared value (core, server, premium or test) or null, effective_category is what Core acts on (a missing category is test), category_missing and category_refused are booleans (category_refused means an install is refused, install only since 1.17.14), category_warning is plain English or null. The UI shows them as a badge. Additive: older UI builds ignore them.",
            "tactical_permissions: a plain object of can_* keys with strict boolean values (needs Core 1.17.7). The UI drops any key that does not start with can_ and any value that is not exactly true or false. A missing or non-object value becomes an empty map. Core sends only booleans from tactical_permission_catalog, so the rule is defence in depth. Use hasTacticalPermission(flag) to read it.",
            "user.id (UI 0.12.101): the signed-in person's Tactical user id, which is Tactical's own user primary key. It is a whole number of at least 1. A module uses it as an owner or author id only when it is valid, and otherwise asks the person to sign in again rather than guess one. Read-only.",
            "user.superuser (sent since before 1.17.38, listed in the row from 1.17.39): the effective superuser, a strict boolean. It is true when Tactical's is_superuser or the role's is_superuser is true, and it is not the Tactical flag alone (that is user.tactical_superuser, which this row does not promise). A display hint only: Core and Tactical decide every call (AD-12, AD-35). A module treats a missing or non-boolean value as false (fail closed).",
            "tactical_scope: {mode, unrestricted, whole_client_count, site_count}, the signed-in user's Tactical client and site scope as counts only (Core 1.17.17, read by UI 0.12.93). mode is unrestricted, clients, sites, mixed or none. unrestricted is true only when mode is unrestricted. The counts are whole numbers and there are no id lists. An older Core, a lookup that failed or a value the UI does not recognise becomes {mode: 'none', unrestricted: false, whole_client_count: 0, site_count: 0}. Use tacticalScope() to read it. A display hint only: Tactical and Core decide every call (AD-12).",
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
            "tacticalPermission (UI 0.12.99): one Tactical flag name, or a list in which every flag must be strictly true in context.tactical_permissions. It is read live, so the item appears or disappears when the role changes. It has no superuser shortcut: Tactical's flags are Tactical's own. Without a backend-supplied context a gated item is hidden. It combines with permission and permissions, and every rule must pass. An item without the field behaves as before. Display only.",
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
            "Since UI 0.12.96 the guard refuses a route path or alias that starts with /popup/. The shell owns that prefix and adds the popup address itself for a route with meta.popup. It also refuses an alias that another owner already holds.",
            "Every other vue-router member (for example push, resolve and currentRoute) passes through unchanged.",
        ],
    },
    {
        "id": "ui.authenticated.popup",
        "phase": "authenticated",
        "service": "popupHref",
        "operations": ["popupHref", "route.meta.popup", "route.meta.permission", "route.meta.permissions", "route.meta.popupPublishers"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Open one of the module's own pages in its own window, without the Tec-Tac chrome. Ask for the address with context.popupHref(path) and open the window with your own window.open call. Needs UI 0.12.95; no Core change.",
        "details": [
            "Doc section: Popup mode.",
            "popupHref(path) returns an absolute address of the form https://<host>/tec-tac/#/popup/<module id><path>, or an empty string when it cannot build the address safely.",
            "It refuses a query string, '..', control characters, zero-width characters, and a path that starts with /popup. It always names the calling module, so one module cannot point at another module's window.",
            "It opens nothing. The module keeps its own window.open call and window features.",
            "popupHref is refused after the module was abandoned by a failed or timed-out register(). Public modules (registerPublic) do not get it.",
            "meta.popup: true lets a route open in a popup. A route without it has no popup address, and a popup request for it shows a refusal.",
            "meta.permission (one Tec-Tac code) or meta.permissions (a list) names the codes the person must hold. A superuser passes. Otherwise every code is required. A context that did not come from the backend is denied. The person sees a plain refusal before the component renders. The backend stays the authority (AD-12).",
            "A popup loads only the owning module's bundle and its hard dependencies from tec_tac.json, dependencies first. It does not load public modules, the dashboard, notice polling, header contributions or the register() of any other module.",
            "Refusal texts: 'This page is not available to you.' (module skipped, not installed, disabled, failed to load, or the permission is missing) and 'This page cannot open in its own window.' (the route does not exist or has no meta.popup). Neither makes a request for the module's page.",
            "route.meta.popupPublishers (UI 0.12.97): true, or an array of module ids. It is opt-in per route. The shell reads it from the matched route after the owner registers and before the popup address is replayed, then loads the extra modules, each with its hard dependencies first. It skips modules already loaded, modules with no authenticated entry, modules the person may not use and ids that are not module ids. Extra modules get no popup alias and keep every loader guard. Each extra module costs one more bundle and one more register().",
            "Route-path rule (UI 0.12.97): a route path may use ':name', one optional '(...)' group, and one modifier '?', '*' or '+' right after it. Any other '?', '#', whitespace, '..', backslash, control character or zero-width character gives the route no popup alias. A route path or alias under /popup/ is refused by the router (UI 0.12.96).",
            "Warnings (UI 0.12.97): a route that asks for a popup and cannot get an alias gets a console.warn that names the module, the route path and the reason. A popup address that does not land on a module route after the modules loaded also warns in the console, with the hash, the module id and the parsed path.",
            "forModule(moduleId, { isAbandoned }) on the context action registry (UI 0.12.97): a handler's confirm is refused (it rejects) once the module that owns the action was abandoned after a failed or timed-out register(), the same as register(context).confirm.",
        ],
    },
    {
        "id": "ui.authenticated.confirm",
        "phase": "authenticated",
        "service": "confirm",
        "operations": ["confirm", "contextActions.execute handler argument: confirm"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Ask the person one plain Yes or No question before an action that changes or deletes something, with context.confirm(options). Answers a Promise of true or false. Needs UI 0.12.96; no Core change.",
        "details": [
            "Doc section: confirm(options).",
            "register(context).confirm(options) is bound to the calling module. It is refused after the module was abandoned by a failed or timed-out register().",
            "A context action handler receives the same helper as the confirm key of its argument. The shell's value wins over a confirm key the caller supplied. Every other key passes through untouched.",
            "Options: question (required, text of at most 300 characters), target (at most 200), count (a whole number of 1 or more; any other value is dropped), noun (at most 30, default endpoints), detail (at most 400), danger (only changes how the Yes button looks), yesLabel and noLabel (at most 24 each, default Yes and No).",
            "A missing or empty question rejects with a TypeError. There is no input field: do not ask the person to type a name, a hostname or a number.",
            "Text is shown as text. Control characters and zero-width characters are removed, and a text over its limit is cut.",
            "One dialog shows at a time and requests queue. A module's call shows 'Asked by <module id>', added by the shell.",
            "Display only. The dialog never authorises anything: permissions, scope, caps and audit rows stay as they are.",
        ],
    },
    {
        "id": "ui.authenticated.module-descriptor",
        "phase": "authenticated",
        "service": "modules.json",
        "operations": ["descriptor.dependencies"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Additive descriptor field dependencies in the UI's modules.json: the hard dependency ids of a module, so a popup can load them. Core writes no descriptor itself; this row documents the field only.",
        "details": [
            "Doc section: Popup mode.",
            "dependencies is a list of the hard dependency ids from the module's tec_tac.json, sorted. The UI's scripts/sync-modules.sh writes it.",
            "Older shells ignore the field. A descriptor without it loads the module alone.",
            "Optional dependencies (optional_dependencies) are never loaded in a popup. A module checks modules.isActive(id) and degrades without them.",
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
        "id": "ui.authenticated.tactical-operation",
        "phase": "authenticated",
        "service": "tacticalOperation",
        "operations": ["tacticalOperation"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Run one declared Tactical operation through Core's server-side executor (AD-19) with tacticalOperation(moduleId, operationId, options), instead of calling Tactical from the browser.",
        "details": [
            "Sends POST /api/tfd/tactical-operations/<moduleId>/<operationId>/ through apiRaw: the JSON {params, body}, or {params, body, query}, or multipart/form-data when a file is given. Needs Core 1.17.7 and UI 0.12.87. The query and file options need Core 1.17.13 and UI 0.12.91.",
            "Both ids must match ^[A-Za-z0-9][A-Za-z0-9_-]*$. params is a plain object of string or number values. body is a plain object.",
            "The options are params, body, query, file and signal. There is no auth option. It never accepts headers or an audit field, so there is no audit option either: Core writes the audit row where the call happens.",
            "query is optional: a flat plain object of at most 16 whitelisted names. Each value is a string or a whole number of at most 512 characters, with no control characters. Core accepts only the names the operation lists and answers query_field_not_allowed or invalid_query. Without a file, a call with query sends the JSON {params, body, query}; a call without query still sends exactly {params, body}.",
            "file is optional: a File, or a Blob with a non-empty name (at most 255 characters, no control characters). A Blob without a name, a string, an array or a second file is refused before any request. A file named params, body or query is refused in the browser, because those are the text parts. With a file the helper sends multipart/form-data with the text parts params, body and (only when given) query, each the JSON of a plain object, then exactly one file part. The file part is named after the file and carries the same filename, which is what an operation with the upload field {file_name} expects. The helper sets no Content-Type, so the browser writes the boundary.",
            "Size and type: Core checks the file against the operation's own cap and the upload ceiling. The ceiling is 10 MiB by default and a system setting since Core 1.17.14 (tactical_operation_upload_max_mib, 1 to 25 MiB). A web-server body limit still applies. Core answers upload_too_large, upload_type_not_allowed, upload_not_allowed or invalid_upload; these pass through as error.code. The helper covers only operations that declare the upload field {file_name}; an operation with a fixed field name is not covered yet.",
            "The result is {ok, status, data, blob, contentType, contentDisposition, filename, audit, auditRecorded}. audit reads the X-Tec-Tac-Audit response header.",
            "A failure keeps status, payload and code, plus a non-enumerable headers property. Core refusal codes such as tactical_permission_denied and object_not_found pass through unchanged.",
            "What Core checks: the operation is declared by the moduleId in the URL, the signed-in user holds the Tactical permission and the role scope, and the route is owned (AD-19, AD-20). Core cannot tell which module's browser code made the call.",
            "Scoping rule (the contract): a module passes its own id. The helper refuses another module's id unless that module is the AD-20 core module the caller replaces, and it refuses calls after a failed or timed-out register() abandoned the module.",
            "From UI 0.12.88 the shell binds tacticalOperation to the calling module. It refuses another module's id except the AD-20 module the caller replaces, which it reads from descriptor.replaces or from the module's module_status row (module_status[].replaces, needs Core 1.17.11). It refuses every call after a failed or timed-out register(), and it fails closed when the row carries no replaces, so a replacement can then pass only its own id.",
            "From UI 0.12.89 api, apiRaw, apiBlob and apiText refuse a tactical-operations path for an id other than the module's own id or the one it replaces. The replaced id is a snapshot taken before any register() runs. The guard is a helper-level guard, not a sandbox: a module that calls fetch itself is not stopped by it. Core's own checks stay the authority: the operation is declared by the module id in the URL, the user holds the Tactical permission and role scope, the route is owned, and the replacement is honoured. A path hidden behind tab, CR, LF or other control characters is a finding held for the UI.",
            "Public modules (registerPublic) do not get tacticalOperation.",
        ],
    },
    {
        "id": "ui.authenticated.tactical-permissions",
        "phase": "authenticated",
        "service": "hasTacticalPermission",
        "operations": ["hasTacticalPermission"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Ask whether the signed-in user holds one Tactical role flag with hasTacticalPermission(flag), to show or hide a control. Needs Core 1.17.7 and UI 0.12.87.",
        "details": [
            "Returns true only when context.context.tactical_permissions[flag] is exactly true.",
            "Returns false for an unknown flag, a flag that is not a string, an empty map, an older Core and a non-backend context.",
            "Display only. Tactical decides every call (AD-12).",
        ],
    },
    {
        "id": "ui.authenticated.tactical-scope",
        "phase": "authenticated",
        "service": "tacticalScope",
        "operations": ["tacticalScope"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-runtime-api.md",
        "purpose": "Ask which clients and sites the signed-in user's Tactical role covers with tacticalScope(), to say 'you see part of the estate' or to hide a control that needs full scope. Needs Core 1.17.17 and UI 0.12.93.",
        "details": [
            "Documented in the section tacticalScope() of tec-tac-ui/docs/module-runtime-api.md.",
            "Returns a fresh object each call: {mode, unrestricted, whole_client_count, site_count}. mode is unrestricted, clients, sites, mixed or none. unrestricted is true only when mode is unrestricted (a role with no client or site limits, a role superuser or a superuser).",
            "The counts are whole numbers. There are no id lists: Core keeps those.",
            "An older Core, a lookup that failed, a non-backend context and a value the UI does not recognise give {mode: 'none', unrestricted: false, whole_client_count: 0, site_count: 0}, so no null check is needed.",
            "Display only. Tactical and Core decide every call (AD-12). A control for an operation declared caller_scope 'unrestricted' (see the tactical-operations rows) should be hidden when unrestricted is false; Core refuses the call with 403 scope_unrestricted_required anyway.",
            "Public modules (registerPublic) do not get tacticalScope.",
        ],
    },
    {
        "id": "ui.authenticated.websocket",
        "phase": "authenticated",
        "service": "tacticalWebSocket",
        "operations": ["open", "session.start", "session.input", "session.resize", "session.kill", "session.close", "session.on"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-tactical-websocket.md",
        "purpose": "Open one Tactical terminal for the signed-in person with tacticalWebSocket.open(moduleId, kind, {agentId, signal}). The module never holds a Tactical token: Core issues a single-use ticket and the browser opens Core's socket with it. Needs Core 1.17.31 or later and UI 0.12.102 or later.",
        "details": [
            "Session members: start({shell, runAsUser}) sends the start frame (shell at most 260 characters, empty for Tactical's default shell); input(text) sends the data frame (at most 64 KB); resize(rows, cols) (whole numbers from 1 to 1000); kill(); close(). Calls before the session is open throw and send nothing. Tactical's own messages are unchanged (AD-25).",
            "Events, through session.on(event, fn): output (fields output, sessionId, exitCode, done, messageId; from trmmcli.output), error (message, code; from terminal_error, and unknown_action for a bare error frame), info (message, code; from terminal_info) and close (code, reason, message). Frames that are not JSON and frames with an unknown action are ignored. No frame is ever logged.",
            "Close codes: 4401 (reason signin-ended): 'Your terminal session ended. Open the terminal again.' 4003 (reason not-allowed): 'You are not allowed to use the terminal on this endpoint.' 4503 (reason unavailable): 'Tactical's terminal is not available right now. Try again later.' 1000 (reason normal): 'The terminal closed.' Any other code (reason unexpected): 'The terminal connection closed unexpectedly.' A close before the socket opens rejects open() with the same message, and the error carries closeCode.",
            "Ticket route: POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/ with the body exactly {agent_id}. The answer is 201 {ticket, path, session_id, expires_in, kind}, where path is exactly /ws/tfd/agent-terminal/<ticket>/. Refusals: 400 invalid_agent_id; 401 authenticated_request_required; 401 tactical_session_required; 403 websocket_owner_required; 403 tactical_permission_denied (the detail names can_use_terminal); 404 object_not_found; 404 websocket_kind_not_found; 429 throttle; 503 websocket_unavailable. Core writes one deny row for each 403 and scope refusal.",
            "A ticket lives 30 seconds and works once. A new one is asked for each terminal tab, and the helper never reuses or retries one. The ticket never appears in an error message, a console line or a stored value.",
            "Bound-module rule: moduleId must be the module's own id, or the core module it replaces under AD-20. Any other id is refused before any request. The api, apiRaw, apiBlob and apiText helpers also refuse a /api/tfd/tactical-websocket/ path for another id.",
            "Public modules (registerPublic) do not get tacticalWebSocket. A module whose register() failed or timed out cannot open a terminal.",
            "At most 8 terminals open or connecting per module; a ninth is refused. Terminals close when the module is cleaned up, when the Tactical session ends and when the page is left. There is no reconnect: a dropped terminal reports close, and a new terminal needs a new ticket.",
            "Display only: hide a Terminal tab with hasTacticalPermission('can_use_terminal'). Core and Tactical decide every call (AD-12).",
            "Core 1.17.34 (AD-35) adds the ticket kind server-terminal for the server web terminal: the body is exactly {}, only the module globalsettings may ask, and only an effective superuser may have it (403 superuser_required; 403 server_terminal_disabled where Tactical's switch is off or can_use_webterm is missing). Its path is /ws/tfd/server-terminal/<ticket>/. Its frames are Tactical's trmmcli.input {data:{input}}, trmmcli.resize {data:{rows, cols}} and trmmcli.disconnect, and it answers trmmcli.output; there is no start frame, the shell starts when the socket is accepted. Close 4502 (audit unavailable, no shell) and 4003 are terminal refusals. UI 0.12.105 or later opens this kind: open('globalsettings', 'server-terminal', {signal}), which refuses agentId before any request, and the ticket path must be exactly /ws/tfd/server-terminal/<ticket>/. session.start() throws and sends nothing. input sends trmmcli.input {data:{input}}, resize sends trmmcli.resize {data:{rows, cols}} and kill sends trmmcli.disconnect. Tactical's answer trmmcli.output {data:{output, messageId}} reaches the output event. Close 4502 (reason audit-unavailable) and 4003 are terminal refusals with no reconnect. The ticket refusals 403 superuser_required and 403 server_terminal_disabled keep error.status and error.code. Only the module's own id may open it: no AD-20 replacement. Needs Core 1.17.34 or later and UI 0.12.105 or later.",
            "Terminal input and resize frames count as session activity (Core 1.17.34, AD-35), so a terminal in use keeps its sign-in alive. Output alone does not. An idle socket, the absolute maximum, a disabled user, a revoked session or a deleted token close 4401. Nothing changes for the helper: the existing close codes and messages apply.",
        ],
    },
    {
        "id": "ui.authenticated.terminal",
        "phase": "authenticated",
        "service": "terminal",
        "operations": [
            "create", "write", "writeln", "clear", "reset", "focus", "blur", "fit", "size", "getText", "getSelection", "hasSelection",
            "copy", "paste", "setTheme", "setOptions", "onInput", "onResize", "dispose",
        ],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-terminal.md",
        "purpose": "Draw a real terminal in the module's own window with context.terminal.create(host, options). The widget is xterm.js, needs no Core API and pairs with ui.authenticated.websocket for a Tactical terminal. Needs UI 0.12.104 or later.",
        "details": [
            "create(host, options) resolves with a handle and rejects with a plain message when it cannot open. The terminal fills the host element you own and keeps it fitted as the window changes. The handle has write, writeln, clear, reset, focus, blur, fit, size, getText, getSelection, hasSelection, copy, paste, setTheme, setOptions, onInput, onResize and dispose.",
            "Options: theme (colour names; each value a # colour of 3, 4, 6 or 8 digits, or an rgb(), rgba(), hsl() or hsla() colour, and any other value is dropped), fontFamily (up to 300 characters, no control characters, none of ; { } < >, no url(), checked), fontSize (whole number 8 to 32, default 14), cursorBlink (default true), scrollback (whole number 0 to 50000, default 50000; a larger value is clamped), convertEol (default true), focus (takes keyboard focus on open, default true), rows and cols (whole numbers 1 to 1000, default 24 and 80, the size until the first fit), ariaLabel (up to 200 characters, control characters removed), onInput(data) and onResize({rows, cols}).",
            "Limits: scrollback 50000 lines at most; 8 live terminals per module, and a ninth create() is refused with a plain message; resize 1 to 1000 rows and 1 to 1000 columns.",
            "Handle rules: write and writeln take text only, drawn as text and never as HTML; any other value throws a plain error. An OSC 8 link from the remote end is shown as text and clicking it does nothing. There is no clipboard addon and no web-links addon, so the remote end cannot read or write the clipboard. Window title changes and window-size requests from the remote end are ignored.",
            "setTheme and setOptions follow the same colour and fontFamily checks; a font change fits the terminal again. copy({selectionOnly}) and paste(text) use the shell's clipboard helper; copy rejects with a plain message where the browser gives no clipboard.",
            "Registered by register(context) only: no registerPublic access, because the public pages are signed out. The scope is bound to the calling module, so no module id is passed and a module cannot open a terminal for another module. The widget needs no Core API.",
            "Pairing with ui.authenticated.websocket: session output is written with write(), and onInput and onResize go to session.input and session.resize. The server terminal (server-terminal, UI 0.12.105) is paired the same way, with no start step.",
        ],
    },
    {
        "id": "ui.authenticated.modulePreferences",
        "phase": "authenticated",
        "service": "modulePreferences",
        "operations": ["get", "getAll", "set", "remove", "flush"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-preferences.md",
        "purpose": "Keep small per-person display choices with context.modulePreferences: get(name, fallback), getAll(), set(name, value), remove(name) and flush(), all async. Core keeps each choice for the one person and one module, so it follows the person to another browser. Needs Core 1.17.35 or later and UI 0.12.106 or later for get, getAll, set and remove; the debounce, flush() and the two refusals below need UI 0.12.108 and Core 1.17.38; the per-caller results of a merged set() and remove() need UI 0.12.109 or later (the earlier helper gave a result of the wrong type).",
        "details": [
            "get(name, fallback) returns the stored value, or fallback when the person has none. getAll() returns a new object of { name: value } for this module. set(name, value) stores one value and returns what Core stored. remove(name) deletes one preference and returns true when Core removed a row. Every call reads from Core: nothing is cached, and nothing is kept in browser storage (no localStorage, sessionStorage or cache).",
            "Debounce (UI 0.12.108): set() and remove() on the same name within 400 ms become one request, which carries the last operation (the last value, or a remove if remove came last). The window restarts with each call, but a write is never held more than 2 seconds from its first call. Each merged call resolves a value of its own type, and the last operation in the window decides it: when the last operation is a set(), every set() resolves the value Core stored and every remove() resolves false (the later set replaced it, so it removed nothing); when the last operation is a remove(), every remove() resolves true or false as Core answered and every set() resolves undefined (it stored nothing). So a merged set() that a later remove() superseded resolves undefined, and a merged remove() that a later set() superseded resolves false. Every merged caller gets the same rejection. Different names are independent. get() and getAll() see a write that has not finished yet, and a waiting remove reads as absent. Validation runs when the call is made, so a refused name or value sends nothing.",
            "flush() (UI 0.12.108): sends every write that is still waiting now, at once, and resolves when they are all done. It does not reject when a write failed: that failure goes to the caller of that write. It is for a module that is leaving its page and wants its last choice saved first.",
            "Own id only: the module id is bound to the loader's descriptor id, so no module id is passed and a module cannot read or change another module's preferences. There is no AD-20 replaced-module exception: a replacement module keeps its own preferences and cannot reach the module it replaces. The api, apiRaw, apiBlob and apiText helpers also refuse a raw path to /api/tfd/module-preferences/ for any other id (the path is decoded first). registerPublic does not get modulePreferences, because a public page has no signed-in person.",
            "Limits, checked in the browser before any request and again by Core: name 1 to 64 characters matching [a-z0-9][a-z0-9._-]{0,63}; value plain JSON (null, booleans, finite numbers, strings, arrays and plain objects), at most 4 KiB when stored and at most 5 levels deep; at most 50 names per module for one person. A bad name gives invalid_name and a bad value gives invalid_value (both status 400, no request).",
            "Refusals from Core: preference_limit (status 400, a 51st name), module_not_found (status 404), and since Core 1.17.38 module_not_allowed (status 403, the person may not use the module) and audit_failed (status 503, the change was not saved and the old value stays; a later get() returns it). From UI 0.12.108 the 403 error carries hideControl: true, so the module hides the control that uses the helper (AD-12). A 401 is treated as signed out (signed_out) and the helper stays silent. Too many writes give 429.",
            "Core 1.17.35 or later and UI 0.12.106 or later. The Python functions of core.module_preferences are a separate contract (Core 1.17.37 adds the verified caller; Core 1.17.38 adds the audit row and the two refusals above).",
        ],
    },
    {
        "id": "ui.authenticated.components",
        "phase": "authenticated",
        "service": "components",
        "operations": ["SearchSelect", "TagEditor", "DataTable", "FormRow", "EditorWindow", "Stepper", "FilterEditor"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-components.md",
        "purpose": "Shared components for a module's own screens, from context.components in register(context): SearchSelect picks one item from a searchable list, TagEditor edits a list of text values, and since UI 0.12.114 DataTable, FormRow, EditorWindow and Stepper draw the board's table, settings row, editor window and step list. Draw them with context.Vue.h(SearchSelect, props) and context.Vue.h(TagEditor, props); the kit components draw the same way. The value stays with the module: each component emits update:modelValue and keeps no value of its own. Needs UI 0.12.111 and Core 1.17.41 or later. Since UI 0.12.116 FilterEditor, the shared filter editor, bound per module.",
        "details": [
            "SearchSelect props: modelValue (the chosen option's value, null for none), options (each { value, label, description, favourite, chip, chipTone, disabled, searchText }), placeholder, inputId, ariaLabel, disabled (default false), clearable (default false), emptyText (default 'No matches. Check the spelling.'), favouriteLabel (default 'Favourites') and allLabel (default 'All'). Events: update:modelValue (the chosen value, or null after clear) and select (the chosen option object, or null after clear), both at the same moment. Server mode props (UI 0.12.112, all off by default): serverSearch, loading, hasMore and selectedLabel (text shown for a chosen value that is not in the loaded rows). Server mode events (UI 0.12.112): search (the typed text, empty when the list opens; server mode only; the module debounces) and more (no payload; server mode only; fires once when the highlight reaches the last row or the list is scrolled to its end while hasMore is true, and not again until options changes or loading returns to false).",
            "SearchSelect server mode (UI 0.12.112): the component skips its own filter and the 300 row cap, shows at most 1000 loaded rows and then the line 'Showing the first 1000 loaded. Keep typing to narrow it.' loading shows one 'Loading...' line, sets aria-busy and hides 'No matches'. Typing never changes modelValue. A static list keeps the local filter and the 300 cap. The new props and events need UI 0.12.112; a picker that does not use them behaves as before.",
            "SearchSelect shows at most 300 rows and then the line 'Showing the first 300. Keep typing to narrow it.' The search matches label, description and searchText, ignoring case. Favourites are grouped first. It has the combobox and listbox roles, with aria-expanded, aria-controls, aria-activedescendant and role option on each row. Keys: ArrowDown and ArrowUp move, Enter chooses, Escape closes the list only, Tab closes and moves on. Disabled rows are skipped and cannot be chosen.",
            "TagEditor props: modelValue (an array of strings, default []), placeholder, ariaLabel, disabled (default false), readonly (default false), maxItems (default 200), maxLength (default 500 characters), commaAdds (default true; a comma adds the typed value), validate(value) (returns '' for a good value or a plain sentence for a bad one). Events: update:modelValue (the new array) and reject ({value, reason}, the plain sentence shown to the person).",
            "TagEditor trims values, ignores empties and duplicates without a message, and strips control characters. A value over maxLength, past maxItems or refused by validate is rejected: the sentence shows under the box, reject fires and the typed text stays in the box. Every label, description and value is shown as text, never as HTML.",
            "Registered by register(context) only: registerPublic gets no components, because a public page has no signed-in person. The components object is frozen. Needs UI 0.12.111 and Core 1.17.41 or later. Documentation only: no endpoint, capability or version moves.",
            "SearchSelect accessibility props (UI 0.12.114, all off by default): required (sets aria-required on the combobox input), invalid (sets aria-invalid and shows the invalid border) and describedBy (sets aria-describedby to one id, or to several ids separated by spaces).",
            "Component kit (UI 0.12.114): DataTable, FormRow, EditorWindow and Stepper join SearchSelect and TagEditor on context.components. Each draws with context.Vue.h(Component, props), keeps no value of its own and shows every label, title and cell as text. They carry the tt-ws work-surface scope, so a module adds nothing for the board's density. No component confirms or discards anything: a module asks one plain Yes or No through context.confirm.",
            "DataTable props: columns ([{ key, label, sortable, align, width }], align left, right or center, at most 40 columns), rows (at most 2000 are drawn), rowKey, selectedKey, sortKey, sortDir (ascending or descending), loading, emptyTitle, emptyText, footer, ariaLabel and cell(row, column). Events: sort (key, dir: ascending, then descending, then null), select (row), rowmenu (row, event) and activate (row).",
            "FormRow props: label, hint, help, error and forId. EditorWindow props: title, dirty, canSave, saving and status. Events: save, discard and close. Stepper props: steps ([{ key, label, state }], state done or error, at most 12 steps), current and ariaLabel. Event: select (key). Needs UI 0.12.114. A module that does not use them behaves as before.",
            "Kit details (UI 0.12.114, added to this row in Core 1.17.51). EditorWindow areas: actions (slot) draws the header buttons, left of the close button; properties (slot) is the left column, left out for a single content area; content (slot, or the default slot) is the main area; footer (slot) holds the footer buttons, left of Discard and Save. FormRow: the control goes in the default slot; the help line has the id forId + '-hint' and the error line the id forId + '-error', so give the control aria-describedby with those two ids. DataTable: a column width is a number with px or %; past 2000 rows the footer says 'Showing the first 2000 rows.'; a cell(row, column) that throws shows an empty cell; keys: Tab reaches the selected row (or the first), ArrowUp and ArrowDown move between rows, Home and End jump to the ends, Enter or Space on a sortable header sorts, Space on a row selects it and Enter activates it. Documentation only: no endpoint, capability or version moves.",
            "UI 0.12.118 props (added to this row in Core 1.17.66; documentation only, all off by default): EditorWindow floating (draws the window fixed over the page as a dialog on layer 1050; it takes the focus when it opens and gives it back to the opener when it closes) and readOnly (hides Save and Discard changes, for a viewer such as a log window; Close and Escape stay), FormRow stacked (puts the label above the control at any width), and TagEditor inputId and describedBy (the id and the aria-describedby of the real text input). Layer order (UI 0.12.118, docs/module-dialogs.md): a floating window sits at 1050, above the resource menu (1000), below module dialogs and the SearchSelect list (1100), the row menu (1150), toasts (1200), the unsaved-changes prompt (1300) and the shell Yes or No confirm (1400). A module that does not pass these props behaves as before.",
            "FilterEditor (UI 0.12.116, added to this row in Core 1.17.53): the shared filter editor, a seventh member of context.components. The first six members are unchanged and keep their places. Props: viewKey (required; a lower-case slug matching ^[a-z0-9][a-z0-9_-]{0,60}$, saved sets are kept per module and view key), modelValue (the current definition { version: 1, match: 'all' or 'any', rules }, or null for no filter) and disabled. Events: update:modelValue (the definition, or null when there are no rules) and apply with the payload { definition, filterSetId }: exactly one of the two is set, and both null means no filter. A module never sends an empty definition, because a filter with no rules matches nothing in Core; null means do not filter.",
            "FilterEditor binding and reads (UI 0.12.116): there is no module id prop. The loader binds each module's own copy to that module's own id, and there is no AD-20 replacement exception: a replacement module registers its own filter fields and gets its own filters. This is not a sandbox: Core, not the editor, decides what a person may read for any module id. The editor reads only GET /api/tfd/filter-sets/fields/, GET /api/tfd/filter-values/ and /api/tfd/filter-sets/ (POST, PUT and DELETE for Only me sets), always with the module's own id, and builds every operator and value picker from Core's answer. registerPublic gets no components. Needs UI 0.12.116 and Core 1.17.50 (core.filter_sets 1.0.0). The guide is tec-tac-ui/docs/module-filters.md; docs above stays the one path tec-tac-ui/docs/module-components.md.",
            "FilterEditor date and number controls (UI 0.12.117): needs UI 0.12.117 and Core 1.17.52 (core.filter_sets 1.1.0). A module declares a date or number field only once UI 0.12.117 is installed. The operators and constraints (integer, minimum, maximum) and relative_units come from the fields answer and are never assumed. A date operator on a single day uses a date box and sends strict YYYY-MM-DD (1970-01-01 to 2100-12-31). A date between sends { from, to }. in_the_last and not_in_the_last send { amount, unit }, with amount a whole number up to the unit's max_amount. A number operator uses a number box and sends a JSON number: no exponent, NaN or infinity, nothing over 10**15, no decimal on an integer field and nothing outside minimum and maximum. A number between sends { from, to } with from <= to. Days are UTC days. A row with no value never matches a positive operator. Documentation only: no endpoint, capability or version moves.",
        ],
    },
    {
        "id": "ui.authenticated.dialogs",
        "phase": "authenticated",
        "service": "dialogs",
        "operations": ["register", "open"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-dialogs.md",
        "purpose": "Open a short task above the page, such as a wizard, an input form or a result, with context.dialogs. register(descriptor) names a dialog and open(id or descriptor) shows it. The shell draws the box and the rules around it; the module draws what goes inside. Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        "details": [
            "register(descriptor) names a dialog and open(id or descriptor) opens a registered one, or one given in the call. open returns a Promise that resolves when the dialog closes.",
            "Descriptor fields: id (required, module-local: letters, digits, _ and -, at most 64 characters, no dot; the full id is <module id>.<id>), title (plain text, at most 200 characters), size ('default' is 520px, 'wide' is 760px), mount(element, {close}) (required; may be async; may return a cleanup function or {unmount}; close() closes at once and does not ask beforeClose) and beforeClose() (optional; false or a rejected Promise keeps the dialog open).",
            "One dialog at a time: a second open is refused with a rejected Error that has status 0 and no code.",
            "Layers: the dialog is at 1100, toasts at 1200, the unsaved-changes prompt at 1300 and the Yes or No confirm at 1400.",
            "Refused in a popup window, while signed out, outside a backend-supplied context, after register() failed or timed out, after the module was unloaded, and for an id the module did not register or that names another module. The shell binds every call to the module's own id.",
            "Mount limit: mount must finish within context.module_register_timeout_seconds, or the dialog shows a plain line with a Close button.",
            "registerPublic gets no dialogs, because a public page has no signed-in person. The shell never runs HTML from a title; the backend still decides every action (AD-12).",
            "Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        ],
    },
    {
        "id": "ui.authenticated.signInLanding",
        "phase": "authenticated",
        "service": "signInLanding",
        "operations": ["register"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-sign-in-landing.md",
        "purpose": "Ask the shell to send a person somewhere after sign-in, such as a first-run setup page, with context.signInLanding.register({id, permission, check}). The module decides whether its page is still needed; the shell only asks, and only at the one moment it is allowed to. Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        "details": [
            "register({id, permission, check}): id is a module-local name (letters, digits, _ and -, at most 64 characters), permission is an optional permission code (the check is called only for a person who has it) and check is required. One registration per module: a second register replaces the first.",
            "check({reason: 'landing', signal, context}) returns nothing, a route path, or {dialog: '<module id>.<dialog id>'}. signal aborts when the person signs out or the session ends. context is the person's shell context.",
            "Shell rules: the check runs on the default landing only (the page opened on / or /dashboards, or with no address). It never runs in a popup window, on a public page, on /sso/callback, or while signed out. Unsaved changes win: the landing is dropped and not retried.",
            "A failure is ignored with one warning: a check that throws, rejects, returns a value the shell cannot use, or does not answer within context.module_register_timeout_seconds is ignored, and the next check still runs.",
            "A route result must be one plain path of the module's own page or one of Core's named pages, and never under /popup/, /public/ or /sso/. A dialog result must start with the module's id and be a dialog the module registered.",
            "One landing per page load: the checks run once, in module load order, and the first check that returns something acts. Disabled, failed or unloaded modules are never called.",
            "registerPublic gets no signInLanding.",
            "Two points are open questions for Johan and are stated here only as built in UI 0.12.112, not as a Core promise: a reload on /dashboards runs the checks again (Q66), and a route may point only at the module's own pages and Core's named pages (Q67).",
            "Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        ],
    },
    {
        "id": "ui.authenticated.rowMenu",
        "phase": "authenticated",
        "service": "rowMenu",
        "operations": ["open", "shouldHandle"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-row-menu.md",
        "purpose": "Show a right-click menu on a module table row without drawing one, with context.rowMenu. The shell places the menu, handles the keys and closes it; the module says what is in it and what each item does. Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        "details": [
            "open({event, element, label, items}) returns true when the menu is shown. event is the contextmenu or keydown event (a key gives no pointer position, so the menu opens under element). element is the row that gets focus back on close. label is the optional accessible name (plain text, at most 80 characters, default 'Actions').",
            "shouldHandle(event) returns false for a right-click on a text field (an input, a textarea, a select or an editable element), which the browser keeps, and true otherwise.",
            "Item fields: id (required; letters, digits and _ - . :, at most 64 characters, unique in the menu), label (required, 80 characters), hint (120), danger, disabled, reason (120, default 'Unavailable for this selection.') and run (required unless disabled).",
            "1 to 40 items; more is a TypeError. A menu with no items, an item without an id or a label, a repeated id, and an enabled item without run are also a TypeError. Labels, hints, reasons and the menu label are plain text only.",
            "Layer 1150: above module dialogs (1100), below toasts (1200), the unsaved-changes prompt (1300) and the Yes or No confirm (1400). One menu at a time: a second open replaces the first.",
            "An error in run() is caught and logged as one warning that names the module. The menu is refused in a popup window, while signed out and outside a signed-in session. After the module is unloaded or fails, open is refused and no item runs.",
            "An action the person may not do is left out of items (AD-12); an action that is allowed but not possible now is disabled with its reason. registerPublic gets no rowMenu.",
            "Needs UI 0.12.112. Documentation only: no endpoint, capability or version moves.",
        ],
    },
    {
        "id": "ui.authenticated.services",
        "phase": "authenticated",
        "service": "services",
        "operations": ["provide", "has", "call", "list"],
        "audience": "provider/consumer browser",
        "docs": "tec-tac-ui/docs/module-services.md",
        "purpose": "Publish a named browser operation with services.provide(name, handler, options) so other modules can call it through services.call(name, args). Services arrived in UI 0.12.101; the one-permission rule needs UI 0.12.102.",
        "details": [
            "provide(name, handler, {label, permission, permissions, tacticalPermission}) returns a remover that removes that service only. The name begins with the provider's module id and a dot, uses letters, digits, '.', '_' and '-', and is at most 120 characters. Another module cannot take a name that is already provided; the same module providing it again replaces it.",
            "Permissions: the provider module's own permissions always apply. permission or permissions can only narrow a service, never widen it. tacticalPermission (one Tactical flag or a list) must be strictly true for each flag. The handler receives (args, {caller}). The shell binds caller to the calling module, so no value in args can change it. caller is a hint for the provider and never authorization.",
            "A service needs at least one permission (UI 0.12.102): the module's permissions, permission or permissions, or tacticalPermission, taken together. A provide with none throws 'Service <name> needs at least one permission: declare one for the module or for this service.' and registers nothing.",
            "Outside a backend-supplied context every service is hidden and a call is refused (AD-12): has() is false, list() is empty and call() refuses with service_denied. A service the person may not use is hidden the same way and does not appear in list().",
            "Calls: has(name) is true only when the provider is loaded and the person passes the checks. call(name, args) checks again at call time and awaits the handler. list() returns {name, label, provider} for each service the person may see. Refusal codes: service_unavailable (no such service) and service_denied (the person may not use it). An error thrown by the handler reaches the caller as 'Service <name> from <provider> failed: <message>'.",
            "Everything a module provides is removed when its register() fails, times out or is abandoned, and an abandoned module cannot provide or call a service. A module switched off while the page is open stops answering at once (UI 0.12.102).",
        ],
    },
    {
        "id": "ui.authenticated.jobs",
        "phase": "authenticated",
        "service": "jobs",
        "operations": ["follow"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/module-job-follow.md",
        "purpose": "Follow a background job through a read route after the person leaves the page.",
        "details": [
            "follow(descriptor) returns {id, cancel()}. The shell polls the read route itself, so the follow keeps running after the person leaves the module's page. The service only reads; the backend decides everything (AD-12). Needs UI 0.12.103.",
            "Descriptor keys: id (a module-local key; a second follow with the same id replaces the first), title, path (a GET read route, called through the module's own guarded api), check(payload) (returns 'success', 'error' or a false value while the job is still running), successMessage, errorMessage and timeoutMessage (each text, or a function of the payload), intervalMs (default 5000, clamped to 2000 to 60000) and timeLimitMs (required, clamped to 10000 to 1800000).",
            "A follow stops at the first finish with one success or error notice, and at the time limit with one timeout notice. cancel(), an unloaded or abandoned module, the end of the session and pagehide stop it silently. A read that fails with status 401 stops it silently. Three failed reads in a row (any other status, or a check that throws) stop it with one error notice.",
            "Notices use dedupeKey job-follow:<id>.",
            "Limits: 10 live follows per module and 50 in all. A further follow throws a plain error.",
            "Refusals: a follow is refused outside a context Core supplied (the same rule as services), while signed out, and for an abandoned or unloaded module. The module id is bound by the shell; an argument cannot name another module.",
            "The read goes through the module's guarded api, so the rule that keeps a module off another module's tactical-operations routes still applies.",
        ],
    },
    {
        "id": "ui.authenticated.styleTokens",
        "phase": "authenticated",
        "service": "styleTokens",
        "operations": ["--text-body", "--text-ws", "--text-sm", "--text-xs", "--cell-y", "--cell-x", "--ctl-y", "--ctl-x", "--radius-control", "--radius-panel", "--label-track-ws", "tt-ws"],
        "audience": "module/browser",
        "docs": "tec-tac-ui/docs/ui-design-standards.md",
        "purpose": "CSS a module's own screens may read since UI 0.12.114: the size, density and radius tokens on :root and the opt-in work-surface scope class tt-ws. They are additive; the older tokens keep their values. Documentation only: no endpoint, capability or version moves.",
        "details": [
            "Tokens on :root: --text-body (Core page text, 15.5px scaled), --text-ws (work-surface text, 12.1px scaled), --text-sm (help lines and small labels, 11px scaled), --text-xs (status lines and footers, 10.5px scaled), --cell-y and --cell-x (table cell padding, 7px and 8px), --ctl-y and --ctl-x (input, select and textarea padding, 6px and 8px), --radius-control (buttons and inputs, 2px), --radius-panel (panels, windows and toasts, 3px) and --label-track-ws (label and header tracking on work surfaces, .08em).",
            "Scaled means calc(Npx * var(--font-scale)), so the person's text-size setting moves it. A module writes every font size through --font-scale or one of these tokens, never a raw px value.",
            "The opt-in scope class tt-ws: inside an element with that class, text, table cells, field labels, inputs, selects, textareas and buttons use the work-surface sizes and padding. Outside tt-ws nothing changes. The module dialog host panel and the four kit components carry tt-ws already.",
            "The older tokens --label, --label-track and --font-scale keep their values. A module does not redefine the tokens or the kit's class names.",
            "Needs UI 0.12.114. registerPublic gets no components. Documentation only: no endpoint, capability or version moves.",
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
    "System actions (core.system_actions 1.2.0 since Core 1.17.68, 1.1.0 since Core 1.17.66; first shipped in Core 1.17.61, AD-13): a module that needs Core to run typed Tactical work unattended for a named owner (a scheduled patch scan) lists the action ids in its manifest key `system_actions` (a JSON list of '<module id>.<name>', at most 20, extensions only) and registers each with tec_tac.system_actions.register_system_action from AppConfig.ready(). A manifest with the key needs requires.framework >=1.17.61: an older Core refuses an unknown manifest key. The function table is Core's: winupdate.scan and winupdate.install, Windows Patching's (patching, or the premium module that honourably replaces it; since 1.17.66 install is allowed for the replacement too, with a fixed plain warning, CQ173), and since 1.17.66 scripts.run, Script Execution's. A run of more than 2000 endpoints is split into groups of at most 2000 (CQ178), up to 20 groups. Since 1.17.66 a person who creates or edits a schedule for a system action passes the permission and scope checks and one plain Yes or No at that moment (POST /api/tfd/scheduler/system-actions/confirmation/); a scheduled run is not re-checked against its creator. There is no global off switch: disable the owning module or its schedule to stop a run. Since 1.17.68 (Johan, 21 October 2026): a schedule keeps the scope its person had when they created or last edited it, an unattended run reads that stored scope and not the person's live row (VerifiedSchedulerRun.held_at_creation and resolved_endpoints), and the next person who edits the schedule or profile through reconcile_schedule(confirmed_by_request=...) becomes its owner if their own scope covers every target; a module-owned target type reads as endpoints through the resolver its module registered (register_target_resolver); a module may start another module's scheduled install through a delegation grant a person confirmed once (describe_delegation, register_delegation_grant, issue_delegation_ticket, start_delegated_run), with run_system_action unchanged; and while an honoured replacement of Windows Patching is installed Tactical's own patch policy is switched off (core.patch_lockdown). Since 1.17.70 (CQ203, AD-45, framework >=1.17.70; core.system_actions is 1.3.0 from this release): the table has a second kind of row, a write, for the premium module that is the honoured replacement of Windows Patching. Its first and only row is winupdate.set_action (the approve, ignore or do-nothing decision of one Windows update). The module registers it with dangerous=True and no delegable_to, its manifest lists the action, and it calls run_system_write(context, action_id=, changes=[{update_id, action}]) from its own Scheduler handler; Core reads the endpoint of every update itself, judges that set like agent_ids, writes one strict audit row with the earlier and the new decision of every update BEFORE it writes, never overwrites a decision a person changed in the meantime, and writes at most once. Windows Patching does not register it. Tactical keeps the decisions if the module is later removed, and Tactical's own audit log does not show Core's write: Core's audit rows are the record. Since 1.17.74 (framework >=1.17.74; core.system_actions is 1.4.0 from this release): resolve_delegated_targets(ticket, *, action_id, endpoint_ids) tells the provider which endpoints a ticket covers. Core publishes no 'endpoint is back' event: polling Agents' get_reboot_status is the supported way to resume after a reboot (docs/system-actions.md, 'Durable runs with a reboot').",
    "A permissionless extension that needs a browser audit trail declares audit_events in tec_tac.json: [{\"object_type\": \"agent\", \"actions\": [\"view\", \"run\"]}]. object_type is a lowercase slug; each action is a standard Tec-Tac audit action or custom:<slug>. For client, site and agent Core checks the signed-in user's scope; other types have no scope check. Core sets the actor and marks the row browser_provenance. A module that declares audit_events must require framework >=1.16.0, and >=1.17.0 when it declares an object type other than client, site or agent.",
    "The UI, not modules, applies the module register() time limit. A module does not read or enforce module_register_timeout_seconds, and its register() must not assume more than the configured time. Core only stores and publishes the value (GET /api/tfd/ui/context/).",
    "Saved views belong to the Core saved views service (tec_tac.saved_views, /api/tfd/saved-views/). Modules must not keep saved views in browser storage, cookies or their own tables. A payload holds filters and layout only, never data, secrets or tokens. A module that uses the service must require framework >=1.17.0.",
    "Module categories (AD-21, since 1.17.13): the manifest key category accepts core, server, premium and test. A manifest with no category is treated as test, and Core refuses to install a test module on a server that is not a development server (root config TEC_TAC_ENVIRONMENT); the refusal is install-only since 1.17.14, so a module that is already installed keeps loading and can be enabled. Module status, the runtime context and the modules/v2 catalogue carry category, effective_category, category_missing, category_refused and category_warning (docs/module-categories.md). A manifest that writes premium or test must require framework >=1.17.13, because an older Core rejects the value. The Tactical operations executor and the AD-20 replacement checks use the effective category: a replacement must be premium (or have no category on a development server, reason code replacement-category), and a test module may not declare replaces.",
    "A module that is neither a core nor a server module may replace one core or server module (AD-20, since 1.17.9; server modules since 1.17.11) by declaring replaces=<module id> and capabilities={id: X.Y.Z} in tec_tac.json; the replaced module declares capabilities too (an empty {} is allowed). Core honours the replacement only while the replacement is enabled, the replaced module is installed and disabled, no other enabled module replaces it, and the replacement declares every capability of the replaced module at the same major version with a minor.patch that is not lower. While honoured the replacement owns the replaced core module's Tactical routes (and no others; a server module has none) and may register its capability names, and it satisfies a hard dependency on the replaced module id (1.17.11). Enabling or installing the replacement names the module it will disable (will_disable) and disables it in the same job once the exact list is confirmed (disable_replaced); the root job helper re-checks the rules. If state shows both enabled, Core does not load the replacement, reports it as not enabled, queues a job that disables it and keeps the replaced module; it never stops Tactical at start-up. Since 1.17.12 handing back is one action either way: disabling the replacement switches the replaced module back on in the same job (when it can be enabled), and enabling the replaced module switches its enabled replacement off in the same job, after two confirmations (disable_replaced, then confirm_replacement_switch: true). A module that uses these keys must require framework >=1.17.9 (>=1.17.11 for category server or for any of the 1.17.11 behaviour). Other modules keep calling capabilities by name.",
    "Module switch fields (AD-20, the HTTP fields the Modules page uses, listed here because this export carries rules and browser rows, not the HTTP field tables; the route entries for /api/tfd/modules/v2/ and /api/tfd/modules/v2/<id>/state/ carry the full tables). On GET /api/tfd/modules/v2/ each module row has will_disable (the modules that enabling it switches off), will_enable (the replaced modules that disabling it hands back, only those that can come back), second_confirmation_required (enabling a replaced module whose replacement is enabled), and, since 1.17.14, replacement_dependants ([{replacement, modules[]}]: the enabled modules that name that replacement directly), hand_back_unavailable ([{module, reasons[], required_modules[]}]: the replaced modules that cannot come back, with the modules they need) and hand_back_confirmation_required (boolean). The request to POST /api/tfd/modules/v2/<id>/state/ may carry disable_replaced (the list the operator was shown), confirm_replacement_switch (the second confirmation, exactly true) and, since 1.17.14, confirm_without_hand_back (exactly true, to disable a replacement whose replaced module cannot come back). The refusal codes are replacement_confirmation_required, replacement_second_confirmation_required (since 1.17.14 it also carries dependants) and, since 1.17.14, replacement_hand_back_confirmation_required (it carries module, will_enable and hand_back_unavailable); each answer carries detail in plain English and queues nothing. A module job carries disabled_modules, enabled_modules and reconciled_modules (what the root helper switched) and, since 1.17.14, hand_back_skipped (the replaced modules a confirmed disable left off). The problem type replacement_has_dependants and the hand_back_blocked refusal were removed in 1.17.14: where 1.17.12 said a disable or an enable was refused for those reasons, it now warns, asks for the confirmation, and continues once it is given. Old callers that send no new flag see the refusal and nothing changes.",
    "Notices Core creates itself (1.17.14, Johan CQ36 and CQ41): when a module job fails (enable, disable, install, bundle install or batch install) the scheduler tick stores one notice per recipient, readable through GET /api/tfd/ui/notices/ like any other: source core, level error, client_id module-job-failed:<job id>, action route /modules. Recipients are every active superuser and the user who started the job. A failed switch says whether the flags were put back. The text is plain English and holds no paths. The browser toast for a new server-created notice is a UI change; until then the notice shows in the notice history.",
    "A core or server module that declares `capabilities` in tec_tac.json must register exactly the capability ids it declares, and a replacement must register at the declared major version with a minor.patch that is not lower (since 1.17.10; server modules since 1.17.11). Core does not register anything else: it logs one warning, registers nothing, drops an earlier registration of the same id by the same module (1.17.11) and never raises out of AppConfig.ready(). A module with no `capabilities` key is unchanged.",
    "A Tactical call that must be audited (reboot, Wake-on-LAN, report changes, code signing) is declared once by the owning core module with tec_tac.tactical_operations.register_tactical_operation and run through core.tactical_operations (POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ or the capability's run). Core writes the audit row where the call happens, so the browser cannot misreport it. The browser-declared audit_events path is deprecated since 1.17.7 for declared events (see docs/module-audit.md for the replacement of each event).",
    "Manifest keys added in 1.17.16: routes {prefix, urlconf} lets Core serve the module's urlconf at /api/tfd/<prefix>/ instead of the module appending to tacticalrmm.urls or tec_tac.urls (see tec_tac.route_mounting.mounted_routes; the old append keeps working); description is a plain text of 1 to 500 characters with no control characters, shown on the module catalogue and runtime rows as description (null when absent). Neither is required. A module that uses routes requires framework >=1.17.16.",
    "Manifest key added in 1.17.17: server_maintenance_actions (extensions only, at most 16 entries) lets a signed module register its own Core server-maintenance actions when it is installed, with no manual root script. Each entry is {id, description, permission, executable, argv, parameters, timeout_seconds, success_exit_codes, revision} and may add protected: true. id must begin with <module_id>.; permission is required and must be one the same module declares in permission_groups; executable is a file below the module's server_maintenance/actions/ folder (relative, no .., no symlink); argv entries are literal strings or {param: name} and parameters are typed (string, integer, boolean or enum), so there is no shell text; the module must also declare publisher_permissions server_maintenance.register, which the publisher that signs the package must hold (AD-10). Core's root job helpers call the root server-maintenance helper after the module files are installed and the runtime is synced: it re-checks the root-owned installed manifest, copies each executable into the Core action root as a root-owned 0755 file (an action never runs from the module folder), records its SHA-256 (dispatch and run check it again, so a changed executable stops the action), and removes the module's actions that a newer manifest no longer declares. Uninstalling the module removes its actions and executables; disabling does not, but start() refuses a permissioned action whose owner module is not enabled. A hotfix does not change the registered copy: it writes only under the module folder and never re-registers, so the executable Core copied at install keeps running, unchanged, until the module is installed again (corrected in 1.17.18; the hash guards the root-owned copy, not the module folder). Removing a module's actions (uninstall, or the sweep of a newer manifest) deletes only the registry files the helper wrote itself (registered_by module-manifest) and never an administrator's hand registration, protected ones included (1.17.18). Actions marked protected: true are never registered automatically. The Tactical account's sudo rule still reaches only --dispatch and --cancel. Capability core.server_maintenance 1.1.0, requires framework >=1.17.17. The module validator under pipeline/ must learn the key before it accepts a manifest that carries it.",
    "API keys (Tactical's /accounts/apikeys/ and /accounts/apikeys/<id>/, Core 1.17.26, parity with Tactical's API key admin; docs/api-keys.md): the browser may call Tactical's own routes. GET lists (needs the Tactical flag can_list_api_keys); POST creates, PUT edits and DELETE deletes (need can_manage_api_keys). Tactical returns and accepts what it does today, key values included in the list. Core adds only its account guard: with account protection on, a caller who is not an effective superuser gets 403 for a key on or for a protected superuser account (one Core deny row, object_type superuser_account_protection, operation create_api_key, update_api_key or delete_api_key) and the list shows [REDACTED] in place of a protected owner's key. A successful create, edit or delete writes one strict Core audit row in the same transaction (module_id core, object_type api_key, action add, modify or delete; a failed audit write rolls the change back). The row names the key's id, name and owner (metadata name, owner, owner_id). An edit row adds metadata changed (field names among name, owner, expiration) and before and after objects of name, owner and expiration. The key value is never in a row. A create row takes its object_id from the new key found by name and owner; when it cannot be found the row still goes out with no object_id and metadata matched 0. A refused call writes the deny row only, and a call Tactical refuses (validation or 404) writes no success row. Nothing in the Python contract changes: the guard is not a module surface.",
    "SSO admin (Tactical's /accounts/ssoproviders/ routes, Core 1.17.28, CQ84 a; docs/sso-admin.md): GET /accounts/ssoproviders/ lists the providers (needs the Tactical flag can_list_accounts) and shows secret as [REDACTED] to anyone who is not an effective superuser. POST /accounts/ssoproviders/ (add), PUT and DELETE /accounts/ssoproviders/<id>/ (edit, delete), POST /accounts/ssoproviders/settings/ (save sso_enabled and block_local_user_logon) and DELETE /accounts/ssoproviders/account/ (disconnect) need the Tactical flag can_manage_accounts and, from Core 1.17.28, an effective superuser. Anyone else gets 403 {detail: 'Only a Tec-Tac superuser may change SSO providers or SSO settings.'}, checked before the body is read, and one Core deny row (object_type sso_admin_superuser_required; metadata operation add_provider, edit_provider, delete_provider, save_settings or disconnect_account). A settings save that would leave block_local_user_logon true with no provider row, and a delete of the last provider while block_local_user_logon is true, give 409 {detail: a plain sentence, code: 'sso_lockout_guard'}, one Core deny row (object_type sso_lockout_guard) and no change. Tactical's 423 (licence) and its 400 or 404 change nothing and write no success row. Each successful write writes one strict Core audit row in the same transaction: sso_provider add; sso_provider modify (module_id core; before and after hold name, provider_id, server_url and role; metadata adds changed, the names among name, client_id, secret, server_url and role that changed; the client id and the secret are never stored); sso_provider delete (the same view); sso_settings modify (object_id sso_settings; before and after {sso_enabled, block_local_user_logon}, read from Tactical's stored settings after the save, so the failsafe is visible); sso_account delete (object_id the Tactical user id; metadata provider and username, never the external uid). A create whose new provider cannot be matched by id is still written, with matched 0 and no id. Sign-in routes (ssoproviders/token/, the OIDC callback and the allauth routes) are not touched. Core reads only sso_enabled, block_local_user_logon and the provider and account rows. Requires framework >=1.17.28.",
    "Use Python tec_tac.* contracts inside the Tec-Tac/Tactical backend; use HTTP only at browser/external process boundaries.",
    "UI modules must use the documented browser contracts passed to register(context) or registerPublic(context); do not import Core UI internals or read Tactical authentication storage.",
    "Swagger grouping is Core-owned: installed extension endpoints are grouped from their registered Django app ownership even when the URL prefix differs from the module ID. Module manifests may declare a readable name and category=core, server, premium or test (premium and test since 1.17.13); groups are named Core module · <name>, Server module · <name> or Module · <name>. Core HTTP surfaces use explicit subsystem groups, module callback ownership wins over path prefixes, and there is no generic Framework catch-all.",
    "Filter sets and value pickers belong to Core's filter-sets service (core.filter_sets 1.1.0, tec_tac.filter_sets, /api/tfd/filter-sets/ and /api/tfd/filter-values/, framework >=1.17.50; date and number fields need >=1.17.52). A module that offers filters registers '<module id>.filter_fields' 1.0.0 (describe_fields and distinct_values), lists it in its manifest capabilities when it is a core or server module, and filters distinct values at the source inside context.scope. It keeps no filter vocabulary of its own for new filters, evaluates a set only with build_q or matches on its own declared fields, and never takes field names, lookups, SQL or regular expressions from the browser. Core publishes no Python function that calls a provider for another module. The saved view key prefix 'fs-' is reserved for filter sets.",
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
    "Module user preferences (core.module_preferences 1.2.0, Core 1.17.38): a module that uses tec_tac.module_preferences or /api/tfd/module-preferences/ must require framework >=1.17.38. A module may use the Python functions only for its own module id: Core verifies the calling module (AD-26, from 1.17.37) and refuses any other caller with 403 caller_not_allowed. Each real add, modify or delete writes one strict Core audit row (1.17.38) that names the person, the module and the name, and holds the size but never the value; reads and unchanged writes write nothing; if the row cannot be written the change is rolled back with 503 audit_failed. Core checks that the person may use the module (403 module_not_allowed, from 1.17.38). A preference is one person's own non-secret display choice for one module. No secret, token or personal data may be stored. Core checks the person and that the module is installed and enabled. Rows of a removed module stay until the person is deleted. What Core can and cannot prove about the module id (1.17.38): Core can prove the person (their session), that the module is installed and enabled, that the person may use it, and that a row belongs only to that person and that module id pair; Core cannot prove that a browser request came from that module's page, so the browser route's module id is a claim and the audit row records it as source browser, module_verified false. See docs/module-preferences.md.",
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
        if getattr(entry, "_tec_tac_module_route", None):
            continue  # a module's own urls, mounted from its manifest routes key (1.17.16): not a Core HTTP contract
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
    # Routes that opt in with export_details (1.17.44) get their authorization, response keys and notes. A row with no contract adds nothing.
    for row in data["http"]:
        for method, block in (row.get("contract") or {}).items():
            if not isinstance(block, dict) or not block.get("export_details"):
                continue
            if "### HTTP response details" not in out:
                out.extend(["", "### HTTP response details", "", "Only the routes below are described in full here.", ""])
            out.extend([f"#### `{method} {row['route']}`", "", f"- Authorization: {block.get('authorization') or ''}"])
            out.extend(f"- Response `{key}`: {text}" for key, text in (block.get("response") or {}).items())
            out.extend(f"- Note: {note}" for note in (block.get("notes") or []))
            out.append("")

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
        "`permission` is a Tec-Tac permission code, a Tactical role flag written `tactical:can_manage_winupdates`, or a list of those (any-of, at most 8). Requires framework >=1.17.17 for the `tactical:` form and the list.",
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
    for row in data["http"]:
        for method, block in (row.get("contract") or {}).items():
            if not isinstance(block, dict) or not block.get("export_details"):
                continue
            if "HTTP RESPONSE DETAILS" not in out:
                out.extend(["", "HTTP RESPONSE DETAILS"])
            out.append(f"- {method} {row['route']}")
            out.append(f"    authorization: {block.get('authorization') or ''}")
            out.extend(f"    response {key}: {text}" for key, text in (block.get("response") or {}).items())
            out.extend(f"    note: {note}" for note in (block.get("notes") or []))

    out.extend([
        "",
        "RULE OF THUMB",
        "Python inside the Tec-Tac backend; HTTP at browser/external process boundaries.",
        "Capabilities are public cross-module business contracts. Scheduler actions expose WHAT can run; the Scheduler owns WHEN.",
        "",
    ])
    return "\n".join(out)
