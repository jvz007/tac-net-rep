import logging

from django.apps import AppConfig
from django.urls import include, path

logger = logging.getLogger("tec_tac.apps")


class TecTacFrameworkConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac"
    verbose_name = "Tec-Tac Framework"

    def ready(self):
        # Framework-owned privileged capabilities are registered before module
        # AppConfig.ready() consumers resolve them. The provider exposes only
        # typed operations; privileged execution remains in the root helper.
        from .session_security import register_core_session_security_capability
        from .server_backup import register_core_server_backup_capability
        from .server_maintenance import register_core_server_maintenance_capability
        from .resources import register_core_resources_capability
        from .reporting import install_tactical_reporting_bridge
        register_core_session_security_capability()
        register_core_server_backup_capability()
        register_core_server_maintenance_capability()
        register_core_resources_capability()
        # 1.17.27: core.accounts (Tactical accounts for an accepted invite, and the roles an inviter may grant). Guarded, so a fault
        # here never aborts start-up; a module that finds no capability refuses (has_capability).
        try:
            from .accounts import register_core_accounts_capability

            register_core_accounts_capability()
        except Exception:
            logger.exception("Tec-Tac core.accounts capability registration failed")
        # 1.17.31 (C4): the ticketed Tactical terminal capability. Guarded like core.accounts; a missing capability refuses.
        try:
            from .tactical_websocket import register_core_tactical_websocket_capability

            register_core_tactical_websocket_capability()
        except Exception:
            logger.exception("Tec-Tac core.tactical_websocket capability registration failed")
        # 1.17.35: core.module_preferences (one per-person choice a module keeps through Core). Guarded like core.accounts.
        try:
            from .module_preferences import register_core_module_preferences_capability

            register_core_module_preferences_capability()
        except Exception:
            logger.exception("Tec-Tac core.module_preferences capability registration failed")
        # 1.17.7: the server-side Tactical operation path. Guarded, because a fault here must never abort start-up.
        # The registry is empty until an owning core module declares an operation, so this changes nothing by itself.
        try:
            from .tactical_operations import register_core_tactical_operations_capability

            register_core_tactical_operations_capability()
            # 1.17.21: the verified calling-module identity. Same guard: a fault here must never abort start-up, and a provider that
            # cannot find the capability (has_capability) refuses, so a missing registration fails closed.
            from .caller_identity import register_core_caller_identity_capability
            register_core_caller_identity_capability()
        except Exception:
            logger.exception("Tec-Tac core.tactical_operations or core.caller_identity capability registration failed")

        # 1.17.45: core.event_jobs (event-started, time-limited system jobs a module publishes from a signal). Guarded like the other
        # capabilities: a fault here never aborts start-up, and a module that finds no capability (has_capability) does not publish.
        try:
            from .event_jobs import register_core_event_jobs_capability

            register_core_event_jobs_capability()
        except Exception:
            logger.exception("Tec-Tac core.event_jobs capability registration failed")

        # 1.17.61: core.system_actions (typed Tactical functions Core runs unattended for a named owner, AD-13). Guarded like the others:
        # a fault here never aborts start-up, and a module that finds no capability (has_capability) registers no system action.
        try:
            from .system_actions import register_core_system_actions_capability

            register_core_system_actions_capability()
        except Exception:
            logger.exception("Tec-Tac core.system_actions capability registration failed")

        # 1.17.50: core.filter_sets (universal filters: vocabulary, validator, evaluators, saved filter sets). Guarded like core.event_jobs:
        # a fault here never aborts start-up, and a module that finds no capability (has_capability) offers no filters.
        try:
            from .filter_sets import register_core_filter_sets_capability

            register_core_filter_sets_capability()
        except Exception:
            logger.exception("Tec-Tac core.filter_sets capability registration failed")

        # Tactical's native role/account editors can otherwise grant effective
        # superuser authority to mid-level managers. Install the Core-owned,
        # authenticated mutation guard without modifying upstream Tactical code.
        try:
            # Keep the precise guard import inside the compatibility boundary.
            # A syntax/import error in that module must not abort AppConfig.ready().
            from .tactical_account_guard import install_tactical_account_guard

            install_tactical_account_guard()
        except Exception:
            # Tec-Tac must never make Tactical unavailable because an upstream
            # account view or the precise guard module itself changed. The
            # fail-closed installer lives in a separate module so it remains
            # available even when the precise module cannot import.
            logger.exception(
                "Tec-Tac precise Tactical account guard failed; enabling fail-closed compatibility guard"
            )
            try:
                from .tactical_account_guard_fallback import install_tactical_account_guard_fail_closed

                install_tactical_account_guard_fail_closed()
            except Exception:
                # Last-resort startup safety: log loudly but never abort Tactical.
                logger.exception("Tec-Tac fail-closed Tactical account guard installation failed")

        # 1.17.68 (Johan, 21 October 2026): while a replacement of Windows Patching (Advanced Patch Management) is honoured, Tactical's own patch
        # policy is switched off: its two documented task switches are set and Agent.approve_updates is inert. Nothing is written to Tactical.
        # Guarded step by step inside apply_at_startup: a fault leaves Tactical's own patching on and never aborts start-up.
        try:
            from .patch_lockdown import apply_at_startup, register_core_patch_lockdown_capability

            register_core_patch_lockdown_capability()
            apply_at_startup()
        except Exception:
            logger.exception("Tec-Tac patch lockdown could not be applied; Tactical's own patch policy stays as it was")

        # 1.17.71: the capability that tells a module which installed modules depend on it (Groups uses it before a delete). Its own try block:
        # a fault is logged and never stops start-up.
        try:
            from .module_dependants import register_core_module_dependants_capability

            register_core_module_dependants_capability()
        except Exception:
            logger.exception("Tec-Tac core.module_dependants capability could not be registered")

        # Core owns the compatibility boundary with Tactical Report Manager.
        # Install this before module AppConfig.ready() registrations execute so
        # modules never need to import ee.reporting internals themselves.
        install_tactical_reporting_bridge()

        # Swagger/OpenAPI is generated after Django app startup. Install one
        # post-processing hook so all Core and dynamically mounted module
        # endpoints under /api/tfd/ are grouped consistently.
        try:
            from .openapi import install_openapi_grouping
            install_openapi_grouping()
        except Exception:
            # Documentation grouping must never affect Tactical availability.
            logger.exception("Tec-Tac OpenAPI grouping hook installation failed")

        # Register framework-owned API routes in memory. This deliberately
        # avoids editing Tactical's tracked tacticalrmm/urls.py file.
        from tacticalrmm import urls as tactical_urls

        route_prefix = "api/tfd/"
        route_exists = any(
            str(getattr(pattern, "pattern", "")) == route_prefix
            for pattern in tactical_urls.urlpatterns
        )
        if not route_exists:
            tactical_urls.urlpatterns.append(
                path(route_prefix, include("tec_tac.urls"))
            )

        # 1.17.31 (C4): the ticketed terminal socket ws/tfd/agent-terminal/<ticket>/, appended once to Tactical's ws_urlpatterns.
        # Guarded: a fault here must never abort start-up. Skipped in DEMO, where Tactical also has no terminal route.
        try:
            from .tactical_websocket import install_tactical_websocket_route

            install_tactical_websocket_route()
        except Exception:
            logger.exception("Tec-Tac ticketed terminal socket route installation failed")
