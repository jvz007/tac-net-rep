from .resource_views import ResourceListView, ResourceDetailView, ResourceMutableListView, ResourceMutableDetailView
from .server_maintenance_views import (
    ServerMaintenanceActionListView, ServerMaintenanceJobListView,
    ServerMaintenanceJobDetailView, ServerMaintenanceJobCancelView,
)
from .session_security_views import (
    CurrentSessionView, SessionActivityView, SessionListView, SessionRevokeView,
    RevokeOtherSessionsView, SessionPolicyView, SessionAuditView, SessionDiagnosticsView,
    AdminLoginSessionListView, AdminLoginSessionRevokeView, AdminUserLoginSessionsRevokeView,
)
from .dashboard_views import DashboardListCreateView, DashboardDetailView
from .preference_views import UserPreferencesView
from .notice_views import NoticeListCreateView, NoticeReadView, NoticeReadAllView, NoticeClearReadView
from .mfa_backup_views import MfaBackupCodesView, AdminUserMfaRecoveryView, BackupCodeLoginView
from .housekeeping_views import HousekeepingStatusView, HousekeepingPurgeView
from .diagnostic_views import SystemDiagnosticsView
from .capability_views import CapabilityListView, CapabilityDetailView
from .contract_views import ContractCatalogView, ContractExportView
from .audit_views import AuditRecordView
from django.urls import path
from .views import (
    ExtensionPermissionCatalogView, ModuleCatalogView, ModuleJobView,
    ModulePackageInspectView, ModulePackageStageView, ModulePackageInstallView,
    ModuleRemoveView, RoleExtensionPermissionsView, TotpEnrollmentView, TotpQrView,
    SystemUpdateStatusView, SystemUpdatePackageInspectView, SystemUpdatePackageStageView,
    SystemUpdatePackageInstallView, SystemUpdateJobView, SystemUpdateOnlineStatusView,
    SystemUpdateBranchesView, SystemUpdateOnlineStageView, SystemUpdateTrustPolicyView, UiContextView,
)
from .module_repository_views import (
    ModuleRepositoryListView, ModuleRepositoryDetailView, ModuleRepositorySyncView,
    ModuleRepositorySyncAllView, ModuleOnlineCatalogView, ModuleOnlineStageView,
)
from .scheduler_views import (
    SchedulerActionListView, SchedulerListView, SchedulerDetailView,
    SchedulerRunNowView, SchedulerRunListView, SchedulerConfigView, SchedulerHealthView, SchedulerSelfTestView,
)
from .module_v2_views import (
    ModuleV2CatalogView, ModuleV2InspectView, ModuleV2StageView, ModuleV2InstallView,
    ModuleV2StateView, ModuleV2VisibilityView, ModuleV2RemoveCheckView, ModuleV2JobHistoryView, ModuleV2JobView,
)
from .module_hotfix_views import (
    ModuleHotfixInspectView, ModuleHotfixStageView, ModuleHotfixApplyView,
    ModuleHotfixListView, ModuleHotfixRollbackView, ModuleHotfixJobView,
)
urlpatterns = [
    path("session/current/", CurrentSessionView.as_view(), name="tec-tac-session-current"),
    path("session/activity/", SessionActivityView.as_view(), name="tec-tac-session-activity"),
    path("session/sessions/", SessionListView.as_view(), name="tec-tac-session-list"),
    path("session/sessions/<uuid:session_id>/revoke/", SessionRevokeView.as_view(), name="tec-tac-session-revoke"),
    path("session/revoke-others/", RevokeOtherSessionsView.as_view(), name="tec-tac-session-revoke-others"),
    path("session/policy/", SessionPolicyView.as_view(), name="tec-tac-session-policy"),
    path("session/audit/", SessionAuditView.as_view(), name="tec-tac-session-audit"),
    path("session/diagnostics/", SessionDiagnosticsView.as_view(), name="tec-tac-session-diagnostics"),
    path("access/sessions/", AdminLoginSessionListView.as_view(), name="tec-tac-access-login-sessions"),
    path("access/sessions/<str:session_ref>/revoke/", AdminLoginSessionRevokeView.as_view(), name="tec-tac-access-login-session-revoke"),
    path("access/users/<int:user_id>/sessions/revoke/", AdminUserLoginSessionsRevokeView.as_view(), name="tec-tac-access-user-login-sessions-revoke"),
    path("auth/mfa/backup-codes/", MfaBackupCodesView.as_view(), name="tec-tac-mfa-backup-codes"),
    path("access/users/<int:user_id>/mfa/", AdminUserMfaRecoveryView.as_view(), name="tec-tac-access-user-mfa-recovery"),
    path("auth/login/backup-code/", BackupCodeLoginView.as_view(), name="tec-tac-backup-code-login"),
    path("dashboards/", DashboardListCreateView.as_view(), name="tec-tac-dashboards"),
    path("dashboards/<uuid:dashboard_id>/", DashboardDetailView.as_view(), name="tec-tac-dashboard-detail"),
    path("contracts/", ContractCatalogView.as_view(), name="tec-tac-contracts"),
    path("contracts/export/", ContractExportView.as_view(), name="tec-tac-contract-export"),
    path("resources/clients/", ResourceMutableListView.as_view(resource_type="client"), name="tec-tac-resource-clients"),
    path("resources/clients/<int:resource_id>/", ResourceMutableDetailView.as_view(resource_type="client"), name="tec-tac-resource-client-detail"),
    path("resources/sites/", ResourceMutableListView.as_view(resource_type="site"), name="tec-tac-resource-sites"),
    path("resources/sites/<int:resource_id>/", ResourceMutableDetailView.as_view(resource_type="site"), name="tec-tac-resource-site-detail"),
    path("resources/agents/", ResourceListView.as_view(resource_type="agent"), name="tec-tac-resource-agents"),
    path("resources/agents/<str:resource_id>/", ResourceDetailView.as_view(resource_type="agent"), name="tec-tac-resource-agent-detail"),
    path("audit/record/", AuditRecordView.as_view(), name="tec-tac-audit-record"),
    path("capabilities/", CapabilityListView.as_view(), name="tec-tac-capabilities"),
    path("capabilities/<str:capability_id>/", CapabilityDetailView.as_view(), name="tec-tac-capability-detail"),
    path("scheduler/actions/", SchedulerActionListView.as_view(), name="tec-tac-scheduler-actions"),
    path("scheduler/schedules/", SchedulerListView.as_view(), name="tec-tac-scheduler-schedules"),
    path("scheduler/schedules/<uuid:schedule_id>/", SchedulerDetailView.as_view(), name="tec-tac-scheduler-schedule-detail"),
    path("scheduler/schedules/<uuid:schedule_id>/run/", SchedulerRunNowView.as_view(), name="tec-tac-scheduler-run-now"),
    path("scheduler/runs/", SchedulerRunListView.as_view(), name="tec-tac-scheduler-runs"),
    path("scheduler/config/", SchedulerConfigView.as_view(), name="tec-tac-scheduler-config"),
    path("scheduler/health/", SchedulerHealthView.as_view(), name="tec-tac-scheduler-health"),
    path("scheduler/self-test/", SchedulerSelfTestView.as_view(), name="tec-tac-scheduler-self-test"),

    path("ui/context/", UiContextView.as_view(), name="tec-tac-ui-context"),
    path("ui/preferences/", UserPreferencesView.as_view(), name="tec-tac-user-preferences"),
    path("ui/notices/", NoticeListCreateView.as_view(), name="tec-tac-notices"),
    path("ui/notices/<uuid:notice_id>/read/", NoticeReadView.as_view(), name="tec-tac-notice-read"),
    path("ui/notices/read-all/", NoticeReadAllView.as_view(), name="tec-tac-notices-read-all"),
    path("ui/notices/clear-read/", NoticeClearReadView.as_view(), name="tec-tac-notices-clear-read"),
    path("system/diagnostics/", SystemDiagnosticsView.as_view(), name="tec-tac-system-diagnostics"),
    path("system/storage/", HousekeepingStatusView.as_view(), name="tec-tac-housekeeping-status"),
    path("system/storage/purge/", HousekeepingPurgeView.as_view(), name="tec-tac-housekeeping-purge"),
    path("system/maintenance/actions/", ServerMaintenanceActionListView.as_view(), name="tec-tac-server-maintenance-actions"),
    path("system/maintenance/jobs/", ServerMaintenanceJobListView.as_view(), name="tec-tac-server-maintenance-jobs"),
    path("system/maintenance/jobs/<uuid:job_id>/", ServerMaintenanceJobDetailView.as_view(), name="tec-tac-server-maintenance-job-detail"),
    path("system/maintenance/jobs/<uuid:job_id>/cancel/", ServerMaintenanceJobCancelView.as_view(), name="tec-tac-server-maintenance-job-cancel"),
    path("system/updates/", SystemUpdateStatusView.as_view(), name="tec-tac-system-update-status"),
    path("system/updates/trust-policy/", SystemUpdateTrustPolicyView.as_view(), name="tec-tac-system-update-trust-policy"),
    path("system/updates/packages/inspect/", SystemUpdatePackageInspectView.as_view(), name="tec-tac-system-update-package-inspect"),
    path("system/updates/packages/<uuid:upload_id>/", SystemUpdatePackageStageView.as_view(), name="tec-tac-system-update-package-stage"),
    path("system/updates/packages/<uuid:upload_id>/install/", SystemUpdatePackageInstallView.as_view(), name="tec-tac-system-update-package-install"),
    path("system/updates/jobs/<uuid:job_id>/", SystemUpdateJobView.as_view(), name="tec-tac-system-update-job"),
    path("system/updates/online/", SystemUpdateOnlineStatusView.as_view(), name="tec-tac-system-update-online-status"),
    path("system/updates/branches/", SystemUpdateBranchesView.as_view(), name="tec-tac-system-update-branches"),
    path("system/updates/online/stage/", SystemUpdateOnlineStageView.as_view(), name="tec-tac-system-update-online-stage"),
    path("auth/totp/enrollment/", TotpEnrollmentView.as_view(), name="tec-tac-totp-enrollment"),
    path("auth/totp/qr/", TotpQrView.as_view(), name="tec-tac-totp-qr"),
    path("access/extensions/", ExtensionPermissionCatalogView.as_view(), name="tec-tac-extension-permissions"),
    path("modules/", ModuleCatalogView.as_view(), name="tec-tac-module-catalog"),
    path("modules/packages/inspect/", ModulePackageInspectView.as_view(), name="tec-tac-module-package-inspect"),
    path("modules/packages/<uuid:upload_id>/", ModulePackageStageView.as_view(), name="tec-tac-module-package-stage"),
    path("modules/packages/<uuid:upload_id>/install/", ModulePackageInstallView.as_view(), name="tec-tac-module-package-install"),
    path("modules/<str:plugin_id>/remove/", ModuleRemoveView.as_view(), name="tec-tac-module-remove"),
    path("modules/jobs/<uuid:job_id>/", ModuleJobView.as_view(), name="tec-tac-module-job"),
    path("modules/repositories/", ModuleRepositoryListView.as_view(), name="tec-tac-module-repositories"),
    path("modules/repositories/sync/", ModuleRepositorySyncAllView.as_view(), name="tec-tac-module-repositories-sync"),
    path("modules/repositories/<str:repository_id>/", ModuleRepositoryDetailView.as_view(), name="tec-tac-module-repository-detail"),
    path("modules/repositories/<str:repository_id>/sync/", ModuleRepositorySyncView.as_view(), name="tec-tac-module-repository-sync"),
    path("modules/catalog/online/", ModuleOnlineCatalogView.as_view(), name="tec-tac-module-online-catalog"),
    path("modules/catalog/online/stage/", ModuleOnlineStageView.as_view(), name="tec-tac-module-online-stage"),
    path("modules/v2/", ModuleV2CatalogView.as_view(), name="tec-tac-module-v2-catalog"),
    path("modules/v2/packages/inspect/", ModuleV2InspectView.as_view(), name="tec-tac-module-v2-inspect"),
    path("modules/v2/packages/<uuid:upload_id>/", ModuleV2StageView.as_view(), name="tec-tac-module-v2-stage"),
    path("modules/v2/packages/<uuid:upload_id>/install/", ModuleV2InstallView.as_view(), name="tec-tac-module-v2-install"),
    path("modules/v2/<str:plugin_id>/state/", ModuleV2StateView.as_view(), name="tec-tac-module-v2-state"),
    path("modules/v2/<str:plugin_id>/visibility/", ModuleV2VisibilityView.as_view(), name="tec-tac-module-v2-visibility"),
    path("modules/v2/<str:plugin_id>/remove-check/", ModuleV2RemoveCheckView.as_view(), name="tec-tac-module-v2-remove-check"),
    path("modules/v2/jobs/", ModuleV2JobHistoryView.as_view(), name="tec-tac-module-v2-job-history"),
    path("modules/v2/jobs/<uuid:job_id>/", ModuleV2JobView.as_view(), name="tec-tac-module-v2-job"),
    path("modules/hotfixes/inspect/", ModuleHotfixInspectView.as_view(), name="tec-tac-module-hotfix-inspect"),
    path("modules/hotfixes/<uuid:upload_id>/", ModuleHotfixStageView.as_view(), name="tec-tac-module-hotfix-stage"),
    path("modules/hotfixes/<uuid:upload_id>/apply/", ModuleHotfixApplyView.as_view(), name="tec-tac-module-hotfix-apply"),
    path("modules/hotfixes/jobs/<uuid:job_id>/", ModuleHotfixJobView.as_view(), name="tec-tac-module-hotfix-job"),
    path("modules/v2/<str:plugin_id>/hotfixes/", ModuleHotfixListView.as_view(), name="tec-tac-module-hotfix-list"),
    path("modules/v2/<str:plugin_id>/hotfixes/<str:hotfix_id>/rollback/", ModuleHotfixRollbackView.as_view(), name="tec-tac-module-hotfix-rollback"),
    path("access/roles/<int:role_id>/permissions/", RoleExtensionPermissionsView.as_view(), name="tec-tac-role-extension-permissions"),
]
