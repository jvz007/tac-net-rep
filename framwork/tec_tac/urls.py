from .dashboard_views import DashboardListCreateView, DashboardDetailView
from .preference_views import UserPreferencesView
from .housekeeping_views import HousekeepingStatusView, HousekeepingPurgeView
from .capability_views import CapabilityListView, CapabilityDetailView
from .contract_views import ContractCatalogView, ContractExportView
from django.urls import path
from .views import (
    ExtensionPermissionCatalogView, ModuleCatalogView, ModuleJobView,
    ModulePackageInspectView, ModulePackageStageView, ModulePackageInstallView,
    ModuleRemoveView, RoleExtensionPermissionsView, TotpQrView,
    SystemUpdateStatusView, SystemUpdatePackageInspectView, SystemUpdatePackageStageView,
    SystemUpdatePackageInstallView, SystemUpdateJobView, SystemUpdateOnlineStatusView,
    SystemUpdateBranchesView, SystemUpdateOnlineStageView, UiContextView,
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
urlpatterns = [
    path("dashboards/", DashboardListCreateView.as_view(), name="tec-tac-dashboards"),
    path("dashboards/<uuid:dashboard_id>/", DashboardDetailView.as_view(), name="tec-tac-dashboard-detail"),
    path("contracts/", ContractCatalogView.as_view(), name="tec-tac-contracts"),
    path("contracts/export/", ContractExportView.as_view(), name="tec-tac-contract-export"),
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
    path("system/storage/", HousekeepingStatusView.as_view(), name="tec-tac-housekeeping-status"),
    path("system/storage/purge/", HousekeepingPurgeView.as_view(), name="tec-tac-housekeeping-purge"),
    path("system/updates/", SystemUpdateStatusView.as_view(), name="tec-tac-system-update-status"),
    path("system/updates/packages/inspect/", SystemUpdatePackageInspectView.as_view(), name="tec-tac-system-update-package-inspect"),
    path("system/updates/packages/<uuid:upload_id>/", SystemUpdatePackageStageView.as_view(), name="tec-tac-system-update-package-stage"),
    path("system/updates/packages/<uuid:upload_id>/install/", SystemUpdatePackageInstallView.as_view(), name="tec-tac-system-update-package-install"),
    path("system/updates/jobs/<uuid:job_id>/", SystemUpdateJobView.as_view(), name="tec-tac-system-update-job"),
    path("system/updates/online/", SystemUpdateOnlineStatusView.as_view(), name="tec-tac-system-update-online-status"),
    path("system/updates/branches/", SystemUpdateBranchesView.as_view(), name="tec-tac-system-update-branches"),
    path("system/updates/online/stage/", SystemUpdateOnlineStageView.as_view(), name="tec-tac-system-update-online-stage"),
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
    path("access/roles/<int:role_id>/permissions/", RoleExtensionPermissionsView.as_view(), name="tec-tac-role-extension-permissions"),
]
