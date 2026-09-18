from django.urls import path

from .views import (
    ExtensionPermissionCatalogView,
    ModuleCatalogView,
    ModuleJobView,
    ModulePackageInspectView,
    ModulePackageStageView,
    ModulePackageInstallView,
    ModuleRemoveView,
    RoleExtensionPermissionsView,
    TotpQrView,
    UiContextView,
)

urlpatterns = [
    path("ui/context/", UiContextView.as_view(), name="tec-tac-ui-context"),
    path("auth/totp/qr/", TotpQrView.as_view(), name="tec-tac-totp-qr"),
    path("access/extensions/", ExtensionPermissionCatalogView.as_view(), name="tec-tac-extension-permissions"),
    path("modules/", ModuleCatalogView.as_view(), name="tec-tac-module-catalog"),
    path("modules/packages/inspect/", ModulePackageInspectView.as_view(), name="tec-tac-module-package-inspect"),
    path("modules/packages/<uuid:upload_id>/", ModulePackageStageView.as_view(), name="tec-tac-module-package-stage"),
    path("modules/packages/<uuid:upload_id>/install/", ModulePackageInstallView.as_view(), name="tec-tac-module-package-install"),
    path("modules/<str:plugin_id>/remove/", ModuleRemoveView.as_view(), name="tec-tac-module-remove"),
    path("modules/jobs/<uuid:job_id>/", ModuleJobView.as_view(), name="tec-tac-module-job"),
    path(
        "access/roles/<int:role_id>/permissions/",
        RoleExtensionPermissionsView.as_view(),
        name="tec-tac-role-extension-permissions",
    ),
]
