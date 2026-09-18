from django.urls import path

from .views import (
    ExtensionPermissionCatalogView,
    RoleExtensionPermissionsView,
    UiContextView,
)

urlpatterns = [
    path("ui/context/", UiContextView.as_view(), name="tec-tac-ui-context"),
    path("access/extensions/", ExtensionPermissionCatalogView.as_view(), name="tec-tac-extension-permissions"),
    path(
        "access/roles/<int:role_id>/permissions/",
        RoleExtensionPermissionsView.as_view(),
        name="tec-tac-role-extension-permissions",
    ),
]
