from rest_framework.permissions import BasePermission, SAFE_METHODS

from tfdreporting.rbac import (
    PERMISSION_NETWORK_AVAILABILITY_LIST,
    PERMISSION_NETWORK_AVAILABILITY_MANAGE,
    has_extension_permission,
)


class NetworkAvailabilityPermission(BasePermission):
    """Map HTTP methods to TFD extension permissions.

    GET/HEAD/OPTIONS require list permission. POST requires manage permission.
    Any other method is denied by default.
    """

    message = "This Tactical role does not have the required TFD reporting permission."

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return has_extension_permission(
                request.user,
                PERMISSION_NETWORK_AVAILABILITY_LIST,
            )

        if request.method == "POST":
            return has_extension_permission(
                request.user,
                PERMISSION_NETWORK_AVAILABILITY_MANAGE,
            )

        return False
