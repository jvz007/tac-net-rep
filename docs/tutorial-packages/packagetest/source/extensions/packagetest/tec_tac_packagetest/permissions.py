from rest_framework.permissions import BasePermission
from tec_tac.rbac import has_extension_permission

class PackageTestPermission(BasePermission):
    def has_permission(self, request, view):
        codename="packagetest.api.read" if request.method in ("GET","HEAD","OPTIONS") else "packagetest.api.manage"
        return has_extension_permission(request.user,codename)
