from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_manager_v2 import LicensingRequirementError
from .module_repository import (
    ModuleRepositoryError,
    all_repository_status,
    delete_repository,
    online_catalog,
    stage_repository_package,
    sync_all,
    sync_repository,
    upsert_repository,
)
from .views import _can_manage_modules, _require_module_manager


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List module repositories"), post=extend_schema(tags=["Tec-Tac Framework"], summary="Add module repository"))
class ModuleRepositoryListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        repos = all_repository_status()
        return Response({"schema": 1, "repositories": repos, "count": len(repos), "manage": _can_manage_modules(request.user)})

    def post(self, request):
        _require_module_manager(request.user)
        try:
            return Response(upsert_repository(request.data), status=201)
        except ModuleRepositoryError as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleRepositoryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, repository_id):
        _require_module_manager(request.user)
        try:
            return Response(upsert_repository(request.data, repository_id=repository_id))
        except ModuleRepositoryError as exc:
            return Response({"detail": str(exc)}, status=400)

    def delete(self, request, repository_id):
        _require_module_manager(request.user)
        try:
            delete_repository(repository_id)
            return Response(status=204)
        except ModuleRepositoryError as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleRepositorySyncView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, repository_id):
        _require_module_manager(request.user)
        try:
            return Response(sync_repository(repository_id))
        except ModuleRepositoryError as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleRepositorySyncAllView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_module_manager(request.user)
        return Response({"repositories": sync_all(enabled_only=True)})


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List online module catalog"))
class ModuleOnlineCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            payload = online_catalog()
            payload["manage"] = _can_manage_modules(request.user)
            return Response(payload)
        except ModuleRepositoryError as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleOnlineStageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_module_manager(request.user)
        repository_id = str(request.data.get("repository_id") or "").strip()
        module_id = str(request.data.get("module_id") or "").strip()
        version = str(request.data.get("version") or "").strip() or None
        allow_source_change = request.data.get("allow_source_change", False)
        if not isinstance(allow_source_change, bool):
            return Response({"detail": "allow_source_change must be true or false."}, status=400)
        if not repository_id or not module_id:
            return Response({"detail": "repository_id and module_id are required."}, status=400)
        try:
            return Response(stage_repository_package(repository_id, module_id, version, allow_source_change=allow_source_change), status=201)
        except LicensingRequirementError as exc:
            return Response(exc.as_payload(), status=403)
        except ModuleRepositoryError as exc:
            # Module Manager validation errors are intentionally returned as a
            # bounded client-visible staging failure, not an unhandled 500.
            return Response({"detail": str(exc)}, status=400)
