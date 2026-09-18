from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_manager import ModuleManagerError, discard_stage, get_job
from .module_manager_v2 import (
    ModuleManagerV2Error,
    installed_catalog_v2,
    queue_batch_install,
    queue_set_enabled,
    queue_v2_install,
    stage_multiple_packages,
    validate_remove,
)
from .views import _can_manage_modules, _require_module_manager


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List Module Management v2 catalog"))
class ModuleV2CatalogView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        modules = installed_catalog_v2()
        return Response({"modules": modules, "count": len(modules), "manage": _can_manage_modules(request.user), "schema": 2})


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Inspect one or more packages or a bundle"))
class ModuleV2InspectView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def post(self, request):
        _require_module_manager(request.user)
        uploads = request.FILES.getlist("packages") or request.FILES.getlist("package")
        if not uploads:
            return Response({"detail": "At least one package or bundle upload is required."}, status=400)
        try:
            return Response(stage_multiple_packages(uploads), status=201)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2InstallView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            kind = str(request.data.get("kind", "artifact"))
            job = queue_batch_install(str(upload_id)) if kind == "batch" else queue_v2_install(str(upload_id))
            return Response(job, status=202)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2StateView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        enabled = request.data.get("enabled")
        cascade = bool(request.data.get("cascade", False))
        if not isinstance(enabled, bool):
            return Response({"detail": "enabled must be true or false."}, status=400)
        try:
            return Response(queue_set_enabled(plugin_id, enabled, cascade=cascade), status=202)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2RemoveCheckView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, plugin_id):
        _require_module_manager(request.user)
        try:
            return Response(validate_remove(plugin_id))
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2JobView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_job(str(job_id)))
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)
