import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_manager import ModuleManagerError, discard_stage, get_job, list_jobs
from .module_manager_v2 import (
    LicensingRequirementError,
    ModuleManagerV2Error,
    discard_v2_stage,
    installed_catalog_v2,
    queue_batch_install,
    queue_set_enabled,
    queue_set_visibility,
    queue_v2_install,
    stage_multiple_packages,
    validate_remove,
)
from .views import _can_manage_modules, _require_module_manager

logger = logging.getLogger(__name__)


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
        except LicensingRequirementError as exc:
            return Response(exc.as_payload(), status=403)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)
        except OSError as exc:
            logger.exception("Tec-Tac Module Manager package staging failed")
            return Response({
                "detail": "Module package inspection could not access its staging area. Run the Tec-Tac permission recovery check.",
                "error_type": exc.__class__.__name__,
            }, status=503)
        except Exception as exc:
            logger.exception("Unexpected Tec-Tac Module Manager package inspection failure")
            return Response({
                "detail": "Module package inspection failed unexpectedly. Check Tec-Tac diagnostics/logs.",
                "error_type": exc.__class__.__name__,
            }, status=500)


class ModuleV2StageView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_v2_stage(str(upload_id))
            return Response(status=204)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2InstallView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            kind = str(request.data.get("kind", "artifact"))
            order = request.data.get("order")
            if order is not None and not isinstance(order, list):
                return Response({"detail": "order must be an array of module IDs."}, status=400)
            job = queue_batch_install(str(upload_id), requested_order=order, requested_by=str(request.user.username)) if kind == "batch" else queue_v2_install(str(upload_id), requested_order=order, requested_by=str(request.user.username))
            return Response(job, status=202)
        except LicensingRequirementError as exc:
            return Response(exc.as_payload(), status=403)
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
            return Response(queue_set_enabled(plugin_id, enabled, cascade=cascade, requested_by=str(request.user.username)), status=202)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2VisibilityView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        visible = request.data.get("visible")
        if not isinstance(visible, bool):
            return Response({"detail": "visible must be true or false."}, status=400)
        try:
            return Response(queue_set_visibility(plugin_id, visible, requested_by=str(request.user.username)), status=202)
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


class ModuleV2JobHistoryView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        _require_module_manager(request.user)
        raw_limit = request.query_params.get("limit", 200)
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return Response({"detail": "limit must be an integer."}, status=400)
        rows = list_jobs(limit=limit)
        return Response({"jobs": rows, "count": len(rows)})


class ModuleV2JobView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_job(str(job_id)))
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)

