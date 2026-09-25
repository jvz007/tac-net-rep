import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .module_hotfix import (
    ModuleHotfixError,
    discard_hotfix_stage,
    get_hotfix_job,
    list_applied_hotfixes,
    queue_apply_hotfix,
    queue_rollback_hotfix,
    stage_uploaded_hotfix,
)
from .session_security import SessionAuthenticated
from .views import _require_module_manager

logger = logging.getLogger(__name__)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Inspect and stage a managed module hotfix"))
class ModuleHotfixInspectView(APIView):
    permission_classes = [SessionAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        _require_module_manager(request.user)
        upload = request.FILES.get("hotfix") or request.FILES.get("package")
        if upload is None:
            return Response({"detail": "A hotfix ZIP upload is required."}, status=400)
        signature = request.FILES.get("signature")
        release_metadata = request.FILES.get("metadata") or request.FILES.get("release_metadata")
        try:
            return Response(stage_uploaded_hotfix(upload, signature_upload=signature, metadata_upload=release_metadata), status=201)
        except ModuleHotfixError as exc:
            return Response({"detail": str(exc)}, status=400)
        except OSError as exc:
            logger.exception("Tec-Tac hotfix staging filesystem failure")
            return Response({"detail": "Hotfix staging storage is unavailable.", "error_type": exc.__class__.__name__}, status=503)
        except Exception as exc:
            logger.exception("Unexpected Tec-Tac hotfix inspection failure")
            return Response({"detail": "Hotfix inspection failed unexpectedly.", "error_type": exc.__class__.__name__}, status=500)


class ModuleHotfixStageView(APIView):
    permission_classes = [SessionAuthenticated]

    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_hotfix_stage(str(upload_id))
            return Response(status=204)
        except ModuleHotfixError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Apply a staged module hotfix"))
class ModuleHotfixApplyView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            return Response(queue_apply_hotfix(str(upload_id), requested_by=str(request.user.username)), status=202)
        except ModuleHotfixError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List applied hotfixes for a module"))
class ModuleHotfixListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, plugin_id):
        _require_module_manager(request.user)
        rows = list_applied_hotfixes(plugin_id)
        public = []
        for row in rows:
            public.append({
                "id": row.get("id"),
                "module_id": row.get("module_id"),
                "base_version": row.get("base_version"),
                "description": row.get("description"),
                "applied_at": row.get("applied_at"),
                "applied_by": row.get("applied_by"),
                "package_sha256": row.get("package_sha256"),
                "publisher_trust": row.get("publisher_trust"),
                "reload": row.get("reload"),
                "ui_sync": bool(row.get("ui_sync")),
                "targets": row.get("targets") or [],
            })
        return Response({"module_id": plugin_id, "hotfixes": public, "count": len(public)})


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Roll back the latest applied module hotfix"))
class ModuleHotfixRollbackView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, plugin_id, hotfix_id):
        _require_module_manager(request.user)
        try:
            return Response(queue_rollback_hotfix(plugin_id, hotfix_id, requested_by=str(request.user.username)), status=202)
        except ModuleHotfixError as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleHotfixJobView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_hotfix_job(str(job_id)))
        except ModuleHotfixError as exc:
            return Response({"detail": str(exc)}, status=404)
