import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated

from . import module_job_logs, module_licensing
from .module_manager import ModuleManagerError, discard_stage, get_job, list_jobs, page_jobs
from .module_manager_v2 import (
    LicensingRequirementError,
    ModuleManagerV2Error,
    ModuleReplacementConfirmationRequired,
    ModuleReplacementHandBackConfirmationRequired,
    ModuleReplacementSecondConfirmationRequired,
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


def _disable_replaced(request):
    """The optional ``disable_replaced`` list from the request: None when absent, else a list of module id strings.
    Raises ModuleManagerV2Error (a refusal, HTTP 400) for anything else."""
    value = request.data.get("disable_replaced")
    if value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ModuleManagerV2Error("disable_replaced must be an array of module IDs.")
    return value


def _override_refusal(exc):
    """The answer for a refused licence override (1.17.58): 403 for a caller who is not a superuser, 400 for a bad reason."""
    if isinstance(exc, module_licensing.OverrideDenied):
        return Response({"detail": str(exc), "code": "licence_override_superuser_required"}, status=403)
    return Response({"detail": str(exc), "code": "invalid_licence_override_reason"}, status=400)


def _confirm_replacement_switch(request):
    """The optional ``confirm_replacement_switch`` flag (1.17.12): None when absent, else a boolean. Only true confirms.
    Raises ModuleManagerV2Error (a refusal, HTTP 400) for anything that is not a boolean."""
    value = request.data.get("confirm_replacement_switch")
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ModuleManagerV2Error("confirm_replacement_switch must be true or false.")
    return value


def _confirm_without_hand_back(request):
    """The optional ``confirm_without_hand_back`` flag (1.17.14): None when absent, else a boolean. Only true confirms.
    Raises ModuleManagerV2Error (a refusal, HTTP 400) for anything that is not a boolean."""
    value = request.data.get("confirm_without_hand_back")
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ModuleManagerV2Error("confirm_without_hand_back must be true or false.")
    return value


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List Module Management v2 catalog"))
class ModuleV2CatalogView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        modules = installed_catalog_v2()
        return Response({"modules": modules, "count": len(modules), "manage": _can_manage_modules(request.user), "schema": 2})


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Inspect one or more packages or a bundle"))
class ModuleV2InspectView(APIView):
    permission_classes = [SessionAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def post(self, request):
        _require_module_manager(request.user)
        try:
            override_reason = module_licensing.read_override(request)  # 1.17.58: before any package work, in every mode
        except (module_licensing.OverrideDenied, module_licensing.OverrideInvalid) as exc:
            return _override_refusal(exc)
        uploads = request.FILES.getlist("packages") or request.FILES.getlist("package")
        if not uploads:
            return Response({"detail": "At least one package or bundle upload is required."}, status=400)
        signatures = request.FILES.getlist("signatures")
        metadata_files = request.FILES.getlist("metadata_files")
        signature = request.FILES.get("signature")
        release_metadata = request.FILES.get("metadata") or request.FILES.get("release_metadata")
        if signature is not None:
            signatures.append(signature)
        if release_metadata is not None:
            metadata_files.append(release_metadata)
        try:
            with module_licensing.override_scope(request.user, override_reason):
                if len(uploads) == 1 and len(signatures) <= 1 and len(metadata_files) <= 1 and (signatures or metadata_files):
                    # Single package, one pair at most: unchanged path (companions are checked by the trust step).
                    from .module_manager_v2 import stage_uploaded_artifact
                    return Response(stage_uploaded_artifact(
                        uploads[0], signature_upload=signatures[0] if signatures else None,
                        metadata_upload=metadata_files[0] if metadata_files else None), status=201)
                return Response(stage_multiple_packages(uploads, signatures, metadata_files), status=201)
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
    permission_classes = [SessionAuthenticated]
    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_v2_stage(str(upload_id))
            return Response(status=204)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2InstallView(APIView):
    permission_classes = [SessionAuthenticated]
    def post(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            override_reason = module_licensing.read_override(request)  # 1.17.58: before any package work, in every mode
        except (module_licensing.OverrideDenied, module_licensing.OverrideInvalid) as exc:
            return _override_refusal(exc)
        try:
            kind = str(request.data.get("kind", "artifact"))
            order = request.data.get("order")
            if order is not None and not isinstance(order, list):
                return Response({"detail": "order must be an array of module IDs."}, status=400)
            disable_replaced = _disable_replaced(request)
            queue = queue_batch_install if kind == "batch" else queue_v2_install
            with module_licensing.override_scope(request.user, override_reason):
                job = queue(str(upload_id), requested_order=order, requested_by=str(request.user.username),
                            disable_replaced=disable_replaced, actor=request.user)
            return Response(job, status=202)
        except LicensingRequirementError as exc:
            return Response(exc.as_payload(), status=403)
        except ModuleReplacementConfirmationRequired as exc:
            return Response(exc.as_payload(), status=400)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2StateView(APIView):
    permission_classes = [SessionAuthenticated]
    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        enabled = request.data.get("enabled")
        cascade = bool(request.data.get("cascade", False))
        if not isinstance(enabled, bool):
            return Response({"detail": "enabled must be true or false."}, status=400)
        try:
            disable_replaced = _disable_replaced(request)
            confirm_switch = _confirm_replacement_switch(request)
            confirm_without = _confirm_without_hand_back(request)
            return Response(queue_set_enabled(plugin_id, enabled, cascade=cascade, requested_by=str(request.user.username),
                                              disable_replaced=disable_replaced, actor=request.user,
                                              confirm_replacement_switch=confirm_switch,
                                              confirm_without_hand_back=confirm_without), status=202)
        except (ModuleReplacementConfirmationRequired, ModuleReplacementSecondConfirmationRequired,
                ModuleReplacementHandBackConfirmationRequired) as exc:
            return Response(exc.as_payload(), status=400)
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2VisibilityView(APIView):
    permission_classes = [SessionAuthenticated]
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
    permission_classes = [SessionAuthenticated]
    def get(self, request, plugin_id):
        _require_module_manager(request.user)
        try:
            return Response(validate_remove(plugin_id))
        except (ModuleManagerError, ModuleManagerV2Error) as exc:
            return Response({"detail": str(exc)}, status=400)


class ModuleV2JobHistoryView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        _require_module_manager(request.user)
        try:
            paged_keys = {"page", "page_size", "status", "action", "search"}
            if not (paged_keys & set(request.query_params.keys())):
                # Exact compatibility path for pre-pagination callers. No params
                # historically returned the bounded 200-row list, and limit=
                # callers retain the same legacy response shape.
                limit = int(request.query_params.get("limit") or 200)
                rows = list_jobs(limit=limit)
                return Response({"jobs": rows, "count": len(rows)})
            result = page_jobs(
                page=int(request.query_params.get("page") or 1),
                page_size=int(request.query_params.get("page_size") or 50),
                status=request.query_params.get("status"),
                action=request.query_params.get("action"),
                search=request.query_params.get("search"),
            )
        except (TypeError, ValueError, ModuleManagerError) as exc:
            return Response({"detail": str(exc) or "Invalid pagination parameters."}, status=400)
        return Response({
            "jobs": result["items"],
            "count": len(result["items"]),
            "total": result["count"],
            "page": result["page"],
            "page_size": result["page_size"],
            "pages": result["pages"],
            "next_page": result["next_page"],
            "previous_page": result["previous_page"],
        })


class ModuleV2JobView(APIView):
    permission_classes = [SessionAuthenticated]
    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_job(str(job_id)))
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Module job history (1.17.60): no log text, no paths"))
class ModuleV2JobHistoryListView(APIView):
    """The whitelisted job list: install, replace, rename, batch, bundle, enable, disable, remove, visibility and hotfix jobs."""
    permission_classes = [SessionAuthenticated]
    def get(self, request):
        _require_module_manager(request.user)
        params = request.query_params
        try:
            result = module_job_logs.page_history(
                page=params.get("page"), page_size=params.get("page_size"), module=params.get("module"),
                action=params.get("action"), status=params.get("status"), kind=params.get("kind"))
        except module_job_logs.HistoryParameterError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response({
            "jobs": result["items"],
            "count": len(result["items"]),
            "total": result["count"],
            "page": result["page"],
            "page_size": result["page_size"],
            "pages": result["pages"],
            "next_page": result["next_page"],
            "previous_page": result["previous_page"],
        })


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Full log of one module job (1.17.60): scrubbed, capped at 5 MB, audited"))
class ModuleV2JobLogView(APIView):
    """One job's log as plain text. Inline by default; ``?download=1`` sends it as a file. Every read writes a strict audit row."""
    permission_classes = [SessionAuthenticated]
    def get(self, request, job_id):
        _require_module_manager(request.user)
        download = request.query_params.get("download") == "1"
        try:
            log = module_job_logs.read_job_log(str(job_id))
        except module_job_logs.JobLogError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status)
        except OSError:
            logger.exception("Tec-Tac module job log could not be read")
            return Response({"detail": "The log could not be read. Check Tec-Tac diagnostics/logs."}, status=503)
        return module_job_logs.serve_log(
            request, log, object_type="module_job_log",
            metadata={"job_id": log.job_id, "kind": log.kind, "action": log.action, "module": log.module,
                      "bytes": log.size, "truncated": log.truncated, "download": download},
            filename=module_job_logs.download_filename(log) if download else None, label="module job log")
