from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from . import module_install_plan, module_install_run
from .module_allowed_views import _allowed_http, _audit_allowed
from .session_security import SessionAuthenticated
from .views import _require_module_manager

# Core 1.18.20 (R1b to R1d): the install run routes. They sit beside module_allowed_views.py, not in it, because the 1.18.10 and 1.18.18 tests
# count that file's audit calls and the 1.18.19 test reads its plan view to the end of the file.


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Install several licensed modules in one run"))
class ModuleOnlineInstallRunView(APIView):
    """Core 1.18.20 (R1b). Plans again on the server, then starts one run. The body has ``modules`` and an optional ``purpose`` (only "install"; 1.18.42 removed "upgrade"): no order, version, licence override or
    replacement confirmation is accepted. The work is done by short Celery ticks (module_install_run.py)."""
    permission_classes = (SessionAuthenticated,)

    def post(self, request):
        _require_module_manager(request.user)
        data = request.data if hasattr(request.data, "get") else {}
        try:
            selection = module_install_plan.clean_selection(data.get("modules"))
            purpose = module_install_plan.clean_purpose(data.get("purpose"))
        except module_install_plan.BadSelection as exc:
            return Response({"ok": False, "state": "bad_request", "message": str(exc)}, status=400)
        refused = module_install_run.refused_fields(data)
        if refused:
            return Response({"ok": False, "state": "bad_request", "message": "A batch install takes no licence override and no replacement confirmation. Install that module on its own."}, status=400)
        status, body = module_install_run.start_run(module_install_run.live_env(), selection, str(request.user), _allowed_http, request=request, purpose=purpose)
        return Response(body, status=status)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Progress of a module install run"))
class ModuleOnlineInstallProgressView(APIView):
    permission_classes = (SessionAuthenticated,)

    def get(self, request, run_id):
        _require_module_manager(request.user)
        status, body = module_install_run.progress(module_install_run.live_env(), str(run_id))
        return Response(body, status=status)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Stop a module install run after the current module"))
class ModuleOnlineInstallStopView(APIView):
    permission_classes = (SessionAuthenticated,)

    def post(self, request, run_id):
        _require_module_manager(request.user)

        def audit_stop(run):
            _audit_allowed(request, action="modify", object_type="module_install_run", object_id=run["run_id"], message="Stop requested",
                           metadata={"status": run["status"]}, correlation_id=run["run_id"])

        status, body = module_install_run.request_stop(module_install_run.live_env(), str(run_id), audit_stop)
        return Response(body, status=status)
