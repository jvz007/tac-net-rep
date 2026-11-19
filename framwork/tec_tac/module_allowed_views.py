import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from . import licensing_catalogue_source
from .session_security import SessionAuthenticated
from .views import _require_module_manager

logger = logging.getLogger(__name__)

# --- the allowed-module list (1.18.10) -------------------------------------------------------------------------------------------
# Three browser routes for the picker Welcome shows. Every one needs core.privileged_operations (checked first, fails closed) and none of
# them reads Licensing's provider itself: licensing_catalogue_source.py does, because Licensing accepts no other caller. Each answer is the
# whitelisted body that file returns. Nothing here installs or removes a module.

_ALLOWED_STATUS = {
    "ok": 200, "saved": 200, "cached": 200, "not_fetched": 200,
    "bad_request": 400, "locked": 403, "unknown_module": 404, "required_by": 409,
    "licensing_unavailable": 503, "invalid_response": 502,
}

# The states that are a "no" to the request itself. Any other state that is not saved means no usable answer (a failure).
_REFUSED_STATES = frozenset({"locked", "unknown_module", "bad_request", "required_by"})


def _allowed_http(state):
    """200 for a list or a saved choice, 4xx for a refusal, 503 or 502 when Licensing gave no usable answer. Any other Licensing state
    (not registered, licence trouble, plan trouble) is a normal answer the administrator reads, so it is 200 with ok false."""
    return _ALLOWED_STATUS.get(state, 200)


def _audit_allowed(request, *, action, object_type, object_id, message, before=None, after=None, metadata=None):
    """One Core audit row. Never raises: a failed write is logged and the request still answers."""
    try:
        from . import audit

        audit.record(actor=request.user, module_id="core", action=action, object_type=object_type, object_id=object_id,
                     message=message, before=before, after=after, metadata=metadata or {}, request=request, strict=False)
    except Exception:
        logger.exception("Unable to persist an allowed-modules audit event")


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List the modules this licence allows"))
class ModuleAllowedCatalogView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        body = licensing_catalogue_source.read_allowed_modules()
        return Response(body, status=_allowed_http(body["state"]))


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Ask Licensing to refresh the allowed modules"))
class ModuleAllowedRefreshView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        _require_module_manager(request.user)
        body = licensing_catalogue_source.refresh_allowed_modules()
        _audit_allowed(request, action="run", object_type="allowed_modules", object_id="refresh",
                       message=f"Asked Licensing to refresh the allowed modules: {body['state']}.", metadata={"result": body["state"]})
        return Response(body, status=_allowed_http(body["state"]))


@extend_schema_view(put=extend_schema(tags=["Tec-Tac Framework"], summary="Select or deselect a licensed premium module"))
class ModuleAllowedSelectionView(APIView):
    permission_classes = [SessionAuthenticated]

    def put(self, request):
        _require_module_manager(request.user)
        data = request.data if hasattr(request.data, "get") else {}
        module_id, selected = data.get("module_id"), data.get("selected")
        body = licensing_catalogue_source.set_premium_selection(module_id, selected)
        shown_id = body["module_id"] or None
        if body["state"] == "saved":
            _audit_allowed(request, action="modify", object_type="module_selection", object_id=shown_id,
                           message=f"{'Selected' if body['selected'] else 'Deselected'} the premium module {shown_id} for the allowed-module list.",
                           before={"deselected": body["before"]}, after={"deselected": body["after"]}, metadata={"selected": body["selected"]})
        else:
            # Every attempt that does not end saved leaves one deny row (1.18.18). A refusal is Core's or Licensing's "no"; a failure is
            # Licensing or the plan giving no usable answer. record() refuses the Core-only failed-operation action, so both are "deny"
            # and the metadata outcome tells them apart. The text uses state words only, never anything Licensing sent.
            state = body["state"]
            refused = state in _REFUSED_STATES
            who = shown_id or "a module"
            metadata = {"result": state, "selected": body["selected"], "outcome": "refused" if refused else "failed"}
            if state == "required_by":
                metadata["required_by"] = [str(item) for item in (body.get("required_by") or [])[:50]]
            message = (f"Refused to change the selection of {who}: {state}." if refused
                       else f"Could not change the selection of {who}: {state}. Nothing was changed.")
            _audit_allowed(request, action="deny", object_type="module_selection", object_id=shown_id, message=message, metadata=metadata)
        return Response(body, status=_allowed_http(body["state"]))
