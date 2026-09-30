from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from .saved_views import (
    SavedViewError,
    SavedViewValidationError,
    create_view,
    delete_view,
    get_view,
    list_views,
    update_view,
)
from .session_security import SessionAuthenticated
from .throttles import SavedViewWriteDayThrottle, SavedViewWriteMinThrottle

_CREATE_FIELDS = {"module_id", "view_key", "name", "payload", "readers"}
_UPDATE_FIELDS = {"module_id", "view_key", "name", "payload", "readers"}


def _error(exc: SavedViewError) -> Response:
    return Response({"detail": str(exc)}, status=exc.status_code)


def _body(request, allowed: set[str]) -> dict:
    data = request.data
    if not isinstance(data, dict):
        raise SavedViewValidationError("Saved view must be a JSON object.")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise SavedViewValidationError("Unknown saved view field(s): " + ", ".join(unknown))
    return data


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Saved Views"], summary="List the saved views the current user can read for a module"),
    post=extend_schema(tags=["Tec-Tac Saved Views"], summary="Create a saved view"),
)
class SavedViewListCreateView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [SavedViewWriteMinThrottle, SavedViewWriteDayThrottle]

    def get(self, request):
        try:
            views = list_views(request.user, request.query_params.get("module"), request.query_params.get("view_key"))
        except SavedViewError as exc:
            return _error(exc)
        return Response({"views": views, "count": len(views)})

    def post(self, request):
        try:
            data = _body(request, _CREATE_FIELDS)
            view = create_view(
                request.user, data.get("module_id"), data.get("view_key"), data.get("name"),
                data.get("payload"), data.get("readers"),
            )
        except SavedViewError as exc:
            return _error(exc)
        return Response(view, status=201)


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Saved Views"], summary="Get a saved view"),
    put=extend_schema(tags=["Tec-Tac Saved Views"], summary="Change a saved view (owner only)"),
    delete=extend_schema(tags=["Tec-Tac Saved Views"], summary="Delete a saved view (owner only)"),
)
class SavedViewDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [SavedViewWriteMinThrottle, SavedViewWriteDayThrottle]

    def get(self, request, view_id):
        try:
            return Response(get_view(request.user, view_id))
        except SavedViewError as exc:
            return _error(exc)

    def put(self, request, view_id):
        try:
            data = _body(request, _UPDATE_FIELDS)
            return Response(update_view(request.user, view_id, **data))
        except SavedViewError as exc:
            return _error(exc)

    def delete(self, request, view_id):
        try:
            delete_view(request.user, view_id)
        except SavedViewError as exc:
            return _error(exc)
        return Response(status=204)
