from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from . import module_preferences
from .module_preferences import ModulePreferenceError
from .session_security import SessionAuthenticated
from .throttles import ModulePreferenceWriteMinThrottle


def _error(exc: ModulePreferenceError) -> Response:
    return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Framework"], summary="List the current person's preferences for one module"),
)
class ModulePreferenceListView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, module_id):
        try:
            values = module_preferences._list_for(request.user, module_id=module_id)
        except ModulePreferenceError as exc:
            return _error(exc)
        return Response({"module_id": module_id, "preferences": values})


@extend_schema_view(
    put=extend_schema(tags=["Tec-Tac Framework"], summary="Set one of the current person's module preferences"),
    delete=extend_schema(tags=["Tec-Tac Framework"], summary="Delete one of the current person's module preferences"),
)
class ModulePreferenceDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [ModulePreferenceWriteMinThrottle]

    def put(self, request, module_id, name):
        data = request.data
        if not isinstance(data, dict) or set(data) != {"value"}:
            return Response(
                {"detail": 'The body must be a JSON object with exactly one key, "value".', "code": "invalid_value"},
                status=400,
            )
        try:
            value = module_preferences._set(
                request.user, name, data["value"], module_id=module_id, source=module_preferences.SOURCE_BROWSER,
            )
        except ModulePreferenceError as exc:
            return _error(exc)
        return Response({"module_id": module_id, "name": name, "value": value})

    def delete(self, request, module_id, name):
        try:
            deleted = module_preferences._delete(
                request.user, name, module_id=module_id, source=module_preferences.SOURCE_BROWSER,
            )
        except ModulePreferenceError as exc:
            return _error(exc)
        return Response({"module_id": module_id, "name": name, "deleted": deleted})
