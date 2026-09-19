from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .preferences import (
    PreferenceValidationError,
    get_user_preferences,
    reset_user_preferences,
    save_user_preferences,
)


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Framework"], summary="Get current Tec-Tac user preferences"),
    put=extend_schema(tags=["Tec-Tac Framework"], summary="Replace current Tec-Tac user preferences"),
    delete=extend_schema(tags=["Tec-Tac Framework"], summary="Reset current Tec-Tac user preferences"),
)
class UserPreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        preferences, initialized, updated_at = get_user_preferences(request.user)
        return Response({
            "preferences": preferences,
            "initialized": initialized,
            "updated_at": updated_at,
        })

    def put(self, request):
        payload = request.data.get("preferences", request.data)
        try:
            preferences, updated_at = save_user_preferences(request.user, payload)
        except PreferenceValidationError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response({
            "preferences": preferences,
            "initialized": True,
            "updated_at": updated_at,
        })

    def delete(self, request):
        preferences = reset_user_preferences(request.user)
        return Response({
            "preferences": preferences,
            "initialized": False,
            "updated_at": None,
        })
