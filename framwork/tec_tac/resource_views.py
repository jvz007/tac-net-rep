from __future__ import annotations

from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from .resources import (
    ResourceDirectoryError,
    ResourceNotFound,
    ResourcePermissionDenied,
    ResourceValidationError,
    get_agent,
    get_client,
    get_site,
    list_agents,
    list_clients,
    list_sites,
    user_context,
)
from .session_security import SessionAuthenticated


def _error_response(exc: ResourceDirectoryError):
    if isinstance(exc, ResourcePermissionDenied):
        status = 403
    elif isinstance(exc, ResourceNotFound):
        status = 404
    else:
        status = 400
    return Response({"detail": str(exc), "code": exc.code}, status=status)


def _common(request):
    return {
        "context": user_context(request.user),
        "search": request.query_params.get("search"),
        "active": request.query_params.get("active"),
        "page": request.query_params.get("page", 1),
        "page_size": request.query_params.get("page_size", 100),
    }


class ResourceListView(APIView):
    permission_classes = [SessionAuthenticated]
    resource_type = ""

    @extend_schema(tags=["Tec-Tac Resources"], summary="List scoped Core resources")
    def get(self, request):
        try:
            params = _common(request)
            if self.resource_type == "client":
                return Response(list_clients(**params))
            if self.resource_type == "site":
                params["client_id"] = request.query_params.get("client_id")
                return Response(list_sites(**params))
            if self.resource_type == "agent":
                params["client_id"] = request.query_params.get("client_id")
                params["site_id"] = request.query_params.get("site_id")
                return Response(list_agents(**params))
            raise ResourceValidationError("Unsupported resource type.")
        except ResourceDirectoryError as exc:
            return _error_response(exc)


class ResourceDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    resource_type = ""

    @extend_schema(tags=["Tec-Tac Resources"], summary="Resolve one scoped Core resource")
    def get(self, request, resource_id):
        try:
            context = user_context(request.user)
            if self.resource_type == "client":
                return Response(get_client(resource_id, context=context))
            if self.resource_type == "site":
                return Response(get_site(resource_id, context=context))
            if self.resource_type == "agent":
                return Response(get_agent(resource_id, context=context))
            raise ResourceValidationError("Unsupported resource type.")
        except ResourceDirectoryError as exc:
            return _error_response(exc)
