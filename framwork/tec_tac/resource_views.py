from __future__ import annotations

from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from .resources import (
    ResourceConflict,
    ResourceDirectoryError,
    ResourceNotFound,
    ResourcePermissionDenied,
    ResourceValidationError,
    create_client,
    create_site,
    get_agent,
    get_client,
    get_site,
    list_agents,
    list_clients,
    list_sites,
    update_client,
    update_site,
    user_context,
)
from .session_security import SessionAuthenticated


def _error_response(exc: ResourceDirectoryError):
    if isinstance(exc, ResourcePermissionDenied):
        status = 403
    elif isinstance(exc, ResourceNotFound):
        status = 404
    elif isinstance(exc, ResourceConflict):
        status = 409
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


def _body(request, allowed: set[str]) -> dict:
    data = request.data
    if not isinstance(data, dict):
        raise ResourceValidationError("Request body must be a JSON object.")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ResourceValidationError("Unsupported field(s): " + ", ".join(unknown))
    return dict(data)


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


class ResourceMutableListView(ResourceListView):
    @extend_schema(tags=["Tec-Tac Resources"], summary="List scoped Core resources")
    def get(self, request):
        return super().get(request)

    @extend_schema(tags=["Tec-Tac Resources"], summary="Create a Core-managed Tactical resource")
    def post(self, request):
        try:
            context = user_context(request.user)
            if self.resource_type == "client":
                data = _body(request, {"name"})
                if "name" not in data:
                    raise ResourceValidationError("name is required.")
                return Response(create_client(name=data["name"], context=context), status=201)
            if self.resource_type == "site":
                data = _body(request, {"name", "client_id"})
                missing = [key for key in ("client_id", "name") if key not in data]
                if missing:
                    raise ResourceValidationError("Missing required field(s): " + ", ".join(missing))
                return Response(create_site(client_id=data["client_id"], name=data["name"], context=context), status=201)
            raise ResourceValidationError("This resource type is read-only.")
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


class ResourceMutableDetailView(ResourceDetailView):
    @extend_schema(tags=["Tec-Tac Resources"], summary="Resolve one scoped Core resource")
    def get(self, request, resource_id):
        return super().get(request, resource_id)

    @extend_schema(tags=["Tec-Tac Resources"], summary="Update a Core-managed Tactical resource")
    def patch(self, request, resource_id):
        try:
            context = user_context(request.user)
            if self.resource_type == "client":
                data = _body(request, {"name"})
                if "name" not in data:
                    raise ResourceValidationError("name is required.")
                return Response(update_client(resource_id, name=data["name"], context=context))
            if self.resource_type == "site":
                data = _body(request, {"name", "client_id"})
                if not data:
                    raise ResourceValidationError("At least one of name or client_id is required.")
                return Response(update_site(
                    resource_id,
                    name=data.get("name"),
                    client_id=data.get("client_id"),
                    context=context,
                ))
            raise ResourceValidationError("This resource type is read-only.")
        except ResourceDirectoryError as exc:
            return _error_response(exc)
