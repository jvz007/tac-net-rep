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
    UNSET,
    create_client,
    create_site,
    delete_client,
    delete_site,
    get_agent,
    get_client,
    get_site,
    list_agents,
    list_clients,
    list_sites,
    list_custom_field_definitions,
    list_custom_fields,
    update_custom_fields,
    update_client,
    update_site,
    user_context,
)
from .session_security import SessionAuthenticated


_POLICY_BODY_KEYS = ("workstation_policy_id", "server_policy_id", "block_policy_inheritance")
# core.resources 1.11.0: the optional compare-and-set guard of a PATCH (never a change by itself)
_EXPECTED_BODY_KEYS = tuple(f"expected_{key}" for key in _POLICY_BODY_KEYS)


def _expected_kwargs(data: dict) -> dict:
    return {key: data.get(key, UNSET) for key in _EXPECTED_BODY_KEYS}


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


def _policy_filters(request):
    """The 1.7.0 list filters of clients and sites. Core validates them (a positive integer or 400)."""
    return {
        "alert_template_id": request.query_params.get("alert_template_id"),
        "policy_id": request.query_params.get("policy_id"),
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
                params.update(_policy_filters(request))
                return Response(list_clients(**params))
            if self.resource_type == "site":
                params["client_id"] = request.query_params.get("client_id")
                params.update(_policy_filters(request))
                return Response(list_sites(**params))
            if self.resource_type == "agent":
                params["client_id"] = request.query_params.get("client_id")
                params["site_id"] = request.query_params.get("site_id")
                # core.resources 1.12.0: absent is None, present but empty is refused by list_agents (a 400)
                params["sort_by"] = request.query_params.get("sort_by")
                params["sort_dir"] = request.query_params.get("sort_dir")
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
                data = _body(request, {"name", "site_name", "custom_fields"})
                if "name" not in data:
                    raise ResourceValidationError("name is required.")
                # site_name is the first site's name (core.resources 1.5.0); without it the site is named "Default Site"
                return Response(create_client(
                    name=data["name"],
                    site_name=data.get("site_name"),
                    custom_fields=data.get("custom_fields"),
                    context=context,
                ), status=201)
            if self.resource_type == "site":
                data = _body(request, {"name", "client_id", "custom_fields"})
                missing = [key for key in ("client_id", "name") if key not in data]
                if missing:
                    raise ResourceValidationError("Missing required field(s): " + ", ".join(missing))
                return Response(create_site(
                    client_id=data["client_id"], name=data["name"],
                    custom_fields=data.get("custom_fields"), context=context,
                ), status=201)
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
                data = _body(request, {"name", "alert_template_id", *_POLICY_BODY_KEYS, *_EXPECTED_BODY_KEYS})
                if not data:
                    raise ResourceValidationError("At least one of name, alert_template_id, workstation_policy_id, server_policy_id or block_policy_inheritance is required.")
                if "name" in data and data["name"] is None:
                    raise ResourceValidationError("name must be a string.")
                # alert_template_id and the policy ids: a positive integer sets, null clears (core.resources 1.4.0 and 1.7.0)
                return Response(update_client(
                    resource_id,
                    name=data.get("name"),
                    alert_template_id=data.get("alert_template_id", UNSET),
                    workstation_policy_id=data.get("workstation_policy_id", UNSET),
                    server_policy_id=data.get("server_policy_id", UNSET),
                    block_policy_inheritance=data.get("block_policy_inheritance", UNSET),
                    **_expected_kwargs(data),
                    context=context,
                ))
            if self.resource_type == "site":
                data = _body(request, {"name", "client_id", "alert_template_id", *_POLICY_BODY_KEYS, *_EXPECTED_BODY_KEYS})
                if not data:
                    raise ResourceValidationError("At least one of name, client_id, alert_template_id, workstation_policy_id, server_policy_id or block_policy_inheritance is required.")
                return Response(update_site(
                    resource_id,
                    name=data.get("name"),
                    client_id=data.get("client_id"),
                    alert_template_id=data.get("alert_template_id", UNSET),
                    workstation_policy_id=data.get("workstation_policy_id", UNSET),
                    server_policy_id=data.get("server_policy_id", UNSET),
                    block_policy_inheritance=data.get("block_policy_inheritance", UNSET),
                    **_expected_kwargs(data),
                    context=context,
                ))
            raise ResourceValidationError("This resource type is read-only.")
        except ResourceDirectoryError as exc:
            return _error_response(exc)

    @extend_schema(tags=["Tec-Tac Resources"], summary="Delete a Core-managed Tactical resource after optional agent relocation")
    def delete(self, request, resource_id):
        try:
            context = user_context(request.user)
            data = _body(request, {"move_to_site_id"})
            destination = data.get("move_to_site_id")
            if self.resource_type == "client":
                return Response(delete_client(resource_id, move_to_site_id=destination, context=context))
            if self.resource_type == "site":
                return Response(delete_site(resource_id, move_to_site_id=destination, context=context))
            raise ResourceValidationError("This resource type is read-only.")
        except ResourceDirectoryError as exc:
            return _error_response(exc)


class ResourceCustomFieldsView(APIView):
    permission_classes = [SessionAuthenticated]
    resource_type = ""

    @extend_schema(tags=["Tec-Tac Resources"], summary="List editable client/site custom-field definitions and values")
    def get(self, request, resource_id):
        try:
            return Response(list_custom_fields(
                self.resource_type,
                resource_id,
                context=user_context(request.user),
            ))
        except ResourceDirectoryError as exc:
            return _error_response(exc)

    @extend_schema(tags=["Tec-Tac Resources"], summary="Update client/site custom-field values")
    def patch(self, request, resource_id):
        try:
            data = _body(request, {"values"})
            if "values" not in data:
                raise ResourceValidationError("values is required.")
            return Response(update_custom_fields(
                self.resource_type,
                resource_id,
                values=data["values"],
                context=user_context(request.user),
            ))
        except ResourceDirectoryError as exc:
            return _error_response(exc)


class ResourceCustomFieldDefinitionsView(APIView):
    """GET /api/tfd/resources/custom-fields/?resource_type=client|site (core.resources 1.6.0, Core 1.17.23)."""

    permission_classes = (SessionAuthenticated,)

    @extend_schema(tags=["Tec-Tac Resources"], summary="List the client or site custom-field definitions with their defaults, before the object exists")
    def get(self, request):
        try:
            unknown = sorted(set(request.query_params) - {"resource_type"})
            if unknown:
                raise ResourceValidationError("Unsupported query parameter(s): " + ", ".join(unknown))
            return Response(list_custom_field_definitions(
                request.query_params.get("resource_type"),
                context=user_context(request.user),
            ))
        except ResourceDirectoryError as exc:
            return _error_response(exc)
