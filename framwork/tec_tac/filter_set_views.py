from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from . import filter_sets
from .filter_sets import FilterSetError, FilterSetValidationError
from .session_security import SessionAuthenticated
from .throttles import FilterSetWriteDayThrottle, FilterSetWriteMinThrottle, FilterValuesMinThrottle

_CREATE_FIELDS = {"module_id", "view_key", "name", "definition", "readers"}
_UPDATE_FIELDS = {"module_id", "view_key", "name", "definition", "readers"}
_TAG = "Tec-Tac · Filter Sets"


def _error(exc: FilterSetError) -> Response:
    return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)


def _body(request, allowed: set[str]) -> dict:
    data = request.data
    if not isinstance(data, dict):
        raise FilterSetValidationError("A filter set must be a JSON object.")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise FilterSetValidationError("Unknown filter set field(s): " + ", ".join(unknown))
    return data


def _reader_fields(user, module_id) -> list | None:
    """The person's own filter fields, read only to decide which rule values another person's set may show them (1.17.51). A provider
    that is missing or fails gives None: every value of a set the person does not own is then withheld, and the read never fails."""
    try:
        return filter_sets.person_fields(user, module_id)
    except (filter_sets.FilterSetNoProvider, filter_sets.FilterSetProviderError):
        return None


def _needs_fields(sets: list) -> bool:
    return any(not row["mine"] and row["values_withheld"] > 0 for row in sets)


@extend_schema_view(
    get=extend_schema(tags=[_TAG], summary="List the filter sets the current user can read for a module and view key"),
    post=extend_schema(tags=[_TAG], summary="Save a filter set"),
)
class FilterSetListCreateView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [FilterSetWriteMinThrottle, FilterSetWriteDayThrottle]

    def get(self, request):
        try:
            module, view_key = request.query_params.get("module"), request.query_params.get("view_key")
            sets = filter_sets.list_filter_sets(request.user, module, view_key)
            if _needs_fields(sets):
                sets = filter_sets.list_filter_sets(request.user, module, view_key, fields=_reader_fields(request.user, module))
        except FilterSetError as exc:
            return _error(exc)
        return Response({"filter_sets": sets, "count": len(sets)})

    def post(self, request):
        try:
            data = _body(request, _CREATE_FIELDS)
            # The person's own declared fields come from the module's provider, read for this person only.
            fields = filter_sets.person_fields(request.user, data.get("module_id"))
            created = filter_sets.create_filter_set(
                request.user, data.get("module_id"), data.get("view_key"), data.get("name"), data.get("definition"),
                data.get("readers"), fields=fields,
            )
        except FilterSetError as exc:
            return _error(exc)
        return Response(created, status=201)


@extend_schema_view(
    get=extend_schema(tags=[_TAG], summary="Get a filter set"),
    put=extend_schema(tags=[_TAG], summary="Change a filter set (owner only)"),
    delete=extend_schema(tags=[_TAG], summary="Delete a filter set (owner only)"),
)
class FilterSetDetailView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [FilterSetWriteMinThrottle, FilterSetWriteDayThrottle]

    def get(self, request, set_id):
        try:
            found = filter_sets.get_filter_set(request.user, set_id)
            if _needs_fields([found]):
                found = filter_sets.get_filter_set(request.user, set_id, fields=_reader_fields(request.user, found["module_id"]))
            return Response(found)
        except FilterSetError as exc:
            return _error(exc)

    def put(self, request, set_id):
        try:
            data = _body(request, _UPDATE_FIELDS)
            kwargs = dict(data)
            current = filter_sets.get_filter_set(request.user, set_id)  # a set the person cannot read is 404 here
            if not current["mine"]:
                # Before any provider call: a reader's change never reaches the module (and a failing provider cannot turn it into a 502).
                raise filter_sets.FilterSetPermissionDenied("Only the owner can change this filter set.")
            if "definition" in data:
                kwargs["fields"] = filter_sets.person_fields(request.user, current["module_id"])
            return Response(filter_sets.update_filter_set(request.user, set_id, **kwargs))
        except FilterSetError as exc:
            return _error(exc)

    def delete(self, request, set_id):
        try:
            filter_sets.delete_filter_set(request.user, set_id)
        except FilterSetError as exc:
            return _error(exc)
        return Response(status=204)


@extend_schema_view(get=extend_schema(tags=[_TAG], summary="The fields the current user may filter on in a module, with their operators"))
class FilterSetFieldsView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [FilterValuesMinThrottle]

    def get(self, request):
        module = request.query_params.get("module")
        try:
            try:
                fields = filter_sets.person_fields(request.user, module)
                available = True
            except filter_sets.FilterSetNoProvider:
                fields, available = [], False
        except FilterSetError as exc:
            return _error(exc)
        return Response({
            "module": str(module), "available": available, "fields": filter_sets.browser_fields(fields),
            "operators": [{"id": key, "label": label} for key, label in filter_sets.OPERATORS.items()],
            "date_operators": filter_sets.operators_for("date"),
            "number_operators": filter_sets.operators_for("number"),
            "relative_units": [{"id": unit, "max_amount": most} for unit, most in filter_sets.RELATIVE_UNITS.items()],
            "limits": filter_sets.filter_sets_contract_metadata()["limits"],
        })


@extend_schema_view(get=extend_schema(tags=[_TAG], summary="Search the values of a filter field for an Equals picker, inside the user's scope"))
class FilterValuesView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [FilterValuesMinThrottle]

    def get(self, request):
        params = request.query_params
        try:
            answer = filter_sets.filter_values(
                request.user, params.get("module"), params.get("field"), params.get("search", ""), params.get("page", 1),
            )
        except FilterSetError as exc:
            return _error(exc)
        return Response(answer)
