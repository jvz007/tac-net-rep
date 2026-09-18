from __future__ import annotations

from django.http import HttpResponse
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .contracts import build_contract_catalog, render_markdown, render_text
from .views import _role_for_user


def _require_contract_access(user):
    role = _role_for_user(user)
    allowed = (
        bool(getattr(user, "is_superuser", False))
        or bool(getattr(role, "is_superuser", False) if role else False)
        or bool(getattr(role, "can_do_server_maint", False) if role else False)
    )
    if not allowed:
        raise PermissionDenied("Developer contract catalog requires server-maintenance authority.")


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Developer Contracts"], summary="List live public development contracts"))
class ContractCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_contract_access(request.user)
        return Response(build_contract_catalog())


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Developer Contracts"], summary="Export live public development contracts"))
class ContractExportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_contract_access(request.user)
        export_format = str(request.query_params.get("format") or "md").strip().lower()
        if export_format not in {"md", "txt"}:
            return Response({"detail": "format must be md or txt."}, status=400)
        catalog = build_contract_catalog()
        if export_format == "md":
            body = render_markdown(catalog)
            content_type = "text/markdown; charset=utf-8"
        else:
            body = render_text(catalog)
            content_type = "text/plain; charset=utf-8"
        version = catalog.get("framework_version") or "unknown"
        response = HttpResponse(body, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="tec-tac-public-contracts-{version}.{export_format}"'
        response["Cache-Control"] = "no-store"
        return response
