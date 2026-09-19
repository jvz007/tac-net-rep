from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .dashboards import (
    DashboardValidationError,
    can_edit_dashboard,
    dashboard_payload,
    get_visible_dashboard,
    normalize_dashboard_payload,
    visible_dashboards,
)
from .models import TecTacDashboard


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Dashboards"], summary="List dashboards visible to the current user"),
    post=extend_schema(tags=["Tec-Tac Dashboards"], summary="Create a dashboard"),
)
class DashboardListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        dashboards = [dashboard_payload(item, request.user) for item in visible_dashboards(request.user)]
        return Response({"dashboards": dashboards, "count": len(dashboards)})

    def post(self, request):
        try:
            values = normalize_dashboard_payload(request.data)
        except DashboardValidationError as exc:
            return Response({"detail": str(exc)}, status=400)
        dashboard = TecTacDashboard.objects.create(owner=request.user, **values)
        dashboard = TecTacDashboard.objects.select_related("owner").get(pk=dashboard.pk)
        return Response(dashboard_payload(dashboard, request.user), status=201)


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Dashboards"], summary="Get a dashboard"),
    put=extend_schema(tags=["Tec-Tac Dashboards"], summary="Update a dashboard"),
    delete=extend_schema(tags=["Tec-Tac Dashboards"], summary="Delete a dashboard"),
)
class DashboardDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get(self, request, dashboard_id):
        try:
            return get_visible_dashboard(request.user, dashboard_id)
        except DashboardValidationError as exc:
            return Response({"detail": str(exc)}, status=404)

    def get(self, request, dashboard_id):
        dashboard = self._get(request, dashboard_id)
        if isinstance(dashboard, Response):
            return dashboard
        return Response(dashboard_payload(dashboard, request.user))

    def put(self, request, dashboard_id):
        dashboard = self._get(request, dashboard_id)
        if isinstance(dashboard, Response):
            return dashboard
        if not can_edit_dashboard(request.user, dashboard):
            return Response({"detail": "You do not have permission to edit this dashboard."}, status=403)
        try:
            values = normalize_dashboard_payload(request.data, current=dashboard)
        except DashboardValidationError as exc:
            return Response({"detail": str(exc)}, status=400)
        if dashboard.owner_id != request.user.id and values.get("visibility", dashboard.visibility) != dashboard.visibility:
            return Response({"detail": "Only the dashboard owner may change shared/private visibility."}, status=403)
        for key, value in values.items():
            setattr(dashboard, key, value)
        dashboard.save(update_fields=["name", "visibility", "layout", "updated_at"])
        return Response(dashboard_payload(dashboard, request.user))

    def delete(self, request, dashboard_id):
        dashboard = self._get(request, dashboard_id)
        if isinstance(dashboard, Response):
            return dashboard
        if not can_edit_dashboard(request.user, dashboard):
            return Response({"detail": "You do not have permission to delete this dashboard."}, status=403)
        dashboard.delete()
        return Response(status=204)
