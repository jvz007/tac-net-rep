"""Read route of a result check (Core 1.18.44, core.result_checks 1.0.0): GET /api/tfd/ui/result-checks/<id>/.

Only the person who started the check may read it. A missing id, a check of another person (a superuser included), a check past its
30-day retention and an inactive person all answer the same 404, so the route never says whether a check exists. The answer holds states,
exit codes and hostnames, never output text, the module's job reference, the reader id or a module id. Success bodies use ``message``.
"""
from __future__ import annotations

from datetime import timedelta

from django.utils import timezone
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.response import Response
from rest_framework.views import APIView

from . import result_checks
from .session_security import SessionAuthenticated

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
NOT_FOUND = {"detail": "Not found."}


def _not_found():
    return Response(dict(NOT_FOUND), status=404)


def _positive_int(value, *, default: int, maximum: int | None = None):
    """The query value as a positive whole number, the default when it is absent, or None when it is not one."""
    if value in (None, ""):
        return default
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or int(text) < 1 or (maximum is not None and int(text) > maximum):
        return None
    return int(text)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Result Checks"], summary="Read one result check of the current user"))
class ResultCheckView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, check_id):
        from .models import TecTacResultCheck, TecTacResultCheckItem

        user = request.user
        if not getattr(user, "is_active", False):
            return _not_found()
        page = _positive_int(request.query_params.get("page"), default=1)
        page_size = _positive_int(request.query_params.get("page_size"), default=DEFAULT_PAGE_SIZE, maximum=MAX_PAGE_SIZE)
        row = TecTacResultCheck.objects.filter(pk=check_id, user=user).first()
        now = timezone.now()
        if row is None or (row.closed_at is not None and row.closed_at < now - timedelta(days=result_checks.RETENTION_DAYS)):
            return _not_found()
        if page is None or page_size is None:
            return Response({"detail": f"page must be a positive whole number and page_size a whole number from 1 to {MAX_PAGE_SIZE}."}, status=400)
        counts = result_checks.summarise(TecTacResultCheckItem.objects.filter(check_id=row.pk).values_list("state", flat=True))
        offset = (page - 1) * page_size
        rows = TecTacResultCheckItem.objects.filter(check_id=row.pk).order_by("hostname", "endpoint_id")[offset:offset + page_size]
        total = counts["total"]
        return Response({
            "id": str(row.pk),
            "label": row.label,
            "status": row.status,
            "created_at": row.created_at.isoformat(),
            "closed_at": row.closed_at.isoformat() if row.closed_at else None,
            "deadline_at": row.deadline_at.isoformat(),
            "summary": counts,
            "message": result_checks.status_message(row.status, row.label, counts),
            "items": [{"endpoint_id": item.endpoint_id, "hostname": item.hostname, "state": item.state, "exit_code": item.exit_code} for item in rows],
            "count": total,
            "page": page,
            "page_size": page_size,
            "next_page": page + 1 if offset + page_size < total else None,
        })
