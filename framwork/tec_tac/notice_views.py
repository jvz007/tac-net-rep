from __future__ import annotations

from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .notices import (
    NoticeError,
    clear_read,
    list_notices,
    mark_all_read,
    mark_read,
    store_notice,
    serialize_notice,
    unread_count,
)
from .session_security import SessionAuthenticated


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Notices"], summary="List current user's notice history"),
    post=extend_schema(tags=["Tec-Tac Notices"], summary="Persist a user-visible notice"),
)
class NoticeListCreateView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        unread_only = str(request.query_params.get("state") or "").lower() == "unread"
        rows = list_notices(request.user, unread_only=unread_only, limit=request.query_params.get("limit", 50))
        return Response({"notices": rows, "count": len(rows), "unread_count": unread_count(request.user)})

    def post(self, request):
        try:
            row, created = store_notice(request.user, request.data)
        except NoticeError as exc:
            return Response({"detail": str(exc)}, status=400)
        return Response(
            {"notice": serialize_notice(row), "unread_count": unread_count(request.user)},
            status=201 if created else 200,
        )


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Notices"], summary="Mark one notice read"))
class NoticeReadView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, notice_id):
        mark_read(request.user, notice_id)
        return Response({"ok": True, "unread_count": unread_count(request.user)})


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Notices"], summary="Mark all notices read"))
class NoticeReadAllView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        changed = mark_all_read(request.user)
        return Response({"ok": True, "changed": changed, "unread_count": 0})


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac Notices"], summary="Clear read notice history"))
class NoticeClearReadView(APIView):
    permission_classes = [SessionAuthenticated]

    def delete(self, request):
        deleted = clear_read(request.user)
        return Response({"ok": True, "deleted": deleted, "unread_count": unread_count(request.user)})
