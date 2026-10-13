"""POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/ (Core 1.17.31, C4).

The browser sends exactly {agent_id} and gets a single-use, 30 second ticket for the socket /ws/tfd/agent-terminal/<ticket>/. The
checks and the store are in tec_tac.tactical_websocket. The body is {agent_id} and nothing else; any other key is refused 400.
"""
from __future__ import annotations

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .session_security import SessionAuthenticated
from .tactical_websocket import TicketRefusal, issue_ticket
from .throttles import TacticalWebSocketTicketDayThrottle, TacticalWebSocketTicketMinThrottle


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Issue a single-use ticket for a Tactical terminal socket"))
class TacticalWebSocketTicketView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [TacticalWebSocketTicketMinThrottle, TacticalWebSocketTicketDayThrottle]
    parser_classes = (JSONParser,)

    def post(self, request, module_id, kind):
        payload = request.data
        if not isinstance(payload, dict) or set(payload) != {"agent_id"}:
            return Response({"detail": "The request must be a JSON object with only agent_id.", "code": "invalid_ticket_request"}, status=400)
        try:
            ticket = issue_ticket(request, module_id=module_id, kind=kind, agent_id=payload.get("agent_id"))
        except TicketRefusal as exc:
            return Response({"detail": exc.message, "code": exc.code}, status=exc.status)
        return Response(ticket, status=201)
