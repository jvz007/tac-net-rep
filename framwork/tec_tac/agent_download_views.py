"""GET /api/tfd/agent-downloads/<token>/ (Core 1.18.37, capability core.agent_downloads 1.0.0).

Serves the one file a verified module granted to the one device that asks. The device proves who it is with the same headers as the
endpoint websocket (Authorization: Token <Tactical agent token>, X-Agent-Id), checked by the same code (AD-54 E5) and counted by the same
failure limits. Every refusal is an empty body with a status code: nothing says which part failed. Never a redirect.

The view takes no Tec-Tac or Tactical authenticator (authentication_classes = []), so Tactical's Knox and API-key checks never see the agent
token and Tactical's audit middleware, which records only signed-in users, logs nothing for it. The link token is never logged: this file
logs reason codes only.
"""
from __future__ import annotations

import hmac
import logging

from django.http import FileResponse, HttpResponse
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from . import agent_downloads as ad
from . import endpoint_transport as et

logger = logging.getLogger("tec_tac.agent_downloads")


def _empty(status: int, retry_after: int | None = None) -> HttpResponse:
    response = HttpResponse(b"", status=status)
    response["Cache-Control"] = "no-store"
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response


def _scope(request) -> dict:
    """The few headers the endpoint transport's own checks read, as the websocket scope would carry them.

    X-Real-IP is deliberately not copied. nginx sets it only on Tactical's /ws/ location; the uwsgi location this route runs on never sets
    it, so a caller could choose it and rotate it to dodge the failure limit. The address is REMOTE_ADDR, which uwsgi_params fills from
    nginx's $remote_addr (1.18.37-fix)."""
    meta = request.META
    headers = []
    for header, key in (("authorization", "HTTP_AUTHORIZATION"), ("x-agent-id", "HTTP_X_AGENT_ID"),
                        ("x-forwarded-proto", "HTTP_X_FORWARDED_PROTO")):
        value = meta.get(key)
        if isinstance(value, str) and value:
            headers.append((header.encode("ascii"), value.encode("latin-1", "replace")))
    remote = meta.get("REMOTE_ADDR")
    return {"headers": headers, "client": (remote, 0) if isinstance(remote, str) and remote else None}


class _SlotFileResponse(FileResponse):
    """A file response that gives its serving slot back when it is closed, however the download ended."""

    def __init__(self, *args, release=None, **kwargs):
        self._release_slot = release
        super().__init__(*args, **kwargs)

    def close(self):
        try:
            super().close()
        finally:
            release, self._release_slot = self._release_slot, None
            if release is not None:
                release()


class AgentDownloadView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = []
    http_method_names = ["get"]

    def get(self, request, token):
        scope = _scope(request)
        if et.forwarded_plaintext(scope):
            return _empty(403)
        ip = et.client_ip(scope)
        if et.rate_limited(ip):
            return _empty(429, 60)
        key, agent_id, reason = et.parse_endpoint_headers(scope)
        result = None
        if reason is None:
            result = et.authenticate_endpoint_agent(key, agent_id)
            if result.transient:
                logger.warning("Agent download identity check unavailable.")
                return _empty(503, 30)
            if not result.ok:
                reason = result.reason or "refused"
        if reason is not None:
            limited = et.note_failed_check(ip, agent_id)
            ad.record_refusal(reason, agent_id, ip)
            return _empty(429, 60) if limited else _empty(401)
        return self._serve(token, result.agent_id or agent_id, ip)

    def _serve(self, token, agent_id, ip):
        try:
            grant = ad.load_grant(token)
        except Exception:
            logger.warning("Agent download grant store unavailable.")
            return _empty(503, 30)
        if grant is None or not hmac.compare_digest(str(grant.get("agent_id", "")).encode("utf-8"), agent_id.encode("utf-8")):
            return _empty(404)
        try:
            if not ad.acquire_slot():
                return _empty(503, 30)
        except Exception:
            logger.warning("Agent download slot store unavailable.")
            return _empty(503, 30)
        try:
            handle, size, reason = ad.open_verified(grant["module_id"], grant["path"], grant["sha256"], grant["size"])
            if reason:
                logger.warning("Agent download file refused (%s).", reason)
                ad.drop_grant(token, grant)
                ad.release_slot()
                return _empty(404)
        except Exception:
            logger.warning("Agent download file could not be read.")
            ad.release_slot()
            return _empty(503, 30)
        try:
            ad.record_served(grant, agent_id, ip)
        except Exception:
            logger.warning("Agent download audit row could not be written; nothing was sent.")
            handle.close()
            ad.release_slot()
            return _empty(503, 30)
        try:
            response = _SlotFileResponse(handle, content_type="application/octet-stream", release=ad.release_slot)
        except Exception:
            handle.close()
            ad.release_slot()
            return _empty(503, 30)
        response["Content-Length"] = str(size)
        response["Content-Disposition"] = f'attachment; filename="{ad.safe_file_name(grant["path"])}"'
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
