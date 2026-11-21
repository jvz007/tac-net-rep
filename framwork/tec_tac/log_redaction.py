"""Keep the agent download link token out of every log file (Core 1.18.38).

Django's ``django.request`` logger writes a line for every 4xx and 5xx answer, and it formats the request path into the message
(``Service Unavailable: /api/tfd/agent-downloads/<token>/``) and keeps the request on the record. The link token is the second key of a
download, so it must not reach ``django_debug.log`` or any other handler Tactical's settings attach.

``AgentDownloadTokenFilter`` is a filter on the logger itself, so it runs before any handler. It rewrites the message, the arguments and the
request attached to the record. The real request object is never changed: the record gets a thin read-only wrapper. A record without the
route passes through as the same object. The filter never drops a record, so the status of every answer stays logged.
"""
from __future__ import annotations

import logging
import re

TOKEN_PATH_RE = re.compile(r"(/api/tfd/agent-downloads/)[^/\s'\"?#]+")
REDACTED = "<redacted>"
LOGGER_NAME = "django.request"
_PATH_ATTRS = ("path", "path_info")
_PATH_CALLS = ("get_full_path", "get_full_path_info")


def redact(text):
    """The text with the token segment of the download route replaced. Anything that is not a string is returned unchanged."""
    if not isinstance(text, str) or "/agent-downloads/" not in text:
        return text
    return TOKEN_PATH_RE.sub(lambda m: m.group(1) + REDACTED, text)


def _redact_value(value):
    """A log argument with the token removed; the same object when there was nothing to remove."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, tuple):
        new = tuple(_redact_value(item) for item in value)
        return new if any(a is not b for a, b in zip(new, value)) else value
    if isinstance(value, dict):
        new = {key: _redact_value(item) for key, item in value.items()}
        return new if any(new[key] is not value[key] for key in value) else value
    return value


class _RedactedRequest:
    """A read-only view of a request whose path attributes hide the link token. Everything else is the real request's."""

    def __init__(self, request):
        object.__setattr__(self, "_real", request)

    def __getattr__(self, name):
        value = getattr(object.__getattribute__(self, "_real"), name)
        if name in _PATH_ATTRS and isinstance(value, str):
            return redact(value)
        if name in _PATH_CALLS and callable(value):
            return lambda *args, **kwargs: redact(value(*args, **kwargs))
        return value

    def __setattr__(self, name, value):
        raise AttributeError("a redacted request is read-only")

    def __repr__(self):
        return redact(repr(object.__getattribute__(self, "_real")))

    __str__ = __repr__


def _carries_token(request) -> bool:
    for name in _PATH_ATTRS:
        value = getattr(request, name, None)
        if isinstance(value, str) and "/agent-downloads/" in value and redact(value) != value:
            return True
    for name in _PATH_CALLS:
        call = getattr(request, name, None)
        if callable(call):
            try:
                value = call()
            except Exception:
                continue
            if isinstance(value, str) and redact(value) != value:
                return True
    return False


class AgentDownloadTokenFilter(logging.Filter):
    """Redacts /api/tfd/agent-downloads/<token>/ in the message, the arguments and the request of a record. Always lets the record through."""

    def filter(self, record):
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                record.args = _redact_value(record.args)
            request = getattr(record, "request", None)
            if request is not None and not isinstance(request, _RedactedRequest) and _carries_token(request):
                record.request = _RedactedRequest(request)
        except Exception:  # a logging filter must never break the request or lose the record
            pass
        return True


def install_log_redaction() -> None:
    """Add the filter to the ``django.request`` logger once (a second call adds nothing)."""
    target = logging.getLogger(LOGGER_NAME)
    if not any(isinstance(item, AgentDownloadTokenFilter) for item in target.filters):
        target.addFilter(AgentDownloadTokenFilter())
