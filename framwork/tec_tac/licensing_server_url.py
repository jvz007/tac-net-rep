"""The Licensing Server address, read-only (1.17.99, AD-56).

The address is the root-owned key TEC_TAC_LICENSING_SERVER_URL in /opt/tec-tac/etc/tec-tac.conf. Nothing on the web can change it, so
no administrator account can point a server's licence traffic at another host. Core only reads it: Core holds no Licensing Server
credentials and makes no call to that server (AD-56). The Licensing module is the only client; it asks Core for this address.

A value that is not usable (not https, user info, a query or fragment, no host, a bad port, control characters) is treated as not set
and the reason is logged once per distinct value. The default is the origin the seeded repository already uses.
"""
from __future__ import annotations

import logging
import os
import re
import urllib.parse
from pathlib import Path

CONFIG_KEY = "TEC_TAC_LICENSING_SERVER_URL"
DEFAULT_LICENSING_SERVER_URL = "https://lic-service.tec-tac.techxflow.net.za"
MAX_URL_LENGTH = 512
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_BAD_CHARACTERS = re.compile(r"[\x00-\x20\x7f-\x9f\\]")

logger = logging.getLogger("tec_tac.licensing_server_url")
_logged_reasons: set[str] = set()


def _config_file() -> Path:
    return Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))


def validate_licensing_server_url(value: object) -> tuple[str | None, str | None]:
    """Return (normalised address, None) or (None, plain reason). The address has no trailing slash, query, fragment or user info."""
    text = str(value or "").strip()
    if not text:
        return None, "the value is empty"
    if len(text) > MAX_URL_LENGTH:
        return None, "the value is too long"
    if _BAD_CHARACTERS.search(text):
        return None, "the value holds spaces, control characters or a backslash"
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        return None, "the value is not a valid address or its port is invalid"
    if parsed.scheme.lower() != "https":
        return None, "only https addresses are accepted"
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None, "the address must not hold a user name or password"
    if parsed.query or "?" in text:
        return None, "the address must not hold a query"
    if parsed.fragment or "#" in text:
        return None, "the address must not hold a fragment"
    host = parsed.hostname or ""
    if not host:
        return None, "the address has no host"
    if ":" not in host and not _HOST_RE.fullmatch(host):
        return None, "the host name is not valid"
    if ";" in parsed.path:
        return None, "the address must not hold path parameters"
    if any(part in {".", ".."} for part in parsed.path.split("/")):
        return None, "the path must not hold dot segments"
    rendered_host = f"[{host}]" if ":" in host else host.lower()
    authority = rendered_host if port in (None, 443) else f"{rendered_host}:{port}"
    return f"https://{authority}{parsed.path.rstrip('/')}", None


def _read_configured_value() -> str | None:
    path = _config_file()
    try:
        if not path.is_file():
            return None
        found = None
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == CONFIG_KEY:
                found = value.strip()  # the last line wins, as for every other key
        return found
    except (OSError, UnicodeDecodeError):
        return None


def get_licensing_server_url() -> dict:
    """The Licensing Server address for the Licensing module (read-only, no network call).

    Returns {url, source, configured, reason}. source is config (a valid root-owned value) or default (unset or invalid). reason is
    null for a valid value or an unset key, and a plain sentence when a configured value was refused. The address holds no secret.
    """
    raw = _read_configured_value()
    if raw is None or raw == "":
        return {"url": DEFAULT_LICENSING_SERVER_URL, "source": "default", "configured": False, "reason": None}
    url, reason = validate_licensing_server_url(raw)
    if url is None:
        marker = f"{reason}|{len(raw)}"
        if marker not in _logged_reasons:
            _logged_reasons.add(marker)
            logger.warning("%s in tec-tac.conf is not used: %s. The default address applies.", CONFIG_KEY, reason)
        return {
            "url": DEFAULT_LICENSING_SERVER_URL,
            "source": "default",
            "configured": False,
            "reason": f"{CONFIG_KEY} is not used: {reason}. The default address applies.",
        }
    return {"url": url, "source": "config", "configured": True, "reason": None}
