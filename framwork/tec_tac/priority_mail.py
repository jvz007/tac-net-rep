"""Core's own Priority 1 email, sent through Tactical's own sender (AD-28 amendment, Johan chose (c) on 13 October 2026).

Core sends mail for one reason: a module job failed and the Tec-Tac administrators should know. The message goes out through
Tactical's ``CoreSettings.send_mail``, called in process, the same sender Tactical uses for its own alerts. This file is the only
place Core touches Tactical's mail. Its Tactical touches are small:

* ``is_configured()``: Tactical's own ``email_is_configured`` property, a yes or no. Core never reads the SMTP password or any other
  mail setting to decide this.
* ``smtp_host()``: the one Tactical field Core reads, the mail server's name. Core needs it to judge where the name points before
  Tactical connects (``public_refusal``). No other mail field is read.
* ``send_one()``: one message to one address with ``test=True``, so Tactical reports a failed send as False instead of swallowing
  it. Tactical's returned text can name the host or the account, so it is never logged, returned or stored here.

No SMTP client, no second mail system and no fallback live here. Who gets a message, the hourly cap, the marker rows and the audit
row are in module_failure_notices.py.

Accepted trade-offs (AD-28): Tactical resolves the mail server's name again when it connects, so a name that changes its answer
between the two lookups is not covered; there is no certificate pinning, because Tactical connects with its own code; Tactical's own
debug log keeps the text of a failed send.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket

logger = logging.getLogger("tec_tac.priority_mail")

HOURLY_CAP = 20
MAX_RECIPIENTS = 20
ADDRESS_MAX = 254
REFUSED = "mail_host_refused"

NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
# Cloud instance-metadata endpoints. 169.254.169.254 is also link-local; the others are not.
METADATA_ADDRESSES = frozenset({"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"})
_PRINTABLE_NO_SPACE = re.compile(r"[\x21-\x7e]+")
_NOT_IN_AN_ADDRESS = frozenset(',;<>"\'')


def clean_address(value) -> str | None:
    """The address to send to, or None. One plain mailbox: printable ASCII with no space or control character, no comma, semicolon,
    angle bracket or quote (Tactical joins the recipients with ', ', so a comma would add a recipient), exactly one @ with text on
    both sides, and at most 254 characters."""
    text = str(value or "").strip()
    if not text or len(text) > ADDRESS_MAX or not _PRINTABLE_NO_SPACE.fullmatch(text):
        return None
    if _NOT_IN_AN_ADDRESS.intersection(text) or text.count("@") != 1:
        return None
    local, _, domain = text.partition("@")
    if not local or not domain:
        return None
    return text


def _embedded_ipv4(ip):
    """The IPv4 address an IPv6 address carries (IPv4-mapped, NAT64 or 6to4), or the address itself."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in NAT64_PREFIX:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def refused_reason(address: str) -> str | None:
    """Why Core must not hand the mail to this address, or None. The rule of globalsettings' address check, written here: cloud
    metadata, loopback, link-local, unspecified, multicast, and anything not globally routable. An embedded IPv4 address (IPv4-mapped,
    NAT64, 6to4) is judged by the IPv4 address it carries."""
    raw = ipaddress.ip_address(address)
    if str(raw) in METADATA_ADDRESSES:
        return "metadata"
    ip = _embedded_ipv4(raw)
    if str(ip) in METADATA_ADDRESSES:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if not ip.is_global:
        return "not public"
    return None


def resolve_addresses(name: str) -> list[str]:
    """Every address the name resolves to. Raises OSError or UnicodeError when it does not resolve. Nothing is connected to."""
    infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


def public_refusal(host) -> str | None:
    """REFUSED when the mail server's name is empty, does not resolve, or resolves to any address that is not public. None when every
    address it resolves to is public. The name is never logged; only the reason category is."""
    name = str(host or "").strip()
    if not name:
        return REFUSED
    try:
        addresses = resolve_addresses(name)
    except (OSError, UnicodeError, ValueError):
        return REFUSED
    if not addresses:
        return REFUSED
    for address in addresses:
        try:
            reason = refused_reason(address)
        except ValueError:
            return REFUSED
        if reason:
            logger.warning("Priority 1 email not sent: the mail server name points at a %s address.", reason)
            return REFUSED
    return None


def is_configured() -> bool:
    """Tactical's own answer to 'is email set up': a yes or no. Core never reads the password."""
    from tacticalrmm.utils import get_core_settings

    return bool(get_core_settings().email_is_configured)


def smtp_host() -> str:
    """The mail server's name, the one Tactical field Core reads (for the public-address check)."""
    from tacticalrmm.utils import get_core_settings

    return str(get_core_settings().smtp_host or "")


def send_one(address: str, subject: str, body: str) -> bool:
    """Send one message to one address through Tactical's sender. True only when Tactical reports success.

    ``test=True`` makes Tactical report a failed send. Without it Tactical swallows the error and still answers ok. Tactical's returned
    text is discarded here: it can name the host or the account."""
    from tacticalrmm.utils import get_core_settings

    try:
        _text, ok = get_core_settings().send_mail(subject, body, override_recipients=[address], test=True)
    except Exception as exc:
        logger.warning("Priority 1 email failed to send (%s).", exc.__class__.__name__)
        return False
    return ok is True
