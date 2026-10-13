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

Private relay (1.17.26, AD-30): an administrator may switch on ``priority_mail_private_relay`` (off by default). With it on, and only
when the call is Core's own, ``host_refusal`` accepts a mail server that resolves to ordinary private-network addresses. Cloud
metadata, loopback, link-local, unspecified, multicast and a name that does not resolve stay refused. A module never gets this path.

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
# Ordinary private-network ranges the relaxed rule accepts (AD-30): 10/8, 172.16/12, 192.168/16, 100.64/10 and fc00::/7.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
))
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


def refused_reason(address: str, *, allow_private: bool = False) -> str | None:
    """Why Core must not hand the mail to this address, or None. The rule of globalsettings' address check, written here: cloud
    metadata, loopback, link-local, unspecified, multicast, and anything not globally routable. An embedded IPv4 address (IPv4-mapped,
    NAT64, 6to4) is judged by the IPv4 address it carries.

    ``allow_private`` is the relaxed rule of AD-30 (Core's own Priority 1 email, setting on): an address inside ``PRIVATE_NETWORKS``
    passes. Every other refusal above stays."""
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
        if allow_private and any(ip in net for net in PRIVATE_NETWORKS if net.version == ip.version):
            return None
        return "not public"
    return None


def resolve_addresses(name: str) -> list[str]:
    """Every address the name resolves to. Raises OSError or UnicodeError when it does not resolve. Nothing is connected to."""
    infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


def _judge_host(host, *, allow_private: bool) -> tuple[str | None, bool]:
    """(refusal, used_private). ``used_private`` is True only when the name was accepted and at least one of its addresses passed
    because of the relaxed rule. Every address is judged on its own: one bad address refuses the name."""
    name = str(host or "").strip()
    if not name:
        return REFUSED, False
    try:
        addresses = resolve_addresses(name)
    except (OSError, UnicodeError, ValueError):
        return REFUSED, False
    if not addresses:
        return REFUSED, False
    used_private = False
    for address in addresses:
        try:
            reason = refused_reason(address, allow_private=allow_private)
            if reason is None and allow_private and refused_reason(address) is not None:
                used_private = True
        except ValueError:
            return REFUSED, False
        if reason:
            logger.warning("Priority 1 email not sent: the mail server name points at a %s address.", reason)
            return REFUSED, False
    return None, used_private


def public_refusal(host) -> str | None:
    """REFUSED when the mail server's name is empty, does not resolve, or resolves to any address that is not public. None when every
    address it resolves to is public. The name is never logged; only the reason category is."""
    return _judge_host(host, allow_private=False)[0]


def _private_relay_on() -> bool:
    """The setting, fail closed: any error reads as off. It is not in the public Python contract."""
    try:
        from .runtime_settings import get_priority_mail_private_relay

        return get_priority_mail_private_relay() is True
    except Exception:
        return False


def host_check(host, *, core_seams: bool = False) -> tuple[str | None, bool]:
    """(refusal, private_relay) for the mail server's name (AD-30). The default is the public-only rule.

    The relaxed rule applies only when the setting is on AND ``core_seams`` is True (``send_p1_email`` is running with its own default
    host and send) AND no frame on the call stack lies inside an installed module's folder. A module that reaches this gets the
    public-only rule, with one warning logged, and never a fallback to another sender. ``private_relay`` is True only when the relaxed
    rule accepted the name."""
    if not _private_relay_on():
        return _judge_host(host, allow_private=False)
    allowed = False
    if core_seams:
        try:
            from .caller_identity import module_frame_on_stack

            allowed = not module_frame_on_stack()
        except Exception:
            allowed = False
    if not allowed:
        logger.warning("Priority 1 email host check: the private relay is not available to this caller; the public-only rule applied.")
    return _judge_host(host, allow_private=allowed)


def host_refusal(host, *, core_seams: bool = False) -> str | None:
    """REFUSED, or None when the name may be used. Public-only unless ``host_check`` allows the private relay."""
    return host_check(host, core_seams=core_seams)[0]


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
