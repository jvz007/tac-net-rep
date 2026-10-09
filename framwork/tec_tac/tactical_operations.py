"""Typed Tactical operations that Core runs server-side and audits where the call happens (Core 1.17.7).

An owning core module declares each operation once, in code at ``AppConfig.ready()``, the way it registers a
capability or a scheduler action. Core then runs the Tactical call for a signed-in user, in this process, through
Tactical's own view for that route, and writes the audit row from Tactical's real answer. A browser can no longer
report the call, so it can no longer misreport it (CQ6, CQ7 mode a).

What this module is not:

* It is not a free proxy. A route is declared in advance by a module, with its Tactical permission flags, its object
  scope, its JSON body keys and its audit event. The browser names an operation, never a path.
* It adds no authority. Tactical's own permission, scope and validation classes run again on the call. Core re-checks
  the Tactical flags and the role's client and site limits first, so a refusal is audited by Core.
* It reads no Knox token, makes no HTTP call, and holds no key or service account. It needs an authenticated request,
  so a Celery task cannot use it (mode b, the Scheduler running as the owner, is a separate Core contract).

The registry is empty until a module declares an operation, so this release changes nothing for installed modules.

1.17.13 (all additive; an operation declared the 1.17.12 way registers and runs unchanged):

* ``audit.object_param`` names a path parameter that is the audit object (a note, a template, a pending action).
* ``audit.before = {route, fields}`` reads the object through Tactical's own GET view, as the signed-in user, and writes
  a whitelisted copy of it as the row's before value. A failed read never blocks the change.
* A scope entry may take its source from that read (``before:<field>``) or its type from the body (``type: body:<field>``
  with a ``type_map``).
* ``query_params`` lets a GET operation pass a whitelisted query string; ``upload`` lets one operation forward one file
  as multipart/form-data, with a size cap and an extension allow-list.
* AD-21: the owning module's effective category (a missing category is ``test``) decides, not only its id.
"""
from __future__ import annotations

import itertools
import json
import logging
import re
import secrets
import threading
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

from . import module_category as _module_category

logger = logging.getLogger("tec_tac.tactical_operations")

CAPABILITY_ID = "core.tactical_operations"
CAPABILITY_VERSION = "1.1.0"
AUDIT_HEADER = "X-Tec-Tac-Audit"
AUDIT_RECORDED = "recorded"
AUDIT_NOT_RECORDED = "not-recorded"
MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 25 * 2**20
MAX_UPLOAD_BYTES = 10 * 2**20  # hard ceiling for one uploaded file; an operation declares its own lower cap (CQ40)
MAX_QUERY_PARAMS = 16
# An upload whose part is named after the file itself. Tactical's report asset upload stores each file under the name of
# its multipart part, not under the filename attribute (ee/reporting/views.py UploadAssets), so the part must be named
# after the cleaned file name.
FILE_NAME_FIELD = "{file_name}"
MAX_QUERY_VALUE = 512
RELAYED_HEADERS = ("Content-Type", "Content-Disposition")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SCOPE_TYPES = ("agent", "client", "site")
OUTCOME_UNKNOWN_ACTION = "custom:outcome-unknown"

# Routes Core owns or that face agents. A module can never declare these, and a param value can never reach them.
FORBIDDEN_FIRST_SEGMENTS = ("accounts", "_allauth", "v2")
FORBIDDEN_FIRST_PREFIXES = ("logout",)  # logout, logoutall
FORBIDDEN_FIRST_TWO = (("api", "tfd"), ("api", "v3"), ("api", "v4"), ("agents", "installer"))

_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_LITERAL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
_PARAM_RE = re.compile(r"^\{([a-z][a-z0-9_]{0,31})(?::(str|int|agent))?\}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SECRET_NAME_RE = re.compile(r"(pass|secret|token|key|credential|auth|cookie|signature)", re.IGNORECASE)
_SCOPE_SOURCE_RE = re.compile(r"^(path|body|before):([A-Za-z_][A-Za-z0-9_]{0,63})$")
_SCOPE_TYPE_BODY_RE = re.compile(r"^body:([A-Za-z_][A-Za-z0-9_]{0,63})$")
_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$")
_CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]{1,60}/[A-Za-z0-9!#$&^_.+-]{1,60}$")
_PARAM_VALUE_RE = {
    "str": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$"),
    "agent": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{20,254}$"),
    "int": re.compile(r"^[0-9]{1,12}$"),
}
_MAX_SEGMENTS = 12
_MAX_ROUTE_LENGTH = 200
_MAX_PERMISSIONS = 8
_MAX_BODY_FIELDS = 64
_MAX_SCOPE = 4
_MAX_BEFORE_FIELDS = 16
_MAX_TYPE_MAP = 8
_MAX_UPLOAD_EXTENSIONS = 16
_BEFORE_STRING_LIMIT = 256
_MAX_FILE_NAME = 255

# One fixed Core text per refusal. None carries any wording from the declaring module or from Tactical.
MESSAGES = {
    "not_found": "The operation was not found.",
    "unauthenticated": "Sign in to run this operation.",
    "permission_denied": "Your Tactical role does not allow this operation.",
    "module_permission_denied": "Your Tec-Tac role does not allow this operation.",
    "object_not_found": "The requested object was not found, or you cannot access it.",
}
DENY_MESSAGES = {
    "permission_denied": "Core refused a Tactical operation: the signed-in user's Tactical role lacks a required permission.",
    "module_permission_denied": "Core refused a Tactical operation: the signed-in user's Tec-Tac role lacks the module permission.",
    "not_found": "Core refused a Tactical operation: the object is missing or outside the signed-in user's scope.",
    "tactical_denied": "Tactical refused an operation that Core ran for the signed-in user.",
}
OUTCOME_UNKNOWN_MESSAGE = (
    "Core ran a Tactical operation and could not confirm the outcome. Tactical may have changed data."
)


class TacticalOperationError(RuntimeError):
    """A typed refusal or failure. ``status`` is the HTTP status, ``code`` a stable machine value."""

    def __init__(self, message: str, *, status: int = 400, code: str = "invalid_operation_request", audit: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.audit = audit


class TacticalOperationRegistrationError(ValueError):
    """A module declared an operation Core refuses to register."""


@dataclass(frozen=True)
class ScopeSpec:
    type: str  # agent, client or site, or body:<field> with a type_map (1.17.13)
    source: str  # path:<name>, body:<field> or before:<field> (1.17.13)
    type_map: tuple = ()  # ((body value, scope type), ...) when ``type`` is body:<field>


@dataclass(frozen=True)
class BeforeSpec:
    """A Tactical GET route that returns the object an operation changes, and the fields copied from it (1.17.13)."""

    route: str
    segments: tuple
    trailing_slash: bool
    fields: tuple


@dataclass(frozen=True)
class UploadSpec:
    """One file part an operation forwards as multipart/form-data (1.17.13)."""

    field: str
    max_bytes: int
    extensions: tuple


@dataclass(frozen=True)
class TacticalOperation:
    id: str
    module_id: str
    method: str
    route: str
    segments: tuple  # (("lit", "agents"), ("param", "agent_id", "str"), ...)
    trailing_slash: bool
    permissions: tuple
    scope: tuple
    body_fields: tuple
    audit_action: str
    audit_object_type: str
    audit_fields: tuple
    module_permission: str | None = None
    message: str | None = None
    audit_object_param: str | None = None
    before: BeforeSpec | None = None
    query_params: tuple = ()
    upload: UploadSpec | None = None

    @property
    def params(self) -> tuple:
        return tuple((seg[1], seg[2]) for seg in self.segments if seg[0] == "param")

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module_id": self.module_id,
            "method": self.method,
            "route": self.route,
            "params": {name: kind for name, kind in self.params},
            "permissions": list(self.permissions),
            "scope": [
                {"type": item.type, "source": item.source, **({"type_map": dict(item.type_map)} if item.type_map else {})}
                for item in self.scope
            ],
            "body_fields": list(self.body_fields),
            "audit": {
                "action": self.audit_action, "object_type": self.audit_object_type, "audit_fields": list(self.audit_fields),
                "object_param": self.audit_object_param,
                "before": {"route": self.before.route, "fields": list(self.before.fields)} if self.before else None,
            },
            "module_permission": self.module_permission,
            "query_params": list(self.query_params),
            "upload": (
                {"field": self.upload.field, "max_bytes": self.upload.max_bytes, "extensions": list(self.upload.extensions)}
                if self.upload else None
            ),
        }


@dataclass(frozen=True)
class TacticalOperationResult:
    """What a Python caller gets back. ``audit`` says whether Core's row was written."""

    status: int
    data: Any
    content_type: str
    headers: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)
    content: bytes = b""


_LOCK = threading.RLock()
_OPERATIONS: dict[tuple[str, str], TacticalOperation] = {}
_ROUTES: dict[tuple[str, str], tuple[str, str]] = {}


# ----------------------------------------------------------------------------------------------- registration

def _forbidden_route(parts: list[str]) -> bool:
    """True when the concrete or templated path segments reach a route Core owns or an agent-facing one."""
    if not parts:
        return True
    first = parts[0].lower()
    if first in FORBIDDEN_FIRST_SEGMENTS or any(first.startswith(prefix) for prefix in FORBIDDEN_FIRST_PREFIXES):
        return True
    return len(parts) >= 2 and (first, parts[1].lower()) in FORBIDDEN_FIRST_TWO


def _parse_route(route: Any) -> tuple[tuple, bool]:
    if not isinstance(route, str) or not route.strip():
        raise TacticalOperationRegistrationError("route is required.")
    if route != route.strip() or len(route) > _MAX_ROUTE_LENGTH:
        raise TacticalOperationRegistrationError("route has stray space or is too long.")
    if route.startswith("/") or "\\" in route or "?" in route or "#" in route or "%" in route or "//" in route:
        raise TacticalOperationRegistrationError("route must be a relative Tactical route template such as agents/{agent_id:agent}/reboot/.")
    trailing = route.endswith("/")
    raw = route.rstrip("/").split("/")
    if not raw or len(raw) > _MAX_SEGMENTS or any(not part for part in raw):
        raise TacticalOperationRegistrationError("route has an empty or too many segments.")
    segments: list[tuple] = []
    seen: set[str] = set()
    for index, part in enumerate(raw):
        if ".." in part or set(part) <= {"."}:
            raise TacticalOperationRegistrationError("route may not contain '..'.")
        if part.startswith("{") or part.endswith("}"):
            match = _PARAM_RE.match(part)
            if not match:
                raise TacticalOperationRegistrationError(f"route parameter {part!r} must look like {{name}} or {{name:str|int|agent}}.")
            name, kind = match.group(1), match.group(2) or "str"
            if name in seen:
                raise TacticalOperationRegistrationError(f"route parameter {name!r} is repeated.")
            if index == 0 or (index == 1 and raw[0].lower() == "api"):
                raise TacticalOperationRegistrationError("a route may not start with a parameter.")
            seen.add(name)
            segments.append(("param", name, kind))
        else:
            if not _LITERAL_RE.match(part):
                raise TacticalOperationRegistrationError(f"route segment {part!r} is not allowed.")
            segments.append(("lit", part))
    literal_parts = [seg[1] if seg[0] == "lit" else "{}" for seg in segments]
    if _forbidden_route(literal_parts):
        raise TacticalOperationRegistrationError(
            "route is Core's own or agent-facing (accounts/, api/tfd/, api/v3/, api/v4/, _allauth/, logout, logoutall, v2/, agents/installer)."
        )
    return tuple(segments), trailing


def _route_key(segments: tuple, trailing: bool) -> str:
    parts = [seg[1] if seg[0] == "lit" else "{}" for seg in segments]
    return "/".join(parts) + ("/" if trailing else "")


def _clean_names(values: Any, label: str, *, maximum: int, pattern=_FIELD_RE) -> tuple:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise TacticalOperationRegistrationError(f"{label} must be a list of names.")
    names = []
    for value in values:
        if not isinstance(value, str) or not pattern.match(value):
            raise TacticalOperationRegistrationError(f"{label} has an invalid name: {value!r}.")
        if value in names:
            raise TacticalOperationRegistrationError(f"{label} repeats {value!r}.")
        names.append(value)
    if len(names) > maximum:
        raise TacticalOperationRegistrationError(f"{label} has more than {maximum} entries.")
    return tuple(names)


# Core-held route owner table (AD-19 condition 1, three-layer design of 8 October 2026; route level since 1.17.8).
# Each rule is a tuple of literal route segments ("{}" stands for any parameter segment) and the set of module ids that may
# declare an operation at or below that prefix. The longest matching rule wins and is the only one applied, so a
# reserved sub-route (agents/{}/cmd) cannot be claimed through its group rule (agents). An empty set means the prefix is
# Core's own, or no core module owns it yet: every module is refused. A route no rule matches is refused as well.
# The table follows the function map (reviews/modules/tactical-function-map.json), AD-11 (clients and sites stay in Core),
# AD-16 (code signing is Licensing's) and AD-18 (pending actions to Agents, webvnc to Take Control, cmd to Remote
# Background). Endpoints is the technician workspace: it composes other modules' contracts and owns no route.
# ``accounts``, ``api``, ``beta`` and the rest of clients/ and core/ are deliberately without a module owner.
_ROUTE_OWNER_RULES = (
    # Core's own (AD-11): clients and sites. Agent Management keeps the install deployments.
    (("clients",), ()),
    (("clients", "deployments"), ("agent-management",)),
    (("clients", "{}", "deploy"), ("agent-management",)),
    # core/: explicit per prefix. Anything not listed is refused.
    (("core",), ()),
    (("core", "codesign"), ("licensing",)),
    (("core", "schedules"), ("reportmanager",)),
    (("core", "serverscript"), ("scriptmanager",)),
    (("core", "openai"), ()),
    (("core", "dashinfo"), ()),
    *((("core", name), ("globalsettings",)) for name in (
        "settings", "customfields", "keystore", "urlaction", "emailtest", "smstest", "clearcache", "servermaintenance",
        "version", "webtermperms",
    )),
    # agents/: Agents owns the group, the sub-paths below are homed elsewhere.
    (("agents",), ("agents",)),
    (("agents", "{}", "cmd"), ("remote-background",)),
    (("agents", "{}", "{}", "webvnc"), ("take-control",)),
    (("agents", "{}", "runscript"), ("scriptexecution",)),
    (("agents", "{}", "meshcentral"), ("take-control",)),
    (("agents", "{}", "processes"), ("remote-background",)),
    (("agents", "{}", "registry"), ("remote-background",)),
    (("agents", "{}", "eventlog"), ("remote-background",)),
    (("agents", "{}", "terminal-defaults"), ("remote-background",)),
    (("agents", "update"), ("agent-management",)),
    (("agents", "versions"), ("agent-management",)),
    (("agents", "bulkrecovery"), ("agent-management",)),
    (("agents", "{}", "recover"), ("agent-management",)),
    # logs/: pending actions are Agents' (AD-18). Any other logs/ route is refused.
    (("logs",), ()),
    (("logs", "pendingactions"), ("agents",)),
    (("logs", "audit"), ("audit",)),
    (("logs", "debug"), ("debug",)),
    # automation/: the patch policy is Windows Patching's.
    (("automation",), ("automation",)),
    (("automation", "patchpolicy"), ("patching",)),
    # One owner for the whole group.
    (("reporting",), ("reportmanager",)),
    (("alerts",), ("alerts",)),
    (("scripts",), ("scriptmanager",)),
    (("checks",), ("checks",)),
    (("software",), ("software",)),
    (("tasks",), ("tasks",)),
    (("services",), ("remote-background",)),
    (("winupdate",), ("patching",)),
)
ROUTE_OWNERS: dict[tuple, frozenset] = {prefix: frozenset(owners) for prefix, owners in _ROUTE_OWNER_RULES}

# The named exceptions to "category core only": (module id, rule prefix). Licensing is a server module and owns
# Tactical's code-signing route (AD-16, AD-17). A module that replaces a core module is not listed here: since 1.17.9
# (AD-20) Core asks module_replacement whether the replacement is honoured right now, and the replacement then joins
# the owners of every rule the replaced core module owns, and of no other.
CATEGORY_EXCEPTIONS: frozenset = frozenset({("licensing", ("core", "codesign"))})


def _honoured_pairs() -> dict[str, str]:
    """{replacement module id: replaced core module id} for every replacement honoured right now (AD-20). Fails closed.

    1.17.11: a replacement of a server module is honoured for capabilities but joins no owner rule. A server module has
    no Tactical routes, so it is left out here."""
    try:
        from . import module_replacement

        model = module_replacement.live_model()
        pairs = {}
        for node in model.values():
            if node.replaces:
                replaced = module_replacement.honoured_replacement(node.id, model=model)
                if replaced and model[replaced].category == "core":
                    pairs[node.id] = replaced
        return pairs
    except Exception:
        logger.exception("Could not read module replacement state; no replacement is honoured for Tactical operations.")
        return {}


def _owners_for_rule(rule: tuple, pairs: dict[str, str] | None = None) -> frozenset:
    """The module ids that may own ``rule``: the table's owners plus any honoured replacement of one of them (AD-20)."""
    owners = ROUTE_OWNERS.get(rule, frozenset())
    pairs = _honoured_pairs() if pairs is None else pairs
    return owners | frozenset(module for module, replaced in pairs.items() if replaced in owners)


# Rules that name one Tactical route and not a family of routes below a prefix: only a path of exactly that length
# lands on them. webvnc is agents/<id>/<port>/webvnc/, so agents/<id>/eventlog/webvnc/<days>/ is the eventlog route.
EXACT_RULES: frozenset = frozenset({("agents", "{}", "{}", "webvnc")})


def _matching_rule(literal: list[str]) -> tuple | None:
    """The longest rule prefix the route starts with, or None. A "{}" in a rule matches any one segment."""
    best = None
    for prefix in ROUTE_OWNERS:
        if prefix in EXACT_RULES and len(prefix) != len(literal):
            continue
        if len(prefix) <= len(literal) and all(want == "{}" or want == have for want, have in zip(prefix, literal)) and (
            best is None or len(prefix) > len(best)
        ):
            best = prefix
    return best


def _expansion_rules(segments: tuple) -> list[tuple]:
    """Every rule a concrete path built from this template can land on (1.17.8-1, parameter kinds since 1.17.9).

    A parameter segment can hold any value, so ``agents/{x}/`` reaches ``agents/update/`` as well as ``agents/<id>/``.
    A parameter of kind ``agent`` (21 or more characters) or ``int`` (digits) can never hold a route word, so its only
    expansion is the ordinary value. A plain ``str`` parameter is tried as every literal a rule has at that position and
    as a value no rule names, including expansions that run on past the matched rule (``agents/{a}/{p}/create-key/``
    reaches ``agents/<id>/registry/``). The longest matching rule of each expansion decides, exactly as it does at dispatch.
    """
    options = []
    for index, seg in enumerate(segments):
        if seg[0] == "lit":
            options.append([seg[1].lower()])
        elif seg[2] in ("agent", "int"):
            options.append(["*other*"])
        else:
            names = {rule[index] for rule in ROUTE_OWNERS if len(rule) > index and rule[index] != "{}"}
            options.append(sorted(names) + ["*other*"])
    found: dict[tuple, None] = {}
    for combo in itertools.product(*options):
        found[_matching_rule(list(combo))] = None
    return list(found)


def _check_route_owner(module: dict, segments: tuple, route: str = "") -> None:
    """Refuse a route the module does not own: a non-core module, or a core module outside the owner rule of any path the route can reach."""
    owner = module["id"]
    literal = [seg[1].lower() if seg[0] == "lit" else "{}" for seg in segments]
    rules = _expansion_rules(segments)
    shown = "/".join(literal) if not route else route
    pairs = _honoured_pairs()
    category = _module_category.effective_category(module.get("category"))
    if category != "core" and owner not in pairs and not all((owner, rule) in CATEGORY_EXCEPTIONS for rule in rules):
        # AD-21 condition 3: a premium, server or test module is refused every route, even one the owner table lists by id.
        raise TacticalOperationRegistrationError(
            f"module {owner!r} is not a core module (its category is {category}). Only the core module that owns a Tactical route can declare its operations."
        )
    for rule in rules:
        if rule is None:
            raise TacticalOperationRegistrationError(
                f"route {shown!r} is in no Tactical group that a core module owns. Core's owner table refuses it until a Core release adds it."
            )
        owners = ROUTE_OWNERS[rule]
        rule_text = "/".join(rule) + "/"
        if owners and pairs.get(owner) in owners:
            continue  # AD-20: the honoured replacement joins the rules of the module it replaces
        if not owners:
            raise TacticalOperationRegistrationError(
                f"route {shown!r} is Core's own or no core module owns it yet (rule {rule_text}). No module may declare it."
            )
        if owner not in owners:
            raise TacticalOperationRegistrationError(
                f"module {owner!r} does not own route {shown!r} (rule {rule_text}, owner: {', '.join(sorted(owners))}). Declare the operation in the core module that does."
            )


def _check_module(module_id: Any) -> dict:
    from . import audit as audit_core

    name = str(module_id or "").strip()
    if not name or name == "core":
        raise TacticalOperationRegistrationError("module_id must name the owning core module.")
    try:
        module = audit_core._resolve_module(name)
    except audit_core.AuditContractError as exc:
        raise TacticalOperationRegistrationError(f"module {name!r} cannot declare operations: {exc}") from None
    if module.get("legacy"):
        raise TacticalOperationRegistrationError(f"module {name!r} is a legacy module and cannot declare operations.")
    return module


def _parse_before(value: Any, module: dict, verb: str, params: dict) -> BeforeSpec | None:
    """Validate ``audit.before = {route, fields}`` (1.17.13)."""
    if value is None:
        return None
    if verb == "GET":
        raise TacticalOperationRegistrationError("a GET operation changes nothing, so it has no audit.before.")
    if not isinstance(value, dict) or set(value) != {"route", "fields"}:
        raise TacticalOperationRegistrationError("audit.before is {route, fields} and nothing else.")
    segments, trailing = _parse_route(value["route"])
    # The read is a Tactical GET like any operation, so the same module must own it.
    _check_route_owner(module, segments, value["route"])
    for seg in segments:
        if seg[0] == "param" and params.get(seg[1]) != seg[2]:
            raise TacticalOperationRegistrationError(
                f"audit.before route parameter {seg[1]!r} must be a parameter of the operation's own route, with the same kind."
            )
    names = _clean_names(value["fields"], "audit.before fields", maximum=_MAX_BEFORE_FIELDS)
    if not names:
        raise TacticalOperationRegistrationError("audit.before fields must name at least one field.")
    for name in names:
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"audit.before field {name!r} looks like a secret. Never put secrets in the audit row.")
    return BeforeSpec(value["route"], segments, trailing, names)


def _parse_type_map(value: Any) -> tuple:
    if not isinstance(value, dict) or not value or len(value) > _MAX_TYPE_MAP:
        raise TacticalOperationRegistrationError(f"a body-selected scope type needs a type_map of 1 to {_MAX_TYPE_MAP} entries.")
    pairs = []
    for key, scope_type in value.items():
        if not isinstance(key, str) or not _LITERAL_RE.match(key):
            raise TacticalOperationRegistrationError(f"type_map key {key!r} is not allowed.")
        if scope_type not in ("client", "site"):
            raise TacticalOperationRegistrationError("type_map maps a body value to client or site.")
        pairs.append((key, scope_type))
    return tuple(sorted(pairs))


def _parse_upload(value: Any, verb: str, fields: tuple) -> UploadSpec | None:
    if value is None:
        return None
    if verb not in ("POST", "PUT", "PATCH"):
        raise TacticalOperationRegistrationError("upload belongs to a POST, PUT or PATCH operation.")
    if not isinstance(value, dict) or set(value) != {"field", "max_bytes", "extensions"}:
        raise TacticalOperationRegistrationError("upload is {field, max_bytes, extensions} and nothing else.")
    name, cap = value["field"], value["max_bytes"]
    if name != FILE_NAME_FIELD and (not isinstance(name, str) or not _FIELD_RE.match(name) or name in ("params", "body", "query") or name in fields):
        raise TacticalOperationRegistrationError(
            f"upload field must be a plain name that is not params, body, query or a body field, or {FILE_NAME_FIELD} to name the part after the file."
        )
    if isinstance(cap, bool) or not isinstance(cap, int) or not 0 < cap <= MAX_UPLOAD_BYTES:
        raise TacticalOperationRegistrationError(f"upload max_bytes must be a whole number from 1 to {MAX_UPLOAD_BYTES}.")
    extensions = _clean_names(value["extensions"], "upload extensions", maximum=_MAX_UPLOAD_EXTENSIONS, pattern=_EXTENSION_RE)
    if not extensions:
        raise TacticalOperationRegistrationError("upload extensions must list at least one allowed file extension (lower case, no dot).")
    return UploadSpec(name, cap, extensions)


def register_tactical_operation(
    id,
    module_id,
    method,
    route,
    permissions,
    scope,
    body_fields,
    audit,
    module_permission=None,
    message=None,
    query_params=None,
    upload=None,
):
    """Declare one Tactical operation. Call it from the owning module's ``AppConfig.ready()``.

    1.17.13 (all optional): ``audit`` may also carry ``object_param`` and ``before``; a scope entry may use a
    ``before:<field>`` source or a ``body:<field>`` type with a ``type_map``; ``query_params`` whitelists the query names
    of a GET operation; ``upload`` declares one multipart file part. See docs/tactical-operations.md.

    Refuses (TacticalOperationRegistrationError, a ValueError) a module that is not a core module (bar the named
    exceptions) or a route the module does not own (the longest matching rule of ``ROUTE_OWNERS`` decides, see
    docs/tactical-operations.md), a route Core owns, ``..``, a second operation on the same (method, route), a flag that is not a boolean ``can_*`` field on Tactical's Role, an unknown, legacy or
    disabled module, a scope source that does not exist, and audit fields that look like secrets. Registering the
    identical operation again is idempotent.
    """
    from . import audit as audit_core
    from .rbac import _validate_tactical_flag, registered_permissions

    op_id = str(id or "").strip()
    if not _ID_RE.match(op_id):
        raise TacticalOperationRegistrationError("id must be a lowercase slug such as reboot or wake-on-lan.")
    module = _check_module(module_id)
    owner = module["id"]
    verb = str(method or "").strip().upper()
    if verb not in METHODS:
        raise TacticalOperationRegistrationError(f"method must be one of {', '.join(METHODS)}.")
    segments, trailing = _parse_route(route)
    _check_route_owner(module, segments, route)

    flags = _clean_names(permissions, "permissions", maximum=_MAX_PERMISSIONS, pattern=re.compile(r"^can_[a-z0-9_]+$"))
    if not flags:
        raise TacticalOperationRegistrationError("permissions must list at least one Tactical Role flag.")
    try:
        for flag in flags:
            _validate_tactical_flag(flag)
    except ValueError as exc:
        raise TacticalOperationRegistrationError(str(exc)) from None

    fields = _clean_names(body_fields, "body_fields", maximum=_MAX_BODY_FIELDS)
    if fields and verb not in BODY_METHODS:
        raise TacticalOperationRegistrationError("a GET operation takes no body_fields.")

    params = {seg[1]: seg[2] for seg in segments if seg[0] == "param"}
    scope_specs = []
    if scope is None:
        scope = ()
    if isinstance(scope, (str, bytes, dict)) or not hasattr(scope, "__iter__"):
        raise TacticalOperationRegistrationError("scope must be a list of {type, source}.")
    # The audit and before declarations come first: a scope source may read from the before fields.
    if not isinstance(audit, dict) or not {"action", "object_type"} <= set(audit) or set(audit) - {"action", "object_type", "audit_fields", "object_param", "before"}:
        raise TacticalOperationRegistrationError("audit is {action, object_type, audit_fields, object_param, before}; the last three are optional.")
    object_param = audit.get("object_param")
    if object_param is not None and (not isinstance(object_param, str) or object_param not in params):
        raise TacticalOperationRegistrationError(f"audit object_param {object_param!r} is not a parameter of the route.")
    before = _parse_before(audit.get("before"), module, verb, params)

    for item in scope:
        if not isinstance(item, dict) or not {"type", "source"} <= set(item) or set(item) - {"type", "source", "type_map"}:
            raise TacticalOperationRegistrationError("each scope entry is {type, source}, plus type_map for a body-selected type, and nothing else.")
        kind, source = item["type"], item["source"]
        match = _SCOPE_SOURCE_RE.match(source) if isinstance(source, str) else None
        type_field = _SCOPE_TYPE_BODY_RE.match(kind) if isinstance(kind, str) else None
        if match is None or (kind not in SCOPE_TYPES and type_field is None):
            raise TacticalOperationRegistrationError(
                f"bad scope entry {item!r}: type is agent, client, site or body:<field>, and source is path:<name>, body:<field> or before:<field>."
            )
        where, name = match.group(1), match.group(2)
        type_map = ()
        if type_field is not None:
            if type_field.group(1) not in fields:
                raise TacticalOperationRegistrationError(f"scope type {kind!r} is not one of body_fields.")
            type_map = _parse_type_map(item.get("type_map"))
        elif "type_map" in item:
            raise TacticalOperationRegistrationError("type_map belongs only to a scope type of the form body:<field>.")
        if where == "path":
            if name not in params:
                raise TacticalOperationRegistrationError(f"scope source {source!r} is not a parameter of the route.")
            if kind in ("client", "site") and params[name] != "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a {kind}.")
            if kind == "agent" and params[name] == "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be a string parameter for an agent.")
            if type_map and params[name] != "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a client or site.")
        elif where == "before":
            if before is None or name not in before.fields:
                raise TacticalOperationRegistrationError(f"scope source {source!r} is not one of the audit.before fields.")
        elif name not in fields:
            raise TacticalOperationRegistrationError(f"scope source {source!r} is not one of body_fields.")
        spec = ScopeSpec(kind, source, type_map)
        if spec in scope_specs:
            raise TacticalOperationRegistrationError(f"scope entry {item!r} is repeated.")
        scope_specs.append(spec)
    if len(scope_specs) > _MAX_SCOPE:
        raise TacticalOperationRegistrationError("too many scope entries.")

    try:
        action = audit_core._normalize_action(audit["action"])
        object_type = audit_core._normalize_object_type(audit["object_type"])
    except audit_core.AuditContractError as exc:
        raise TacticalOperationRegistrationError(f"audit: {exc}") from None
    if action == "deny" or action == OUTCOME_UNKNOWN_ACTION:
        raise TacticalOperationRegistrationError("audit action deny and custom:outcome-unknown are written by Core only.")
    query_names = _clean_names(query_params, "query_params", maximum=MAX_QUERY_PARAMS)
    if query_names and verb != "GET":
        raise TacticalOperationRegistrationError("query_params belong to a GET operation.")
    for name in query_names:
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"query parameter {name!r} looks like a secret. A query string is logged; never put secrets in it.")
    upload_spec = _parse_upload(upload, verb, fields)

    audit_fields = _clean_names(audit.get("audit_fields"), "audit_fields", maximum=_MAX_BODY_FIELDS)
    for name in audit_fields:
        if name not in fields and name not in query_names:
            raise TacticalOperationRegistrationError(f"audit field {name!r} is not one of body_fields or query_params.")
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"audit field {name!r} looks like a secret. Never put secrets in the audit row.")

    codename = None
    if module_permission is not None:
        codename = str(module_permission).strip()
        if codename not in registered_permissions():
            raise TacticalOperationRegistrationError(f"module_permission {codename!r} is not a registered Tec-Tac permission.")
    text = None
    if message is not None:
        text = str(message).strip()
        if not text or len(text.encode("utf-8")) > 255 or any(ord(ch) < 32 for ch in text):
            raise TacticalOperationRegistrationError("message must be one line of at most 255 bytes.")

    operation = TacticalOperation(
        id=op_id, module_id=owner, method=verb, route=route, segments=segments, trailing_slash=trailing,
        permissions=flags, scope=tuple(scope_specs), body_fields=fields, audit_action=action, audit_object_type=object_type,
        audit_fields=audit_fields, module_permission=codename, message=text,
        audit_object_param=object_param, before=before, query_params=query_names, upload=upload_spec,
    )
    key = (owner, op_id)
    route_key = (verb, _route_key(segments, trailing))
    with _LOCK:
        existing = _OPERATIONS.get(key)
        if existing is not None:
            if existing == operation:
                return existing
            raise TacticalOperationRegistrationError(f"operation {owner}/{op_id} is already registered with a different definition.")
        holder = _ROUTES.get(route_key)
        if holder is not None:
            raise TacticalOperationRegistrationError(
                f"{verb} {route} is already declared by {holder[0]}/{holder[1]}. One caller per Tactical route (AD-6)."
            )
        _OPERATIONS[key] = operation
        _ROUTES[route_key] = key
    return operation


def get_operation(module_id: str, operation_id: str) -> dict[str, Any] | None:
    with _LOCK:
        operation = _OPERATIONS.get((str(module_id), str(operation_id)))
    return operation.describe() if operation else None


def list_operations(module_id: str | None = None) -> list[dict[str, Any]]:
    with _LOCK:
        rows = [op for op in _OPERATIONS.values() if module_id in (None, "") or op.module_id == module_id]
    return [op.describe() for op in sorted(rows, key=lambda op: (op.module_id, op.id))]


def _clear_operations_for_tests() -> None:
    """Private test helper; never use for production lifecycle management."""
    with _LOCK:
        _OPERATIONS.clear()
        _ROUTES.clear()


# ----------------------------------------------------------------------------------------------- execution

def _fail(kind: str, status: int, code: str, *, audit: dict | None = None) -> TacticalOperationError:
    return TacticalOperationError(MESSAGES[kind], status=status, code=code, audit=audit)


def _lookup(module_id: Any, operation_id: Any) -> TacticalOperation:
    from . import audit as audit_core

    with _LOCK:
        operation = _OPERATIONS.get((str(module_id), str(operation_id)))
    if operation is None:
        raise _fail("not_found", 404, "tactical_operation_not_found")
    try:
        module = audit_core._resolve_module(operation.module_id)
    except audit_core.AuditContractError:
        module = None
    if module is None or module.get("legacy"):
        raise _fail("not_found", 404, "tactical_operation_not_found")
    # A replacement's operation stays dead once its replacement is no longer honoured (AD-20), even in a process
    # that registered it before the operator changed module state.
    if (
        _module_category.effective_category(module.get("category")) != "core"
        and operation.module_id not in {name for name, _ in CATEGORY_EXCEPTIONS}
        and operation.module_id not in _honoured_pairs()
    ):
        raise _fail("not_found", 404, "tactical_operation_not_found")
    return operation


def _printable(value: Any, limit: int = 255) -> str:
    return "".join(ch for ch in str(value) if 32 <= ord(ch) < 127)[:limit]


def _scope_values(operation: TacticalOperation, params: Any, body: Any, before: Any = None, *, phase: str = "direct") -> list[tuple[str, list[str]]]:
    """Resolve the declared scope entries to (type, [ids]). Raises 400 for a missing or malformed value.

    ``phase`` is "direct" for entries read from the path or the body, and "before" for entries read from the
    audit.before answer (1.17.13), which exist only after Core has read the object."""
    resolved = []
    for spec in operation.scope:
        where, name = spec.source.split(":", 1)
        if (where == "before") != (phase == "before"):
            continue
        if where == "path":
            raw = (params or {}).get(name)
        elif where == "before":
            raw = (before or {}).get(name)
        else:
            raw = (body or {}).get(name)
        values = raw if isinstance(raw, list) else [raw]
        if not values or len(values) > 1000:
            raise TacticalOperationError(f"{name} is required.", status=400, code="scope_field_required")
        ids = []
        for value in values:
            if value is None or isinstance(value, (bool, dict, list, float)) or not str(value).strip():
                raise TacticalOperationError(f"{name} is required.", status=400, code="scope_field_required")
            ids.append(str(value).strip())
        kind = spec.type
        if kind.startswith("body:"):
            field_name = kind.split(":", 1)[1]
            chosen = (body or {}).get(field_name)
            kind = dict(spec.type_map).get(chosen) if isinstance(chosen, str) else None
            if kind is None:
                raise TacticalOperationError(f"{field_name} is required and must be one of the declared types.", status=400, code="scope_field_required")
        resolved.append((kind, ids))
    return resolved


def _object_id(scope: list[tuple[str, list[str]]], operation: TacticalOperation | None = None, params: Any = None) -> str | None:
    """The audit row's object id. A declared ``audit.object_param`` wins (1.17.13); otherwise the first scope object."""
    if operation is not None and operation.audit_object_param and isinstance(params, dict):
        value = params.get(operation.audit_object_param)
        if value is not None and not isinstance(value, (bool, dict, list, float)):
            text = _printable(str(value).strip())
            if text:
                return text
    if not scope:
        return None
    ids = scope[0][1]
    return _printable(",".join(ids)) or None


def _body_scope_type(operation: TacticalOperation, scope: list[tuple[str, list[str]]]) -> str | None:
    """The scope type a body-selected entry resolved to, for the row metadata."""
    for spec, (kind, _) in zip([item for item in operation.scope if not item.source.startswith("before:")], scope):
        if spec.type.startswith("body:"):
            return kind
    return None


def _clean_params(operation: TacticalOperation, params: Any) -> dict[str, str]:
    expected = {name: kind for name, kind in operation.params}
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise TacticalOperationError("params must be an object.", status=400, code="invalid_params")
    extra = sorted(set(params) - set(expected))
    if extra:
        raise TacticalOperationError("Unknown parameter: " + ", ".join(_printable(name, 40) for name in extra), status=400, code="invalid_params")
    cleaned = {}
    for name, kind in expected.items():
        value = params.get(name)
        if value is None or isinstance(value, (bool, dict, list, float)):
            raise TacticalOperationError(f"Parameter {name} is required.", status=400, code="invalid_params")
        text = str(value).strip()
        if not _PARAM_VALUE_RE[kind].match(text) or ".." in text:
            raise TacticalOperationError(f"Parameter {name} is not valid.", status=400, code="invalid_params")
        cleaned[name] = text
    return cleaned


def _clean_body(operation: TacticalOperation, body: Any) -> dict:
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise TacticalOperationError("body must be a JSON object.", status=400, code="invalid_body")
    if body and operation.method not in BODY_METHODS:
        raise TacticalOperationError("This operation takes no body.", status=400, code="body_field_not_allowed")
    try:
        size = len(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        raise TacticalOperationError("body must be JSON.", status=400, code="invalid_body") from None
    if size > MAX_BODY_BYTES:
        raise TacticalOperationError(f"body is larger than {MAX_BODY_BYTES} bytes.", status=413, code="body_too_large")
    return body


_QUERY_SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _quote(text: str) -> str:
    """Percent-encode one query name or value. Written here so this module imports no URL library (no HTTP, 1.17.7)."""
    return "".join(chr(byte) if byte in _QUERY_SAFE else f"%{byte:02X}" for byte in text.encode("utf-8"))


def _query_string(query: dict) -> str:
    return "&".join(f"{_quote(str(name))}={_quote(str(value))}" for name, value in query.items())


def _unquote(text: str) -> str:
    return _PERCENT_RE.sub(lambda found: chr(int(found.group(1), 16)), text)


def _has_control(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _dotdot_segment(text: str) -> bool:
    return any(".." in re.split(r"[\\/]", candidate) for candidate in (text, _unquote(text)))


def _clean_query(operation: TacticalOperation, query: Any) -> dict[str, str]:
    """The query string of a GET operation: whitelisted names, flat string or whole-number values (1.17.13)."""
    if query is None:
        query = {}
    if not isinstance(query, dict):
        raise TacticalOperationError("query must be an object.", status=400, code="invalid_query")
    extra = sorted(set(query) - set(operation.query_params))
    if extra:
        raise TacticalOperationError(
            "Query field not allowed: " + ", ".join(_printable(name, 40) for name in extra), status=400, code="query_field_not_allowed",
        )
    cleaned = {}
    for name in operation.query_params:
        if name not in query:
            continue
        value = query[name]
        if value is None or isinstance(value, (bool, dict, list, float)):
            raise TacticalOperationError(f"Query field {name} must be a string or a whole number.", status=400, code="invalid_query")
        text = str(value)
        if not text.strip() or len(text) > MAX_QUERY_VALUE or _has_control(text) or _dotdot_segment(text):
            raise TacticalOperationError(f"Query field {name} is not valid.", status=400, code="invalid_query")
        cleaned[name] = text
    return cleaned


def _clean_file_name(raw: Any) -> str:
    if not isinstance(raw, str):
        raise TacticalOperationError("The file needs a name.", status=400, code="invalid_upload")
    if _has_control(raw):
        raise TacticalOperationError("The file name has control characters.", status=400, code="invalid_upload")
    name = re.split(r"[\\/]", raw)[-1].strip().replace('"', "_")
    if not name or name in (".", "..") or len(name) > _MAX_FILE_NAME:
        raise TacticalOperationError("The file name is not valid.", status=400, code="invalid_upload")
    return name


def _clean_upload(operation: TacticalOperation, upload: Any) -> dict | None:
    """Check the one file an operation may forward: field, name, extension and size (1.17.13). Returns the clean part."""
    spec = operation.upload
    if upload is None:
        if spec is not None:
            raise TacticalOperationError("This operation needs one file.", status=400, code="invalid_upload")
        return None
    if spec is None:
        raise TacticalOperationError("This operation takes no file.", status=400, code="upload_not_allowed")
    if not isinstance(upload, dict):
        raise TacticalOperationError("upload must be an object.", status=400, code="invalid_upload")
    if spec.field != FILE_NAME_FIELD and upload.get("field") not in (None, spec.field):
        raise TacticalOperationError("The file part has the wrong name.", status=400, code="upload_not_allowed")
    content = upload.get("content")
    if not isinstance(content, (bytes, bytearray)):
        raise TacticalOperationError("The file has no content.", status=400, code="invalid_upload")
    cap = min(spec.max_bytes, MAX_UPLOAD_BYTES)
    if len(content) > cap:
        raise TacticalOperationError(f"The file is larger than {cap} bytes.", status=413, code="upload_too_large")
    name = _clean_file_name(upload.get("name"))
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if extension not in spec.extensions:
        raise TacticalOperationError("This file type is not allowed. Allowed: " + ", ".join(spec.extensions) + ".", status=400, code="upload_type_not_allowed")
    content_type = str(upload.get("content_type") or "").split(";")[0].strip()
    if not _CONTENT_TYPE_RE.match(content_type):
        content_type = "application/octet-stream"
    part = spec.field
    if part == FILE_NAME_FIELD:
        part = name  # Tactical stores the file under its part name
        if part in operation.body_fields or part in ("params", "body", "query"):
            raise TacticalOperationError("The file name clashes with a field of this operation.", status=400, code="invalid_upload")
    return {"field": part, "name": name, "content_type": content_type, "content": bytes(content)}


def _check_whitelist(operation: TacticalOperation, body: dict) -> None:
    extra = sorted(set(body) - set(operation.body_fields))
    if extra:
        raise TacticalOperationError(
            "Body field not allowed: " + ", ".join(_printable(name, 40) for name in extra),
            status=400, code="body_field_not_allowed",
        )


def _write_row(request, operation: TacticalOperation, *, action: str, object_id, message: str, after=None,
               tactical_status: int | None, refusal: bool = False, extra: dict | None = None, before=None) -> dict:
    """Write one Core audit row. Never raises: a failed write is logged and reported."""
    from . import audit as audit_core

    metadata = {"operation": operation.id, "method": operation.method, "route": operation.route, "tactical_status": tactical_status}
    metadata.update(extra or {})
    try:
        result = audit_core._record_tactical_operation(
            actor=getattr(request, "user", None), module_id=operation.module_id, action=action,
            object_type=operation.audit_object_type, object_id=object_id, message=message, before=before, after=after,
            metadata=metadata, operation=operation.id, tactical_status=tactical_status, refusal=refusal, request=request,
        )
    except Exception:
        logger.exception("Tec-Tac audit row for Tactical operation %s/%s could not be written", operation.module_id, operation.id)
        return {"recorded": False, "error": "audit_write_failed"}
    if not result.get("recorded"):
        logger.error(
            "Tec-Tac audit row for Tactical operation %s/%s was not recorded (Tactical status %s).",
            operation.module_id, operation.id, tactical_status,
        )
    return {"recorded": bool(result.get("recorded")), "id": result.get("id"), "action": action}


def _refuse(request, operation: TacticalOperation, reason: str, status: int, code: str, object_id=None) -> TacticalOperationError:
    """Core's own refusal (steps 3 to 5): a deny row with a fixed Core text, and the typed error to raise."""
    audit = _write_row(
        request, operation, action="deny", object_id=object_id, message=DENY_MESSAGES[reason], tactical_status=None, refusal=True,
        extra={"refused_action": operation.audit_action, "reason": reason, "status": status},
    )
    text = "object_not_found" if reason == "not_found" else reason
    return TacticalOperationError(MESSAGES[text], status=status, code=code, audit=audit)


def _encode_multipart(fields: dict[str, str], part: dict) -> tuple[bytes, str]:
    """A multipart/form-data payload of text parts and one file part, with a random boundary. No django.test (1.17.13)."""
    content = part["content"]
    while True:
        boundary = "TecTacBoundary" + secrets.token_hex(16)
        if boundary.encode("ascii") not in content:
            break
    lines = []
    for name, value in fields.items():
        lines.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode() + str(value).encode() + b"\r\n")
    lines.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{part['field']}\"; filename=\"{part['name']}\"\r\n"
        f"Content-Type: {part['content_type']}\r\n\r\n".encode() + content + b"\r\n"
    )
    lines.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(lines), boundary


def _text_part(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))


def _build_request(request, operation: TacticalOperation, path: str, body: dict, match, *, method: str | None = None, query=None, file=None):
    """A copy of the incoming request with path, method, query and body replaced, authenticated as the signed-in user."""
    from django.http import HttpRequest

    verb = method or operation.method
    source = getattr(request, "_request", request)
    content_type = ""
    params_of_type = {}
    if verb not in BODY_METHODS:
        payload = b""
    elif file is not None:
        # Tactical's own MultiPartParser reads the file and the text parts, as it would from a browser.
        payload, boundary = _encode_multipart({key: _text_part(value) for key, value in body.items()}, file)
        content_type, params_of_type = "multipart/form-data", {"boundary": boundary}
    else:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        content_type = "application/json"
    header = content_type + (f"; boundary={params_of_type['boundary']}" if params_of_type else "")
    query_string = _query_string(query) if query else ""
    clone = HttpRequest()
    meta = {key: value for key, value in dict(getattr(source, "META", {}) or {}).items() if key not in ("HTTP_AUTHORIZATION", "HTTP_COOKIE")}
    meta.update(
        REQUEST_METHOD=verb, PATH_INFO=path, QUERY_STRING=query_string, CONTENT_TYPE=header if payload else "",
        CONTENT_LENGTH=str(len(payload)),
    )
    clone.META = meta
    clone.method = verb
    clone.path = path
    clone.path_info = path
    clone.content_type = content_type if payload else ""
    clone.content_params = params_of_type if payload else {}
    clone._body = payload
    clone._stream = BytesIO(payload)
    clone._read_started = False
    if query_string:
        from django.http import QueryDict

        clone.GET = QueryDict(query_string)  # DRF's request.query_params reads this
    clone.resolver_match = match
    clone._dont_enforce_csrf_checks = True
    # DRF's ForcedAuthentication reads this. No Knox token is read or forwarded.
    clone._force_auth_user = request.user
    # Tactical's LogIPMiddleware sets this on the outer request only, and several Tactical views read it.
    clone._client_ip = _source_client_ip(source, meta)
    return clone


def _source_client_ip(source, meta: dict) -> str:
    """The caller's address as Tactical's LogIPMiddleware would set it: copied when present, else worked out from META."""
    value = getattr(source, "_client_ip", None)
    if value is not None:
        return str(value)
    try:
        from ipware import IpWare

        found, _ = IpWare().get_client_ip(meta)
        return str(found) if found else ""
    except (ImportError, ValueError, TypeError, AttributeError):
        return str(meta.get("REMOTE_ADDR") or "")


def _concrete_path(operation: TacticalOperation, params: dict[str, str]) -> str:
    parts = [seg[1] if seg[0] == "lit" else params[seg[1]] for seg in operation.segments]
    if _forbidden_route(parts):
        raise TacticalOperationError(MESSAGES["not_found"], status=404, code="tactical_operation_not_found")
    return "/" + "/".join(parts) + ("/" if operation.trailing_slash else "")


def _recheck_route_owner(operation: TacticalOperation, path: str) -> None:
    """Defence in depth: the module must own the rule that the concrete path lands on, whatever registration let through.

    Core re-reads the owner table and the honoured replacements here, so an operation registered in-process still cannot
    reach another module's route, nor a route its replacement no longer owns.
    """
    parts = [part.lower() for part in path.strip("/").split("/")]
    rule = _matching_rule(parts)
    if rule is not None and ((operation.module_id, rule) in CATEGORY_EXCEPTIONS or operation.module_id in ROUTE_OWNERS[rule]):
        return
    if rule is None or operation.module_id not in _owners_for_rule(rule):
        raise TacticalOperationError(MESSAGES["not_found"], status=404, code="tactical_operation_not_found")


def _after_values(operation: TacticalOperation, body: dict, query: dict | None = None, file: dict | None = None) -> dict | None:
    """The declared audit fields, copied from the body or the query string, and for an upload only its name, size and type."""
    if not operation.audit_fields and file is None:
        return None
    values = {}
    for name in operation.audit_fields:
        if name in body:
            values[name] = body[name]
        elif query and name in query:
            values[name] = query[name]
    if file is not None:
        values["upload"] = {"file_name": _printable(file["name"]), "size": len(file["content"]), "content_type": file["content_type"]}
    return values


def _before_values(operation: TacticalOperation, data: Any) -> dict | None:
    """The whitelisted scalar fields of Tactical's own answer: strings cut to 256 characters, everything else dropped."""
    if not isinstance(data, dict):
        return None
    values = {}
    for name in operation.before.fields:
        value = data.get(name)
        if isinstance(value, str):
            values[name] = "".join(ch for ch in value if ord(ch) >= 32 and ord(ch) != 127)[:_BEFORE_STRING_LIMIT]
        elif value is None or isinstance(value, (bool, int, float)):
            values[name] = value
    return values


def _dispatch(match, forwarded):
    response = match.func(forwarded, *match.args, **match.kwargs)
    if hasattr(response, "render") and callable(response.render) and not getattr(response, "is_rendered", True):
        response.render()
    return response


def _read_before(request, operation: TacticalOperation, params: dict[str, str]) -> dict:
    """Run the declared before-read in-process through Tactical's own view, as the signed-in user (1.17.13).

    Never raises and never blocks the change: the answer is {"status", "values"}, and ``values`` is None when the read
    did not answer 200 or could not be read. No HTTP call, no token."""
    spec = operation.before
    try:
        from django.urls import resolve

        parts = [seg[1] if seg[0] == "lit" else params[seg[1]] for seg in spec.segments]
        if _forbidden_route(parts):
            return {"status": None, "values": None}
        path = "/" + "/".join(parts) + ("/" if spec.trailing_slash else "")
        _recheck_route_owner(operation, path)
        match = resolve(path)
        response = _dispatch(match, _build_request(request, operation, path, {}, match, method="GET"))
        status = int(getattr(response, "status_code", 500))
        if status != 200 or getattr(response, "streaming", False):
            return {"status": status, "values": None}
        content = bytes(getattr(response, "content", b"") or b"")
        if len(content) > MAX_RESPONSE_BYTES:
            return {"status": status, "values": None}
        return {"status": status, "values": _before_values(operation, json.loads(content.decode("utf-8")))}
    except Exception:
        logger.warning("The before-read of Tactical operation %s/%s did not answer.", operation.module_id, operation.id, exc_info=True)
        return {"status": None, "values": None}


def _unknown_outcome(request, operation, object_id, tactical_status, code: str, text: str) -> TacticalOperationError:
    """After dispatch, a non-GET call whose result Core cannot trust may have changed Tactical: say so in the log."""
    audit = None
    if operation.method != "GET":
        audit = _write_row(
            request, operation, action=OUTCOME_UNKNOWN_ACTION, object_id=object_id, message=OUTCOME_UNKNOWN_MESSAGE,
            tactical_status=tactical_status,
        )
    return TacticalOperationError(text, status=502, code=code, audit=audit)


def run_tactical_operation(request, module_id, operation_id, params=None, body=None, query=None, upload=None) -> TacticalOperationResult:
    """Run one declared Tactical operation for the signed-in user and audit it. Needs an authenticated request.

    ``query`` (1.17.13) is a flat object of the operation's whitelisted query names, for a GET operation. ``upload`` is
    {name, content_type, content} (bytes) for an operation that declares a file part.

    Raises TacticalOperationError (``status``, ``code``, ``message``, ``audit``) for Core's own refusals and for a
    failure around the call. A Tactical answer, whatever its status, comes back as the result.
    """
    operation = _lookup(module_id, operation_id)  # 1. exists and its module is enabled
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):  # 2.
        raise _fail("unauthenticated", 401, "authentication_required")

    from .rbac import has_extension_permission, tactical_permission_flags

    hint = None
    try:
        hint_params = params if isinstance(params, dict) else {}
        hint = _object_id(_scope_values(operation, hint_params, body if isinstance(body, dict) else {}), operation, hint_params)
    except TacticalOperationError:
        hint = _object_id([], operation, params if isinstance(params, dict) else {})
    flags = tactical_permission_flags(user, operation.permissions)  # 3.
    if not all(flags.values()):
        raise _refuse(request, operation, "permission_denied", 403, "tactical_permission_denied", hint)
    if operation.module_permission:  # 4.
        try:
            allowed = has_extension_permission(user, operation.module_permission)
        except Exception:
            logger.exception("Unable to check module permission %s for operation %s", operation.module_permission, operation.id)
            allowed = False
        if not allowed:
            raise _refuse(request, operation, "module_permission_denied", 403, "module_permission_denied", hint)

    params = _clean_params(operation, params)  # 5. shape, then scope
    body = _clean_body(operation, body)
    query = _clean_query(operation, query)
    file = _clean_upload(operation, upload)
    scope = _scope_values(operation, params, body)
    object_id = _object_id(scope, operation, params)
    if scope:
        from . import resources_adapter as adapter

        for kind, ids in scope:
            if not adapter.objects_in_role_scope(user=user, resource_type=kind, identifiers=ids):
                raise _refuse(request, operation, "not_found", 404, "object_not_found", object_id)
    _check_whitelist(operation, body)  # 6.

    from django.urls import resolve  # 7.

    path = _concrete_path(operation, params)
    _recheck_route_owner(operation, path)
    try:
        match = resolve(path)
    except Exception:
        # Tactical renamed or removed the route. Never fall back to another path.
        raise TacticalOperationError(
            "Tactical no longer serves this route. The owning module needs an update.", status=502, code="tactical_route_changed",
        ) from None

    extra: dict = {}
    body_type = _body_scope_type(operation, scope)
    if body_type:
        extra["scope_type"] = body_type
    before_state = None
    if operation.before is not None:  # 7a. Tactical's own record of the object, read as the signed-in user (1.17.13)
        before_state = _read_before(request, operation, params)
        if any(item.source.startswith("before:") for item in operation.scope):
            fresh = None
            try:
                fresh = _scope_values(operation, params, body, before_state["values"], phase="before") if before_state["values"] is not None else None
            except TacticalOperationError:
                fresh = None
            if fresh is None:  # fails closed: no answer, no scope decision
                raise _refuse(request, operation, "not_found", 404, "object_not_found", object_id)
            from . import resources_adapter as adapter

            for kind, ids in fresh:
                if not adapter.objects_in_role_scope(user=user, resource_type=kind, identifiers=ids):
                    raise _refuse(request, operation, "not_found", 404, "object_not_found", object_id)
            scope = scope + fresh
            if object_id is None:
                object_id = _object_id(scope, operation, params)
        extra["before"] = "recorded" if before_state["values"] is not None else "unavailable"
        if before_state["values"] is None:
            extra["before_status"] = before_state["status"]

    forwarded = _build_request(request, operation, path, body, match, query=query, file=file)
    try:
        response = _dispatch(match, forwarded)
    except Exception:
        logger.exception("Tactical operation %s/%s raised after dispatch", operation.module_id, operation.id)
        raise _unknown_outcome(request, operation, object_id, None, "tactical_call_failed", "Tactical failed while running this operation.") from None

    status = int(getattr(response, "status_code", 500))
    if getattr(response, "streaming", False):
        raise _unknown_outcome(request, operation, object_id, status, "tactical_response_refused", "Core does not relay streaming responses.")
    content = bytes(getattr(response, "content", b"") or b"")
    if len(content) > MAX_RESPONSE_BYTES:
        raise _unknown_outcome(request, operation, object_id, status, "tactical_response_refused", "Tactical's answer is larger than Core relays.")

    audit = None  # 8.
    if 200 <= status < 300:
        audit = _write_row(
            request, operation, action=operation.audit_action, object_id=object_id,
            message=operation.message or f"Core ran Tactical operation {operation.id}.",
            before=before_state["values"] if before_state else None,
            after=_after_values(operation, body, query, file), tactical_status=status, extra=extra,
        )
    elif status in (401, 403):
        audit = _write_row(
            request, operation, action="deny", object_id=object_id, message=DENY_MESSAGES["tactical_denied"], tactical_status=status,
            refusal=True, extra={"refused_action": operation.audit_action, "reason": "tactical_denied", "status": status},
        )
    elif status >= 500 and operation.method != "GET":
        audit = _write_row(
            request, operation, action=OUTCOME_UNKNOWN_ACTION, object_id=object_id, message=OUTCOME_UNKNOWN_MESSAGE, tactical_status=status,
        )

    content_type = str(response.get("Content-Type", "") or "") if hasattr(response, "get") else ""
    headers = {}
    for name in RELAYED_HEADERS:
        value = response.get(name) if hasattr(response, "get") else None
        if value:
            headers[name] = str(value)
    data: Any = content
    if content_type.split(";")[0].strip().lower() in ("application/json",) or content_type.split(";")[0].strip().lower().endswith("+json"):
        try:
            data = json.loads(content.decode("utf-8")) if content else None
        except (ValueError, UnicodeDecodeError):
            data = content
    return TacticalOperationResult(status=status, data=data, content_type=content_type, headers=headers, audit=audit or {}, content=content)


# ----------------------------------------------------------------------------------------------- capability

class _TacticalOperationsProvider:
    run = staticmethod(run_tactical_operation)
    list_operations = staticmethod(list_operations)
    get_operation = staticmethod(get_operation)


_PROVIDER = _TacticalOperationsProvider()


def tactical_operations_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["run", "list_operations", "get_operation"],
        "declaration": "tec_tac.tactical_operations.register_tactical_operation(id, module_id, method, route, permissions, scope, body_fields, audit, module_permission=None, message=None, query_params=None, upload=None), called from AppConfig.ready()",
        "http": "POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ with {params, body, query} as JSON, or as multipart/form-data with the text parts params, body and query (each a JSON object) and one file part",
        "limits": {"body_bytes": MAX_BODY_BYTES, "response_bytes": MAX_RESPONSE_BYTES, "upload_bytes": MAX_UPLOAD_BYTES, "query_params": MAX_QUERY_PARAMS, "query_value_chars": MAX_QUERY_VALUE},
        "declaration_keys_added_in_1_1_0": [
            "audit.object_param", "audit.before", "scope source before:<field>", "scope type body:<field> with type_map", "query_params", "upload",
        ],
        "refusal_codes_added_in_1_1_0": ["query_field_not_allowed", "invalid_query", "upload_not_allowed", "upload_too_large", "upload_type_not_allowed", "invalid_upload"],
        "audit_header": AUDIT_HEADER,
        "modes": "(a) a signed-in user's request only. Background runs as the schedule owner (mode b) are not part of this contract.",
    }


def register_core_tactical_operations_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Typed Tactical operations that Core runs server-side for a signed-in user and audits where the call happens.",
        operations=("run", "list_operations", "get_operation"),
        metadata=tactical_operations_contract_metadata(),
    )
