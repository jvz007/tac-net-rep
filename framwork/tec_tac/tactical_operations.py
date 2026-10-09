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
"""
from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

logger = logging.getLogger("tec_tac.tactical_operations")

CAPABILITY_ID = "core.tactical_operations"
CAPABILITY_VERSION = "1.0.0"
AUDIT_HEADER = "X-Tec-Tac-Audit"
AUDIT_RECORDED = "recorded"
AUDIT_NOT_RECORDED = "not-recorded"
MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 25 * 2**20
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
_SCOPE_SOURCE_RE = re.compile(r"^(path|body):([A-Za-z_][A-Za-z0-9_]{0,63})$")
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
    type: str
    source: str  # path:<name> or body:<field>


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
            "scope": [{"type": item.type, "source": item.source} for item in self.scope],
            "body_fields": list(self.body_fields),
            "audit": {"action": self.audit_action, "object_type": self.audit_object_type, "audit_fields": list(self.audit_fields)},
            "module_permission": self.module_permission,
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
        raise TacticalOperationRegistrationError("route must be a relative Tactical route template such as agents/{agent_id}/reboot/.")
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


# Core-held owner map (AD-19 condition 1, three-layer design of 8 October 2026). The first segment of a Tactical route is
# its API group. Only the core modules listed for a group may declare an operation in it. It follows the function map
# (reviews/modules/TACTICAL-FUNCTION-MAP-30-09-2026.md) and the route homes in AD-18. A group missing here is refused:
# add it here, in a Core release, when a core module owns it. ``accounts``, ``api``, ``beta`` and clients/sites writes
# that belong to Core are deliberately absent.
GROUP_OWNERS: dict[str, frozenset] = {
    "agents": frozenset({"endpoints", "agents", "agent-management", "remote-background", "take-control", "scriptexecution"}),
    "logs": frozenset({"endpoints", "agents", "audit", "debug"}),
    "reporting": frozenset({"reportmanager"}),
    "core": frozenset({"globalsettings", "reportmanager", "scriptmanager"}),
    "automation": frozenset({"automation", "patching"}),
    "clients": frozenset({"agent-management"}),
    "alerts": frozenset({"alerts"}),
    "scripts": frozenset({"scriptmanager"}),
    "checks": frozenset({"checks"}),
    "software": frozenset({"software"}),
    "tasks": frozenset({"tasks"}),
    "services": frozenset({"remote-background"}),
    "winupdate": frozenset({"patching"}),
}

# The named exceptions to "category core only": (module id, first two literal route segments). Licensing is a server
# module and owns Tactical's code-signing route (AD-16, AD-17). A premium module that replaces a core module 100% is
# not listed: Core has no signal yet that says it is the one installed (reviews/questions/core.md, 9 October 2026).
CATEGORY_EXCEPTIONS: frozenset = frozenset({("licensing", ("core", "codesign"))})


def _check_route_owner(module: dict, segments: tuple) -> None:
    """Refuse a route the module does not own: a non-core module, or a core module outside its Tactical group."""
    owner = module["id"]
    literal = [seg[1].lower() if seg[0] == "lit" else "{}" for seg in segments]
    if (owner, tuple(literal[:2])) in CATEGORY_EXCEPTIONS:
        return
    if module.get("category") != "core":
        raise TacticalOperationRegistrationError(
            f"module {owner!r} is not a core module. Only the core module that owns a Tactical group can declare its operations."
        )
    if owner not in GROUP_OWNERS.get(literal[0], frozenset()):
        raise TacticalOperationRegistrationError(
            f"module {owner!r} does not own Tactical group {literal[0]!r}. Declare the operation in the core module that does."
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
):
    """Declare one Tactical operation. Call it from the owning module's ``AppConfig.ready()``.

    Refuses (TacticalOperationRegistrationError, a ValueError) a module that is not a core module (bar the named
    exceptions) or a route outside the module's Tactical group (``GROUP_OWNERS``), a route Core owns, ``..``, a second operation on the
    same (method, route), a flag that is not a boolean ``can_*`` field on Tactical's Role, an unknown, legacy or
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
    _check_route_owner(module, segments)

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
    for item in scope:
        if not isinstance(item, dict) or set(item) != {"type", "source"}:
            raise TacticalOperationRegistrationError("each scope entry is {type, source} and nothing else.")
        kind, source = item["type"], item["source"]
        match = _SCOPE_SOURCE_RE.match(source) if isinstance(source, str) else None
        if kind not in SCOPE_TYPES or match is None:
            raise TacticalOperationRegistrationError(f"bad scope entry {item!r}: type is agent, client or site and source is path:<name> or body:<field>.")
        where, name = match.group(1), match.group(2)
        if where == "path":
            if name not in params:
                raise TacticalOperationRegistrationError(f"scope source {source!r} is not a parameter of the route.")
            if kind in ("client", "site") and params[name] != "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a {kind}.")
            if kind == "agent" and params[name] == "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be a string parameter for an agent.")
        elif name not in fields:
            raise TacticalOperationRegistrationError(f"scope source {source!r} is not one of body_fields.")
        spec = ScopeSpec(kind, source)
        if spec in scope_specs:
            raise TacticalOperationRegistrationError(f"scope entry {item!r} is repeated.")
        scope_specs.append(spec)
    if len(scope_specs) > _MAX_SCOPE:
        raise TacticalOperationRegistrationError("too many scope entries.")

    if not isinstance(audit, dict) or not {"action", "object_type"} <= set(audit) or set(audit) - {"action", "object_type", "audit_fields"}:
        raise TacticalOperationRegistrationError("audit is {action, object_type, audit_fields}.")
    try:
        action = audit_core._normalize_action(audit["action"])
        object_type = audit_core._normalize_object_type(audit["object_type"])
    except audit_core.AuditContractError as exc:
        raise TacticalOperationRegistrationError(f"audit: {exc}") from None
    if action == "deny" or action == OUTCOME_UNKNOWN_ACTION:
        raise TacticalOperationRegistrationError("audit action deny and custom:outcome-unknown are written by Core only.")
    audit_fields = _clean_names(audit.get("audit_fields"), "audit_fields", maximum=_MAX_BODY_FIELDS)
    for name in audit_fields:
        if name not in fields:
            raise TacticalOperationRegistrationError(f"audit field {name!r} is not one of body_fields.")
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
    return operation


def _printable(value: Any, limit: int = 255) -> str:
    return "".join(ch for ch in str(value) if 32 <= ord(ch) < 127)[:limit]


def _scope_values(operation: TacticalOperation, params: Any, body: Any) -> list[tuple[str, list[str]]]:
    """Resolve every declared scope entry to (type, [ids]). Raises 400 for a missing or malformed value."""
    resolved = []
    for spec in operation.scope:
        where, name = spec.source.split(":", 1)
        if where == "path":
            raw = (params or {}).get(name)
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
        resolved.append((spec.type, ids))
    return resolved


def _object_id(scope: list[tuple[str, list[str]]]) -> str | None:
    if not scope:
        return None
    ids = scope[0][1]
    return _printable(",".join(ids)) or None


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


def _check_whitelist(operation: TacticalOperation, body: dict) -> None:
    extra = sorted(set(body) - set(operation.body_fields))
    if extra:
        raise TacticalOperationError(
            "Body field not allowed: " + ", ".join(_printable(name, 40) for name in extra),
            status=400, code="body_field_not_allowed",
        )


def _write_row(request, operation: TacticalOperation, *, action: str, object_id, message: str, after=None,
               tactical_status: int | None, refusal: bool = False, extra: dict | None = None) -> dict:
    """Write one Core audit row. Never raises: a failed write is logged and reported."""
    from . import audit as audit_core

    metadata = {"operation": operation.id, "method": operation.method, "route": operation.route, "tactical_status": tactical_status}
    metadata.update(extra or {})
    try:
        result = audit_core.record_tactical_operation(
            actor=getattr(request, "user", None), module_id=operation.module_id, action=action,
            object_type=operation.audit_object_type, object_id=object_id, message=message, after=after,
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


def _build_request(request, operation: TacticalOperation, path: str, body: dict, match):
    """A copy of the incoming request with path, method and body replaced, authenticated as the signed-in user."""
    from django.http import HttpRequest

    source = getattr(request, "_request", request)
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8") if operation.method in BODY_METHODS else b""
    clone = HttpRequest()
    meta = {key: value for key, value in dict(getattr(source, "META", {}) or {}).items() if key not in ("HTTP_AUTHORIZATION", "HTTP_COOKIE")}
    meta.update(
        REQUEST_METHOD=operation.method, PATH_INFO=path, QUERY_STRING="", CONTENT_TYPE="application/json" if payload else "",
        CONTENT_LENGTH=str(len(payload)),
    )
    clone.META = meta
    clone.method = operation.method
    clone.path = path
    clone.path_info = path
    clone.content_type = "application/json" if payload else ""
    clone.content_params = {}
    clone._body = payload
    clone._stream = BytesIO(payload)
    clone._read_started = False
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


def _after_values(operation: TacticalOperation, body: dict) -> dict | None:
    if not operation.audit_fields:
        return None
    return {name: body[name] for name in operation.audit_fields if name in body}


def _unknown_outcome(request, operation, object_id, tactical_status, code: str, text: str) -> TacticalOperationError:
    """After dispatch, a non-GET call whose result Core cannot trust may have changed Tactical: say so in the log."""
    audit = None
    if operation.method != "GET":
        audit = _write_row(
            request, operation, action=OUTCOME_UNKNOWN_ACTION, object_id=object_id, message=OUTCOME_UNKNOWN_MESSAGE,
            tactical_status=tactical_status,
        )
    return TacticalOperationError(text, status=502, code=code, audit=audit)


def run_tactical_operation(request, module_id, operation_id, params=None, body=None) -> TacticalOperationResult:
    """Run one declared Tactical operation for the signed-in user and audit it. Needs an authenticated request.

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
        hint = _object_id(_scope_values(operation, params if isinstance(params, dict) else {}, body if isinstance(body, dict) else {}))
    except TacticalOperationError:
        hint = None
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
    scope = _scope_values(operation, params, body)
    object_id = _object_id(scope)
    if scope:
        from . import resources_adapter as adapter

        for kind, ids in scope:
            if not adapter.objects_in_role_scope(user=user, resource_type=kind, identifiers=ids):
                raise _refuse(request, operation, "not_found", 404, "object_not_found", object_id)
    _check_whitelist(operation, body)  # 6.

    from django.urls import resolve  # 7.

    path = _concrete_path(operation, params)
    try:
        match = resolve(path)
    except Exception:
        # Tactical renamed or removed the route. Never fall back to another path.
        raise TacticalOperationError(
            "Tactical no longer serves this route. The owning module needs an update.", status=502, code="tactical_route_changed",
        ) from None
    forwarded = _build_request(request, operation, path, body, match)
    try:
        response = match.func(forwarded, *match.args, **match.kwargs)
        if hasattr(response, "render") and callable(response.render) and not getattr(response, "is_rendered", True):
            response.render()
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
            after=_after_values(operation, body), tactical_status=status,
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
        "declaration": "tec_tac.tactical_operations.register_tactical_operation(id, module_id, method, route, permissions, scope, body_fields, audit, module_permission=None, message=None), called from AppConfig.ready()",
        "http": "POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ with {params, body}",
        "limits": {"body_bytes": MAX_BODY_BYTES, "response_bytes": MAX_RESPONSE_BYTES},
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
