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
* A scope entry may take its type from the body (``type: body:<field>`` with a ``type_map``).
* ``query_params`` lets an operation pass a whitelisted query string (a GET only until 1.17.41); ``upload`` lets one operation forward one file
  as multipart/form-data, with a size cap and an extension allow-list.
* AD-21: the owning module's effective category (a missing category is ``test``) decides, not only its id.

1.17.14 (Johan CQ37, CQ40; the capability is 1.2.0, still major 1):

* The scope source ``before:<field>`` is gone, and so is the fail-closed 404 ``object_not_found`` that came from a before-read
  that did not answer 200. An operation that has only an object id (a note edit or delete: route ``agents/notes/{pk:int}/``,
  ``audit.object_param`` ``pk``, ``scope`` empty) registers and runs with Tactical's own check deciding, as the Agents
  cancel-pending-action operation already does. ``audit.object_param`` is unchanged, so the audit row still names the id.
  ``audit.before`` stays as a non-blocking audit value: it never refuses a call.
* The upload ceiling is a system setting (``tactical_operation_upload_max_mib``, default 10 MiB, 1 to 25). An operation's
  declared ``max_bytes`` may be at most 25 MiB (``MAX_UPLOAD_ABSOLUTE_BYTES``, checked at registration, which must not read
  the database), and a file is held to the smaller of that and the setting at the time of the call.

1.17.18 (Johan CQ56 to CQ60; the capability is 1.4.0, still major 1; all additive, an operation declared the 1.17.17 way
registers and runs unchanged):

* ``caller_scope="unrestricted"``: only a caller with no client or site limits may run the operation (403
  ``scope_unrestricted_required``, a deny row, Tactical never called).
* A scope entry may be ``optional`` (resolved only when the body field is present), may have the type ``agent_pk`` (Tactical
  agent numbers), and may name a ``row_lookup``: a function the owning module registers with ``register_tactical_row_lookup``
  that maps the row a path id loads to its agent, so Core can apply the role's scope to that agent (CQ56 a, CQ57).
* ``audit.before`` keeps lists of whole numbers or short strings, ``count_fields`` records only a list's length, and
  ``select`` finds the row of a list GET by the path id (CQ58 a). ``audit.params`` records named path parameters.
* ``body_selector`` lets one module declare several operations on one Tactical route when their bodies are provably
  exclusive (CQ60).

1.17.19 (the capability is 1.5.0, still major 1; all additive, an operation declared the 1.17.18 way registers and runs unchanged):

* ``server_only=True`` keeps an operation off the browser and off Core's general route. Only a module backend can run it,
  through ``run_tactical_operation``. It stops the browser path; it is not a verified caller identity.
* The 403 ``tactical_permission_denied`` text names the missing Tactical role flag. The code and the deny row text are unchanged.

1.17.20 (the capability is 1.6.0, still major 1; additive):

* A non-GET operation that Tactical answers with a 4xx other than 401 and 403 (400, 404, 409, 422, 429 ...) writes one failed
  audit row: the Core-only action ``custom:operation-failed`` with the declared action in ``metadata.declared_action``, the
  declared object type, ``result: failed``, a fixed Core text, and no before or after value and none of Tactical's own text.
  ``result.audit`` and the ``X-Tec-Tac-Audit`` header are a verdict for these answers (before they were ``{}`` and absent).
  A GET 4xx still writes nothing. A module cannot declare or record this action.

1.17.21 (the capability is 1.7.0, still major 1; additive, an operation declared the 1.17.20 way registers and runs unchanged):

* Core's own refusal before Tactical is called writes one Core-only row for a call that is not ``GET``: ``custom:operation-failed``
  with ``failure: core_refused`` and ``code``, for ``body_field_not_allowed``, ``invalid_body``, ``invalid_params``,
  ``scope_field_required``, ``invalid_correlation_id`` and ``invalid_audit_before``. ``error.audit`` is the verdict. The two
  cleaners of ``correlation_id`` and ``audit_before`` now run at the validation step, after the operation lookup and the permission
  checks, so a row can be written. Until then an invalid correlation id is held back and no earlier deny row carries it.
* ``audit.object_field`` (a top-level scalar of Tactical's JSON answer) and ``audit.object_body_field`` (a cleaned body field) give the
  success row's object id when no ``audit.object_param`` and no scope object gives one. No other row carries them.

1.17.23 (the capability is 1.8.0, still major 1; additive, a scalar-only ``audit_before`` is unchanged):

* The Python-only ``audit_before`` keyword also accepts, per field, a list of whole numbers or short texts. It is kept to its first 1000
  entries (and 65536 characters) as declared before fields are, and the row carries ``<field>_count`` (the full length) and, when cut,
  ``<field>_truncated: true``. A list holding anything else, or a caller field named ``<list>_count`` or ``<list>_truncated`` next to
  a list, is refused 400 ``invalid_audit_before``.

1.17.26 (the capability is 1.9.0, still major 1; additive and opt-in, a declaration that passes neither key behaves exactly as before):

* ``permissions_any`` (optional): a list of Tactical role flags (``can_...``) of which the caller needs at least one. It combines with
  ``permissions``: the caller needs every flag of ``permissions`` and at least one of ``permissions_any``. Tactical's report generation
  is "view or manage reports", and ``permissions`` alone could only say "both". ``permissions`` may be empty only when
  ``permissions_any`` is given. The 403 ``tactical_permission_denied`` names the flags ("It needs one of can_view_reports,
  can_manage_reports."). A flag may not be in both lists. The deny row, ``describe()`` and the exported contract show the list.
* ``body_max_bytes`` (optional): a whole number from the 256 KiB default up to ``MAX_BODY_CEILING_BYTES`` (8 MiB, a Core constant), for
  an operation that forwards a large JSON body such as a template import. ``MAX_BODY_BYTES`` stays the default for every other
  operation. ``body_too_large`` (413) names the cap that applied. A value below the default, above the ceiling, a bool or a non-integer
  is refused at registration. The body and JSON depth parsing rules are unchanged.

1.17.28 (the capability is 1.10.0, still major 1; additive and opt-in, a declaration without ``audit_lists`` behaves exactly as before):

* ``audit_lists`` (optional, Python only): up to two body or before field names that hold a list of flat objects, such as a task's
  actions. Each is recorded IN CLEAR, with no masking, in the success row: the after value from the cleaned body, and, when the
  operation has a before read, the before value from Tactical's own GET answer. Script arguments and environment values appear as
  Tactical stores them. Bounds: 50 entries per list, 24 keys per entry (names that match the field-name pattern), a text value cut at
  4096 characters with control characters other than tab and newline removed, numbers, booleans and nulls, or one level of up to 100
  scalars, and 64 KiB of text per list field. ``<name>_count`` is the full length and ``<name>_truncated`` is true when anything was cut
  or dropped. A malformed list is recorded as its count only. Failed, denied and outcome-unknown rows carry no list. Since 1.17.52
  ``audit_list_masks`` can keep a key's value out of the row (see below); without it the list is still recorded in clear.

1.17.45 (the capability is 1.14.0, still major 1; all additive and opt-in, a declaration that passes none of them behaves exactly as before):

* ``audit.action_by_body = {field, map}``: the success row's audit action is chosen from the cleaned value of one declared body field
  (``{"field": "action", "map": {"approve": "approve", "ignore": "modify"}}``). A value that is missing, not text or not in the map keeps
  ``audit.action`` as the default. Registration refuses a field that is not in ``body_fields`` (or is a secret field), more than 8 map
  entries, a key that is not text or is over 40 characters, an action outside the audit vocabulary, and the Core-only actions (``deny``,
  ``custom:outcome-unknown``, ``custom:operation-failed``). Deny and other Core-only rows keep their own action; the chosen action is
  recorded in ``metadata.declared_action`` on failed and outcome-unknown rows.
* A scope entry may name a nested body source, ``body:<field>.<key>``, one level deep. ``<field>`` is one of ``body_fields`` and its value
  must be an object (a present non-object is 400 ``scope_field_required``). Optional entries, list values and the 1000 id cap behave as
  for a top-level source. The nested path is refused for ``row_lookup``, for ``audit.object_body_field`` and for ``audit.secret_fields``
  (the id would carry the value). The body Core forwards to Tactical is the object that was checked.
* A ``core_refused`` row for ``invalid_correlation_id``, ``invalid_audit_before`` or ``invalid_params`` now carries the declared
  ``audit.object_id`` (declared text, never caller input).

1.17.52 (the capability is 1.15.0, still major 1; additive and opt-in, a declaration that passes neither key behaves exactly as before):

* ``audit_list_masks`` (optional, Python only, ``{list name: {key: mode}}``): a per-key mask for a list already named in
  ``audit_lists``. ``audit_lists`` itself is unchanged, so a declaration that records a list in clear still does. Modes: ``names``
  (the key holds a list of text items such as ``script_args`` or ``env_vars``: only the NAME part of each item is recorded) and
  ``mask`` (the value is replaced by ``***``). Names rule, per item: text with ``=`` keeps what is before the first ``=`` (``KEY=VALUE``
  becomes ``KEY``, ``--flag=value`` becomes ``--flag``); other text that starts with ``-`` or ``/`` keeps its first token
  (``-Name value`` becomes ``-Name``); anything else is a positional argument with no name and becomes ``***``; a non-text item is
  ``***``. A name must look like a name (letters, digits, ``_``, ``.``, ``-``, at most 64 characters, optionally one or two leading
  dashes, or one leading ``/`` for a switch) and, for the ``=`` form, must be followed by a value that is not empty or only ``=``
  (base64 padding): otherwise the item is recorded as ``***``. Mask rule: a list item keeps its name and shows ``***`` for the value
  (``KEY=***``, ``--flag=***``, ``-Name ***``, a positional item ``***``); a scalar text key (a cmd action's ``command``) is ``***``.
  ``names`` on a scalar key records ``***`` too. Fail closed: a masked key whose value is not text or a list of scalars is ``***``;
  ``None`` stays null. The bounds of ``audit_lists`` apply after masking. The mask is applied to the body (after) and to Tactical's own
  before answer alike, and the unmasked text never reaches the row. Registration refuses a list that is not in ``audit_lists``, more
  than 8 keys per list, a key that is not a field-name, an unknown mode and a mapping that is not a dict.
* A scope entry may carry ``names_object: false`` (a strict bool, default true). The entry is resolved and checked exactly as before
  (scope check, deny rows and 400s unchanged), but it does not name the audit row's object. A create that checks
  ``body:dependencies.client`` can then have ``audit.object_field`` or ``audit.object_body_field`` name the created record. Registration
  refuses a non-bool, and a scope whose entries are all ``names_object: false`` unless the declaration has ``audit.object_param``,
  ``audit.object_field``, ``audit.object_body_field`` or ``audit.object_id``.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import logging
import math
import re
import secrets
import threading
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

from . import module_category as _module_category

logger = logging.getLogger("tec_tac.tactical_operations")

CAPABILITY_ID = "core.tactical_operations"
CAPABILITY_VERSION = "1.15.0"  # 1.17.52: audit_list_masks (names and *** for a list's keys) and scope names_object; 1.17.45: audit.action_by_body, a nested body scope source (body:<field>.<key>), object_id on early core_refused rows; 1.17.44: audit.object_id (a declared literal object id); 1.17.43: audit.secret_fields and metadata.object_count
AUDIT_HEADER = "X-Tec-Tac-Audit"
AUDIT_RECORDED = "recorded"
AUDIT_NOT_RECORDED = "not-recorded"
MAX_BODY_BYTES = 256 * 1024  # the DEFAULT body cap; an operation may declare a larger body_max_bytes up to the ceiling (1.17.26)
MAX_BODY_CEILING_BYTES = 8 * 2**20  # the most any operation may declare (1.17.26): a Core constant, never a module's choice
MAX_RESPONSE_BYTES = 25 * 2**20
MAX_UPLOAD_BYTES = 10 * 2**20  # the DEFAULT ceiling for one uploaded file (kept exported for older importers); the system setting changes it (CQ40)
MAX_UPLOAD_ABSOLUTE_BYTES = 25 * 2**20  # the most any operation may declare, and the setting's upper limit (1.17.14)
MAX_QUERY_PARAMS = 16
# An upload whose part is named after the file itself. Tactical's report asset upload stores each file under the name of
# its multipart part, not under the filename attribute (ee/reporting/views.py UploadAssets), so the part must be named
# after the cleaned file name.
FILE_NAME_FIELD = "{file_name}"
MAX_QUERY_VALUE = 512
RELAYED_HEADERS = ("Content-Type", "Content-Disposition")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SCOPE_TYPES = ("agent", "client", "site", "agent_pk")
OUTCOME_UNKNOWN_ACTION = "custom:outcome-unknown"
FAILED_ACTION = "custom:operation-failed"  # 1.17.20: Core-only; the declared action sits in metadata.declared_action

# Routes Core owns or that face agents. A module can never declare these, and a param value can never reach them.
FORBIDDEN_FIRST_SEGMENTS = ("accounts", "_allauth", "v2")
FORBIDDEN_FIRST_PREFIXES = ("logout",)  # logout, logoutall
FORBIDDEN_FIRST_TWO = (("api", "tfd"), ("api", "v3"), ("api", "v4"), ("agents", "installer"))

_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_LITERAL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
_PARAM_RE = re.compile(r"^\{([a-z][a-z0-9_]{0,31})(?::(str|int|agent|service))?\}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")  # 1.17.44: audit.object_id, a fixed text such as tactical-server
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SECRET_NAME_RE = re.compile(r"(pass|secret|token|key|credential|auth|cookie|signature)", re.IGNORECASE)
_PARAM_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SCOPE_SOURCE_RE = re.compile(r"^(path|body):([A-Za-z_][A-Za-z0-9_]{0,63})(?:\.([A-Za-z_][A-Za-z0-9_]{0,63}))?$")  # 1.17.45: body:<field>.<key>
_SCOPE_TYPE_BODY_RE = re.compile(r"^body:([A-Za-z_][A-Za-z0-9_]{0,63})$")
_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$")
_CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]{1,60}/[A-Za-z0-9!#$&^_.+-]{1,60}$")
_PARAM_VALUE_RE = {
    "str": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$"),
    "agent": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{20,254}$"),
    "int": re.compile(r"^[0-9]{1,12}$"),
    # 1.17.41: a Windows service name (services/{agent_id:agent}/{svcname:service}/). It may hold a space and $ # ( ) , which the
    # str kind refuses, but never a slash or a leading dot or space. The value is checked for '..' as every kind is.
    "service": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9 $#().,_-]{0,255}$"),
}
_MAX_SEGMENTS = 12
_MAX_ROUTE_LENGTH = 200
_MAX_PERMISSIONS = 8
_MAX_BODY_FIELDS = 64
_MAX_SCOPE = 4
_MAX_BEFORE_FIELDS = 32  # 1.17.18: 16 before (alerts asked for more)
_MAX_BEFORE_LIST = 1000  # entries of one list-valued before field (1.17.18)
_MAX_BEFORE_LIST_CHARS = 65536  # characters kept across one list-valued before field (1.17.18)
_MAX_BEFORE_SELECT_ROWS = 1000  # rows scanned in a list answer by audit.before.select (1.17.18)
_MAX_AUDIT_PARAMS = 8
_MAX_BODY_SELECTOR = 3
_MAX_TYPE_MAP = 8
_MAX_UPLOAD_EXTENSIONS = 16
_BEFORE_STRING_LIMIT = 256
_MAX_AUDIT_BEFORE_FIELDS = 16
_MAX_AUDIT_LISTS = 2  # 1.17.28: list fields one operation may record in clear
_LIST_MAX_ENTRIES = 50  # objects kept from one list
_LIST_MAX_KEYS = 24  # keys kept from one object
_LIST_MAX_ITEMS = 100  # scalars kept from one list value inside an object
_LIST_VALUE_MAX_CHARS = 4096  # characters kept from one text value
_LIST_MAX_TEXT_BYTES = 64 * 1024  # text bytes kept across one list field
_LIST_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # control characters, but not tab (\x09) or newline (\x0a)
_DROPPED = object()
_LIST_MASK_MODES = ("names", "mask")  # 1.17.52: audit_list_masks
_MAX_LIST_MASK_KEYS = 8  # keys one list may mask
_MASKED = "***"
# A name Core will record from a list item (1.17.52): optional dashes, then a letter or underscore. A switch may start with one "/".
_ITEM_NAME_RE = re.compile(r"^-{0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")
_ITEM_SWITCH_RE = re.compile(r"^(?:-{1,2}|/)[A-Za-z0-9_?][A-Za-z0-9_.\-]{0,63}$")
_MAX_FILE_NAME = 255

# One fixed Core text per refusal. None carries any wording from the declaring module or from Tactical.
MESSAGES = {
    "not_found": "The operation was not found.",
    "unauthenticated": "Sign in to run this operation.",
    "permission_denied": "Your Tactical role does not allow this operation.",
    "module_permission_denied": "Your Tec-Tac role does not allow this operation.",
    "object_not_found": "The requested object was not found, or you cannot access it.",
    "authenticated_request_required": "This operation needs a signed-in Tec-Tac request.",
    "scope_unrestricted_required": "This operation needs access to all clients and sites. Ask an administrator to change your role's scope.",
    "body_selector_mismatch": "The request does not match this operation. Check the fields you sent.",
    "server_only": "This operation can only be run by a module on the server, not from the browser.",
}
DENY_MESSAGES = {
    "permission_denied": "Core refused a Tactical operation: the signed-in user's Tactical role lacks a required permission.",
    "module_permission_denied": "Core refused a Tactical operation: the signed-in user's Tec-Tac role lacks the module permission.",
    "not_found": "Core refused a Tactical operation: the object is missing or outside the signed-in user's scope.",
    "scope_unrestricted_required": "Core refused a Tactical operation: it is for callers with access to all clients and sites, and the signed-in user's role is limited.",
    "body_selector_mismatch": "Core refused a Tactical operation: the request body does not match the operation that was named.",
    "tactical_denied": "Tactical refused an operation that Core ran for the signed-in user.",
    "server_only": "Core refused a Tactical operation: it is declared server-only and was called from the browser route.",
}
FAILED_MESSAGE = "Tactical refused this change (HTTP {status}); nothing was changed."
# 1.17.21: Core's own refusal before dispatch. A fixed Core text; the code is one of CORE_REFUSAL_ROW_CODES, never caller text.
CORE_REFUSED_MESSAGE = "Core refused this change before sending it to Tactical ({code}); nothing was changed."
# The six refusals of a non-GET call that write one Core row (requests/core.md, globalsettings 0.4.0). The other validation
# refusals (body_too_large, invalid_query, the upload codes, tactical_route_changed ...) write none in this release.
CORE_REFUSAL_ROW_CODES = (
    "body_field_not_allowed", "invalid_body", "invalid_params", "scope_field_required", "invalid_correlation_id", "invalid_audit_before",
)
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
    source: str  # path:<name> or body:<field>
    type_map: tuple = ()  # ((body value, scope type), ...) when ``type`` is body:<field>
    optional: bool = False  # 1.17.18: resolved only when the body field is present and not null
    row_lookup: str | None = None  # 1.17.18: id of a lookup the owning module registered (CQ56 a)
    names_object: bool = True  # 1.17.52: False keeps the entry checked but leaves it out of the audit row's object id


@dataclass(frozen=True)
class BeforeSpec:
    """A Tactical GET route that returns the object an operation changes, and the fields copied from it (1.17.13)."""

    route: str
    segments: tuple
    trailing_slash: bool
    fields: tuple
    count_fields: tuple = ()  # 1.17.18: list fields of the same read whose length only is recorded
    select: tuple | None = None  # 1.17.18: (path param, row key) for a list GET with no single-row read


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
    caller_scope: str | None = None  # 1.17.18: "unrestricted" or None
    body_selector: tuple = ()  # 1.17.18: ((field, "present"|"equals", value), ...), all must hold
    audit_params: tuple = ()  # 1.17.18: path parameters copied into the row's after value
    server_only: bool = False  # 1.17.19: only a module backend may run it (never the browser route)
    audit_object_field: str | None = None  # 1.17.21: top-level scalar of Tactical's JSON answer that is the row's object id
    audit_object_body_field: str | None = None  # 1.17.21: cleaned body field that is the row's object id when the answer gives none
    permissions_any: tuple = ()  # 1.17.26: the caller needs at least one of these flags (and every flag of ``permissions``)
    body_max_bytes: int | None = None  # 1.17.26: a larger body cap than MAX_BODY_BYTES; None means the default
    audit_lists: tuple = ()  # 1.17.28: body or before fields that hold a list of flat objects, recorded in clear (CQ85 a)
    file_response: bool = False  # 1.17.41: Tactical answers with a streamed file that Core relays (GET or POST only)
    secret_fields: tuple = ()  # 1.17.43: body fields whose value Core never records; the row carries only changed or unchanged
    audit_object_id: str | None = None  # 1.17.44: a fixed text from the module's declaration; the last fallback for the row's object id
    audit_action_by_body: tuple = ()  # 1.17.45: (field, ((body value, audit action), ...)); the success row's action follows the body
    audit_list_masks: tuple = ()  # 1.17.52: ((list name, ((key, "names"|"mask"), ...)), ...) for lists in audit_lists

    @property
    def body_cap(self) -> int:
        """The body size limit that applies to this operation, in bytes."""
        return self.body_max_bytes if self.body_max_bytes is not None else MAX_BODY_BYTES

    @property
    def params(self) -> tuple:
        return tuple((seg[1], seg[2]) for seg in self.segments if seg[0] == "param")

    def _describe_before(self) -> dict | None:
        if not self.before:
            return None
        out: dict[str, Any] = {"route": self.before.route, "fields": list(self.before.fields)}
        if self.before.count_fields:
            out["count_fields"] = list(self.before.count_fields)
        if self.before.select:
            out["select"] = {"param": self.before.select[0], "field": self.before.select[1]}
        return out

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module_id": self.module_id,
            "method": self.method,
            "route": self.route,
            "params": {name: kind for name, kind in self.params},
            "permissions": list(self.permissions),
            "permissions_any": list(self.permissions_any),
            "body_max_bytes": self.body_cap,
            "scope": [
                {
                    "type": item.type, "source": item.source,
                    **({"type_map": dict(item.type_map)} if item.type_map else {}),
                    **({"optional": True} if item.optional else {}),
                    **({"row_lookup": item.row_lookup} if item.row_lookup else {}),
                    **({"names_object": False} if not item.names_object else {}),
                }
                for item in self.scope
            ],
            "body_fields": list(self.body_fields),
            "audit": {
                "action": self.audit_action, "object_type": self.audit_object_type, "audit_fields": list(self.audit_fields),
                "object_param": self.audit_object_param,
                "before": self._describe_before(),
                "params": list(self.audit_params),
                "object_field": self.audit_object_field,
                "object_body_field": self.audit_object_body_field,
                "lists": list(self.audit_lists),
                "list_masks": {name: dict(pairs) for name, pairs in self.audit_list_masks},
                "secret_fields": list(self.secret_fields),
                "object_id": self.audit_object_id,
                "action_by_body": (
                    {"field": self.audit_action_by_body[0], "map": dict(self.audit_action_by_body[1])} if self.audit_action_by_body else None
                ),
            },
            "caller_scope": self.caller_scope,
            "server_only": self.server_only,
            "body_selector": [
                {"field": name, kind: value} for name, kind, value in self.body_selector
            ],
            "module_permission": self.module_permission,
            "query_params": list(self.query_params),
            "file_response": self.file_response,
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
# (method, route key) -> the (module id, operation id) pairs declared on it. One pair, unless the owning module declared
# several operations with provably exclusive body selectors (1.17.18, CQ60).
_ROUTES: dict[tuple[str, str], list[tuple[str, str]]] = {}
_ROW_LOOKUPS: dict[tuple[str, str], Any] = {}


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
                raise TacticalOperationRegistrationError(f"route parameter {part!r} must look like {{name}} or {{name:str|int|agent|service}}.")
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
        if not isinstance(value, str) or not pattern.fullmatch(value):
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
    # 1.17.18 (Johan, 10 October 2026): the agent's own task and check lists belong to the modules that own those groups.
    (("agents", "{}", "tasks"), ("tasks",)),
    (("agents", "{}", "checks"), ("checks",)),
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
    """Validate ``audit.before = {route, fields, count_fields?, select?}`` (1.17.13, extended 1.17.18)."""
    if value is None:
        return None
    if verb == "GET":
        raise TacticalOperationRegistrationError("a GET operation changes nothing, so it has no audit.before.")
    if not isinstance(value, dict) or not {"route", "fields"} <= set(value) or set(value) - {"route", "fields", "count_fields", "select"}:
        raise TacticalOperationRegistrationError("audit.before is {route, fields}, plus count_fields and select when needed, and nothing else.")
    segments, trailing = _parse_route(value["route"])
    # The read is a Tactical GET like any operation, so the same module must own it.
    _check_route_owner(module, segments, value["route"])
    for seg in segments:
        if seg[0] == "param" and params.get(seg[1]) != seg[2]:
            raise TacticalOperationRegistrationError(
                f"audit.before route parameter {seg[1]!r} must be a parameter of the operation's own route, with the same kind."
            )
    names = _clean_names(value["fields"], "audit.before fields", maximum=_MAX_BEFORE_FIELDS)
    counts = _clean_names(value.get("count_fields"), "audit.before count_fields", maximum=_MAX_BEFORE_FIELDS)
    if not names and not counts:
        raise TacticalOperationRegistrationError("audit.before fields must name at least one field.")
    for name in (*names, *counts):
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"audit.before field {name!r} looks like a secret. Never put secrets in the audit row.")
    overlap = set(names) & set(counts)
    if overlap:
        raise TacticalOperationRegistrationError(f"audit.before names {sorted(overlap)[0]!r} in both fields and count_fields.")
    # A list field also writes <name>_count (and <name>_truncated when cut), and a count field writes <name>_count: no clash.
    for name in names:
        for suffix in ("_count", "_truncated"):
            if f"{name}{suffix}" in names:
                raise TacticalOperationRegistrationError(f"audit.before field {name + suffix!r} would be written twice.")
        if f"{name}_count" in counts:
            raise TacticalOperationRegistrationError(f"audit.before field {name + '_count'!r} would be written twice.")
    for name in counts:
        if f"{name}_count" in names:
            raise TacticalOperationRegistrationError(f"audit.before field {name + '_count'!r} would be written twice.")
    select = None
    raw_select = value.get("select")
    if raw_select is not None:
        if not isinstance(raw_select, dict) or "param" not in raw_select or set(raw_select) - {"param", "field"}:
            raise TacticalOperationRegistrationError("audit.before select is {param, field}; field is optional and defaults to id.")
        param, key = raw_select["param"], raw_select.get("field", "id")
        if not isinstance(param, str) or params.get(param) not in ("int", "str"):
            raise TacticalOperationRegistrationError("audit.before select param must be an int or str path parameter of the operation's route.")
        if not isinstance(key, str) or not _FIELD_RE.fullmatch(key) or _SECRET_NAME_RE.search(key):
            raise TacticalOperationRegistrationError("audit.before select field must be a plain, non-secret key name.")
        select = (param, key)
    return BeforeSpec(value["route"], segments, trailing, names, counts, select)


def _parse_object_name(value: Any, label: str, verb: str) -> str | None:
    """Validate ``audit.object_field`` or ``audit.object_body_field`` (1.17.21): a plain, non-secret name on a non-GET operation."""
    if value is None:
        return None
    if verb == "GET":
        raise TacticalOperationRegistrationError(f"a GET operation changes nothing, so it has no {label.replace('audit ', 'audit.')}.")
    if not isinstance(value, str) or not _FIELD_RE.fullmatch(value):
        raise TacticalOperationRegistrationError(f"{label} must be a plain field name.")
    if _SECRET_NAME_RE.search(value):
        raise TacticalOperationRegistrationError(f"{label} {value!r} looks like a secret. Never put secrets in the audit row.")
    return value


def _parse_object_id(value: Any, verb: str) -> str | None:
    """Validate ``audit.object_id`` (1.17.44): a fixed, plain, non-secret text on a non-GET operation. The module's signed code
    declares it, so it is not caller or body input."""
    if value is None:
        return None
    if verb == "GET":
        raise TacticalOperationRegistrationError("a GET operation changes nothing, so it has no audit.object_id.")
    if not isinstance(value, str) or not _OBJECT_ID_RE.fullmatch(value):
        raise TacticalOperationRegistrationError(
            "audit.object_id must be a plain text of 1 to 64 characters: letters, digits and . _ : -, starting with a letter or digit."
        )
    if _SECRET_NAME_RE.search(value):
        raise TacticalOperationRegistrationError(f"audit.object_id {value!r} looks like a secret. Never put secrets in the audit row.")
    return value


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
    if name != FILE_NAME_FIELD and (not isinstance(name, str) or not _FIELD_RE.fullmatch(name) or name in ("params", "body", "query") or name in fields):
        raise TacticalOperationRegistrationError(
            f"upload field must be a plain name that is not params, body, query or a body field, or {FILE_NAME_FIELD} to name the part after the file."
        )
    # Registration runs in AppConfig.ready() and must not read the database, so it checks the fixed absolute ceiling. The system
    # setting (1 to 25 MiB, default 10) is applied on every call by upload_ceiling_bytes() (1.17.14, CQ40).
    if isinstance(cap, bool) or not isinstance(cap, int) or not 0 < cap <= MAX_UPLOAD_ABSOLUTE_BYTES:
        raise TacticalOperationRegistrationError(f"upload max_bytes must be a whole number from 1 to {MAX_UPLOAD_ABSOLUTE_BYTES}.")
    extensions = _clean_names(value["extensions"], "upload extensions", maximum=_MAX_UPLOAD_EXTENSIONS, pattern=_EXTENSION_RE)
    if not extensions:
        raise TacticalOperationRegistrationError("upload extensions must list at least one allowed file extension (lower case, no dot).")
    return UploadSpec(name, cap, extensions)


def _parse_body_selector(value: Any, fields: tuple) -> tuple:
    """Validate ``body_selector`` (1.17.18, CQ60): at most 3 conditions on body fields, all of which must hold."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes, dict)) or not hasattr(value, "__iter__"):
        raise TacticalOperationRegistrationError("body_selector must be a list of conditions.")
    conditions = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or "field" not in item or len(item) != 2 or len({"present", "equals"} & set(item)) != 1:
            raise TacticalOperationRegistrationError("each body_selector condition is {field, present} or {field, equals}.")
        name = item["field"]
        if not isinstance(name, str) or name not in fields:
            raise TacticalOperationRegistrationError(f"body_selector field {name!r} is not one of body_fields.")
        if name in seen:
            raise TacticalOperationRegistrationError(f"body_selector names field {name!r} twice.")
        seen.add(name)
        if "present" in item:
            if not isinstance(item["present"], bool):
                raise TacticalOperationRegistrationError("body_selector present must be true or false.")
            conditions.append((name, "present", item["present"]))
        else:
            expected = item["equals"]
            if not isinstance(expected, (str, int, bool)):
                raise TacticalOperationRegistrationError("body_selector equals must be a string, a whole number or a boolean.")
            conditions.append((name, "equals", expected))
    if len(conditions) > _MAX_BODY_SELECTOR:
        raise TacticalOperationRegistrationError(f"body_selector has more than {_MAX_BODY_SELECTOR} conditions.")
    return tuple(conditions)


def _same_value(left: Any, right: Any) -> bool:
    """Equality that does not read True as 1."""
    return type(left) is type(right) and left == right


def _selectors_exclusive(first: tuple, second: tuple) -> bool:
    """True when no body can satisfy both selectors: one field has contradicting conditions in the two."""
    mine = {name: (kind, value) for name, kind, value in first}
    for name, kind, value in second:
        other = mine.get(name)
        if other is None:
            continue
        other_kind, other_value = other
        if kind == "present" and other_kind == "present" and value != other_value:
            return True
        if kind == "equals" and other_kind == "equals" and not _same_value(value, other_value):
            return True
        if {kind, other_kind} == {"present", "equals"}:
            present_value = value if kind == "present" else other_value
            if present_value is False:
                return True
    return False


def _check_route_sharing(operation: TacticalOperation, holders: list, verb: str, route: str) -> None:
    """Refuse a second operation on one (method, route), unless the same module declares provably exclusive body selectors."""
    first_module, first_id = holders[0]
    others = [_OPERATIONS[key] for key in holders]
    if not operation.body_selector or any(not other.body_selector or other.module_id != operation.module_id for other in others):
        raise TacticalOperationRegistrationError(
            f"{verb} {route} is already declared by {first_module}/{first_id}. One caller per Tactical route (AD-6)."
        )
    for other in others:
        if not _selectors_exclusive(other.body_selector, operation.body_selector):
            raise TacticalOperationRegistrationError(
                f"{verb} {route} is already declared by {other.module_id}/{other.id}, and the body selectors of the two are not "
                "provably exclusive. Give each operation a condition on a field that the other contradicts "
                "(present true against present false, or two different equals values)."
            )


def _clean_body_max_bytes(value):
    """The declared body cap, or None for the default (1.17.26). A whole number (never a bool) from MAX_BODY_BYTES to the ceiling."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TacticalOperationRegistrationError("body_max_bytes must be a whole number of bytes.")
    if value < MAX_BODY_BYTES:
        raise TacticalOperationRegistrationError(f"body_max_bytes must be at least the default of {MAX_BODY_BYTES} bytes.")
    if value > MAX_BODY_CEILING_BYTES:
        raise TacticalOperationRegistrationError(f"body_max_bytes must be at most {MAX_BODY_CEILING_BYTES} bytes, the ceiling Core keeps.")
    return None if value == MAX_BODY_BYTES else value


# 1.17.43: audit.secret_fields. A secret field is declared here and nowhere else in the audit declaration, so it is never recorded.
_MAX_SECRET_FIELDS = 8


def _clean_secret_fields(value: Any, fields: tuple, audit_fields: tuple, lists: tuple, before: BeforeSpec | None,
                         object_body_field: str | None, scope_specs: list, object_field: str | None = None) -> tuple:
    """audit.secret_fields (1.17.43): body fields whose value Core never records, only a change marker.

    Refused: a name that is not a body field, one the row already records (audit_fields, audit_lists, audit.before fields), the
    audit.object_body_field or audit.object_field (the object id would carry the value, 1.17.44 for object_field: Tactical's answer
    often echoes the field) and a body scope source (the ids would carry the value)."""
    names = _clean_names(value, "audit secret_fields", maximum=_MAX_SECRET_FIELDS)
    body_sources = {spec.source.split(":", 1)[1].split(".", 1)[0] for spec in scope_specs if spec.source.startswith("body:")}  # 1.17.45: a nested source counts by its parent
    for name in names:
        if name not in fields:
            raise TacticalOperationRegistrationError(f"audit secret_fields {name!r} is not one of body_fields.")
        if name in audit_fields or name in lists:
            raise TacticalOperationRegistrationError(
                f"audit secret_fields {name!r} is also recorded in clear (audit_fields or audit_lists). A secret field is never recorded."
            )
        if before is not None and name in before.fields:
            raise TacticalOperationRegistrationError(f"audit secret_fields {name!r} is also an audit.before field: the before read would record it.")
        if name == object_body_field or name == object_field or name in body_sources:
            raise TacticalOperationRegistrationError(f"audit secret_fields {name!r} is the object id or a body scope source, so the id would carry its value.")
    return names


# 1.17.45: audit.action_by_body.
_MAX_ACTION_MAP = 8
_MAX_ACTION_KEY = 40


def _parse_action_by_body(value: Any, verb: str, fields: tuple, secret_fields: tuple, audit_core) -> tuple:
    """audit.action_by_body (1.17.45): ``{field, map}``. Returns ``(field, ((body value, action), ...))`` or ``()``.

    The success row's action is chosen from the cleaned body value of ``field``. Refused: a GET, a field that is not one of
    ``body_fields`` or is a secret field (the action would leak a hint of the value), an empty map or more than 8 entries, a key that
    is not text or is empty or over 40 characters, an action outside the audit vocabulary, and the Core-only actions."""
    if value is None:
        return ()
    if verb not in BODY_METHODS:
        raise TacticalOperationRegistrationError("audit action_by_body belongs to an operation with a body.")
    if not isinstance(value, dict) or set(value) != {"field", "map"}:
        raise TacticalOperationRegistrationError("audit action_by_body is {field, map}.")
    name = value["field"]
    if not isinstance(name, str) or not _FIELD_RE.match(name):
        raise TacticalOperationRegistrationError("audit action_by_body field must be a body field name.")
    if name not in fields:
        raise TacticalOperationRegistrationError(f"audit action_by_body field {name!r} is not one of body_fields.")
    if name in secret_fields:
        raise TacticalOperationRegistrationError(f"audit action_by_body field {name!r} is a secret field: the action would show a hint of its value.")
    mapping = value["map"]
    if not isinstance(mapping, dict) or not mapping:
        raise TacticalOperationRegistrationError("audit action_by_body map is a non-empty object of body value to audit action.")
    if len(mapping) > _MAX_ACTION_MAP:
        raise TacticalOperationRegistrationError(f"audit action_by_body map has more than {_MAX_ACTION_MAP} entries.")
    pairs = []
    for key, action_text in mapping.items():
        if not isinstance(key, str) or not key or len(key) > _MAX_ACTION_KEY:
            raise TacticalOperationRegistrationError(f"audit action_by_body map keys are text of 1 to {_MAX_ACTION_KEY} characters.")
        try:
            chosen = audit_core._normalize_action(action_text)
        except audit_core.AuditContractError as exc:
            raise TacticalOperationRegistrationError(f"audit action_by_body: {exc}") from None
        if chosen == "deny" or chosen == OUTCOME_UNKNOWN_ACTION or chosen == FAILED_ACTION:
            raise TacticalOperationRegistrationError("audit action_by_body may not choose deny, custom:outcome-unknown or custom:operation-failed: Core writes those only.")
        pairs.append((key, chosen))
    return (name, tuple(pairs))


def _action_for(operation: TacticalOperation, body: Any) -> str:
    """The audit action of the success row (1.17.45): ``audit.action_by_body`` picks it from the cleaned body, else ``audit.action``."""
    if operation.audit_action_by_body and isinstance(body, dict):
        field_name, pairs = operation.audit_action_by_body
        chosen = body.get(field_name)
        if isinstance(chosen, str):
            for key, action in pairs:
                if key == chosen:
                    return action
    return operation.audit_action


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
    caller_scope=None,
    body_selector=None,
    server_only=False,
    permissions_any=None,
    body_max_bytes=None,
    audit_lists=None,
    file_response=False,
    audit_list_masks=None,
):
    """Declare one Tactical operation. Call it from the owning module's ``AppConfig.ready()``.

    1.17.52 (both optional, capability 1.15.0): ``audit_list_masks={list name: {key: "names"|"mask"}}`` keeps a key's value out of a list
    named in ``audit_lists`` (``names`` records only the name part of each text item, ``mask`` records ``***``; see the module docstring
    for the rules). It is a Python keyword, like ``audit_lists``. A scope entry may carry ``names_object: false`` (a strict bool):
    the entry is still checked but does not name the audit row's object, so ``audit.object_field`` or ``audit.object_body_field`` can.

    1.17.41 (all optional, capability 1.11.0): ``file_response=True`` (a strict bool, GET or POST only) lets Core relay a streamed file
    answer (Tactical's FileResponse) up to ``MAX_RESPONSE_BYTES``; without it a streaming answer is refused as before. ``query_params``
    is allowed on any method (a DELETE reads ``request.query_params`` too). The route parameter kind ``service`` takes a Windows
    service name.

    1.17.44 (optional, capability 1.13.0): ``audit.object_id`` is a fixed text (letters, digits and . _ : -, 1 to 64 characters, not
    secret-looking) for an operation with no path parameter that names the object, such as a settings save. It is the last fallback:
    ``audit.object_param`` and the first scope object come first, and it may not be declared with ``audit.object_param``,
    ``audit.object_field`` or ``audit.object_body_field``. Because it is declared text, never caller or body input, it names the
    object on every row of that operation: success, tactical_denied and scope deny, failed, outcome-unknown and core_refused. A GET
    operation takes none. A body field named by ``audit.object_field`` may no longer be a secret field. ``describe()`` shows
    ``audit.object_id`` and ``audit.secret_fields``.

    1.17.43 (optional, capability 1.12.0): ``audit.secret_fields`` names up to 8 body fields whose value Core never records, in the
    row, the metadata or a log. A success row carries ``<field>: changed`` when the body sends the field. When ``audit.before`` is also
    declared and Tactical's read holds the field, Core compares the sent value with it in memory (a SHA-256 of the canonical JSON,
    the value dropped at once) and writes ``present`` on the before side and ``changed`` or ``unchanged`` on the after side. A secret
    field may not be in audit_fields, audit_lists, audit.before fields, audit.object_body_field or a body scope source. It must be a
    body field. A failed, denied, core_refused or outcome-unknown row carries no marker.

    1.17.28 (optional): ``audit_lists`` names up to two body or before fields that hold a list of flat objects (a task's actions).
    Each is recorded in clear in the success row (after from the cleaned body, before from Tactical's GET answer), with the bounds
    of ``_list_record``. It needs a changing operation, and each name must be a body field or come from a before read. It may not
    name a field already in ``audit.before`` (fields or count_fields) or ``audit.audit_fields``, nor clash with another list's
    ``<name>_count`` or ``<name>_truncated``. The name must not look like a secret.

    1.17.26 (both optional): ``permissions_any`` lists Tactical role flags of which the caller needs at least one, on top of every flag
    of ``permissions`` (``permissions`` may be empty only when this is given). ``body_max_bytes`` is a whole number from
    ``MAX_BODY_BYTES`` up to ``MAX_BODY_CEILING_BYTES`` for an operation that forwards a large JSON body.

    1.17.21 (optional): ``audit.object_field`` names a top-level scalar field of Tactical's JSON answer, and
    ``audit.object_body_field`` names a body field (one of ``body_fields``). Either gives the success row's object id when no
    ``audit.object_param`` and no scope object does; neither is read for a GET operation or written on any other row.

    1.17.19 (optional): ``server_only=True`` (a strict bool) keeps the operation off Core's browser route. A module backend
    runs it through ``run_tactical_operation``. It stops the browser path; it is not a verified caller identity.

    1.17.18 (all optional): ``caller_scope="unrestricted"`` (only a caller with no client or site limits); a scope entry may
    carry ``optional: true`` or ``row_lookup``, and may have the type ``agent_pk``; ``audit`` may carry ``params`` and its
    ``before`` may carry ``count_fields`` and ``select``; ``body_selector`` lets the same module declare several operations on
    one route when their bodies are provably exclusive.

    1.17.13 (all optional): ``audit`` may also carry ``object_param`` and ``before``; a scope entry may use a
    ``body:<field>`` type with a ``type_map``; ``query_params`` whitelists the query names
    of an operation (any method since 1.17.41); ``upload`` declares one multipart file part. See docs/tactical-operations.md.

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

    flag_pattern = re.compile(r"^can_[a-z0-9_]+$")
    flags = _clean_names(permissions, "permissions", maximum=_MAX_PERMISSIONS, pattern=flag_pattern)
    any_flags = _clean_names(permissions_any, "permissions_any", maximum=_MAX_PERMISSIONS, pattern=flag_pattern)
    if not flags and not any_flags:
        raise TacticalOperationRegistrationError("permissions must list at least one Tactical Role flag.")
    both = [flag for flag in any_flags if flag in flags]
    if both:
        raise TacticalOperationRegistrationError(f"permissions_any repeats {both[0]!r} from permissions: the flag would be required and optional at once.")
    try:
        for flag in (*flags, *any_flags):
            _validate_tactical_flag(flag)
    except ValueError as exc:
        raise TacticalOperationRegistrationError(str(exc)) from None
    body_cap = _clean_body_max_bytes(body_max_bytes)

    fields = _clean_names(body_fields, "body_fields", maximum=_MAX_BODY_FIELDS)
    if fields and verb not in BODY_METHODS:
        raise TacticalOperationRegistrationError("a GET operation takes no body_fields.")

    params = {seg[1]: seg[2] for seg in segments if seg[0] == "param"}
    scope_specs = []
    if scope is None:
        scope = ()
    if isinstance(scope, (str, bytes, dict)) or not hasattr(scope, "__iter__"):
        raise TacticalOperationRegistrationError("scope must be a list of {type, source}.")
    # The audit declaration comes first. A scope source is a path or body value only; Tactical decides the rest (1.17.14).
    if not isinstance(audit, dict) or not {"action", "object_type"} <= set(audit) or set(audit) - {"action", "object_type", "audit_fields", "object_param", "before", "params", "object_field", "object_body_field", "secret_fields", "object_id", "action_by_body"}:
        raise TacticalOperationRegistrationError(
            "audit is {action, object_type, audit_fields, object_param, before, params, object_field, object_body_field, secret_fields, object_id, action_by_body}; all after object_type are optional."
        )
    if caller_scope is not None and caller_scope != "unrestricted":
        raise TacticalOperationRegistrationError('caller_scope must be "unrestricted" or left out.')
    if not isinstance(server_only, bool):
        raise TacticalOperationRegistrationError("server_only must be true or false.")
    audit_params = _clean_names(audit.get("params"), "audit params", maximum=_MAX_AUDIT_PARAMS, pattern=_PARAM_NAME_RE)
    for name in audit_params:
        if name not in params:
            raise TacticalOperationRegistrationError(f"audit param {name!r} is not a parameter of the route.")
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"audit param {name!r} looks like a secret. Never put secrets in the audit row.")
    object_param = audit.get("object_param")
    if object_param is not None and (not isinstance(object_param, str) or object_param not in params):
        raise TacticalOperationRegistrationError(f"audit object_param {object_param!r} is not a parameter of the route.")
    before = _parse_before(audit.get("before"), module, verb, params)
    object_field = _parse_object_name(audit.get("object_field"), "audit object_field", verb)
    object_body_field = _parse_object_name(audit.get("object_body_field"), "audit object_body_field", verb)
    if object_body_field is not None and object_body_field not in fields:
        raise TacticalOperationRegistrationError(f"audit object_body_field {object_body_field!r} is not one of body_fields.")
    object_id_literal = _parse_object_id(audit.get("object_id"), verb)
    if object_id_literal is not None and (object_param is not None or object_field is not None or object_body_field is not None):
        raise TacticalOperationRegistrationError(
            "audit.object_id is the only source of the object id: leave out audit.object_param, audit.object_field and audit.object_body_field."
        )

    row_lookup_entries = 0
    for item in scope:
        if not isinstance(item, dict) or not {"type", "source"} <= set(item) or set(item) - {"type", "source", "type_map", "optional", "row_lookup", "names_object"}:
            raise TacticalOperationRegistrationError(
                "each scope entry is {type, source}, plus type_map for a body-selected type, optional, row_lookup or names_object, and nothing else."
            )
        kind, source = item["type"], item["source"]
        if isinstance(source, str) and source.startswith("before:"):
            raise TacticalOperationRegistrationError(
                f"scope source {source!r} was removed in Core 1.17.14. An operation with only an object id declares no scope for it, and Tactical's own check decides."
            )
        match = _SCOPE_SOURCE_RE.match(source) if isinstance(source, str) else None
        type_field = _SCOPE_TYPE_BODY_RE.match(kind) if isinstance(kind, str) else None
        if match is None or (kind not in SCOPE_TYPES and type_field is None):
            raise TacticalOperationRegistrationError(
                f"bad scope entry {item!r}: type is agent, agent_pk, client, site or body:<field>, and source is path:<name> or body:<field>."
            )
        where, name, nested = match.group(1), match.group(2), match.group(3)
        if nested is not None:
            # 1.17.45: body:<field>.<key>, one level deep. The parent must be a body field; the key is read from its object value.
            if where != "body":
                raise TacticalOperationRegistrationError(f"scope source {source!r}: only a body source may be nested.")
            if item.get("row_lookup") is not None:
                raise TacticalOperationRegistrationError("scope row_lookup belongs to an agent entry with a path source, never a body source.")
            if name == object_body_field:
                raise TacticalOperationRegistrationError(f"scope source {source!r} is nested under audit.object_body_field: the object id would carry the value.")
        type_map = ()
        if type_field is not None:
            if type_field.group(1) not in fields:
                raise TacticalOperationRegistrationError(f"scope type {kind!r} is not one of body_fields.")
            type_map = _parse_type_map(item.get("type_map"))
        elif "type_map" in item:
            raise TacticalOperationRegistrationError("type_map belongs only to a scope type of the form body:<field>.")
        optional = item.get("optional", False)
        if not isinstance(optional, bool):
            raise TacticalOperationRegistrationError("scope optional must be true or false.")
        if optional and where != "body":
            raise TacticalOperationRegistrationError("scope optional belongs to a body source: a path parameter is always present.")
        lookup_id = item.get("row_lookup")
        if lookup_id is not None:
            if not isinstance(lookup_id, str) or not _ID_RE.match(lookup_id):
                raise TacticalOperationRegistrationError("scope row_lookup must be a lookup id (a lowercase slug).")
            if kind != "agent" or where != "path":
                raise TacticalOperationRegistrationError("scope row_lookup belongs to an agent entry with a path source, never a body source.")
            row_lookup_entries += 1
            if row_lookup_entries > 1:
                raise TacticalOperationRegistrationError("an operation may declare one row_lookup scope entry.")
        if where == "path":
            if name not in params:
                raise TacticalOperationRegistrationError(f"scope source {source!r} is not a parameter of the route.")
            if kind in ("client", "site", "agent_pk") and params[name] != "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a {kind}.")
            if kind == "agent" and lookup_id is not None:
                if params[name] != "int":
                    raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a row_lookup.")
            elif kind == "agent" and params[name] == "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be a string parameter for an agent.")
            if type_map and params[name] != "int":
                raise TacticalOperationRegistrationError(f"scope source {source!r} must be an int parameter for a client or site.")
        elif name not in fields:
            raise TacticalOperationRegistrationError(f"scope source {source!r} is not one of body_fields.")
        names_object = item.get("names_object", True)
        if not isinstance(names_object, bool):
            raise TacticalOperationRegistrationError("scope names_object must be true or false.")
        spec = ScopeSpec(kind, source, type_map, optional, lookup_id, names_object)
        if spec in scope_specs:
            raise TacticalOperationRegistrationError(f"scope entry {item!r} is repeated.")
        scope_specs.append(spec)
    if len(scope_specs) > _MAX_SCOPE:
        raise TacticalOperationRegistrationError("too many scope entries.")
    if scope_specs and not any(spec.names_object for spec in scope_specs) and not (
        object_param is not None or object_field is not None or object_body_field is not None or object_id_literal is not None
    ):
        raise TacticalOperationRegistrationError(
            "every scope entry has names_object false, so nothing would name the audit row's object: declare audit.object_param, "
            "audit.object_field, audit.object_body_field or audit.object_id."
        )

    try:
        action = audit_core._normalize_action(audit["action"])
        object_type = audit_core._normalize_object_type(audit["object_type"])
    except audit_core.AuditContractError as exc:
        raise TacticalOperationRegistrationError(f"audit: {exc}") from None
    if action == "deny" or action == OUTCOME_UNKNOWN_ACTION or action == FAILED_ACTION:
        raise TacticalOperationRegistrationError("audit action deny, custom:outcome-unknown and custom:operation-failed are written by Core only.")
    query_names = _clean_names(query_params, "query_params", maximum=MAX_QUERY_PARAMS)
    if not isinstance(file_response, bool):
        raise TacticalOperationRegistrationError("file_response must be true or false.")
    if file_response and verb not in ("GET", "POST"):
        raise TacticalOperationRegistrationError("file_response belongs to a GET or POST operation.")
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
        if name in audit_params:
            raise TacticalOperationRegistrationError(f"audit field {name!r} is also an audit param: the row would carry it twice.")
    lists = _clean_audit_lists(audit_lists, verb, fields, before, audit_fields)
    list_masks = _clean_audit_list_masks(audit_list_masks, lists)
    secret_declared = _clean_secret_fields(audit.get("secret_fields"), fields, audit_fields, lists, before, object_body_field, scope_specs, object_field)
    action_by_body = _parse_action_by_body(audit.get("action_by_body"), verb, fields, secret_declared, audit_core)
    selector = _parse_body_selector(body_selector, fields)

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
        caller_scope=caller_scope, body_selector=selector, audit_params=audit_params, server_only=server_only,
        audit_object_field=object_field, audit_object_body_field=object_body_field,
        permissions_any=any_flags, body_max_bytes=body_cap, audit_lists=lists, file_response=file_response,
        secret_fields=secret_declared, audit_object_id=object_id_literal, audit_action_by_body=action_by_body,
        audit_list_masks=list_masks,
    )
    key = (owner, op_id)
    route_key = (verb, _route_key(segments, trailing))
    with _LOCK:
        existing = _OPERATIONS.get(key)
        if existing is not None:
            if existing == operation:
                return existing
            raise TacticalOperationRegistrationError(f"operation {owner}/{op_id} is already registered with a different definition.")
        holders = _ROUTES.get(route_key) or []
        if holders:
            _check_route_sharing(operation, holders, verb, route)
        _OPERATIONS[key] = operation
        _ROUTES.setdefault(route_key, []).append(key)
    return operation


def register_tactical_row_lookup(module_id, lookup_id, fn):
    """Register a row lookup for the scope of an operation whose path id loads a row (1.17.18, CQ56 a).

    The owning core module calls this from ``AppConfig.ready()``, with the same module and category rules as
    ``register_tactical_operation``. ``fn(pk: str)`` returns None when the row does not exist, or a dict
    ``{"agent_id": "<canonical agent id>"}`` (``None`` when the row belongs to no agent, such as a policy task). An operation
    names it in a scope entry ``{type: "agent", source: "path:<int param>", row_lookup: "<lookup id>"}``. A module can only
    name its own lookups. The lookup reads the module's own data in-process; Core never reads Tactical models itself.
    Registering the same function again is idempotent."""
    name = str(lookup_id or "").strip()
    if not _ID_RE.match(name):
        raise TacticalOperationRegistrationError("lookup_id must be a lowercase slug such as task-row.")
    if not callable(fn):
        raise TacticalOperationRegistrationError("a row lookup must be a function that takes the row id.")
    module = _check_module(module_id)
    owner = module["id"]
    category = _module_category.effective_category(module.get("category"))
    if category != "core" and owner not in _honoured_pairs():
        raise TacticalOperationRegistrationError(
            f"module {owner!r} is not a core module (its category is {category}). Only a core module may register a row lookup."
        )
    with _LOCK:
        existing = _ROW_LOOKUPS.get((owner, name))
        if existing is not None and existing is not fn:
            raise TacticalOperationRegistrationError(f"row lookup {owner}/{name} is already registered with a different function.")
        _ROW_LOOKUPS[(owner, name)] = fn
    return fn


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
        _ROW_LOOKUPS.clear()


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


def _scope_entries(operation: TacticalOperation, params: Any, body: Any) -> list[tuple]:
    """Resolve the declared scope entries to (spec, type, [ids]). Raises 400 for a missing or malformed value.

    1.17.18: an ``optional`` entry whose body field is absent or null (or an empty list) adds nothing."""
    resolved = []
    for spec in operation.scope:
        where, name = spec.source.split(":", 1)
        if where == "path":
            raw = (params or {}).get(name)
        elif "." in name:
            # 1.17.45: body:<field>.<key>. An absent or null parent is an absent value; a present non-object parent is a refusal.
            parent_name, name = name.split(".", 1)
            parent = (body or {}).get(parent_name)
            if parent is None:
                raw = None
            elif isinstance(parent, dict):
                raw = parent.get(name)
            else:
                raise TacticalOperationError(f"{parent_name} must be an object.", status=400, code="scope_field_required")
        else:
            raw = (body or {}).get(name)
        if spec.optional and (raw is None or (isinstance(raw, list) and not raw)):
            continue
        values = raw if isinstance(raw, list) else [raw]
        if not values or len(values) > 1000:
            raise TacticalOperationError(f"{name} is required.", status=400, code="scope_field_required")
        ids = []
        for value in values:
            if value is None or isinstance(value, (bool, dict, list, float)) or not str(value).strip():
                raise TacticalOperationError(f"{name} is required.", status=400, code="scope_field_required")
            text = str(value).strip()
            if spec.type == "agent_pk" and not (text.isdigit() and 0 < int(text) < 2**63):
                raise TacticalOperationError(f"{name} must be whole numbers.", status=400, code="scope_field_required")
            ids.append(text)
        kind = spec.type
        if kind.startswith("body:"):
            field_name = kind.split(":", 1)[1]
            chosen = (body or {}).get(field_name)
            kind = dict(spec.type_map).get(chosen) if isinstance(chosen, str) else None
            if kind is None:
                raise TacticalOperationError(f"{field_name} is required and must be one of the declared types.", status=400, code="scope_field_required")
        resolved.append((spec, kind, ids))
    return resolved


def _scope_values(operation: TacticalOperation, params: Any, body: Any) -> list[tuple[str, list[str]]]:
    """The declared scope as (type, [ids]) pairs (see ``_scope_entries``)."""
    return [(kind, ids) for _, kind, ids in _scope_entries(operation, params, body)]


def _object_id(scope: list[tuple[str, list[str]]], operation: TacticalOperation | None = None, params: Any = None, declared: bool = True) -> str | None:
    """The audit row's object id. A declared ``audit.object_param`` wins (1.17.13); otherwise the first scope object; last, the
    declared ``audit.object_id`` literal (1.17.44; ``declared=False`` leaves it to the caller, see ``_refusal_object_id``)."""
    if operation is not None and operation.audit_object_param and isinstance(params, dict):
        value = params.get(operation.audit_object_param)
        if value is not None and not isinstance(value, (bool, dict, list, float)):
            text = _printable(str(value).strip())
            if text:
                return text
    found = _printable(",".join(scope[0][1])) or None if scope else None
    if found is None and declared and operation is not None:
        return operation.audit_object_id
    return found


def _refusal_object_id(operation: TacticalOperation, params: Any) -> str | None:
    """The object id of a ``core_refused`` row (1.17.22, AD-19 condition 4 second amendment: never body values).

    Called only with cleaned path parameters, after ``_clean_params`` succeeded. A declared ``audit.object_param`` wins, else the
    first path-sourced scope entry. A body-sourced scope entry never names the row, and neither does a raw, uncleaned value."""
    if not isinstance(params, dict):
        return None
    found = _object_id([], operation, params, declared=False)
    if found:
        return found
    for spec in operation.scope:
        where, name = spec.source.split(":", 1)
        if where != "path":
            continue
        value = params.get(name)
        if value is None or isinstance(value, (bool, dict, list, float)):
            continue
        text = _printable(str(value).strip())
        if text:
            return text
    return operation.audit_object_id  # 1.17.44: declared text, not a body value, so it may name a core_refused row


def _answer_object_id(operation: TacticalOperation, data: Any, body: dict) -> tuple[str | None, str | None]:
    """The success row's object id from Tactical's answer, then the cleaned body (1.17.21). Returns (id, source), or (None, None).

    Used only when no ``audit.object_param`` and no scope object gave an id. The answer value must be a text or a whole number
    (a bool, float, list, dict or null is ignored); the body value likewise. Both are cleaned like every object id (printable
    ASCII, 255 characters). Never used on a deny, failed, core_refused or outcome-unknown row."""
    sources = (
        (operation.audit_object_field, data if isinstance(data, dict) else None, "answer"),
        (operation.audit_object_body_field, body if isinstance(body, dict) else None, "body"),
    )
    for name, holder, label in sources:
        if not name or holder is None:
            continue
        value = holder.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        text = _printable(str(value).strip())
        if text:
            return text, label
    return None, None


def _body_scope_type(operation: TacticalOperation, scope: list) -> str | None:
    """The scope type a body-selected entry resolved to, for the row metadata. ``scope`` is ``_scope_entries`` output."""
    for spec, kind, _ in scope:
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
    cap = operation.body_cap
    if size > cap:
        raise TacticalOperationError(f"body is larger than {cap} bytes.", status=413, code="body_too_large")
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
    """The query string of an operation (any method since 1.17.41): whitelisted names, flat string or whole-number values (1.17.13)."""
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


def upload_ceiling_bytes() -> int:
    """The system setting's upload ceiling in bytes, read now (1.17.14, CQ40). Never raises.

    A lowered setting takes effect at once, with no restart. Any failure to read it (no database, a value out of range)
    gives the 10 MiB default, so a broken read can only be stricter than the setting's maximum, never looser."""
    try:
        from .runtime_settings import get_tactical_upload_max_bytes

        value = int(get_tactical_upload_max_bytes())
    except Exception:
        logger.debug("Could not read the upload limit setting; using the default.", exc_info=True)
        return MAX_UPLOAD_BYTES
    return value if 0 < value <= MAX_UPLOAD_ABSOLUTE_BYTES else MAX_UPLOAD_BYTES


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
    cap = min(spec.max_bytes, upload_ceiling_bytes())
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


def _selector_holds(operation: TacticalOperation, body: dict) -> bool:
    """True when the cleaned body satisfies every condition of the operation's own ``body_selector`` (1.17.18)."""
    for name, kind, expected in operation.body_selector:
        value = body.get(name)
        if kind == "present":
            if (value is not None) != expected:
                return False
        elif not _same_value(value, expected):
            return False
    return True


def _caller_unrestricted(user) -> bool:
    """True when the caller sees every client and site, by ``core.resources.scope_unrestricted``. Any failure is False (fail closed)."""
    try:
        from . import resources

        return bool(resources.scope_unrestricted(resources.user_context(user)))
    except Exception:
        logger.warning("Could not read the caller's Tactical scope; treating the caller as limited.", exc_info=True)
        return False


_LOOKUP_FAILED = object()


def _row_lookup_agent(operation: TacticalOperation, spec: ScopeSpec, pk: str):
    """Ask the owning module's row lookup which agent the row belongs to (1.17.18, CQ56 a).

    Returns the canonical agent id, or None for a row with no agent, or ``_LOOKUP_FAILED`` when the lookup is missing, raises,
    answers None (no such row) or answers the wrong shape. The caller fails closed on ``_LOOKUP_FAILED``."""
    with _LOCK:
        lookup = _ROW_LOOKUPS.get((operation.module_id, spec.row_lookup))
    if lookup is None:
        logger.warning("Row lookup %s/%s is not registered.", operation.module_id, spec.row_lookup)
        return _LOOKUP_FAILED
    try:
        row = lookup(pk)
    except Exception:
        logger.warning("Row lookup %s/%s raised.", operation.module_id, spec.row_lookup, exc_info=True)
        return _LOOKUP_FAILED
    if not isinstance(row, dict) or "agent_id" not in row:
        return _LOOKUP_FAILED
    agent_id = row["agent_id"]
    if agent_id is None:
        return None
    if not isinstance(agent_id, str) or not agent_id.strip():
        return _LOOKUP_FAILED
    return agent_id.strip()


def _check_whitelist(operation: TacticalOperation, body: dict) -> None:
    extra = sorted(set(body) - set(operation.body_fields))
    if extra:
        raise TacticalOperationError(
            "Body field not allowed: " + ", ".join(_printable(name, 40) for name in extra),
            status=400, code="body_field_not_allowed",
        )


def _write_row(request, operation: TacticalOperation, *, action: str, object_id, message: str, after=None,
               tactical_status: int | None, refusal: bool = False, extra: dict | None = None, before=None,
               correlation_id: str | None = None) -> dict:
    """Write one Core audit row. Never raises: a failed write is logged and reported."""
    from . import audit as audit_core

    metadata = {"operation": operation.id, "method": operation.method, "route": operation.route, "tactical_status": tactical_status}
    metadata.update(extra or {})
    try:
        result = audit_core._record_tactical_operation(
            actor=getattr(request, "user", None), module_id=operation.module_id, action=action,
            object_type=operation.audit_object_type, object_id=object_id, message=message, before=before, after=after,
            metadata=metadata, operation=operation.id, tactical_status=tactical_status, refusal=refusal, request=request,
            correlation_id=correlation_id,
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


def _refuse(request, operation: TacticalOperation, reason: str, status: int, code: str, object_id=None,
            correlation_id: str | None = None, text: str | None = None, row_extra: dict | None = None) -> TacticalOperationError:
    """Core's own refusal (steps 3 to 5): a deny row with a fixed Core text, and the typed error to raise.

    ``text`` replaces the answer's detail only (1.17.19, the missing Tactical flag). The deny row keeps its fixed wording."""
    audit = _write_row(
        request, operation, action="deny", object_id=object_id, message=DENY_MESSAGES[reason], tactical_status=None, refusal=True,
        extra={"refused_action": operation.audit_action, "reason": reason, "status": status, **(row_extra or {})},
        correlation_id=correlation_id,
    )
    key = "object_not_found" if reason == "not_found" else reason
    return TacticalOperationError(text or MESSAGES[key], status=status, code=code, audit=audit)


def _write_core_refusal(request, operation: TacticalOperation, error: TacticalOperationError, object_id=None,
                        correlation_id: str | None = None) -> dict:
    """The one Core row of a refusal made before Tactical is called (1.17.21). A fixed Core text and the refusal code only.

    The row has no before or after value and no body, query or upload value, and carries nothing from the caller's input but the
    object id the deny rows already use. It never raises: a failed write is ``{recorded: False, error: audit_write_failed}``."""
    return _write_row(
        request, operation, action=FAILED_ACTION, object_id=object_id, message=CORE_REFUSED_MESSAGE.format(code=error.code),
        tactical_status=None, refusal=True, correlation_id=correlation_id,
        extra={
            "declared_action": operation.audit_action, "result": "failed", "failure": "core_refused", "code": error.code,
            "status": error.status,
        },
    )


def _missing_flag_text(operation: TacticalOperation, flags: dict) -> str:
    """The 403 detail that names every Tactical role flag the caller lacks (1.17.19). Flags are validated ``can_*`` names."""
    missing = [_printable(name, 80) for name in operation.permissions if not flags.get(name)]
    any_missing = bool(operation.permissions_any) and not any(flags.get(name) for name in operation.permissions_any)
    if not any_missing:
        if len(missing) == 1:
            return f"{MESSAGES['permission_denied']} It needs the Tactical permission {missing[0]}."
        return f"{MESSAGES['permission_denied']} It needs the Tactical permissions {', '.join(missing)}."
    one_of = ", ".join(_printable(name, 80) for name in operation.permissions_any)  # 1.17.26: the caller holds none of the any-of flags
    if not missing:
        return f"{MESSAGES['permission_denied']} It needs one of {one_of}."
    noun = "permission" if len(missing) == 1 else "permissions"
    return f"{MESSAGES['permission_denied']} It needs the Tactical {noun} {', '.join(missing)} and one of {one_of}."


def _permissions_hold(operation: TacticalOperation, flags: dict) -> bool:
    """Every flag of ``permissions`` and, when ``permissions_any`` is declared, at least one of it (1.17.26)."""
    if not all(flags.get(name) for name in operation.permissions):
        return False
    return not operation.permissions_any or any(flags.get(name) for name in operation.permissions_any)


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


def _clean_audit_lists(value: Any, verb: str, fields: tuple, before: BeforeSpec | None, audit_fields: tuple) -> tuple:
    """Validate ``audit_lists`` (1.17.28, CQ85 a). At most two names, each a body field or a field of the before read. Refused:
    a GET, a name that looks like a secret, and a name that would write a key another part of the row also writes."""
    names = _clean_names(value, "audit_lists", maximum=_MAX_AUDIT_LISTS)
    if not names:
        return ()
    if verb not in BODY_METHODS:
        raise TacticalOperationRegistrationError("audit_lists belongs to a changing operation: a GET changes nothing.")
    written = set(audit_fields)
    if before is not None:
        written |= set(before.fields) | set(before.count_fields)
    for name in names:
        if name not in fields and before is None:
            raise TacticalOperationRegistrationError(
                f"audit_lists {name!r} is not one of body_fields, and the operation has no before read to take it from."
            )
        if _SECRET_NAME_RE.search(name):
            raise TacticalOperationRegistrationError(f"audit_lists {name!r} looks like a secret. Never put secrets in the audit row.")
        for key in (name, f"{name}_count", f"{name}_truncated"):
            if key in written:
                raise TacticalOperationRegistrationError(f"audit_lists {name!r} would write {key!r} twice in the audit row.")
            written.add(key)
    return names


def _clean_audit_list_masks(value: Any, lists: tuple) -> tuple:
    """Validate ``audit_list_masks`` (1.17.52): ``{list name: {key: "names"|"mask"}}`` for lists already named in ``audit_lists``.
    Refused: a mapping that is not a dict, a list that is not in ``audit_lists``, a non-dict or empty key map, more than 8 keys per
    list, a key that is not a field name and a mode other than ``names`` or ``mask``. Core cannot tell a scalar key from a list key
    at registration, so ``names`` on a scalar value is handled when the row is written (it records ``***``)."""
    if value is None:
        return ()
    if not isinstance(value, dict):
        raise TacticalOperationRegistrationError("audit_list_masks must be a dict of {list name: {key: mode}}.")
    if not value:
        return ()
    out = []
    for name, keys in value.items():
        if not isinstance(name, str) or name not in lists:
            raise TacticalOperationRegistrationError(f"audit_list_masks {name!r} is not one of audit_lists.")
        if not isinstance(keys, dict) or not keys:
            raise TacticalOperationRegistrationError(f"audit_list_masks {name!r} must be a dict of {{key: mode}} with at least one key.")
        if len(keys) > _MAX_LIST_MASK_KEYS:
            raise TacticalOperationRegistrationError(f"audit_list_masks {name!r} may mask at most {_MAX_LIST_MASK_KEYS} keys.")
        pairs = []
        for key, mode in keys.items():
            if not isinstance(key, str) or not _FIELD_RE.fullmatch(key):
                raise TacticalOperationRegistrationError(f"audit_list_masks {name!r}: {key!r} is not a field name.")
            if not isinstance(mode, str) or mode not in _LIST_MASK_MODES:
                raise TacticalOperationRegistrationError(f"audit_list_masks {name!r}.{key}: the mode is 'names' or 'mask'.")
            pairs.append((key, mode))
        out.append((name, tuple(pairs)))
    return tuple(out)


def _item_name(text: str) -> tuple[str | None, str, bool]:
    """The name part of one text item of a masked list: ``(name, separator, has_value)``, or ``(None, "", False)`` for an item with
    no name (a positional argument), which the caller records as ``***``.

    ``KEY=VALUE`` gives ``KEY`` and ``--flag=value`` gives ``--flag``. Otherwise an item that starts with ``-`` or ``/`` gives its first
    whitespace-delimited token (``-Name value`` gives ``-Name``). The name must look like a name, and an ``=`` must be followed by a
    value that is not empty or only ``=`` (base64 padding), so a positional secret is not recorded as a name."""
    clean = _LIST_CONTROL.sub("", text).strip()
    if "=" in clean:
        head, _, tail = clean.partition("=")
        if tail.strip("=") and _ITEM_NAME_RE.fullmatch(head):
            return head, "=", True
        return None, "", False
    if clean[:1] in ("-", "/"):
        parts = clean.split(None, 1)
        if _ITEM_SWITCH_RE.fullmatch(parts[0]):
            return parts[0], " ", len(parts) > 1
    return None, "", False


def _mask_item(item: Any, mode: str) -> str:
    if not isinstance(item, str):
        return _MASKED
    name, separator, has_value = _item_name(item)
    if name is None:
        return _MASKED
    if mode == "names" or not has_value:
        return name
    return f"{name}{separator}{_MASKED}"


def _mask_value(value: Any, mode: str) -> tuple[Any, bool]:
    """A masked key's value as it may be recorded, and whether items were cut (1.17.52). ``None`` stays null; a list of items is
    masked item by item (at most ``_LIST_MAX_ITEMS`` are kept); a text value, a number and anything else is ``***`` (fail closed)."""
    if value is None:
        return None, False
    if isinstance(value, list):
        return [_mask_item(item, mode) for item in value[:_LIST_MAX_ITEMS]], len(value) > _LIST_MAX_ITEMS
    return _MASKED, False


def _list_masks_for(operation: TacticalOperation, name: str) -> dict | None:
    for list_name, pairs in operation.audit_list_masks:
        if list_name == name:
            return dict(pairs)
    return None


def _list_text(value: str) -> tuple[str, bool]:
    """Control characters but tab and newline removed, then cut to the text limit. Returns (text, cut)."""
    clean = _LIST_CONTROL.sub("", value)
    return clean[:_LIST_VALUE_MAX_CHARS], len(clean) > _LIST_VALUE_MAX_CHARS


def _list_value(value: Any) -> tuple[Any, int, bool]:
    """(clean value, text bytes kept, cut) for one value of a list object, or (_DROPPED, 0, True).

    A scalar is kept as it is (text cleaned as ``_list_text``). A list is kept when it holds scalars, at most ``_LIST_MAX_ITEMS`` of
    them; anything deeper, and any object, is dropped."""
    if value is None or isinstance(value, bool):
        return value, 0, False
    if isinstance(value, int):
        return value, len(str(value)), False
    if isinstance(value, float):
        return (value, len(repr(value)), False) if math.isfinite(value) else (_DROPPED, 0, True)
    if isinstance(value, str):
        text, cut = _list_text(value)
        return text, len(text.encode("utf-8")), cut
    if isinstance(value, list):
        items: list = []
        used = 0
        cut = len(value) > _LIST_MAX_ITEMS
        for item in value[:_LIST_MAX_ITEMS]:
            if isinstance(item, (list, dict)):
                cut = True  # one level only: a nested list or object is dropped
                continue
            clean, size, item_cut = _list_value(item)
            cut = cut or item_cut
            if clean is _DROPPED:
                continue
            items.append(clean)
            used += size
        return items, used, cut
    return _DROPPED, 0, True


def _list_entry(item: dict, masks: dict | None = None) -> tuple[dict, int, bool]:
    """One object of a declared list: its first ``_LIST_MAX_KEYS`` keys whose names match the field-name pattern. Returns
    (entry, text bytes kept, cut). ``masks`` (1.17.52, ``{key: mode}``) masks those keys before the bounds apply."""
    entry: dict = {}
    size = 0
    cut = False
    for key, value in item.items():
        if len(entry) >= _LIST_MAX_KEYS or not isinstance(key, str) or not _FIELD_RE.fullmatch(key):
            cut = True
            continue
        if masks and key in masks:
            value, mask_cut = _mask_value(value, masks[key])
            cut = cut or mask_cut
        clean, used, value_cut = _list_value(value)
        cut = cut or value_cut
        if clean is _DROPPED:
            continue
        entry[key] = clean
        size += len(key.encode("utf-8")) + used
    return entry, size, cut


def _list_record(name: str, value: Any, masks: dict | None = None) -> dict:
    """The clear-text record of one declared list field (1.17.28, CQ85 a): the kept objects, ``<name>_count`` (the full length) and
    ``<name>_truncated`` (true when anything was cut or dropped). Never raises. A value that is not a list is recorded as an empty
    list with count 0. A list with an item that is not an object is recorded as its count only. Nothing is masked unless ``masks``
    (1.17.52, ``{key: "names"|"mask"}`` from ``audit_list_masks``) says so: then those keys are masked before anything is kept."""
    try:
        if not isinstance(value, list):
            return {name: [], f"{name}_count": 0, f"{name}_truncated": True}
        if any(not isinstance(item, dict) for item in value):
            return {name: [], f"{name}_count": len(value), f"{name}_truncated": True}
        truncated = len(value) > _LIST_MAX_ENTRIES
        entries: list = []
        used = 0
        for item in value[:_LIST_MAX_ENTRIES]:
            entry, size, cut = _list_entry(item, masks)
            if used + size > _LIST_MAX_TEXT_BYTES:
                truncated = True
                break
            entries.append(entry)
            used += size
            truncated = truncated or cut
        record = {name: entries, f"{name}_count": len(value)}
        if truncated:
            record[f"{name}_truncated"] = True
        return record
    except Exception:
        logger.warning("A declared audit list could not be recorded; its count only is kept.", exc_info=True)
        count = len(value) if isinstance(value, list) else 0
        return {name: [], f"{name}_count": count, f"{name}_truncated": True}


def _after_values(operation: TacticalOperation, body: dict, query: dict | None = None, file: dict | None = None,
                  params: dict | None = None) -> dict | None:
    """The declared audit fields, copied from the body or the query string, and for an upload only its name, size and type.

    1.17.18: ``audit.params`` names path parameters whose cleaned values are copied in as well. 1.17.28: ``audit_lists`` are copied
    from the cleaned body in clear."""
    if not operation.audit_fields and file is None and not operation.audit_params and not operation.audit_lists:
        return None
    values = {}
    for name in operation.audit_fields:
        if name in body:
            values[name] = body[name]
        elif query and name in query:
            values[name] = query[name]
    for name in operation.audit_params:
        if params and name in params:
            values[name] = _printable(params[name])
    for name in operation.audit_lists:
        if name in body:
            values.update(_list_record(name, body[name], _list_masks_for(operation, name)))
    if file is not None:
        values["upload"] = {"file_name": _printable(file["name"]), "size": len(file["content"]), "content_type": file["content_type"]}
    return values


def _object_count_extra(scope: list) -> dict:
    """metadata.object_count (1.17.43): how many ids the first scope entry names, only when it names more than one. A number, never an id."""
    if scope and len(scope[0][1]) > 1:
        return {"object_count": len(scope[0][1])}
    return {}


def _secret_digest(value: Any) -> str:
    """A SHA-256 of a value's canonical JSON (1.17.43). It serves one in-memory comparison and is never stored, logged or returned."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _secret_digests(operation: TacticalOperation, payload: Any) -> dict | None:
    """The digests of the declared secret fields that Tactical's before read holds (1.17.43). None when the read is not an object."""
    if not operation.secret_fields or not isinstance(payload, dict):
        return None
    return {name: _secret_digest(payload[name]) for name in operation.secret_fields if name in payload}


def _secret_markers(operation: TacticalOperation, body: Any, digests: dict | None) -> tuple[dict, dict]:
    """The (after, before) markers of a success row for the declared secret fields (1.17.43). Never a value.

    A field the body does not send is not marked. A field sent with no before read, or a before read without the field, is
    'changed' on the after side and omitted from the before side. A field the read holds gets 'present' before and 'changed' or
    'unchanged' after."""
    after: dict = {}
    before: dict = {}
    for name in operation.secret_fields:
        if not isinstance(body, dict) or name not in body:
            continue
        if digests is None or name not in digests:
            after[name] = "changed"
            continue
        before[name] = "present"
        after[name] = "unchanged" if digests[name] == _secret_digest(body[name]) else "changed"
    return after, before


def _before_text(value: str) -> str:
    return "".join(ch for ch in value if ord(ch) >= 32 and ord(ch) != 127)[:_BEFORE_STRING_LIMIT]


def _before_list(value: list) -> tuple[list, int] | None:
    """A list of whole numbers or short strings, capped, with its full length (1.17.18). None for anything else.

    A list that holds an object, a float, a boolean, a null or another list is never recorded."""
    kept: list = []
    used = 0
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            return None
        if len(kept) < _MAX_BEFORE_LIST and used <= _MAX_BEFORE_LIST_CHARS:
            clean = _before_text(item) if isinstance(item, str) else item
            used += len(str(clean))
            kept.append(clean)
    return kept, len(value)


def _before_values(operation: TacticalOperation, data: Any) -> dict | None:
    """The whitelisted fields of Tactical's own answer.

    Strings are cut to 256 characters. Numbers, booleans and nulls are kept. Since 1.17.18 a list of whole numbers or short
    strings is kept too (capped, with ``<field>_count`` and ``<field>_truncated`` when cut), ``count_fields`` record only the
    length of a list as ``<field>_count``, and everything else (objects, lists of objects) is dropped."""
    if not isinstance(data, dict):
        return None
    values = {}
    for name in operation.before.fields:
        value = data.get(name)
        if isinstance(value, str):
            values[name] = _before_text(value)
        elif value is None or isinstance(value, (bool, int, float)):
            values[name] = value
        elif isinstance(value, list):
            cleaned = _before_list(value)
            if cleaned is not None:
                values[name], total = cleaned
                values[f"{name}_count"] = total
                if total > len(cleaned[0]):
                    values[f"{name}_truncated"] = True
    for name in operation.before.count_fields:
        value = data.get(name)
        if isinstance(value, list):
            values[f"{name}_count"] = len(value)
    for name in operation.audit_lists:  # 1.17.28: the declared lists, in clear, from Tactical's own answer
        if name in data:
            values.update(_list_record(name, data[name], _list_masks_for(operation, name)))
    return values


def _select_row(operation: TacticalOperation, payload: Any, params: dict[str, str]) -> dict | None:
    """The row of a list answer whose key equals the cleaned path parameter (1.17.18, CQ58 a), or None.

    A bare list and a paginated ``{"results": [...]}`` answer are read; at most the first 1000 rows are scanned. The value to
    match is the path parameter Core already cleaned, never anything the browser sent as a before value."""
    param, key = operation.before.select
    rows = payload if isinstance(payload, list) else (payload.get("results") if isinstance(payload, dict) else None)
    if not isinstance(rows, list):
        return None
    wanted = params.get(param)
    for row in rows[:_MAX_BEFORE_SELECT_ROWS]:
        if not isinstance(row, dict):
            continue
        value = row.get(key)
        if value is None or isinstance(value, (bool, dict, list, float)):
            continue
        if wanted is not None and str(value) == wanted:
            return row
    return None


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
        payload = json.loads(content.decode("utf-8"))
        if spec.select:
            payload = _select_row(operation, payload, params)
        # 1.17.43: digests of the declared secret fields, for the in-memory comparison only; the values are not kept.
        return {"status": status, "values": _before_values(operation, payload), "secret_digests": _secret_digests(operation, payload)}
    except Exception:
        logger.warning("The before-read of Tactical operation %s/%s did not answer.", operation.module_id, operation.id, exc_info=True)
        return {"status": None, "values": None}


def _close_stream(response) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            logger.warning("A streamed Tactical answer did not close cleanly.", exc_info=True)


def _read_stream(response) -> bytes | None:
    """The bytes of a streamed answer, or None when it passes MAX_RESPONSE_BYTES (reading stops and the stream is closed)."""
    chunks: list[bytes] = []
    size = 0
    try:
        for chunk in response.streaming_content:
            piece = chunk if isinstance(chunk, bytes) else bytes(chunk) if isinstance(chunk, (bytearray, memoryview)) else str(chunk).encode("utf-8")
            size += len(piece)
            if size > MAX_RESPONSE_BYTES:
                return None
            chunks.append(piece)
    finally:
        _close_stream(response)
    return b"".join(chunks)


def _unknown_outcome(request, operation, object_id, tactical_status, code: str, text: str, correlation_id: str | None = None,
                     row_extra: dict | None = None) -> TacticalOperationError:
    """After dispatch, a non-GET call whose result Core cannot trust may have changed Tactical: say so in the log."""
    audit = None
    if operation.method != "GET":
        audit = _write_row(
            request, operation, action=OUTCOME_UNKNOWN_ACTION, object_id=object_id, message=OUTCOME_UNKNOWN_MESSAGE,
            tactical_status=tactical_status, correlation_id=correlation_id, extra=row_extra,
        )
    return TacticalOperationError(text, status=502, code=code, audit=audit)


def _is_real_request(request) -> bool:
    """A Django HttpRequest, or a DRF Request that wraps one. Anything else, a stand-in object with a ``user``, is no proof."""
    from django.http import HttpRequest

    if isinstance(request, HttpRequest):
        return True
    try:
        from rest_framework.request import Request as DRFRequest
    except ImportError:
        return False
    return isinstance(request, DRFRequest) and isinstance(getattr(request, "_request", None), HttpRequest)


def _clean_correlation_id(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _CORRELATION_RE.fullmatch(value):
        raise TacticalOperationError(
            "correlation_id must be 1 to 128 characters of letters, digits and . _ : -.", status=400, code="invalid_correlation_id",
        )
    return value


def _held_correlation_id(value: Any) -> str | None:
    """The correlation id a row may carry before the validation step: the value when it is valid, else None (1.17.21).

    An invalid id is refused at the validation step (``invalid_correlation_id``). Until then no row carries it."""
    try:
        return _clean_correlation_id(value)
    except TacticalOperationError:
        return None


def _clean_audit_before(value: Any) -> dict | None:
    """A caller's own before value (1.17.16): a flat dict of at most 16 fields. Python only; never from a browser.

    A field is a scalar (text up to 256 characters, a number, true/false or null). Since 1.17.23 it may also be a list of whole
    numbers or short texts. A list is kept to its first 1000 entries as declared before fields are, and the row carries
    ``<field>_count`` (the full length) and, when cut, ``<field>_truncated: true``. A caller field with either of those names
    next to a list is refused, because the row would hold it twice."""
    if value is None:
        return None
    bad = TacticalOperationError(
        "audit_before must be a flat object of at most 16 values. Each is text (up to 256 characters), a number, true/false, null, "
        "or a list of whole numbers or texts (up to 256 characters each).",
        status=400, code="invalid_audit_before",
    )
    if not isinstance(value, dict) or len(value) > _MAX_AUDIT_BEFORE_FIELDS:
        raise bad
    clean = {}
    lists = []
    for name, item in value.items():
        if not isinstance(name, str) or not _FIELD_RE.fullmatch(name) or _SECRET_NAME_RE.search(name):
            raise bad
        if isinstance(item, str):
            if len(item) > _BEFORE_STRING_LIMIT or any(ord(ch) < 32 or ord(ch) == 127 for ch in item):
                raise bad
        elif isinstance(item, (list, tuple)):
            # A tuple is refused: a list is the one sequence a caller may send.
            if not isinstance(item, list):
                raise bad
            for entry in item:
                if isinstance(entry, str) and (len(entry) > _BEFORE_STRING_LIMIT or any(ord(ch) < 32 or ord(ch) == 127 for ch in entry)):
                    raise bad
            cleaned = _before_list(item)
            if cleaned is None:
                raise bad
            clean[name], total = cleaned
            clean[f"{name}_count"] = total
            if total > len(cleaned[0]):
                clean[f"{name}_truncated"] = True
            lists.append(name)
            continue
        elif not (item is None or isinstance(item, (bool, int))):
            raise bad
        clean[name] = item
    for name in lists:
        if f"{name}_count" in value or f"{name}_truncated" in value:
            raise bad
    return clean


def run_tactical_operation(request, module_id, operation_id, params=None, body=None, query=None, upload=None, *,
                           correlation_id=None, audit_before=None, _via_http_route=False) -> TacticalOperationResult:
    """Run one declared Tactical operation for the signed-in user and audit it. Needs an authenticated request.

    ``query`` (1.17.13) is a flat object of the operation's whitelisted query names, for a GET operation. ``upload`` is
    {name, content_type, content} (bytes) for an operation that declares a file part.

    1.17.16: ``request`` must be a real Django or DRF request that went through Core's session check (it carries
    ``tec_tac_session``); anything else is refused 401 ``authenticated_request_required`` with no audit row. The keyword
    ``correlation_id`` (server-set, 1 to 128 characters) is written on every Core row of this call. ``audit_before`` is a
    flat object the caller asserts as the before value, used only when the operation declares no ``audit.before`` read;
    the row says ``before_source: caller``. Neither keyword is available over HTTP.

    1.17.19: an operation declared ``server_only`` is refused 403 ``operation_server_only`` when it arrives through Core's HTTP
    route (the private ``_via_http_route`` keyword, set only by ``TacticalOperationView``). A module backend that calls this
    function directly runs it. Module code must never pass ``_via_http_route``.

    Raises TacticalOperationError (``status``, ``code``, ``message``, ``audit``) for Core's own refusals and for a
    failure around the call. A Tactical answer, whatever its status, comes back as the result.
    """
    # 0. (1.17.16, AD-19 condition 2) a real request that passed Core's session check, never an object that merely has a user
    if not _is_real_request(request) or getattr(request, "tec_tac_session", None) is None:
        raise _fail("authenticated_request_required", 401, "authenticated_request_required")
    # 1.17.21: the two cleaners run at the validation step (5). Until then an invalid correlation id is held back (None).
    raw_correlation_id, raw_audit_before = correlation_id, audit_before
    correlation_id = _held_correlation_id(raw_correlation_id)
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
    if _via_http_route and operation.server_only:  # 2a. (1.17.19) a server-only operation never runs from the browser route
        raise _refuse(request, operation, "server_only", 403, "operation_server_only", hint, correlation_id)
    flags = tactical_permission_flags(user, (*operation.permissions, *operation.permissions_any))  # 3. (1.17.26: all of permissions, one of permissions_any)
    if not _permissions_hold(operation, flags):
        raise _refuse(
            request, operation, "permission_denied", 403, "tactical_permission_denied", hint, correlation_id,
            text=_missing_flag_text(operation, flags),
            row_extra={"needs_one_of": list(operation.permissions_any)} if operation.permissions_any else None,
        )
    if operation.module_permission:  # 4.
        try:
            allowed = has_extension_permission(user, operation.module_permission)
        except Exception:
            logger.exception("Unable to check module permission %s for operation %s", operation.module_permission, operation.id)
            allowed = False
        if not allowed:
            raise _refuse(request, operation, "module_permission_denied", 403, "module_permission_denied", hint, correlation_id)

    if operation.caller_scope == "unrestricted" and not _caller_unrestricted(user):  # 4a. (1.17.18) only for no client or site limits
        raise _refuse(request, operation, "scope_unrestricted_required", 403, "scope_unrestricted_required", hint, correlation_id)

    # 1.17.22: a core_refused row names an object only after the path parameters were cleaned. 1.17.45: until then it carries the
    # declared audit.object_id (declared text, never caller input, AD-19 condition 4), so an early refusal still names its object.
    refusal_object_id = operation.audit_object_id
    try:
        correlation_id = _clean_correlation_id(raw_correlation_id)  # 5. (1.17.21: the two cleaners run here) shape, then scope
        audit_before = _clean_audit_before(raw_audit_before)
        params = _clean_params(operation, params)  # 5. shape, then scope
        refusal_object_id = _refusal_object_id(operation, params)
        body = _clean_body(operation, body)
        if operation.body_selector and not _selector_holds(operation, body):  # 5a. (1.17.18) never run under another operation's scope or verb
            raise _refuse(request, operation, "body_selector_mismatch", 400, "body_selector_mismatch", hint, correlation_id)
        query = _clean_query(operation, query)
        file = _clean_upload(operation, upload)
        entries = _scope_entries(operation, params, body)
        scope = [(kind, ids) for _, kind, ids in entries]
        scope_object_id = _object_id(scope, operation, params)  # names every scope entry: the scope's own deny rows keep it
        # 1.17.52: an entry flagged names_object false is checked above but does not name the row (the answer or body field does).
        object_id = _object_id([(kind, ids) for spec, kind, ids in entries if spec.names_object], operation, params) if entries else scope_object_id
        count_extra = _object_count_extra(scope)  # 1.17.43: the rows of this call that read the scope carry how many ids it names
        extra: dict = dict(count_extra)
        action_now = _action_for(operation, body)  # 1.17.45: the success row's action (audit.action_by_body)
        unknown_extra = {**count_extra, "declared_action": action_now} if operation.audit_action_by_body else count_extra
        if entries:
            from . import resources_adapter as adapter

            for spec, kind, ids in entries:
                if spec.row_lookup:
                    # CQ56 a, CQ57: the owning module says which agent the row belongs to. A row with no agent is allowed to anyone
                    # who holds the Tactical flag (Tactical decides); a row with an agent is held to the caller's role scope.
                    agent_id = _row_lookup_agent(operation, spec, ids[0])
                    if agent_id is _LOOKUP_FAILED:
                        raise _refuse(request, operation, "not_found", 404, "object_not_found", scope_object_id, correlation_id, row_extra=count_extra)
                    extra["scope_source"] = "row_lookup"
                    extra["agentless"] = agent_id is None
                    if agent_id is not None and not adapter.objects_in_role_scope(user=user, resource_type="agent", identifiers=[agent_id]):
                        raise _refuse(request, operation, "not_found", 404, "object_not_found", scope_object_id, correlation_id, row_extra=count_extra)
                elif kind == "agent_pk":
                    if not adapter.agent_pks_in_role_scope(user=user, pks=ids):
                        raise _refuse(request, operation, "not_found", 404, "object_not_found", scope_object_id, correlation_id, row_extra=count_extra)
                elif not adapter.objects_in_role_scope(user=user, resource_type=kind, identifiers=ids):
                    raise _refuse(request, operation, "not_found", 404, "object_not_found", scope_object_id, correlation_id, row_extra=count_extra)
        _check_whitelist(operation, body)  # 6.
    except TacticalOperationError as exc:
        # 1.17.21: Core's own refusal of a change writes one row. An error that already carries a verdict (a deny row) keeps it.
        if exc.audit is None and exc.code in CORE_REFUSAL_ROW_CODES and operation.method != "GET":
            exc.audit = _write_core_refusal(request, operation, exc, refusal_object_id, correlation_id)
        raise

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

    body_type = _body_scope_type(operation, entries)
    if body_type:
        extra["scope_type"] = body_type
    before_state = None
    if operation.before is None and audit_before is not None and operation.method != "GET":  # 7a. the caller's own before value, only where Core has no read
        before_state = {"status": None, "values": audit_before}
        extra["before"] = "recorded"
        extra["before_source"] = "caller"
    if operation.before is not None:  # 7a. Tactical's own record of the object, read as the signed-in user, for the audit row only (1.17.13)
        before_state = _read_before(request, operation, params)
        # 1.17.14 (CQ37): the read only fills the audit before-value. It never decides scope and never refuses the call.
        extra["before"] = "recorded" if before_state["values"] is not None else "unavailable"
        extra["before_source"] = "tactical"
        if before_state["values"] is None:
            extra["before_status"] = before_state["status"]

    forwarded = _build_request(request, operation, path, body, match, query=query, file=file)
    try:
        response = _dispatch(match, forwarded)
    except Exception:
        logger.exception("Tactical operation %s/%s raised after dispatch", operation.module_id, operation.id)
        raise _unknown_outcome(request, operation, object_id, None, "tactical_call_failed", "Tactical failed while running this operation.", correlation_id, row_extra=unknown_extra) from None

    status = int(getattr(response, "status_code", 500))
    if getattr(response, "streaming", False):
        if not operation.file_response:
            _close_stream(response)
            raise _unknown_outcome(request, operation, object_id, status, "tactical_response_refused", "Core does not relay streaming responses.", correlation_id, row_extra=unknown_extra)
        # 1.17.41: a declared file answer is read chunk by chunk up to the same cap as any answer, then closed.
        try:
            content = _read_stream(response)
        except Exception:
            # 1.17.42: a stream that fails part way is an outcome-unknown refusal, never a bare 500. _read_stream has already closed it.
            logger.exception("Tactical operation %s/%s failed while sending its file answer", operation.module_id, operation.id)
            raise _unknown_outcome(request, operation, object_id, status, "tactical_call_failed", "Tactical failed while sending its answer.", correlation_id, row_extra=unknown_extra) from None
        if content is None:
            raise _unknown_outcome(request, operation, object_id, status, "tactical_response_refused", "Tactical's answer is larger than Core relays.", correlation_id, row_extra=unknown_extra)
    else:
        content = bytes(getattr(response, "content", b"") or b"")
    if len(content) > MAX_RESPONSE_BYTES:
        raise _unknown_outcome(request, operation, object_id, status, "tactical_response_refused", "Tactical's answer is larger than Core relays.", correlation_id, row_extra=unknown_extra)

    content_type = str(response.get("Content-Type", "") or "") if hasattr(response, "get") else ""
    data: Any = content
    if content_type.split(";")[0].strip().lower() in ("application/json",) or content_type.split(";")[0].strip().lower().endswith("+json"):
        try:
            data = json.loads(content.decode("utf-8")) if content else None
        except Exception:  # review round 3: any parse error (RecursionError, MemoryError ...) must never skip the row of a change Tactical ran
            data = content

    audit = None  # 8.
    if 200 <= status < 300:
        success_extra = extra
        if object_id is None and (operation.audit_object_field or operation.audit_object_body_field):
            # 1.17.21: a create has no id in the path or scope. Tactical's answer, then the cleaned body, names it. Success rows only.
            object_id, object_source = _answer_object_id(operation, data, body)
            if object_source:
                success_extra = {**extra, "object_source": object_source}
        before_payload = before_state["values"] if before_state else None
        after_payload = _after_values(operation, body, query, file, params)
        if operation.secret_fields:  # 1.17.43: one marker per sent secret field; the value is never recorded
            secret_after, secret_before = _secret_markers(operation, body, before_state.get("secret_digests") if before_state else None)
            if secret_after:
                after_payload = {**(after_payload or {}), **secret_after}
            if secret_before:
                before_payload = {**(before_payload or {}), **secret_before}
        audit = _write_row(
            request, operation, action=action_now, object_id=object_id,
            message=operation.message or f"Core ran Tactical operation {operation.id}.",
            before=before_payload, after=after_payload, tactical_status=status, extra=success_extra, correlation_id=correlation_id,
        )
    elif status in (401, 403):
        audit = _write_row(
            request, operation, action="deny", object_id=object_id, message=DENY_MESSAGES["tactical_denied"], tactical_status=status,
            refusal=True, extra={"refused_action": operation.audit_action, "reason": "tactical_denied", "status": status, **count_extra},
            correlation_id=correlation_id,
        )
    elif 400 <= status < 500 and operation.method != "GET":
        # 1.17.20: Tactical refused the change (400, 404, 409, 422, 429 ...). A failed attempt changed nothing, so the row
        # carries no before or after value and none of Tactical's own text.
        failed_extra = {key: value for key, value in extra.items() if not key.startswith("before")}
        failed_extra.update(declared_action=action_now, result="failed", failure="tactical_refused")
        audit = _write_row(
            request, operation, action=FAILED_ACTION, object_id=object_id,
            message=FAILED_MESSAGE.format(status=status), tactical_status=status, extra=failed_extra, correlation_id=correlation_id,
        )
    elif status >= 500 and operation.method != "GET":
        audit = _write_row(
            request, operation, action=OUTCOME_UNKNOWN_ACTION, object_id=object_id, message=OUTCOME_UNKNOWN_MESSAGE, tactical_status=status,
            correlation_id=correlation_id, extra=unknown_extra,
        )

    headers = {}
    for name in RELAYED_HEADERS:
        value = response.get(name) if hasattr(response, "get") else None
        if value:
            headers[name] = str(value)
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
        "declaration": "tec_tac.tactical_operations.register_tactical_operation(id, module_id, method, route, permissions, scope, body_fields, audit, module_permission=None, message=None, query_params=None, upload=None, caller_scope=None, body_selector=None, server_only=False, permissions_any=None, body_max_bytes=None, audit_lists=None, file_response=False, audit_list_masks=None), called from AppConfig.ready(). A core module that names a row_lookup also calls tec_tac.tactical_operations.register_tactical_row_lookup(module_id, lookup_id, fn) from AppConfig.ready().",
        "http": "POST /api/tfd/tactical-operations/<module_id>/<operation_id>/ with {params, body, query} as JSON, or as multipart/form-data with the text parts params, body and query (each a JSON object) and one file part",
        "limits": {
            "body_bytes": MAX_BODY_BYTES, "response_bytes": MAX_RESPONSE_BYTES,
            # 1.17.26: body_bytes is the default cap; an operation may declare body_max_bytes up to body_bytes_max.
            "body_bytes_max": MAX_BODY_CEILING_BYTES,
            # 1.17.14 (CQ40): upload_bytes is the effective ceiling now (the system setting), with the default and the absolute maximum.
            "upload_bytes": upload_ceiling_bytes(), "upload_bytes_default": MAX_UPLOAD_BYTES, "upload_bytes_max": MAX_UPLOAD_ABSOLUTE_BYTES,
            "query_params": MAX_QUERY_PARAMS, "query_value_chars": MAX_QUERY_VALUE,
        },
        "declaration_keys_added_in_1_1_0": [
            "audit.object_param", "audit.before", "scope type body:<field> with type_map", "query_params", "upload",
        ],
        "declaration_keys_removed_in_1_2_0": ["scope source before:<field>"],
        # 1.17.16: Python-only keywords of run, never accepted over HTTP (the view's allowed fields are params, body and query).
        "declaration_keys_added_in_1_3_0": ["run(correlation_id=)", "run(audit_before=)"],
        # 1.17.18 (capability 1.4.0, still major 1): all optional, an older declaration registers and runs unchanged.
        "declaration_keys_added_in_1_4_0": [
            "caller_scope", "body_selector", "scope.optional", "scope type agent_pk", "scope.row_lookup", "audit.params",
            "audit.before.count_fields", "audit.before.select", "audit.before list values", "register_tactical_row_lookup",
        ],
        "refusal_codes_added_in_1_4_0": ["scope_unrestricted_required", "body_selector_mismatch"],
        "limits_added_in_1_4_0": {
            "audit_before_fields": _MAX_BEFORE_FIELDS, "audit_before_list_entries": _MAX_BEFORE_LIST,
            "audit_before_select_rows": _MAX_BEFORE_SELECT_ROWS, "audit_params": _MAX_AUDIT_PARAMS,
            "body_selector_conditions": _MAX_BODY_SELECTOR,
        },
        # 1.17.28: the bounds of audit_lists (a Core constant, never a module's choice).
        "limits_added_in_1_10_0": {
            "audit_lists_per_operation": _MAX_AUDIT_LISTS, "audit_list_entries": _LIST_MAX_ENTRIES, "audit_list_keys": _LIST_MAX_KEYS,
            "audit_list_items": _LIST_MAX_ITEMS, "audit_list_text_chars": _LIST_VALUE_MAX_CHARS, "audit_list_text_bytes": _LIST_MAX_TEXT_BYTES,
        },
        # 1.17.19 (capability 1.5.0, still major 1): server_only stops the browser path only; it is not a verified caller identity.
        "declaration_keys_added_in_1_5_0": ["server_only"],
        "refusal_codes_added_in_1_5_0": ["operation_server_only"],
        # 1.17.20 (capability 1.6.0, still major 1): a feature-detect for the failed row. No declaration key changes.
        "declaration_keys_added_in_1_6_0": [],
        "behaviour_added_in_1_6_0": [
            (
                "a non-GET operation that Tactical refuses with a 4xx other than 401 and 403 writes one custom:operation-failed row "
                "(metadata.declared_action, result failed, no before or after value, no Tactical text); result.audit and X-Tec-Tac-Audit are a verdict for it"
            ),
        ],
        # 1.17.21 (capability 1.7.0, still major 1): two optional audit keys and one behaviour, so a module can feature-detect each.
        "declaration_keys_added_in_1_7_0": ["audit.object_field", "audit.object_body_field"],
        "behaviour_added_in_1_7_0": [
            (
                "a non-GET call that Core refuses before Tactical is called, with one of refusal_row_codes, writes one custom:operation-failed row "
                "(failure core_refused, metadata.code, declared_action, fixed Core text, no body, query or upload value); error.audit and "
                "X-Tec-Tac-Audit are the verdict, so a module stops writing its own failed row for these codes when error.audit is not None"
            ),
            (
                "audit.object_field or audit.object_body_field gives the success row's object id (metadata.object_source answer or body) when "
                "no audit.object_param and no scope object does; no other row carries it"
            ),
        ],
        # 1.17.23 (capability 1.8.0, still major 1): a feature-detect for list values in the caller's audit_before.
        "declaration_keys_added_in_1_8_0": [],
        "behaviour_added_in_1_8_0": [
            (
                "run(audit_before=) accepts a list of whole numbers or short texts per field, kept to the first 1000 entries; the row carries "
                "<field>_count and, when cut, <field>_truncated; a caller field named <list>_count or <list>_truncated next to a list is refused"
            ),
        ],
        # 1.17.26 (capability 1.9.0, still major 1): two optional declaration keys. A declaration that passes neither behaves as before.
        "declaration_keys_added_in_1_9_0": ["permissions_any", "body_max_bytes"],
        "behaviour_added_in_1_9_0": [
            (
                "permissions_any: the caller needs every flag of permissions and at least one flag of permissions_any; permissions may be empty "
                "only when permissions_any is given; the 403 tactical_permission_denied names 'one of' the flags and the deny row carries needs_one_of; "
                "list_operations and get_operation show permissions_any"
            ),
            (
                "body_max_bytes: a whole number from the default body_bytes up to limits.body_bytes_max; body_too_large (413) names the cap that "
                "applied; list_operations and get_operation show the effective cap as body_max_bytes"
            ),
        ],
        # 1.17.28 (capability 1.10.0, still major 1): one optional declaration key. A declaration without it behaves as before.
        "declaration_keys_added_in_1_10_0": ["audit_lists (register_tactical_operation(audit_lists=)), shown as audit.lists"],
        "behaviour_added_in_1_10_0": [
            (
                "audit_lists: up to two body or before fields that hold a list of flat objects are recorded IN CLEAR, with no masking, in the "
                "success row (after from the cleaned body, before from Tactical's own GET answer) with <field>_count and, when cut or dropped, "
                "<field>_truncated; a failed, denied or outcome-unknown row carries no list; the docs state the clear-text rule"
            ),
        ],
        # 1.17.41 (capability 1.11.0, still major 1): three optional additions. A declaration that uses none behaves as before.
        "declaration_keys_added_in_1_11_0": [
            "file_response (register_tactical_operation(file_response=)), shown as file_response",
            "query_params on any method",
            "route parameter kind {name:service}",
        ],
        "behaviour_added_in_1_11_0": [
            (
                "file_response: a streamed Tactical answer (FileResponse) is read up to limits.response_bytes and relayed with its status, Content-Type "
                "and Content-Disposition; the same status handling and audit rows apply as for any answer; the row never carries the file name or bytes; "
                "a stream over the cap is cut, closed and refused as tactical_response_refused; without file_response a stream is refused as before"
            ),
            (
                "query_params may be declared on a DELETE, POST, PUT or PATCH operation; names stay a whitelist, values stay flat (512 characters, "
                "no control characters, no '..' segment), a secret-looking name is refused at registration"
            ),
            (
                "route parameter kind service: a Windows service name (first character a letter, digit or underscore, then letters, digits, space "
                "and $ # ( ) . , _ -, at most 256 characters, no slash, no '..'), built into the path unquoted"
            ),
        ],
        # 1.17.43 (capability 1.12.0, still major 1): one optional declaration key and one metadata key. A declaration that uses
        # neither behaves exactly as before, and a row without them is unchanged.
        "declaration_keys_added_in_1_12_0": ["audit.secret_fields (register_tactical_operation audit={... 'secret_fields'}), shown as audit.secret_fields"],
        "behaviour_added_in_1_12_0": [
            (
                "audit.secret_fields: a success row writes '<field>': 'changed' when the body sends the field. With an audit.before read that holds "
                "the field, the before side writes 'present' and the after side 'changed' or 'unchanged' (a SHA-256 of the canonical JSON, compared "
                "in memory, the value dropped at once). The value is never recorded in the row, the metadata or a log. The marker proves the value "
                "was sent or differs, not what it holds. A failed, denied, core_refused or outcome-unknown row carries no marker"
            ),
            (
                "metadata.object_count: when the first scope entry names more than one id, the success, tactical_denied deny, scope refusal, failed "
                "and outcome-unknown rows of that call carry the number of ids. A number, never an id; the object id itself is unchanged"
            ),
        ],
        # 1.17.44 (capability 1.13.0, still major 1): one optional declaration key. A declaration without it behaves exactly as before.
        "declaration_keys_added_in_1_13_0": ["audit.object_id (register_tactical_operation audit={... 'object_id'}), shown as audit.object_id"],
        "behaviour_added_in_1_13_0": [
            (
                "audit.object_id: a fixed text declared by the module (letters, digits and . _ : -, at most 64 characters, not secret-looking; refused on a GET "
                "operation and together with audit.object_param, audit.object_field or audit.object_body_field). It is the last fallback: the path "
                "parameter of audit.object_param and the first scope object come first. It names the object on every row of that operation: success, "
                "tactical_denied and scope deny, failed, outcome-unknown and core_refused. It is declared text, never caller or body input"
            ),
            (
                "list_operations and get_operation show audit.object_id and audit.secret_fields (an empty list for a declaration that has none). "
                "audit.secret_fields may no longer name the same field as audit.object_field"
            ),
        ],
        # 1.17.45 (capability 1.14.0, still major 1): two optional declaration additions. A declaration that uses neither behaves exactly as before.
        "declaration_keys_added_in_1_14_0": [
            "audit.action_by_body (register_tactical_operation audit={... 'action_by_body': {'field', 'map'}}), shown as audit.action_by_body",
            "a nested body scope source, scope {'source': 'body:<field>.<key>'}, one level deep",
        ],
        "behaviour_added_in_1_14_0": [
            (
                "audit.action_by_body: the success row's audit action is chosen from the cleaned body value of one body field through a map of at most 8 "
                "entries (keys text of at most 40 characters, values audit actions that are not deny, custom:outcome-unknown or custom:operation-failed). "
                "A missing, non-text or unmatched value keeps audit.action. Deny and other Core-only rows keep their own action; failed and outcome-unknown "
                "rows carry the chosen action in metadata.declared_action (outcome-unknown rows only for an operation that declares action_by_body)"
            ),
            (
                "nested scope source body:<field>.<key>: <field> is one of body_fields and must hold an object (400 scope_field_required otherwise); "
                "optional entries, list values and the 1000 id cap behave as for a top-level source; refused with row_lookup, audit.object_body_field "
                "and audit.secret_fields; Core checks scope before Tactical runs and forwards the body it checked"
            ),
            (
                "a core_refused row for invalid_correlation_id, invalid_audit_before or invalid_params carries the declared audit.object_id"
            ),
        ],
        # 1.17.52 (capability 1.15.0, still major 1): two optional additions. A declaration that uses neither behaves exactly as before.
        "declaration_keys_added_in_1_15_0": [
            "audit_list_masks (register_tactical_operation(audit_list_masks={list: {key: 'names'|'mask'}})), shown as audit.list_masks",
            "scope names_object (a strict bool, default true; false keeps the entry checked but off the audit row's object id), shown as names_object: false",
        ],
        "limits_added_in_1_15_0": {"audit_list_mask_keys_per_list": _MAX_LIST_MASK_KEYS, "audit_list_mask_modes": list(_LIST_MASK_MODES), "masked_text": _MASKED},
        "behaviour_added_in_1_15_0": [
            (
                "audit_list_masks: for a list in audit_lists, a masked key never reaches the audit row in clear, on the after side (cleaned body) or the before "
                "side (Tactical's answer). names: each text item of the list keeps only its name (KEY=VALUE gives KEY, --flag=value gives --flag, -Name value "
                "gives -Name); an item with no name (a positional argument, an empty value, base64 padding, a name that is not name-shaped) and any non-text item "
                "is ***. mask: an item keeps its name and shows *** for the value (KEY=***, --flag=***, -Name ***); a scalar text key is ***. names on a scalar "
                "key is ***. A masked key whose value is not text or a list of scalars is ***; null stays null. The audit_lists bounds (50 entries, 24 keys, "
                "100 items, 4096 characters, 64 KiB, <name>_count, <name>_truncated) apply after masking. Registration refuses a list not in audit_lists, more "
                "than 8 keys per list, a key that is not a field name, a mode other than names or mask and a mapping that is not a dict. audit_lists without "
                "audit_list_masks is still recorded in clear"
            ),
            (
                "scope names_object: false: the entry is resolved and checked exactly as before and its deny rows are unchanged, but it is left out when Core picks "
                "the object id of the success, failed, tactical-denied and outcome-unknown rows, so audit.object_field or audit.object_body_field can name the "
                "created record. Registration refuses a non-bool and a scope whose entries are all names_object false unless the declaration has audit.object_param, "
                "audit.object_field, audit.object_body_field or audit.object_id"
            ),
        ],
        "refusal_row_codes": list(CORE_REFUSAL_ROW_CODES),
        "audit_actions_core_only": ["deny", OUTCOME_UNKNOWN_ACTION, FAILED_ACTION],
        "refusal_codes_added_in_1_3_0": ["authenticated_request_required", "invalid_correlation_id", "invalid_audit_before"],
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
