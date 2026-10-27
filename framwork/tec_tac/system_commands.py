"""System commands: the third kind of Tactical work Core does for a verified module (core.system_actions 1.5.0, Core 1.17.75, rebuilt 1.17.76, AD-45, AD-49).

The first kind starts a Tactical Celery task; the second writes one fixed column. A command has no task and no column: Tactical's own route
``POST agents/<agent_id>/cmd/`` (``agents/views.py send_raw_cmd``, operation ``agents_cmd_create``, string agent id) runs one command on one endpoint and answers with
the output text. Core holds ONE fixed row for it, ``agent.command``. The module that owns the piece of Tactical (Remote Background) registers it; Core defines and
enforces everything else, so no module can widen it.

1.17.76 (Johan, 23 October 2026, chat): Core no longer copies the steps of ``send_raw_cmd`` (the 1.17.75 history row and ``nats_cmd``). It runs Tactical's OWN
view in process. Johan's signed call: the person's Communicator rights are checked when the schedule is made, and the command runs as the Communicator module, not
as the owner and without the owner needing Tactical's ``can_send_cmd``. The narrowest build: a dedicated, least-privilege Tactical service user
(``SERVICE_USERNAME``, role ``SERVICE_ROLE``) that Core makes at install or upgrade time (migration 0038) and checks on every call. It may hold ``can_send_cmd`` and nothing else, is not a superuser or
installer user, cannot sign in (unusable password, ``block_dashboard_login``), and is used by ``_send`` only: ``run_one`` refuses any row but ``agent.command``, and
``_send`` is reached only after every check of ``run_system_command`` (verified Communicator run, action bound to the run, owner scope, templates and hashes).
Tactical's own scope check for that user is open (its role has no client or site limits); the endpoint was validated against the OWNER's creation-time scope
before, and the string agent id is resolved from that one validated number. Known issue (Johan, fix next week): docs/system-actions.md.

What is fixed here
    * Templates are registered at ``AppConfig.ready()`` through ``register_command_template`` by a module on REGISTRANTS only. A template is immutable: the same
      content again is accepted, different content under the same id is refused and logged. Core hashes each template (shell, fixed text or the SHA-256 of the
      file content, slot schema, timeout) at registration.
    * A template may be a code constant (``text``) or a file shipped in the module (``file``). A file is read again at every run; a content change makes its
      hash differ, and the run is refused.
    * The person confirms ``allowed_templates`` with their ``template_hashes`` and ``max_timeout`` when they make the schedule. At run time a template whose
      current hash differs from the confirmed hash is refused (``template_changed``): a module update changed it and the person must confirm again.
    * Slots are typed: a whole number in a range, short text from an allowed character set that excludes quotes and shell metacharacters, or an enum.
      A text slot is ONE token unless its spec says ``spaces: true``; a value never starts with ``-`` or ``/`` or with a space, so a slot cannot add a flag or an argument.
    * One endpoint per call, a timeout of 1 to 60 seconds, the caller on the row's allow-list (``communicator``), its Scheduler run being the run the context
      belongs to (checked in ``_run``).
    * One ``command_id`` per endpoint, once. The claim is ``cache.add`` with a 24-hour expiry: atomic, and shared by every worker when the cache is shared
      (Tactical's Redis). A cache that cannot be reached refuses the call (fail closed). Since 1.17.76 the claim is backed by the strict audit 'before' row, which
      is durable: after the claim Core looks for an earlier row of the same endpoint and command_id, and one that exists refuses the call (``duplicate_command``) even
      after a cache flush or eviction. A lookup that fails refuses the call (fail closed).
    * The route takes Tactical's STRING agent id, not the number; Core resolves it from the number and refuses the call when it cannot (``bad_agents``).
    * The strict audit row is written BEFORE the send and a closing row after. Neither holds the command text or the output: they hold the run, the schedule,
      the endpoint, the command_id, the template id and hash, the shell, the timeout and the lengths.
    * The output text is cut at MAX_OUTPUT_BYTES (1 MiB) and the result says so.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from pathlib import Path

logger = logging.getLogger("tec_tac.system_actions")

OWNER_MODULE = "remote-background"  # owns agents/{}/cmd (tactical_operations route owners; AD-18, AD-45)
SHELLS = ("cmd", "powershell", "/bin/bash", "/bin/sh")
REGISTRANTS = ("communicator",)  # the row's allow-list: the only module ids that may register a template (and call the row)
MIN_TIMEOUT = 1
MAX_TIMEOUT = 60
MAX_COMMAND_CHARS = 8000
MAX_FILE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TEMPLATES = 16
MAX_SLOTS = 8
CLAIM_SECONDS = 24 * 3600
COMMAND_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TEMPLATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\.[a-z0-9][a-z0-9._-]{0,63}$")
SLOT_RE = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_CHARS = set("\"'`\\$&|;<>(){}[]^%!*?~#\r\n\t\0=,@")  # never allowed in a text slot's character set
CLOSING_ACTION = "custom:command-closed"
UNREACHABLE_REPLIES = ("timeout", "natsdown")  # send_raw_cmd answers 200 with this bare text when the agent never answered (as Remote Background's service.py maps it)
OWNER_VIEW_DISPATCH_SIGNED = True  # 1.17.76 (Johan, chat, 23 October 2026): run as the Communicator module; False would switch the row off again (fail closed)
SERVICE_USERNAME = "tectac-communicator"
SERVICE_ROLE = "Tec-Tac Communicator (send commands only)"
SERVICE_FLAG = "can_send_cmd"
RIGHT_SEND, RIGHT_REBOOT = "communicator.send", "communicator.reboot"  # 1.17.76 (AD-50): the Communicator rights the person held when the schedule was made
RIGHTS = (RIGHT_SEND, RIGHT_REBOOT)
CLAIM_LOOKUP_DAYS = 7  # the durable claim lookup reads only this window of the audit log (the cache claim itself lasts 24 hours)
MAX_COMMANDS_PER_RUN = 2000  # defense in depth (Communicator caps a call at 2 000 endpoints); one run sends at most this many, above it the call is refused
RUN_COUNT_SECONDS = 2 * 24 * 3600
UNREACHABLE_TEXT = "Unable to contact the agent"  # what send_raw_cmd answers with HTTP 400 when nats_cmd returned "timeout"


class CommandRefused(Exception):
    """The call is refused. ``reason`` is a code of ``system_actions.REASONS``."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class SendFailed(RuntimeError):
    """Tactical's send-command view did not answer 2xx. ``status`` is its HTTP status; ``reason`` is a short code (1.17.82). Never holds the command, the output or a token."""

    def __init__(self, status: int):
        super().__init__(f"Tactical answered the send-command view with HTTP {status}.")
        self.status = status
        self.reason = failure_reason(status)


def failure_reason(status) -> str:
    """The short plain code for the HTTP status of Tactical's view (None: the view raised instead of answering)."""
    if status is None:
        return "tactical_view_raised"
    if status in (401, 403):
        return "tactical_permission_denied"
    if status == 404:
        return "tactical_not_found"
    if 400 <= status < 500:
        return "tactical_bad_request"
    return "tactical_error"


class CommandTemplateError(ValueError):
    """A template registration is refused."""


# ------------------------------------------------------------------------------------------------ the template registry (memory only)
_LOCK = threading.Lock()
_TEMPLATES: dict[str, dict] = {}


def _clean_slots(slots) -> dict:
    if slots is None:
        slots = {}
    if not isinstance(slots, dict) or len(slots) > MAX_SLOTS:
        raise CommandTemplateError("slots must be a dict of at most 8 slots.")
    out = {}
    for name, spec in slots.items():
        if not isinstance(name, str) or not SLOT_RE.fullmatch("{" + name + "}") or not isinstance(spec, dict):
            raise CommandTemplateError("a slot needs a lower-case name and a dict spec.")
        kind = spec.get("type")
        if kind == "int":
            lo, hi = spec.get("min"), spec.get("max")
            if set(spec) != {"type", "min", "max"} or any(isinstance(v, bool) or not isinstance(v, int) for v in (lo, hi)) or not -10**9 <= lo <= hi <= 10**9:
                raise CommandTemplateError("an int slot is exactly {type, min, max} with whole numbers.")
            out[name] = {"type": "int", "min": lo, "max": hi}
        elif kind == "text":
            limit, chars, spaces = spec.get("max"), spec.get("chars"), spec.get("spaces", False)
            if not {"type", "max", "chars"} <= set(spec) <= {"type", "max", "chars", "spaces"} or not isinstance(spaces, bool) or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
                raise CommandTemplateError("a text slot is {type, max (1 to 500), chars} and optionally spaces: true.")
            if not isinstance(chars, str) or not chars or set(chars) & FORBIDDEN_CHARS or any(ord(c) < 32 or ord(c) > 126 for c in chars):
                raise CommandTemplateError("a text slot's chars must be printable ASCII without quotes or shell metacharacters.")
            if " " in chars and not spaces:
                raise CommandTemplateError("a text slot is one token: a space in chars needs spaces: true in the slot spec.")
            out[name] = {"type": "text", "max": limit, "chars": "".join(sorted(set(chars))), "spaces": spaces}
        elif kind == "enum":
            values = spec.get("values")
            if set(spec) != {"type", "values"} or not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 32 \
                    or not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", v) for v in values) or len(set(values)) != len(values):
                raise CommandTemplateError("an enum slot is exactly {type, values} with 1 to 32 simple, distinct texts.")
            out[name] = {"type": "enum", "values": sorted(values)}
        else:
            raise CommandTemplateError("a slot type is int, text or enum.")
    return out


def _check_text(text) -> str:
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_COMMAND_CHARS or any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
        raise CommandTemplateError("the template text must be 1 to 8000 characters without control characters.")
    return text


def _template_hash(shell: str, source: str, slots: dict, timeout: int) -> str:
    """The hash of a template: its shell, its fixed text (or the SHA-256 of the file content), its slot schema and its timeout."""
    body = json.dumps({"shell": shell, "source": source, "slots": slots, "timeout": timeout}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _load(template: dict) -> tuple[str, str]:
    """``(text, hash)`` as they are NOW: a code template is fixed; a file template is read again and hashed again."""
    if template["file"] is None:
        return template["text"], template["hash"]
    raw = Path(template["file"]).read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise CommandTemplateError("the template file is too large.")
    text = _check_text(raw.decode("utf-8"))
    return text, _template_hash(template["shell"], "file:" + hashlib.sha256(raw).hexdigest(), template["slots"], template["timeout"])


def _installed_root(module_id: str) -> str:
    """The real install directory of an installed extension module; ``CommandTemplateError`` when it cannot be read (fail closed)."""
    try:
        from . import system_actions as _sa

        return os.path.normcase(os.path.realpath(str(_sa._registered_plugin(module_id).root)))
    except Exception as exc:  # not an installed extension module (or the modules could not be read)
        raise CommandTemplateError("module_id is not an installed extension module.") from exc


def _check_file_inside(module_id: str, file: str) -> None:
    """A template file lies inside the module's own install directory and no part of its path is a symlink."""
    root = _installed_root(module_id)
    real = os.path.normcase(os.path.realpath(file))
    if real != os.path.normcase(os.path.normpath(file)) or not real.startswith(root.rstrip(os.sep) + os.sep):
        raise CommandTemplateError("a template file must lie inside the module's install directory and may not be, or sit behind, a symlink.")


def register_command_template(module_id, template_id, *, shell, text=None, file=None, slots=None, timeout=30, right=RIGHT_SEND) -> dict:
    """Register one fixed command template. Call it from ``AppConfig.ready()`` of a module on REGISTRANTS. Memory only.

    ``text`` is the fixed command with ``{slot}`` placeholders; ``file`` is the absolute path of a file shipped in the module (its content is the template,
    read and hashed again at every run). Exactly one of the two. ``slots`` maps a slot name to ``{"type": "int", "min", "max"}``,
    ``{"type": "text", "max", "chars"}`` or ``{"type": "enum", "values"}``. ``right`` (1.17.76) is the Communicator right a person needs for this template: ``communicator.send`` (default) or
    ``communicator.reboot`` for a restart template; Core refuses a run whose confirmed ``rights`` do not hold it. ``template_id`` is ``<module_id>.<name>``. Returns ``{id, hash}``.
    The same content again returns the same record; different content under the same id is refused (``CommandTemplateError``) and logged."""
    try:
        from .caller_identity import calling_module_for_core_provider

        identity = calling_module_for_core_provider(provider_file=__file__)  # AD-31: the module whose own code called this, not the argument
        if identity is None or identity.module_id != module_id:
            raise CommandTemplateError("the caller is not the module it names.")
        if module_id not in REGISTRANTS:
            raise CommandTemplateError("this module may not register command templates.")
        if not isinstance(template_id, str) or not TEMPLATE_ID_RE.fullmatch(template_id) or not template_id.startswith(module_id + "."):
            raise CommandTemplateError("template_id must be '<module_id>.<name>'.")
        if shell not in SHELLS:
            raise CommandTemplateError("shell must be cmd, powershell, /bin/bash or /bin/sh.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
            raise CommandTemplateError("timeout must be 1 to 60 seconds.")
        if (text is None) == (file is None):
            raise CommandTemplateError("give exactly one of text and file.")
        if right not in RIGHTS:
            raise CommandTemplateError("right must be communicator.send or communicator.reboot.")
        clean = _clean_slots(slots)
        record = {"id": template_id, "module_id": module_id, "right": right, "shell": shell, "slots": clean, "timeout": timeout, "text": None, "file": None}
        if file is not None:
            if not isinstance(file, (str, Path)) or not Path(file).is_absolute() or not Path(file).is_file():
                raise CommandTemplateError("file must be the absolute path of an existing file.")
            _check_file_inside(module_id, str(file))
            record["file"] = str(file)
            body, record["hash"] = _load(record)
        else:
            record["text"] = body = _check_text(text)
            record["hash"] = _template_hash(shell, "text:" + body, clean, timeout)
        if set(SLOT_RE.findall(body)) != set(clean):
            raise CommandTemplateError("every {slot} in the template needs a slot spec, and every spec must be used.")
        _installed_root(module_id)
        with _LOCK:
            previous = _TEMPLATES.get(template_id)
            if previous is not None:
                if previous["hash"] == record["hash"] and previous["file"] == record["file"] and previous["module_id"] == module_id and previous.get("right") == right:
                    return {"id": template_id, "hash": previous["hash"]}
                raise CommandTemplateError("this template id is already registered with different content; a template never changes after registration.")
            if len(_TEMPLATES) >= 64:
                raise CommandTemplateError("too many command templates.")
            _TEMPLATES[template_id] = record
        return {"id": template_id, "hash": record["hash"]}
    except CommandTemplateError as exc:
        logger.warning("Command template %r is refused: %s", template_id if isinstance(template_id, str) else "?", exc)
        raise


def template_hashes(template_ids) -> dict:
    """``{template_id: current hash}`` of registered ids: what the module shows the person and passes back in the confirmed parameters. ``ValueError`` for an unknown id."""
    from .caller_identity import calling_module_for_core_provider

    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None or identity.module_id not in REGISTRANTS:
        raise ValueError("the caller may not read command template hashes.")
    out = {}
    for tid in template_ids:
        with _LOCK:
            record = _TEMPLATES.get(tid) if isinstance(tid, str) else None
        if record is None:
            raise ValueError("unknown command template.")
        try:
            out[tid] = _load(record)[1]
        except (OSError, ValueError):
            raise ValueError("the command template cannot be read.") from None
    return out


# ------------------------------------------------------------------------------------------------ what the person confirms
def parameters(values) -> dict:
    """What the person confirmed: ``allowed_templates`` (1 to 16 registered ids), their ``template_hashes`` (as Core showed them) and ``max_timeout`` (1 to 60), and since 1.17.76 ``rights``: the
    Communicator rights the person held when the schedule was made (AD-50). Core cannot read a module permission, so the module attests them in what the person confirms;
    ``communicator.send`` is always required, ``communicator.reboot`` too for a restart template, and a run refuses ``permission_lost`` without them."""
    if not isinstance(values, dict) or not {"allowed_templates", "template_hashes", "rights"} <= set(values) <= {"allowed_templates", "template_hashes", "max_timeout", "rights"}:
        raise ValueError("a command run takes allowed_templates, template_hashes, rights and max_timeout.")
    ids = values.get("allowed_templates")
    if isinstance(ids, (str, bytes, dict)) or not isinstance(ids, (list, tuple)) or not 1 <= len(ids) <= MAX_TEMPLATES:
        raise ValueError("allowed_templates must be a list of one to sixteen template ids.")
    if not all(isinstance(i, str) and TEMPLATE_ID_RE.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("allowed_templates must name each template id once.")
    hashes = values.get("template_hashes")
    if not isinstance(hashes, dict) or set(hashes) != set(ids) or not all(isinstance(h, str) and HASH_RE.fullmatch(h) for h in hashes.values()):
        raise ValueError("template_hashes must hold the 64-character hash of exactly each allowed template.")
    with _LOCK:
        if not all(i in _TEMPLATES for i in ids):
            raise ValueError("an allowed template is not registered.")
    limit = values.get("max_timeout", MAX_TIMEOUT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not MIN_TIMEOUT <= limit <= MAX_TIMEOUT:
        raise ValueError("max_timeout must be a whole number of seconds from 1 to 60.")
    rights = values.get("rights")
    if isinstance(rights, (str, bytes, dict)) or not isinstance(rights, (list, tuple)) or not rights or not all(r in RIGHTS for r in rights) or len(set(rights)) != len(rights) \
            or RIGHT_SEND not in rights:
        raise ValueError("rights must list the Communicator rights the person holds: communicator.send, and communicator.reboot for a restart template.")
    with _LOCK:
        needed = {_TEMPLATES[i].get("right", RIGHT_SEND) for i in ids}
    if not needed <= set(rights):
        raise ValueError("rights must cover every allowed template.")
    return {"allowed_templates": sorted(ids), "template_hashes": {i: hashes[i] for i in sorted(ids)}, "max_timeout": limit, "rights": sorted(rights)}


def audit_extra(cleaned) -> dict:
    return {"allowed_templates": list(cleaned["allowed_templates"]), "template_hashes": dict(cleaned["template_hashes"]), "max_timeout": cleaned["max_timeout"], "rights": list(cleaned["rights"])}


def confirmation_line(cleaned) -> str:
    return (f"Each time it runs, the module you named sends one of these fixed commands to the endpoint: {', '.join(cleaned['allowed_templates'])}, "
            f"waiting at most {cleaned['max_timeout']} seconds. The commands are built into the module and change only when the module is updated; "
            "then you confirm again. Core records who, where and when in its audit log, never the command or its output.")


def _slot_value(spec: dict, value) -> str:
    if spec["type"] == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not spec["min"] <= value <= spec["max"]:
            raise CommandRefused("bad_command")
        return str(value)
    if not isinstance(value, str):
        raise CommandRefused("bad_command")
    if spec["type"] == "text":
        if not 1 <= len(value) <= spec["max"] or any(ch not in spec["chars"] for ch in value) or value[0] in "-/" or value != value.strip():
            raise CommandRefused("bad_command")
        return value
    if value not in spec["values"]:
        raise CommandRefused("bad_command")
    return value


def resolve(command, cleaned) -> tuple[dict, int]:
    """``(clean call, endpoint number)`` or ``CommandRefused``. Strict: exactly the four keys, no command text, nothing repaired. Core renders the command."""
    if not isinstance(command, dict) or set(command) != {"agent_id", "command_id", "template_id", "params"}:
        raise CommandRefused("bad_command")
    agent_id, command_id, template_id, params = (command[k] for k in ("agent_id", "command_id", "template_id", "params"))
    if isinstance(agent_id, bool) or not isinstance(agent_id, int) or not 0 < agent_id < 2**63:
        raise CommandRefused("bad_agents")
    if not isinstance(command_id, str) or not COMMAND_ID_RE.fullmatch(command_id) or not isinstance(template_id, str) or not isinstance(params, dict):
        raise CommandRefused("bad_command")
    if template_id not in cleaned["allowed_templates"]:
        raise CommandRefused("action_not_allowed")
    with _LOCK:
        record = _TEMPLATES.get(template_id)
    if record is None:
        raise CommandRefused("bad_command")
    try:
        text, current = _load(record)
    except Exception:
        logger.warning("A command template could not be read; the call is refused.", exc_info=True)
        raise CommandRefused("function_unavailable") from None
    if current != record["hash"] or current != cleaned["template_hashes"].get(template_id):
        logger.warning("Command template %r no longer matches what was registered or confirmed; the call is refused.", template_id)
        raise CommandRefused("template_changed")
    if record.get("right", RIGHT_SEND) not in cleaned.get("rights", ()):  # the Communicator right the person attested when the schedule was made (AD-50)
        raise CommandRefused("permission_lost")
    slots = record["slots"]
    if set(params) != set(slots):
        raise CommandRefused("bad_command")
    values = {name: _slot_value(slots[name], params[name]) for name in slots}
    rendered = SLOT_RE.sub(lambda m: values[m.group(1)], text)
    if len(rendered) > MAX_COMMAND_CHARS:
        raise CommandRefused("bad_command")
    timeout = min(record["timeout"], cleaned["max_timeout"])
    return {"command_id": command_id, "template_id": template_id, "template_hash": current, "shell": record["shell"], "command": rendered, "timeout": timeout}, agent_id


def _claim_key(run, agent_id: int, command_id: str) -> str:
    return "tectac:syscmd:" + hashlib.sha256(f"{agent_id}\0{command_id}".encode()).hexdigest()


_RUN = threading.local()  # the run whose claims are being made (set by run_one around claim())
_RECORDED: dict = {}  # run id -> {(agent_id, command_id)}: the audit lookup, read ONCE per run (at most the last few runs are kept)
CLAIM_PREFETCH_MAX = 100000  # more recent rows than this in the window: the lookup is refused (fail closed), never truncated


def _recent_recorded() -> set:
    """1.17.76: the (agent_id, command_id) pairs of Core's strict 'run' rows of kind 'command' in the last CLAIM_LOOKUP_DAYS days: ONE query, bounded."""
    from datetime import timedelta

    from django.utils import timezone
    from logs.models import AuditLog

    rows = list(AuditLog.objects.filter(
        entry_time__gte=timezone.now() - timedelta(days=CLAIM_LOOKUP_DAYS), action="run", object_type="system_action", debug_info__metadata__kind="command",
    ).values_list("debug_info__metadata__agent_id", "debug_info__metadata__command_id")[: CLAIM_PREFETCH_MAX + 1])
    if len(rows) > CLAIM_PREFETCH_MAX:
        raise RuntimeError("Too many recent command rows to read safely.")
    return {(int(a), str(c)) for a, c in rows if a is not None and c is not None}


def _already_recorded(agent_id: int, command_id: str) -> bool:
    """1.17.76: is there an earlier strict 'before' row of this endpoint and command_id in the last 7 days? The audit log is durable; the cache is not.
    The rows are read once per run (not once per send); a send of this run is added to the set. A command_id older than 7 days is outside the lookup."""
    run_id = getattr(_RUN, "run_id", None)
    if run_id is None:
        return (agent_id, command_id) in _recent_recorded()
    if run_id not in _RECORDED:
        _RECORDED[run_id] = _recent_recorded()
        while len(_RECORDED) > 8:
            _RECORDED.pop(next(iter(_RECORDED)))
    return (agent_id, command_id) in _RECORDED[run_id]


def claim(agent_id: int, command_id: str) -> bool:
    """True once per (endpoint, command_id) across workers and cache flushes. A cache or a lookup that raises refuses the call (fail closed)."""
    from django.core.cache import cache

    try:
        if not cache.add(_claim_key(None, agent_id, command_id), 1, CLAIM_SECONDS):
            return False
    except Exception:
        logger.warning("The command claim could not be made; the call is refused.", exc_info=True)
        raise CommandRefused("function_unavailable") from None
    try:
        return not _already_recorded(agent_id, command_id)  # the cache was flushed or evicted: the audit row remembers; an earlier row keeps the claim
    except Exception:
        release(agent_id, command_id)  # 1.17.77: nothing was sent, so the claim must not read as a duplicate for 24 hours
        logger.warning("The command's audit lookup failed; the claim was released and the call is refused.", exc_info=True)
        raise CommandRefused("function_unavailable") from None


def release(agent_id: int, command_id: str) -> None:
    from django.core.cache import cache

    try:
        cache.delete(_claim_key(None, agent_id, command_id))
    except Exception:
        logger.warning("A command claim could not be released.", exc_info=True)


def count_run(run_id) -> int:
    """The number of this call within its run (1 for the first), counted in the cache shared by the workers. Above ``MAX_COMMANDS_PER_RUN`` the call is refused
    ``too_many_commands``; a cache that raises refuses too (fail closed)."""
    from django.core.cache import cache

    key = "tectac:syscmd-run:" + hashlib.sha256(str(run_id).encode()).hexdigest()
    try:
        cache.add(key, 0, RUN_COUNT_SECONDS)
        number = int(cache.incr(key))
    except Exception:
        logger.warning("The command count of a run could not be made; the call is refused.", exc_info=True)
        raise CommandRefused("function_unavailable") from None
    if number > MAX_COMMANDS_PER_RUN:
        raise CommandRefused("too_many_commands", f"A run sends at most {MAX_COMMANDS_PER_RUN} commands; this was number {number}.")
    return number


def available() -> bool:
    """True only when the signed dispatch is on and Tactical's agent and account models are importable."""
    if not OWNER_VIEW_DISPATCH_SIGNED:
        logger.warning("agent.command is switched off (fail closed).")
        return False
    try:
        from accounts.models import Role, User  # noqa: F401
        from agents.models import Agent  # noqa: F401

        return True
    except Exception:
        logger.warning("Tactical's agent models are not available.", exc_info=True)
        return False


def route_agent_id(agent_pk: int) -> str:
    """Tactical's STRING agent id for the route ``agents/{agent_id:agent}/cmd/`` (operationId agents_cmd_create) from the endpoint number. Fails closed."""
    try:
        from agents.models import Agent

        value = Agent.objects.filter(pk=agent_pk).values_list("agent_id", flat=True).first()
    except Exception:
        logger.warning("The endpoint's agent id could not be read; the call is refused.", exc_info=True)
        raise CommandRefused("bad_agents") from None
    if not isinstance(value, str) or len(value) < 21 or "/" in value:
        raise CommandRefused("bad_agents")
    return value


def interpret_reply(reply) -> tuple[str, str, bool]:
    """``(outcome, output, truncated)`` from the text the view answered with: the bare 'timeout' or 'natsdown' means the agent never answered (unreachable)."""
    if reply is None or reply in UNREACHABLE_REPLIES:
        return "unreachable", "", False
    raw = str(reply).encode("utf-8", "replace")
    return "ran", raw[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore"), len(raw) > MAX_OUTPUT_BYTES


def _service_user():
    """The dedicated Tactical service user. It is made at install or upgrade time (Core migration 0038); this function only READS it and checks it on EVERY call.
    It never creates anything (AD-50). Missing or deviating, the call is refused ``function_unavailable`` with a plain reason."""
    from accounts.models import Role, User

    role = Role.objects.filter(name=SERVICE_ROLE).first()
    user = User.objects.filter(username=SERVICE_USERNAME).first()
    if role is None or user is None:
        raise CommandRefused("function_unavailable", "The Communicator service user is not installed. Run Core's upgrade (database migration) again; nothing was sent.")
    for field in Role._meta.get_fields():
        if getattr(field, "get_internal_type", lambda: "")() == "BooleanField" and bool(getattr(role, field.name, False)) != (field.name == SERVICE_FLAG):
            raise CommandRefused("function_unavailable", "The service role holds more or less than can_send_cmd.")
    if not user.is_active or user.is_superuser or user.is_staff or getattr(user, "is_installer_user", False) or not user.block_dashboard_login \
            or user.role_id != role.pk or user.has_usable_password():
        raise CommandRefused("function_unavailable", "The service user is not the least-privilege user Core made.")
    return user


def _build_view_request(call: dict, user, match, path: str):
    """The in-process request for Tactical's view, built by the SAME builder every Tactical operation uses (``tactical_operations._build_request``: META without
    credentials, DRF forced authentication as ``user``, no token read or forwarded, ``_client_ip`` through ``_source_client_ip``). The source is the scheduler's own
    in-process call, so its address is the loopback one."""
    from types import SimpleNamespace

    from .tactical_operations import _build_request

    body = {"shell": call["shell"], "cmd": call["command"], "timeout": call["timeout"], "custom_shell": None, "run_as_user": False}
    source = SimpleNamespace(user=user, META={"SERVER_NAME": "localhost", "SERVER_PORT": "443"}, _client_ip="127.0.0.1")
    return _build_request(source, SimpleNamespace(method="POST"), path, body, match)


def _dispatch_view(match, request):
    from .tactical_operations import _dispatch

    return _dispatch(match, request)


def _check_route(path: str) -> None:
    """The same two guards every Tactical operation passes (1.17.77): the path is not a route Core owns, and the OWNER of this piece (``OWNER_MODULE``) still owns the
    rule the path lands on (``tactical_operations._recheck_route_owner``). A refusal sends nothing."""
    from types import SimpleNamespace

    from .tactical_operations import (
        TacticalOperationError,
        _forbidden_route,
        _recheck_route_owner,
    )

    try:
        if _forbidden_route([part for part in path.strip("/").split("/")]):
            raise TacticalOperationError("not found", status=404, code="tactical_operation_not_found")
        _recheck_route_owner(SimpleNamespace(module_id=OWNER_MODULE), path)
    except TacticalOperationError:
        raise CommandRefused("function_unavailable", "The send-command route is not owned by the module that owns this piece of Tactical; nothing was sent.") from None


def _send(route_agent: str, call: dict, username: str, user=None):
    """Run Tactical's own ``send_raw_cmd`` view for ``route_agent`` as the service user and return the answer text ('timeout' when the agent never answered).
    ``username`` (the owner) is for the audit rows only. Any other answer raises, and the claim stays (at most once)."""
    from django.urls import resolve

    user = user if user is not None else _service_user()
    path = f"/agents/{route_agent}/cmd/"
    _check_route(path)
    match = resolve(path)
    if getattr(match.func, "__name__", "") != "send_raw_cmd":
        raise CommandRefused("function_unavailable", "Tactical no longer serves the send-command view on this route.")
    response = _dispatch_view(match, _build_view_request(call, user, match, path))
    status = int(getattr(response, "status_code", 500))
    content = bytes(getattr(response, "content", b"") or b"")
    try:
        data = json.loads(content.decode("utf-8")) if content else None
    except ValueError:
        data = content.decode("utf-8", "replace")
    if 200 <= status < 300:
        return data if isinstance(data, str) else ("" if data is None else str(data))
    if status == 400 and isinstance(data, str) and UNREACHABLE_TEXT in data:
        return "timeout"
    raise SendFailed(status)


def _meta(definition, run, schedule_id, provenance, extra, agent_pk, call, number=0) -> dict:
    return {"run_send_number": number, "run_as": "communicator", "service_user": SERVICE_USERNAME, "owner_username": str(provenance.get("creator") or "")[:150],
        "requested_by": "scheduler", "run_id": str(run.id), "schedule_id": str(schedule_id), "owner_module": definition.module_id, "action_id": definition.id,
        "function": definition.function, "kind": "command", "agent_id": agent_pk, "command_id": call["command_id"], "template_id": call["template_id"],
        "template_hash": call["template_hash"], "shell": call["shell"],
        "timeout": call["timeout"], "command_length": len(call["command"]), **provenance, **extra,
    }


def run_one(*, definition, run, verified, owner, provenance, extra, agent_pk, call) -> dict:
    """Claim (cache, then the durable audit row), audit (strict, before), send through Tactical's own view, audit (after). Returns the result dict. The command text is never logged or audited."""
    if getattr(definition, "function", None) != "agent.command":  # the service path is this ONE row's, never another row's
        raise CommandRefused("wrong_kind")
    from . import system_actions as _sa
    from .scheduler import SchedulerTransientError

    actor = _sa._actor_for(owner)
    username = str(provenance.get("creator") or getattr(owner, "username", "") or "")
    service_user = _service_user()  # read and re-checked BEFORE the claim and the audit row: a missing or deviant user sends nothing and creates nothing
    route_agent = route_agent_id(agent_pk)  # before the claim: a number with no string id claims and sends nothing
    _check_route(f"/agents/{route_agent}/cmd/")  # 1.17.79: before the count and the claim, so a refused route burns no command_id (_send checks again)
    number = count_run(run.id)  # the per-run cap, before the claim
    _RUN.run_id = str(run.id)
    try:
        claimed = claim(agent_pk, call["command_id"])
    finally:
        _RUN.run_id = None
    if not claimed:
        raise CommandRefused("duplicate_command")
    _RECORDED.get(str(run.id), set()).add((agent_pk, call["command_id"]))
    try:
        _sa._audit().record(
            actor=actor, module_id="core", action="run", object_type="system_action", object_id=definition.id,
            message=f"Run as the communicator module for {username[:100] or 'unknown'}: a scheduled command is being sent to one endpoint through Tactical.", metadata=_meta(definition, run, verified.schedule_id, provenance, extra, agent_pk, call, number),
            strict=True,
        )
    except Exception:
        logger.exception("The audit row of a command could not be written; nothing is sent.")
        release(agent_pk, call["command_id"])
        raise SchedulerTransientError("The audit row could not be written, so nothing was sent.") from None
    outcome, output, truncated = "ran", "", False
    status, reason = None, ""
    try:
        outcome, output, truncated = interpret_reply(_send(route_agent, call, username, service_user))
    except Exception as exc:
        logger.exception("The command could not be sent; Core never sends it again under this command_id.")  # the claim stays: at most once
        outcome = "failed"
        if isinstance(exc, SendFailed):
            status, reason = exc.status, exc.reason
        elif isinstance(exc, CommandRefused):
            reason = str(exc.reason or "")[:60]  # a Core code, never the detail text
        else:
            reason = failure_reason(None)
        logger.info("Scheduled command to endpoint %s failed: status=%s reason=%s (run %s).", agent_pk, status, reason, run.id)  # no command, no output, no token
    try:
        metadata = _meta(definition, run, verified.schedule_id, provenance, extra, agent_pk, call, number)
        metadata.update(phase="closed", outcome=outcome, output_bytes=len(output.encode("utf-8")), truncated=truncated)
        _sa._audit().record(
            actor=actor, module_id="core", action=CLOSING_ACTION, object_type="system_action", object_id=definition.id,
            message=f"A scheduled command to one endpoint ended: {outcome}.", metadata=metadata, strict=True,
        )
    except Exception:
        logger.exception("The closing audit row of a command could not be written; the 'before' row holds the record.")
    result = {"outcome": outcome, "agent_id": agent_pk, "command_id": call["command_id"], "output": output, "truncated": truncated,
              "message": "Sent through Tactical." if outcome == "ran" else "The endpoint did not answer in time." if outcome == "unreachable" else "The command could not be sent."}
    if outcome == "failed":  # 1.17.82, additive: the HTTP status of Tactical's view (None when it raised or Core refused the route) and a short code
        result.update(status=status, reason=reason)
    return result
