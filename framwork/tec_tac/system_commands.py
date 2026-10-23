"""System commands: the third kind of Tactical work Core does for a verified module (core.system_actions 1.5.0, Core 1.17.75, AD-45, AD-49).

The first kind starts a Tactical Celery task; the second writes one fixed column. A command has no task and no column: Tactical's own route
``agents/views.py send_raw_cmd`` runs one command on one endpoint and waits for the text. Core holds ONE fixed row for it, ``agent.command``. The module that owns
the piece of Tactical (Remote Background) registers it; Core defines and enforces everything else, so no module can widen it.

AD-49 (Johan, 23 October 2026): Core never accepts a command string from a caller. It runs only FIXED TEMPLATES, hardcoded in the signed code of the owning
module (Communicator), so they change only with a module update. A call is ``{agent_id, command_id, template_id, params}``; Core renders the final command itself
from the template and the typed, validated params.

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
      (Tactical's Redis). A cache that cannot be reached refuses the call (fail closed). A claim that expires or is evicted lets the same id run again after
      24 hours; that is the recorded limit.
    * The strict audit row is written BEFORE the send and a closing row after. Neither holds the command text or the output: they hold the run, the schedule,
      the endpoint, the command_id, the template id and hash, the shell, the timeout and the lengths.
    * The output text is cut at MAX_OUTPUT_BYTES (1 MiB) and the result says so.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
from pathlib import Path

logger = logging.getLogger("tec_tac.system_actions")

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


class CommandRefused(Exception):
    """The call is refused. ``reason`` is a code of ``system_actions.REASONS``."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


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


def register_command_template(module_id, template_id, *, shell, text=None, file=None, slots=None, timeout=30) -> dict:
    """Register one fixed command template. Call it from ``AppConfig.ready()`` of a module on REGISTRANTS. Memory only.

    ``text`` is the fixed command with ``{slot}`` placeholders; ``file`` is the absolute path of a file shipped in the module (its content is the template,
    read and hashed again at every run). Exactly one of the two. ``slots`` maps a slot name to ``{"type": "int", "min", "max"}``,
    ``{"type": "text", "max", "chars"}`` or ``{"type": "enum", "values"}``. ``template_id`` is ``<module_id>.<name>``. Returns ``{id, hash}``.
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
        clean = _clean_slots(slots)
        record = {"id": template_id, "module_id": module_id, "shell": shell, "slots": clean, "timeout": timeout, "text": None, "file": None}
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
                if previous["hash"] == record["hash"] and previous["file"] == record["file"] and previous["module_id"] == module_id:
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
    """What the person confirmed: ``allowed_templates`` (1 to 16 registered ids), their ``template_hashes`` (as Core showed them) and ``max_timeout`` (1 to 60)."""
    if not isinstance(values, dict) or not {"allowed_templates", "template_hashes"} <= set(values) <= {"allowed_templates", "template_hashes", "max_timeout"}:
        raise ValueError("a command run takes allowed_templates, template_hashes and max_timeout.")
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
    return {"allowed_templates": sorted(ids), "template_hashes": {i: hashes[i] for i in sorted(ids)}, "max_timeout": limit}


def audit_extra(cleaned) -> dict:
    return {"allowed_templates": list(cleaned["allowed_templates"]), "template_hashes": dict(cleaned["template_hashes"]), "max_timeout": cleaned["max_timeout"]}


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


def claim(agent_id: int, command_id: str) -> bool:
    """True once per (endpoint, command_id) across workers. A cache that raises refuses the call (fail closed)."""
    from django.core.cache import cache

    try:
        return bool(cache.add(_claim_key(None, agent_id, command_id), 1, CLAIM_SECONDS))
    except Exception:
        logger.warning("The command claim could not be made; the call is refused.", exc_info=True)
        raise CommandRefused("function_unavailable") from None


def release(agent_id: int, command_id: str) -> None:
    from django.core.cache import cache

    try:
        cache.delete(_claim_key(None, agent_id, command_id))
    except Exception:
        logger.warning("A command claim could not be released.", exc_info=True)


def available() -> bool:
    try:
        from agents.models import Agent, AgentHistory  # noqa: F401
        from tacticalrmm.constants import AgentHistoryType  # noqa: F401

        return True
    except Exception:
        logger.warning("Tactical's agent models are not available.", exc_info=True)
        return False


def _send(agent_pk: int, call: dict, username: str):
    """Tactical's own send_raw_cmd steps: a history row, then ``nats_cmd`` rawcmd and wait. Returns the reply or the text 'timeout'."""
    from agents.models import Agent, AgentHistory
    from tacticalrmm.constants import AgentHistoryType

    agent = Agent.objects.get(pk=agent_pk)
    hist = AgentHistory.objects.create(agent=agent, type=AgentHistoryType.CMD_RUN, command=call["command"], username=username[:50])
    data = {"func": "rawcmd", "timeout": call["timeout"], "payload": {"command": call["command"], "shell": call["shell"]}, "run_as_user": False, "id": hist.pk}
    return asyncio.run(agent.nats_cmd(data, timeout=call["timeout"] + 2))


def _meta(definition, run, schedule_id, provenance, extra, agent_pk, call) -> dict:
    return {
        "requested_by": "scheduler", "run_id": str(run.id), "schedule_id": str(schedule_id), "owner_module": definition.module_id, "action_id": definition.id,
        "function": definition.function, "kind": "command", "agent_id": agent_pk, "command_id": call["command_id"], "template_id": call["template_id"],
        "template_hash": call["template_hash"], "shell": call["shell"],
        "timeout": call["timeout"], "command_length": len(call["command"]), **provenance, **extra,
    }


def run_one(*, definition, run, verified, owner, provenance, extra, agent_pk, call) -> dict:
    """Claim, audit (strict, before), send, audit (after). Returns the result dict. The command text is never logged or audited."""
    from . import system_actions as _sa
    from .scheduler import SchedulerTransientError

    actor = _sa._actor_for(owner)
    if not claim(agent_pk, call["command_id"]):
        raise CommandRefused("duplicate_command")
    try:
        _sa._audit().record(
            actor=actor, module_id="core", action="run", object_type="system_action", object_id=definition.id,
            message="A scheduled command is being sent to one endpoint through Tactical.", metadata=_meta(definition, run, verified.schedule_id, provenance, extra, agent_pk, call),
            strict=True,
        )
    except Exception:
        logger.exception("The audit row of a command could not be written; nothing is sent.")
        release(agent_pk, call["command_id"])
        raise SchedulerTransientError("The audit row could not be written, so nothing was sent.") from None
    username = str(provenance.get("creator") or getattr(owner, "username", "") or "")
    outcome, output, truncated = "ran", "", False
    try:
        reply = _send(agent_pk, call, username)
        if reply == "timeout" or reply is None:
            outcome = "unreachable"
        else:
            raw = str(reply).encode("utf-8", "replace")
            truncated = len(raw) > MAX_OUTPUT_BYTES
            output = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
    except Exception:
        logger.exception("The command could not be sent; Core never sends it again under this command_id.")  # the claim stays: at most once
        outcome = "failed"
    try:
        metadata = _meta(definition, run, verified.schedule_id, provenance, extra, agent_pk, call)
        metadata.update(phase="closed", outcome=outcome, output_bytes=len(output.encode("utf-8")), truncated=truncated)
        _sa._audit().record(
            actor=actor, module_id="core", action=CLOSING_ACTION, object_type="system_action", object_id=definition.id,
            message=f"A scheduled command to one endpoint ended: {outcome}.", metadata=metadata, strict=True,
        )
    except Exception:
        logger.exception("The closing audit row of a command could not be written; the 'before' row holds the record.")
    return {"outcome": outcome, "agent_id": agent_pk, "command_id": call["command_id"], "output": output, "truncated": truncated,
            "message": "Sent through Tactical." if outcome == "ran" else "The endpoint did not answer in time." if outcome == "unreachable" else "The command could not be sent."}
