#!/usr/bin/env python3
"""1.17.14: what the exported public contract says (UI 0.12.91 export items 1 and 2; Johan's CQ34 to CQ40 wording).

Wording only, no behaviour change. contracts.py needs Django, so the literal tables (BROWSER_CONTRACTS, RULES, HTTP_CONTRACT_DETAILS,
CORE_CONTRACTS) are read with ``ast`` and the real ``render_markdown`` is run on a catalogue built from them, the way
tests/browser-contract-catalog-1.15.170.py does it. Extends tests/browser-contract-tactical-operation-1.17.12.py.

Item 1: the ui.authenticated.tactical-operation row lists the five options (params, body, query, file, signal), the 16-name and
512-character query limits, the multipart part names, the Core and UI versions that need it, and the size sentence (10 MiB by default,
a system setting since 1.17.14). It no longer says "options accepts only params, body and signal".
Item 2: one development rule names the modules/v2 fields, request fields, refusal codes and job fields, says which were added in
1.17.14, and says replacement_has_dependants and the hand_back_blocked refusal were removed. The route entries carry the same fields.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
source = PATH.read_text(encoding="utf-8")
tree = ast.parse(source)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
RULES = literal("RULES")
DETAILS = literal("HTTP_CONTRACT_DETAILS")
CORE = literal("CORE_CONTRACTS")
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)
catalog = {"framework_version": "1.17.14", "generated_at": "2026-10-09T00:00:00+00:00", "rules": list(RULES), "core": [dict(r, signature="()") for r in CORE],
           "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [], "scheduler_actions": [], "permissions": [],
           "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)

# ------------------------------------------------------------------------------------------------ item 1: the browser row
row = next(r for r in BROWSER if r["id"] == "ui.authenticated.tactical-operation")
text = " ".join(row["details"])
must("options accepts only params, body and signal" not in md and "accepts only params, body and signal" not in text, "the old option list is gone")
must("The options are params, body, query, file and signal" in md, "the five options")
for option in ("params", "body", "query", "file", "signal"):
    must(option in "The options are params, body, query, file and signal", option)
for needle in (
    "at most 16 whitelisted names", "at most 512 characters", "a flat plain object", "a File, or a Blob with a non-empty name", "multipart/form-data",
    "the text parts params, body and (only when given) query", "exactly one file part", "named after the file", "carries the same filename",
    "A file named params, body or query is refused in the browser", "There is no auth option", "so there is no audit option either", "Core 1.17.13 and UI 0.12.91",
    "query_field_not_allowed", "invalid_query", "upload_too_large", "pass through as error.code", "10 MiB by default", "a system setting since Core 1.17.14",
    "tactical_operation_upload_max_mib", "{file_name}", "not covered yet", "A web-server body limit still applies",
):
    must(needle in md, f"the exported row lacks {needle!r}")
# the facts agree with the UI documentation the row was written from (read only)
ui_doc = ROOT.parent / "ui" / "docs" / "module-runtime-api.md"
if ui_doc.is_file():
    doc = ui_doc.read_text(encoding="utf-8")
    for fact in ("at most 16 names", "512 characters", "form.append(file.name, file, file.name)", "0.12.91"):
        must(fact in doc, f"the UI documentation no longer says {fact!r}: re-check the row")
# the older text the row keeps is untouched
for kept in ("From UI 0.12.89", "not a sandbox", "A path hidden behind tab, CR, LF or other control characters is a finding held for the UI."):
    must(kept in text, kept)

# ------------------------------------------------------------------------------------------------ item 2: the development rule
rule = next((r for r in RULES if r.startswith("Module switch fields")), None)
must(rule is not None and rule in md, "the rule is in the export")
for needle in (
    "will_disable", "will_enable", "second_confirmation_required", "replacement_dependants", "hand_back_unavailable", "hand_back_confirmation_required",
    "disable_replaced", "confirm_replacement_switch", "confirm_without_hand_back",
    "replacement_confirmation_required", "replacement_second_confirmation_required", "replacement_hand_back_confirmation_required",
    "disabled_modules", "enabled_modules", "reconciled_modules", "hand_back_skipped",
):
    must(needle in rule, f"the rule lacks {needle!r}")
for added in ("replacement_dependants", "hand_back_unavailable", "hand_back_confirmation_required", "confirm_without_hand_back",
              "replacement_hand_back_confirmation_required", "hand_back_skipped"):
    must(f"since 1.17.14, {added}" in rule or f"{added}" in rule.split("since 1.17.14")[1], f"{added} is marked as added in 1.17.14")
must("replacement_has_dependants and the hand_back_blocked refusal were removed in 1.17.14" in rule, "the removal is stated")
must("now warns" in rule and "refused" in rule, "the 1.17.12 wording 'refused' is replaced by a warning")
# no live mention of the removed refusals anywhere else in the export
for stale in ("is refused when an enabled module depends on the replacement", "Disabling is refused, with no code"):
    must(stale not in md, f"stale wording: {stale!r}")
for line in md.splitlines():
    for removed in ("replacement_has_dependants", "hand_back_blocked"):
        if removed in line:
            must("removed" in line or "gone" in line or "no longer" in line or "Until 1.17.14" in line or "1.17.14" in line, f"{removed} is mentioned as live: {line[:160]}")

# the route entries carry the same fields (the field tables are not in the export, but they are the contract the export points to)
catalogue = DETAILS["/api/tfd/modules/v2/"]["response"]
for field in ("modules[].will_disable", "modules[].will_enable", "modules[].second_confirmation_required", "modules[].replacement_dependants",
              "modules[].hand_back_unavailable", "modules[].hand_back_confirmation_required"):
    must(field in catalogue, field)
state = DETAILS["/api/tfd/modules/v2/<str:plugin_id>/state/"]["POST"]
for field in ("disable_replaced", "confirm_replacement_switch", "confirm_without_hand_back"):
    must(field in state["request"], field)
errors = state["errors"]["400"]
for code in ("replacement_confirmation_required", "replacement_second_confirmation_required", "replacement_hand_back_confirmation_required"):
    must(code in errors, code)
must("dependants" in errors and "hand_back_unavailable" in errors and "will_enable" in errors, "the refusal payloads")
notes = " ".join(state["notes"])
must("hand_back_skipped" in notes and "confirm_without_hand_back" in notes and "A deliberate disable always hands back" in notes, "the 1.17.14 note")
must("A warning" in catalogue["modules[].replacement_dependants"] and "never a refusal" in catalogue["modules[].replacement_dependants"], "dependants are a warning")
must("CAN come back" in catalogue["modules[].will_enable"], "will_enable lists only what can come back")

# ------------------------------------------------------------------------------------------------ the rest of 1.17.14 that reaches the export
core = {r["name"]: r for r in CORE}
purpose = core["register_tactical_operation"]["purpose"]
must("hard ceiling 10 MiB" not in purpose and "tactical_operation_upload_max_mib" in purpose and "25 MiB" in purpose, "the upload ceiling is a setting")
must("source before:<field> (field listed in before.fields" not in purpose and "removed in 1.17.14" in purpose and "core.tactical_operations 1.2.0" in purpose, "before: scope removal")
must("get_tactical_upload_max_bytes" in core and "never raises" in core["get_tactical_upload_max_bytes"]["purpose"].lower(), "the getter is listed")
settings = DETAILS["/api/tfd/system/runtime-settings/"]
must("tactical_operation_upload_max_mib" in settings["GET"]["response"] and "tactical_operation_upload_max_mib" in settings["PATCH"]["request"], "runtime settings entry")
must("Superuser only" in settings["PATCH"]["request"]["tactical_operation_upload_max_mib"], "permission split")
must("Notices Core creates itself" in " ".join(RULES) and "module-job-failed:<job id>" in " ".join(RULES), "the notice rule")
for category_text in (md,):
    must("install only since 1.17.14" in category_text or "install-only since 1.17.14" in category_text, "the category refusal is install-only")
    must("Core refuses to install or enable a test module" not in category_text, "stale category text")

print("[TEST] PASS contract export 1.17.14")
