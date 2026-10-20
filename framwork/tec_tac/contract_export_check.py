"""Compare an exported public contract with what the code publishes (Core 1.17.66; the gate that the 1.17.65 review held as a Low).

Pure Python: no Django, so a test can run it on small fixture files. ``check_export_text`` reads the exported Markdown (the file the contract
route writes) and reports every difference as one plain line. The management command ``tec_tac_check_contract_export`` feeds it the live
catalog on the dev server; ``tests/contract-export-gate-1.17.66.py`` feeds it the source on this PC when an export for this version exists.
"""
from __future__ import annotations

import json
import re

STALE_PHRASES = ("inactive until the amended", "registered with unattended=True")
CAPABILITY_ID = "core.system_actions"
_VERSION_RE = re.compile(r"^Framework: \*\*([^*]+)\*\*", re.MULTILINE)


def export_version(text: str) -> str | None:
    match = _VERSION_RE.search(text)
    return match.group(1).strip() if match else None


def capability_metadata(text: str, capability_id: str = CAPABILITY_ID) -> dict | None:
    """The published metadata JSON of one capability in the export, or None when the section or the block is missing."""
    marker = f"### `{capability_id}`"
    start = text.find(marker)
    if start < 0:
        return None
    block = text.find("```json", start)
    next_section = text.find("\n### ", start + len(marker))
    if block < 0 or (0 <= next_section < block):
        return None
    begin = text.index("\n", block) + 1
    end = text.find("```", begin)
    if end < 0:
        return None
    try:
        return json.loads(text[begin:end])
    except ValueError:
        return None


def _differing_keys(exported: dict, live: dict) -> list[str]:
    live = json.loads(json.dumps(live, sort_keys=True, default=str))
    return sorted(key for key in set(exported) | set(live) if exported.get(key, "<missing>") != live.get(key, "<missing>"))


def check_export_text(text: str, *, rows, metadata: dict, version: str | None = None, stale_sources: dict | None = None) -> list[str]:
    """Every difference between the exported ``text`` and the code, as plain lines (empty when they agree).

    ``rows`` is the CORE_CONTRACTS tuple (each row names ``import_path``, ``name`` and ``purpose``); ``metadata`` is
    ``system_actions_contract_metadata()``; ``stale_sources`` maps a label to text that must not carry a stale phrase."""
    problems: list[str] = []
    text = text.replace("\r\n", "\n")
    if version is not None and export_version(text) != version:
        problems.append(f"the export is for Core {export_version(text)}, not {version}")
    exported = capability_metadata(text)
    if exported is None:
        problems.append(f"the export has no published metadata for {CAPABILITY_ID}")
    else:
        for key in _differing_keys(exported, metadata):
            problems.append(f"{CAPABILITY_ID} metadata field '{key}' differs from the code")
    lines = text.split("\n")
    for row in rows:
        head = f"| `{row['import_path']}` | `{row['name']}"
        tail = f" | {row['purpose']} |"
        if not any(line.startswith(head) and line.endswith(tail) for line in lines):
            problems.append(f"contract row {row['import_path']}.{row['name']} is missing from the export or its purpose text differs")
    sources = {"the export": text, **(stale_sources or {})}
    for label, body in sources.items():
        for phrase in STALE_PHRASES:
            if phrase in body:
                problems.append(f"{label} still carries the stale wording '{phrase}'")
    return problems


def diff_against_live(exported_text: str, live_text: str, *, limit: int = 10) -> list[str]:
    """A line diff of the export against the Markdown the live catalog renders now. The 'Generated' line is ignored."""
    def clean(value: str) -> list[str]:
        return [line.rstrip() for line in value.replace("\r\n", "\n").strip().split("\n") if not line.startswith("Generated: ")]

    left, right = clean(exported_text), clean(live_text)
    if left == right:
        return []
    problems = []
    for number, (a, b) in enumerate(zip(left, right), start=1):
        if a != b:
            problems.append(f"line {number} differs: export {a[:90]!r} against live {b[:90]!r}")
            if len(problems) >= limit:
                break
    if len(left) != len(right):
        problems.append(f"the export has {len(left)} lines and the live catalog renders {len(right)}")
    return problems or ["the export differs from the live catalog"]
