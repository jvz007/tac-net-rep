#!/usr/bin/env python3
"""1.18.46 regression: docs/probe-transport.md names every operation, close code, limit constant, refusal code, disconnect reason and audit
action in the code, with the number the code holds; docs/capabilities.md has the section; the docs carry no forbidden filler."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, must = H.pt, H.must
ROOT = H.ROOT

doc = (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
caps = (ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
meta = pt.probe_transport_contract_metadata()

must(doc.startswith("# Network Probe transport (Core 1.18.46)"), "the title names the release")
for operation in meta["operations"]:
    must(f"`{operation}" in doc, "the docs name " + operation)
for code in meta["close_codes"]:
    must(re.search(r"\| " + code + r" \|", doc), "the close-code table has " + code)
for constant in ("MAX_FRAME_BYTES", "MAX_FRAMES_PER_SECOND", "MAX_BAD_FRAMES", "PING_SECONDS", "MAX_UNANSWERED_PINGS", "PRESENCE_SECONDS", "RECHECK_SECONDS",
                 "RECHECK_JITTER_SECONDS", "RECHECK_GRACE_SECONDS", "FAILURES_PER_ADDRESS_PER_MINUTE", "FAILURES_PER_PROBE_PER_MINUTE"):
    value = getattr(pt, constant)
    must(f"`{constant}`" in doc, "the docs name " + constant)
    shown = "16 KiB" if constant == "MAX_FRAME_BYTES" else str(value)
    must(re.search(re.escape(f"`{constant}`") + r"[^.\n]*?\(?" + re.escape(shown), doc), f"the docs give {constant} as {shown}")
for text in pt.REFUSAL_CODES + pt.DISCONNECT_REASONS:
    must(f"`{text}`" in doc, "the docs name " + text)
for reason in ("wrong_scheme", "malformed_header"):
    must(f"`{reason}`" in doc, reason)
for action in ("custom:probe-connect", "custom:probe-disconnect", "custom:probe-refused"):
    must(f"`{action}`" in doc, action)
for needle in ("/ws/tfd/network-probe/", "Probe <probe_id>.<key>", "networkprobe", "probe-transport", "AD-54", "C2", "never the key", "authenticate(probe_id, key)",
               "1 second", "60 seconds", "4401"):
    must(needle in doc, needle)
must("later release" in doc and "not in this one" in doc, "C2 is said to be a later release")
must("never cross" in doc, "credentials never cross")

section = caps[caps.index("## Core probe transport"):caps.index("## Core agent downloads")]
must("`core.probe_transport` 1.0.0" in section and "docs/probe-transport.md" in section and ">=1.18.46" in section, "the capabilities section")
for operation in meta["operations"]:
    must(f"`{operation}`" in section, "the capabilities section names " + operation)
must("\r\n" in caps and caps.count("\n") == caps.count("\r\n"), "capabilities.md stays CRLF")

for label, text in (("probe-transport.md", doc), ("capabilities section", section)):
    lowered = text.lower()
    for forbidden in ("kindly", "don't hesitate", "do not hesitate", "ethnocentric", "please be advised"):
        must(forbidden not in lowered, f"{label} has {forbidden!r}")
print("PASS probe transport docs 1.18.46")
