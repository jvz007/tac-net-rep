#!/usr/bin/env python3
"""1.17.92 regression: the documentation and the contract metadata agree with the code.

The doc and the metadata both name close code 1013, the new ceilings (10 per address as AD-54 signs, 10 per agent id, no refusal row budget by default) and the pass target;
the contract version is still 1.0.0 and matches the CORE_CONTRACTS rows; the numbers in the text are the constants in the code.
"""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must = H.et, H.must

doc = (H.ROOT / "docs" / "endpoint-transport.md").read_text(encoding="utf-8")
meta = et.endpoint_transport_contract_metadata()
text = json.dumps(meta)

must(meta["version"] == "1.0.0" and et.CAPABILITY_VERSION == "1.0.0", "the contract version does not change")
must("core.endpoint_transport` 1.0.0" in doc and "stays at 1.0.0" in doc, "the doc says the version stays")
must(sorted(meta["operations"]) == ["presence", "register_owner", "request", "send_many"], "operations unchanged")

for label, source in (("doc", doc), ("metadata", text)):
    must("1013" in source, label + " names 1013")
    must(("10 a minute" in source or "10 failed" in source), label + " names the ceilings")
    must("agent id" in source, label + " names the per-agent limit")
must("1013" in meta["close_codes"] and "1013" in doc.split("## Close codes")[1].split("## Audit")[0], "1013 is in both close-code tables")
must(et.CLOSE_RETRY_LATER == 1013 and et.FAILURES_PER_ADDRESS_PER_MINUTE == 10 and et.FAILURES_PER_AGENT_PER_MINUTE == 10
     and et.REFUSAL_ROWS_PER_MINUTE == 0, "the constants are the documented numbers")
must("10 a minute" in doc and "/64" in doc, "doc numbers")
must("10 failed attempts" in meta["close_codes"]["4429"] and "10 failed checks" in meta["close_codes"]["4429"] and "/64" in meta["close_codes"]["4429"], "4429 text")

# the pass target figures
for figure in ("2 000 agents", "60 s ping", "ramp 20 ms", "p95 under 2 s", "502"):
    must(figure in doc, "doc pass target: " + figure)
must("2 000 agent" in meta["load_target"] and "60 s" in meta["load_target"] and "20 ms" in meta["load_target"] and "p95 under 2 s" in meta["load_target"], "metadata pass target")
for figure in ("1968 of 2000", "10.6 s", "6.6 s", "164", "42", "1129", "32", "67%", "222 to 240 MB"):
    must(figure in doc, "load test number: " + figure)
must("1.17.92" in meta["added_in"] and "1013" in meta["added_in"], "the added_in line")

# the metadata matches the CORE_CONTRACTS rows
tree = ast.parse((H.APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
mine = [r for r in rows if r["area"] == "endpoint-transport"]
must(len(mine) == 4 and all("1.0.0" in r["purpose"] for r in mine), "CORE_CONTRACTS rows still say 1.0.0")

# the release files
version = (H.ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(version == "1.17.92" and json.loads((H.ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"] == version, "version")
notes = (H.ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
must("## Module-facing change" in notes and "1013" in notes and "dev02" in notes and "502" in notes, "release notes")
print("PASS endpoint transport docs 1.17.92")
