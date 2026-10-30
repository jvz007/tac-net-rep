#!/usr/bin/env python3
"""1.17.94 regression: metadata and docs name endpoint-comms and nats-comms as owners; the contract stays 1.0.0; the 1.17.94 release notes say so."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must = H.et, H.must

meta = et.endpoint_transport_contract_metadata()
must(meta["version"] == "1.0.0" and et.CAPABILITY_VERSION == "1.0.0", "the contract version does not change")
must(sorted(meta["operations"]) == ["presence", "register_owner", "request", "send_many"], "operations unchanged")
must("endpoint-comms" in meta["owner"] and "nats-comms" in meta["owner"], "metadata owner names both ids")
doc = (H.ROOT / "docs" / "endpoint-transport.md").read_text(encoding="utf-8")
must("`endpoint-comms`" in doc and "`nats-comms`" in doc and "until the dev server has moved" in doc, "docs name both ids")
caps = (H.ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8")
must("`endpoint-comms`" in caps, "capabilities doc")
contracts = (H.ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must(contracts.count("nats-comms is accepted until the dev server has moved to endpoint-comms") >= 4, "the four operation purposes")

version = (H.ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(json.loads((H.ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"] == version, "package version")
notes = (H.ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.94.md").read_text(encoding="utf-8")  # the 1.17.94 notes moved to docs/releases in 1.17.95
must("## Module-facing change" in notes and "endpoint-comms" in notes and "nats-comms" in notes, "release notes")
print("PASS endpoint transport docs 1.17.94")
