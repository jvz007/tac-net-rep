#!/usr/bin/env python3
"""1.17.58 regression: the licence status read, GET /api/tfd/system/licensing/ (Johan, 19 October 2026).

Covered: the exact shape and key allow-list; a missing, disabled, unhealthy, unreadable or provisional Licensing provider reports
'licensing_unavailable' and never 'licensed' (Johan's Q7); a provider health dict carrying a licence key, token, fingerprint and private key
never reaches the answer; an unknown licence state reads 'unknown'; 'would block' lists the stub installed modules the gate refuses, honours the
cap of 50 and counts only modules that declare licensing.required (the real manifest reader runs against a folder of manifests); the mode
is ignored when counting; days_left is null; a person with neither superuser nor runtime-settings permission gets 403 and a read writes no
audit row; Core makes no network call.

Django and the real registry of a server are dev-server work (tests/licensing-mode-runtime-1.17.58.py).
"""
from __future__ import annotations

import http.client
import json
import socket
import sys
import tempfile
import urllib.request
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
ml, v2, lv, caps = H.ml, H.v2, H.lv, H.caps
User, PermissionDenied = H.User, H.PermissionDenied
candidate = harness.candidate
MARKERS = ("MARKER-KEY-5521", "MARKER-TOKEN-5522", "MARKER-FINGERPRINT-5523", "MARKER-PRIVATE-5524", "MARKER-REASON-5525", "MARKER-DETAIL-5526")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def clean(label, answer):
    text = json.dumps(answer, default=str) + "\n".join(H.log) + json.dumps(H.audits, default=str)
    for marker in MARKERS:
        must(marker not in text, (label, marker))


SECRET_HEALTH = {"healthy": True, "license_key": MARKERS[0], "token": MARKERS[1], "fingerprint": MARKERS[2], "private_key": MARKERS[3],
                 "server_license": {"state": "licensed", "key": MARKERS[0]}, "states": sorted(ml.LICENCE_STATES)}


def provider(**over):
    """A public capability status of licensing.entitlements."""
    status = {"id": "licensing.entitlements", "available": True, "state": "available", "module_id": "licensing", "capability_version": "1.3.0",
              "metadata": {"module_licensing": "provisional"}, "health": {**SECRET_HEALTH, "module_licensing": "provisional", "license_state": "provisional"}}
    status.update(over)
    return status


def set_provider(value):
    if isinstance(value, Exception):
        def boom(*a, **k):
            raise value
        caps.capability_status = boom
    else:
        caps.capability_status = lambda *a, **k: value


class Unlicensed:
    def check_entitlement(self, *, product, module_id, module_version):
        return {"licensed": False, "reason": MARKERS[4], "details": {"license_key": MARKERS[0]}, "token": MARKERS[1]}


class Licensed:
    def check_entitlement(self, *, product, module_id, module_version):
        return {"licensed": True}


def gate_world(provider_class=Unlicensed):
    v2.capability_status = lambda *a, **k: {"available": True, "capability_version": "1.3.0", "module_id": "licensing", "state": "available"}
    v2.get_capability = lambda *a, **k: provider_class()


def installed(*items):
    ml._installed_licensed_candidates = lambda: list(items)


REAL_INSTALLED = ml._installed_licensed_candidates
H.reset()
gate_world()
installed(candidate("reportmanager"))

# (1) the shape and the allow-list
set_provider(provider())
answer = lv.LicensingStatusView().get(SimpleNamespace(user=User("root", superuser=True))).data
must(set(answer) == {"mode", "enforcing", "licence", "would_block", "grace", "never_blocked", "revoked_effect"}, set(answer))
must(set(answer["mode"]) == {"value", "source", "choices", "default"} and answer["mode"] == {"value": "log-only", "source": "default", "choices": ["off", "log-only", "enforce"], "default": "log-only"}, answer["mode"])
must(answer["enforcing"] is False, "log-only does not enforce")
must(set(answer["licence"]) == {"state", "module_licensing", "reason"}, answer["licence"])
must(set(answer["would_block"]) == {"count", "modules", "limit"} and answer["would_block"]["limit"] == 50, answer["would_block"])
must(all(set(row) == {"module_id", "version", "state", "reason"} for row in answer["would_block"]["modules"]), answer["would_block"])
must(answer["grace"] == {"window_days": 7, "days_left": None, "reason": ml.GRACE_REASON}, answer["grace"])
must(answer["never_blocked"] == ["sign-in", "Tactical operations", "rollback", "security updates"], answer["never_blocked"])
must("only when enforcement is on" in answer["revoked_effect"] and "not active" in answer["revoked_effect"], answer["revoked_effect"])
clean("shape", answer)
print("       the answer has exactly the allow-listed keys and the binding rules in plain words")

# (2) a missing, disabled, unhealthy, unreadable or provisional provider: licensing_unavailable, never licensed
for label, value in (
    ("unreadable", RuntimeError(MARKERS[5])),
    ("missing", provider(available=False, state="capability-unavailable", reason=MARKERS[4], health={})),
    ("disabled", provider(available=False, state="disabled", reason=MARKERS[4])),
    ("unhealthy", provider(available=False, state="unhealthy", reason=MARKERS[4])),
    ("reentrant", provider(available=False, state="health-reentrant", reason=MARKERS[4])),
    ("provisional", provider()),
    ("provisional with a licensed state", provider(health={**SECRET_HEALTH, "module_licensing": "provisional", "license_state": "licensed"})),
    ("enforced but still provisional state", provider(health={**SECRET_HEALTH, "module_licensing": "enforced", "license_state": "provisional"})),
    ("no health keys, registered metadata provisional", provider(health={"healthy": True})),
    ("nothing at all", provider(health={}, metadata={})),
    ("garbage", {"available": True, "health": "text", "metadata": ["x"]}),
    ("not a dict", None),
):
    set_provider(value)
    licence = ml.build_licensing_status()["licence"]
    must(licence["state"] == "licensing_unavailable" and licence["state"] != "licensed", (label, licence))
    must(isinstance(licence["reason"], str) and MARKERS[4] not in licence["reason"], (label, licence))
    clean(label, licence)
must(ml.build_licensing_status()["licence"]["module_licensing"] == "unknown", "module_licensing unknown for garbage")
set_provider(provider())
must(ml.build_licensing_status()["licence"]["module_licensing"] == "provisional", "provisional is named")
print("       a missing, disabled, unhealthy, unreadable or provisional provider reports licensing_unavailable, never licensed")

# (3) enforced provider: only the allow-listed names come through
for state in sorted(ml.LICENCE_STATES - {"provisional"}):
    set_provider(provider(health={**SECRET_HEALTH, "module_licensing": "enforced", "license_state": state}))
    licence = ml.build_licensing_status()["licence"]
    must(licence == {"state": state, "module_licensing": "enforced", "reason": None}, (state, licence))
for odd in ("platinum", "LICENSED", "", None, 5, ["licensed"], {"state": "licensed"}, MARKERS[0]):
    set_provider(provider(health={**SECRET_HEALTH, "module_licensing": "enforced", "license_state": odd}))
    licence = ml.build_licensing_status()["licence"]
    must(licence["state"] == "unknown", (odd, licence))
    clean("unknown state", licence)
set_provider(provider(health={**SECRET_HEALTH, "module_licensing": "forced", "license_state": "licensed"}))
must(ml.build_licensing_status()["licence"]["state"] == "licensing_unavailable", "an unknown module_licensing value is not enforcement")
print("       an enforced provider's state is read only from Core's own list of names; anything else is unknown")

# (4) would block: the stub installed modules that the gate refuses
set_provider(provider())
gate_world(Unlicensed)
installed(candidate("reportmanager"), candidate("other", "2.0.0", product="other"))
blocked = ml.build_licensing_status()["would_block"]
must(blocked["count"] == 2 and [row["module_id"] for row in blocked["modules"]] == ["reportmanager", "other"], blocked)
must(blocked["modules"][0] == {"module_id": "reportmanager", "version": "1.0.0", "state": "unlicensed", "reason": "Product 'reportmanager' is not licensed."}, blocked["modules"][0])
clean("would block", blocked)
gate_world(Licensed)
must(ml.build_licensing_status()["would_block"] == {"count": 0, "modules": [], "limit": 50}, "licensed modules are not listed")
# a missing provider counts every licensed module as would-block, with the code, never the provider's text
gate_world(Unlicensed)
v2.capability_status = lambda *a, **k: {"available": False, "state": "unhealthy", "reason": MARKERS[4], "capability_version": None, "module_id": "licensing"}
row = ml.build_licensing_status()["would_block"]["modules"][0]
must(row["state"] == "unhealthy" and row["reason"] == "The licensing provider reports that it is not healthy.", row)
v2.capability_status = lambda *a, **k: {"available": True, "capability_version": "1.3.0", "module_id": "licensing", "state": "available"}
# a check that fails in an unexpected way is counted, with a fixed code
gate_world(Unlicensed)
real_check = v2.check_licensing_requirement
v2.check_licensing_requirement = lambda c: (_ for _ in ()).throw(KeyError(MARKERS[5]))
row = ml.build_licensing_status()["would_block"]["modules"][0]
must(row["state"] == "check-error" and MARKERS[5] not in json.dumps(row), row)
v2.check_licensing_requirement = real_check
# the cap
installed(*[candidate(f"mod{n:03d}", product=f"mod{n:03d}") for n in range(60)])
blocked = ml.build_licensing_status()["would_block"]
must(blocked["count"] == 60 and len(blocked["modules"]) == 50 and blocked["modules"][0]["module_id"] == "mod000" and blocked["modules"][-1]["module_id"] == "mod049", (blocked["count"], len(blocked["modules"])))
# the mode is ignored: off and enforce count the same
for mode in ("off", "log-only", "enforce"):
    H.config.licensing_enforcement_mode = mode
    answer = ml.build_licensing_status()
    must(answer["would_block"]["count"] == 60 and answer["mode"]["value"] == mode and answer["enforcing"] is (mode == "enforce"), (mode, answer["mode"]))
H.config.licensing_enforcement_mode = ""
print("       would block lists what the gate refuses, capped at 50 with the true count, whatever the mode")

# the real manifest reader: only extensions that declare licensing.required are listed
from tec_tac import registry  # noqa: E402

ml._installed_licensed_candidates = REAL_INSTALLED
TMP = Path(tempfile.mkdtemp(prefix="tectac-licensing-status-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension", "version": "1.2.3"}
    payload.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


LICENSED = {"required": True, "product": "reportmanager", "capability": "licensing.entitlements", "capability_version": ">=1.0.0,<2.0.0"}
manifest("reportmanager", licensing=LICENSED)
manifest("free", licensing={"required": False})
manifest("plain")
manifest("badlicence", licensing={"required": True})  # incomplete: the manifest reader refuses it, so it is skipped
found = REAL_INSTALLED()
must([item["id"] for item in found] == ["reportmanager"] and found[0]["extension_version"] == "1.2.3", found)
must(found[0]["licensing"]["required"] is True and found[0]["licensing"]["capability"] == "licensing.entitlements", found)
gate_world(Unlicensed)
blocked = ml.build_licensing_status()["would_block"]
must(blocked["count"] == 1 and blocked["modules"][0]["module_id"] == "reportmanager", blocked)
print("       only an installed extension that declares licensing.required is listed")

# (5) who may read, and what a read writes
installed(candidate("reportmanager"))
view = lv.LicensingStatusView()
H.reset()
for user in (User("nobody"), User("viewer")):
    try:
        view.get(SimpleNamespace(user=user))
        raise AssertionError("not refused")
    except PermissionDenied as exc:
        must(lv.LICENSING_STATUS_DENIED in str(exc), exc)
for user in (User("root", superuser=True), User("manager", runtime=True)):
    must(set(view.get(SimpleNamespace(user=user)).data) >= {"mode", "licence", "would_block", "grace"}, user.username)
must(not H.audits, "a read writes no audit row")
print("       a superuser and a runtime-settings manager may read; anyone else gets 403; a read writes no row")

# (6) Core makes no network call
def refuse(*a, **k):
    raise AssertionError("a network call was made")


saved = (socket.socket, socket.create_connection, urllib.request.urlopen, http.client.HTTPConnection.connect)
socket.socket, socket.create_connection, urllib.request.urlopen, http.client.HTTPConnection.connect = refuse, refuse, refuse, refuse
try:
    set_provider(provider(health={**SECRET_HEALTH, "module_licensing": "enforced", "license_state": "licensed"}))
    gate_world(Unlicensed)
    answer = ml.build_licensing_status()
    must(answer["licence"]["state"] == "licensed" and answer["would_block"]["count"] == 1, answer)
finally:
    socket.socket, socket.create_connection, urllib.request.urlopen, http.client.HTTPConnection.connect = saved
clean("no network", answer)
print("       no network call is made")
print("[TEST] PASS licensing status 1.17.58")
