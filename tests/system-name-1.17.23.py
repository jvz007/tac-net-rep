#!/usr/bin/env python3
"""1.17.23 regression: the system name an authenticator shows (Johan chose option b, 12 October 2026).

Django is not installed on the development PC, so the real runtime_settings.py is loaded against the stubs of
tests/update-source-1.17.2.py, and the issuer helpers of views.py are extracted with ast and run against a stub pyotp.
Covered: default, validation, null reset, who may change it, one strict audit row per change and none for an unchanged value,
the issuer and the otpauth URI (no colon in the issuer, no host, no /tec-tac), the enrollment answer and audit metadata, and
the read paths (runtime-settings GET, ui/context). The real migration and PATCH run on the dev server with
tests/system-name-runtime-1.17.23.py.
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from urllib.parse import quote

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "update-source-1.17.2.py"
source = HARNESS.read_text(encoding="utf-8")
marker = 'rs = load("runtime_settings")'
H = {"__file__": str(HARNESS), "__name__": "update_source_harness"}
exec(compile(source[: source.index(marker)], "update-source-1.17.2.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse of the 1.17.x harness
must, mods, load = H["must"], H["mods"], H["load"]
ROOT, APP, CONFIG, AUDITS, Config = H["ROOT"], H["APP"], H["CONFIG"], H["AUDITS"], H["Config"]
PermissionDenied = H["PermissionDenied"]
CURRENT_FAILS = H["CURRENT_FAILS"]

mods["tec_tac.rbac"].is_effective_superuser = lambda user: bool(getattr(user, "superuser", False))
mods["tec_tac.rbac"].can_manage_runtime_settings = lambda user: bool(
    getattr(user, "superuser", False) or getattr(user, "manage", False) or getattr(user, "privileged", False)
)
rs = load("runtime_settings")
CONFIG.system_name = "Tec-Tac"  # the migration's default for the existing row
CONFIG.tactical_operation_upload_max_mib = 10


def person(**rights):
    return types.SimpleNamespace(**{"username": "u", "superuser": False, "manage": False, "privileged": False, **rights})


def patch(body, who):
    return rs.RuntimeSettingsView().patch(types.SimpleNamespace(user=who, data=body))


def refused_value(value):
    try:
        rs.validate_system_name(value)
    except rs.RuntimeSettingsError:
        return True
    return False


# (1) default
must(rs.DEFAULT_SYSTEM_NAME == "Tec-Tac" and rs.get_system_name() == "Tec-Tac", "default")
must(rs.serialize_runtime_settings()["system_name"] == {"value": "Tec-Tac", "maximum_length": 60, "default": "Tec-Tac"}, rs.serialize_runtime_settings())
must("system_name" in rs.RUNTIME_SETTING_NAMES, "name is a runtime setting")

# (2) validation
for good in ("Tec-Tac", "Tech Flow Dynamics", "Acme IT (Cape Town)", "a", "x" * 60, "Caf\u00e9 \u00dcn\u00ef", "  padded  "):
    out = rs.validate_system_name(good)
    must(out == good.strip(), good)
must(rs.validate_system_name("e\u0301") == "\u00e9", "NFC normalised")
for bad in ("", "   ", "x" * 61, "a:b", ":", "line\nbreak", "tab\there", "zero\u200bwidth", "bom\ufeffx", "bell\x07", True, False, 5, 1.5, ["Tec-Tac"], {"a": 1}, None, b"bytes"):
    must(refused_value(bad), f"must refuse {bad!r}")

# (3) get_system_name never raises and falls back
CURRENT_FAILS["on"] = True
must(rs.get_system_name() == "Tec-Tac", "database error falls back")
CURRENT_FAILS["on"] = False
CONFIG.system_name = "bad:value"
must(rs.get_system_name() == "Tec-Tac", "invalid stored value falls back")
must(rs.serialize_runtime_settings()["system_name"]["value"] == "Tec-Tac", "serialize falls back too")
CONFIG.system_name = "Tec-Tac"

# (4) who may change it
before = (len(AUDITS), len(Config.saved))
try:
    patch({"system_name": "Acme"}, person())
except PermissionDenied as exc:
    must(str(exc) == rs.RUNTIME_SETTINGS_DENIED, exc)
else:
    raise AssertionError("a user with no right must be refused")
must((len(AUDITS), len(Config.saved)) == before and CONFIG.system_name == "Tec-Tac", "refused: nothing saved or audited")

# (5) manage right and superuser may change it, one strict row each, before and after in the row
for who, name in ((person(superuser=True), "Acme IT"), (person(superuser=True, manage=True), "Acme IT South")):  # 1.17.24: superuser only
    AUDITS.clear()
    resp = patch({"system_name": name}, who)
    must(resp.status_code == 200 and resp.data["system_name"]["value"] == name, resp.data)
    must(CONFIG.system_name == name, CONFIG.system_name)
    must(len(AUDITS) == 1, AUDITS)
    row = AUDITS[0]
    must(row["object_type"] == "runtime_settings" and row["object_id"] == "system_name" and row["strict"] is True and row["module_id"] == "core", row)
    must(row["after"] == {"system_name": name} and set(row["before"]) == {"system_name"}, row)
must(AUDITS[0]["before"] == {"system_name": "Acme IT"}, AUDITS[0])

# (6) an unchanged value writes no row, even when sent with stray spaces
AUDITS.clear()
saved = len(Config.saved)
resp = patch({"system_name": "  Acme IT South  "}, person(superuser=True))
must(resp.status_code == 200 and not AUDITS and len(Config.saved) == saved, "unchanged value: no row, no save")

# (7) bad values are 400 and change nothing
for bad in ("", "a:b", "x" * 61, "no\u200bway", True, 7, ["x"]):
    resp = patch({"system_name": bad}, person(superuser=True))
    must(resp.status_code == 400 and CONFIG.system_name == "Acme IT South" and not AUDITS, (bad, resp.data))

# (8) null resets to the default; one row
resp = patch({"system_name": None}, person(superuser=True))
must(resp.status_code == 200 and CONFIG.system_name == "Tec-Tac" and len(AUDITS) == 1 and AUDITS[0]["after"] == {"system_name": "Tec-Tac"}, (resp.data, AUDITS))

# (9) together with the timeout: one row per changed setting; the integer settings behave as before
AUDITS.clear()
resp = patch({"system_name": "Acme", rs.SETTING_MODULE_REGISTER_TIMEOUT: 60}, person(superuser=True))
must(resp.status_code == 200 and sorted(r["object_id"] for r in AUDITS) == [rs.SETTING_MODULE_REGISTER_TIMEOUT, "system_name"], AUDITS)
must(next(r for r in AUDITS if r["object_id"] == rs.SETTING_MODULE_REGISTER_TIMEOUT)["after"] == {rs.SETTING_MODULE_REGISTER_TIMEOUT: 60}, AUDITS)
# the upload limit stays superuser only, even next to the name
try:
    patch({"system_name": "Z", rs.SETTING_TACTICAL_UPLOAD_MAX_MIB: 12}, person(manage=True))
except PermissionDenied as exc:
    must(str(exc) == rs.UPLOAD_LIMIT_DENIED, exc)
else:
    raise AssertionError("upload limit is superuser only")
# a failed audit write propagates out of the transaction block, which rolls the change back
H["AUDIT_FAIL"]["on"] = True
errors_before = H["AtomicCtx"].exited_with_error
try:
    patch({"system_name": "Other"}, person(superuser=True))
except RuntimeError:
    pass
else:
    raise AssertionError("a failed audit write must raise")
H["AUDIT_FAIL"]["on"] = False
must(H["AtomicCtx"].exited_with_error == errors_before + 1, "the transaction saw the error")
CONFIG.system_name = "Acme"

# (10) the issuer and the otpauth URI, from the real views.py functions
views_src = (APP / "views.py").read_text(encoding="utf-8")
tree = ast.parse(views_src)
funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"_tec_tac_totp_issuer", "_tec_tac_totp_uri"}]
must(len(funcs) == 2, "both helpers exist")


class TOTP:
    def __init__(self, key):
        self.key = key

    def provisioning_uri(self, name, issuer_name=None):  # same label grammar as pyotp
        label = quote(issuer_name) + ":" + quote(name)
        return f"otpauth://totp/{label}?secret={self.key}&issuer={quote(issuer_name)}"


ns = {"pyotp": types.SimpleNamespace(TOTP=TOTP), "get_system_name": rs.get_system_name}
exec(compile(ast.Module(body=funcs, type_ignores=[]), "views.py", "exec"), ns)  # noqa: S102
request = types.SimpleNamespace(user=types.SimpleNamespace(username="sam", totp_key="KEY1"), META={"HTTP_HOST": "rmm.example.co.za"},
                                query_params={"ui_url": "https://rmm.example.co.za:8443/tec-tac/"})
for name in ("Tec-Tac", "Acme IT"):
    CONFIG.system_name = name
    issuer = ns["_tec_tac_totp_issuer"](request)
    must(issuer == name, issuer)
    uri = ns["_tec_tac_totp_uri"](request)
    must(uri.startswith(f"otpauth://totp/{quote(name)}:sam?"), uri)
    must(uri.endswith(f"issuer={quote(name)}"), uri)
    must(":" not in issuer and "example" not in uri and "/tec-tac" not in uri and "8443" not in uri, uri)
# the last defence: even a stored colon never reaches the label
ns["get_system_name"] = lambda: "a:b"
must(ns["_tec_tac_totp_issuer"](request) == "a-b", "colon replaced as a last defence")

# (11) the enrollment answer and its audit metadata use the issuer; ui_url stays for older UI builds
must('"issuer": _tec_tac_totp_issuer(request)' in views_src, "answer issuer")
must('metadata={"issuer": _tec_tac_totp_issuer(request)' in views_src, "audit metadata issuer")
must('"ui_url": _tec_tac_ui_url(request)' in views_src and "def _tec_tac_ui_url" in views_src, "ui_url stays")
issuer_body = views_src.split("def _tec_tac_totp_issuer")[1].split("def _tec_tac_totp_uri")[0]
must("urlsplit" not in issuer_body and "_tec_tac_ui_url" not in issuer_body, "no host-based issuer")
ctx = views_src.split("class UiContextView")[1].split("class ExtensionPermissionCatalogView")[0]
must('"system_name": get_system_name()' in ctx, "ui/context carries it")
must("get_system_name" in views_src.split("from .runtime_settings import")[1].split("\n")[0], "imported")

# (12) the model, the migration and the contract rows
models_src = (APP / "models.py").read_text(encoding="utf-8")
must('system_name = models.CharField(max_length=60, default="Tec-Tac")' in models_src, "model field")
mig = (APP / "migrations" / "0027_runtime_system_name.py").read_text(encoding="utf-8")
must('"0026_runtime_upload_limit"' in mig and "AddField" in mig and 'default="Tec-Tac"' in mig and "max_length=60" in mig and "RunPython" not in mig, "additive migration")
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def table(name):
    return next(ast.literal_eval(n.value) for n in contracts.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == name for t in n.targets))


http = table("HTTP_CONTRACT_DETAILS")
rt = http["/api/tfd/system/runtime-settings/"]
must("system_name" in rt["GET"]["response"] and "system_name" in rt["PATCH"]["request"], "runtime-settings table")
must("system_name" in http["/api/tfd/ui/context/"]["GET"]["response"], "ui/context table")
must("colon" in rt["PATCH"]["request"]["system_name"] and "null" in rt["PATCH"]["request"]["system_name"], "PATCH row names the colon and the null reset")
runtime = next(r for r in table("BROWSER_CONTRACTS") if r["id"] == "ui.authenticated.runtime-context")
must("system_name" in runtime["operations"] and "system_name" in " ".join(runtime["details"]), "runtime-context row")
doc = (ROOT / "docs" / "account-security-policy.md").read_text(encoding="utf-8")
must("system_name" in doc and "1.17.23" in doc, "account security doc")
rdoc = (ROOT / "docs" / "runtime-settings.md").read_text(encoding="utf-8")
must("system_name" in rdoc, "runtime settings doc")

print("system name 1.17.23: ok")
