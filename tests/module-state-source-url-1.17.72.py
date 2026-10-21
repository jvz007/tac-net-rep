#!/usr/bin/env python3
"""1.17.72 regression (external audit H2): no query string or fragment in module-state.json ``source.repository_url``.

A repository URL may carry a token (``?token=...``). module-state.json is world-readable (0o644), so only scheme, host, port and path may be stored.
``strip_repository_url`` exists four times: tec_tac/module_state.py (Core, re-used by module_repository.py) and one copy in each root helper
(scripts/module-job-helper.py, scripts/module-v2-job-helper.py), because the helpers never import the Tactical-writable tree. (A) runs every copy over
one matrix and asserts the same output. (B) the source dict built by stage_repository_package holds no query or fragment while the fetch URLs are untouched.
(C) the v2 install write (remember_version) cleans the incoming source and keeps everything else. (D) a state file already on disk is cleaned by every
state writer (v2 set_enabled and set_visible, the three v1 writers, Core's save_state); other modules and keys are unchanged; the file mode is unchanged.
(E) a non-dict source is not made worse and a corrupt state is still refused. (F) source check: every state write is preceded by the scrub and 0o644 stays.

No Django, no root. What cannot run here: the helpers as root, a real install from a repository, a real state file owned by root.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


for _name, _attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None},
                      "pwd": {"getpwnam": lambda name: types.SimpleNamespace(pw_gid=0)}}.items():
    _module = types.ModuleType(_name)
    _module.__dict__.update(_attrs)
    sys.modules.setdefault(_name, _module)
for _shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, _shim):
        setattr(os, _shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 0

from tec_tac import module_repository as mrepo
from tec_tac import module_state as ms

LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"


def load_helper(name):
    path = ROOT / "scripts" / name
    source = path.read_text(encoding="utf-8")
    must(source.count(LOOKUP) == 1, f"the trusted-bash line of {name} moved; update this test")
    module = types.ModuleType(name.replace("-", "_").replace(".py", ""))
    module.__file__ = str(path)
    exec(compile(source.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(path), "exec"), module.__dict__)  # noqa: S102 - the helper under test
    return module


v1 = load_helper("module-job-helper.py")
v2 = load_helper("module-v2-job-helper.py")
v2.development_server = lambda: True

# ---- (A) the strip matrix, all copies
COPIES = {"core": ms.strip_repository_url, "repository": mrepo.strip_repository_url, "v1": v1.strip_repository_url, "v2": v2.strip_repository_url}
MATRIX = [
    ("https://repo.example.com:8443/modules/index.json?token=abc#frag", "https://repo.example.com:8443/modules/index.json"),
    ("https://repo.example.com/modules/index.json", "https://repo.example.com/modules/index.json"),
    ("https://repo.example.com/modules/index.json?token=abc", "https://repo.example.com/modules/index.json"),
    ("https://repo.example.com/modules/index.json#frag", "https://repo.example.com/modules/index.json"),
    ("https://repo.example.com/modules/index.json;secret=1", "https://repo.example.com/modules/index.json"),
    ("https://repo.example.com/a;x=1/b?token=abc", "https://repo.example.com/a"),
    ("HTTPS://Repo.Example.COM/Mods/Index.json?t=1", "https://repo.example.com/Mods/Index.json"),
    ("http://repo.example.com", "http://repo.example.com"),
    ("https://[2001:db8::1]:8443/idx.json?token=abc#f", "https://[2001:db8::1]:8443/idx.json"),
    ("https://[2001:db8::1]/idx.json", "https://[2001:db8::1]/idx.json"),
    ("https://user:pw@repo.example.com/idx.json?x=1", "https://repo.example.com/idx.json"),
    ("  https://repo.example.com/idx.json?x=1  ", "https://repo.example.com/idx.json"),
    ("https://repo.example.com:99999/idx.json?x=1", ""),
    ("ftp://repo.example.com/idx.json?x=1", ""),
    ("https:///idx.json?token=abc", ""),
    ("not a url?token=abc", ""),
    ("", ""),
    (None, ""),
    (5, ""),
    (["https://repo.example.com/?token=abc"], ""),
    (b"https://repo.example.com/?token=abc", ""),
]
for given, expected in MATRIX:
    for label, function in COPIES.items():
        got = function(given)
        must(got == expected, f"{label}({given!r}) gave {got!r}, expected {expected!r}")
    must(len({repr(function(given)) for function in COPIES.values()}) == 1, f"the copies drifted apart on {given!r}")
print("       the strip matrix gives the same answer in Core, module_repository and both root helpers")

# ---- (B) module_repository: what is staged holds no query, the fetch URLs are untouched
TOKEN_URL = "https://repo.example.com/modules/index.json?token=abc#frag"
DOWNLOAD = "https://repo.example.com/pkg/demo-1.0.0.zip?token=abc"
PACKAGE = b"package bytes"
repo = {"id": "main", "name": "Main", "trust": "custom", "enabled": True, "url": TOKEN_URL}
fetched, provenance = [], []
mrepo._repo = lambda repository_id: repo
mrepo.installed_catalog_v2 = list
mrepo._cached_modules = lambda r: [{"id": "demo", "version": "1.0.0", "download_url": DOWNLOAD, "sha256": hashlib.sha256(PACKAGE).hexdigest()}]
mrepo._fetch = lambda url, maximum, timeout=12, *, trust="custom": fetched.append(url) or PACKAGE
mrepo.stage_uploaded_artifact = lambda upload, **kw: {"upload_id": "u1", "kind": "package", "preview": {"id": "demo", "extension_version": "1.0.0"}}
mrepo.attach_source_provenance = lambda upload_id, source: provenance.append(dict(source))
staged = mrepo.stage_repository_package("main", "demo", "1.0.0")
for text in (json.dumps(staged["source"]), json.dumps(provenance)):
    must("token" not in text and "frag" not in text and "?" not in text, text)
must(staged["source"]["repository_url"] == "https://repo.example.com/modules/index.json", staged["source"])
must(provenance and provenance[0] == staged["source"], "the provenance attached to the stage is the cleaned source")
must(fetched == [DOWNLOAD], fetched)
must(repo["url"] == TOKEN_URL, "the repository record and its fetch URL are not changed")
must(staged["source"]["repository_id"] == "main" and staged["source"]["package_sha256"] == hashlib.sha256(PACKAGE).hexdigest(), "other source keys stay")
print("       a staged source holds no query or fragment; the fetch URL and the repository record keep theirs")

# ---- (C) v2 remember_version
TMP = Path(tempfile.mkdtemp(prefix="tectac-src-url-"))
MODES = []


def recording(real):
    def write(path, payload, *args, **kw):
        mode = kw.get("mode", args[0] if args else None)
        MODES.append((Path(path).name, mode))
        return real(path, payload, *args, **kw)
    return write


def v2_world(name):
    folder = TMP / name
    folder.mkdir()
    v2.MODULE_STATE = folder / "module-state.json"
    return v2.MODULE_STATE


v2.atomic_json = recording(v2.atomic_json)
state_file = v2_world("v2-install")
source = {"repository_id": "main", "repository_url": TOKEN_URL, "package_sha256": "abc123", "requested_version": "1.0.0"}
v2.remember_version("demo", "1.0.0", source=source, category="premium")
text = state_file.read_text(encoding="utf-8")
must("token" not in text and "frag" not in text, text)
record = json.loads(text)["modules"]["demo"]
must(record["version"] == "1.0.0" and record["category"] == "premium" and record["enabled"] is True and record["source"]["installed_at"], record)
must(record["source"]["repository_url"] == "https://repo.example.com/modules/index.json", record)
must(record["source"]["repository_id"] == "main" and record["source"]["package_sha256"] == "abc123" and record["source"]["requested_version"] == "1.0.0", record)
must(source["repository_url"] == TOKEN_URL, "the caller's own dict is not changed")
v2.remember_version("plain", "2.0.0", source={"repository_id": "main"})
must("repository_url" not in json.loads(state_file.read_text(encoding="utf-8"))["modules"]["plain"]["source"], "no repository_url is invented")
print("       the v2 install write stores a clean URL and keeps version, category, enabled and the other source keys")

# ---- (D) a state file already on disk is cleaned by every writer
UNTOUCHED = {"enabled": False, "version": "3.1.0", "category": "core", "visible": True, "extra": {"repository_url": "keep?this"}}


def planted():
    return {"schema": 1, "modules": {
        "tokened": {"enabled": True, "version": "1.0.0", "category": "premium",
                    "source": {"repository_id": "main", "repository_url": TOKEN_URL, "package_sha256": "abc123", "installed_at": "2026-10-21T00:00:00+00:00"}},
        "nosource": dict(UNTOUCHED),
    }}


def check_clean(path, label, expect_enabled=None):
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    must("token=" not in text and "frag" not in text, f"{label}: {text}")
    tokened = data["modules"]["tokened"]
    must(tokened["source"]["repository_url"] == "https://repo.example.com/modules/index.json", label)
    must(tokened["source"]["repository_id"] == "main" and tokened["source"]["package_sha256"] == "abc123" and tokened["version"] == "1.0.0"
         and tokened["category"] == "premium" and tokened["source"]["installed_at"] == "2026-10-21T00:00:00+00:00", label)
    must(data["modules"]["nosource"] == UNTOUCHED, f"{label}: the other module changed: {data['modules']['nosource']}")
    if expect_enabled is not None:
        must(tokened["enabled"] is expect_enabled, label)
    must(data["schema"] == 1, label)


def plant(path, data=None):
    path.write_text(json.dumps(data or planted(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


MODES.clear()
path = v2_world("v2-enable")
plant(path)
v2.set_enabled(["tokened"], False)
check_clean(path, "v2 set_enabled", False)
plant(path)
v2.set_visible("tokened", False)
check_clean(path, "v2 set_visible")
must(MODES and all(name == "module-state.json" and mode == 0o644 for name, mode in MODES), MODES)

CHMODS = []
real_chmod = os.chmod
os.chmod = lambda p, mode, *a, **k: CHMODS.append((Path(p).name, mode)) or real_chmod(p, mode, *a, **k)
folder = TMP / "v1"
folder.mkdir()
v1.STATE_ROOT, v1.STATE_FILE, v1.MODULE_STATE_LOCK = folder, folder / "module-state.json", folder / "module-state.lock"
try:
    for label, call, enabled in (("v1 forget_module_state", lambda: v1.forget_module_state("gone"), None),
                                 ("v1 set_module_enabled", lambda: v1.set_module_enabled(["tokened"], False), False),
                                 ("v1 remember_category", lambda: v1.remember_category("tokened", "premium"), None)):
        data = planted()
        data["modules"]["gone"] = {"enabled": True}
        plant(v1.STATE_FILE, data)
        CHMODS.clear()
        call()
        written = json.loads(v1.STATE_FILE.read_text(encoding="utf-8"))
        written["modules"].pop("gone", None)
        copy = folder / "copy.json"
        plant(copy, written)
        check_clean(copy, label, enabled)
        must("token=" not in v1.STATE_FILE.read_text(encoding="utf-8"), label)
        must(("module-state.json", 0o644) in CHMODS, f"{label}: the 0o644 chmod stays: {CHMODS}")
finally:
    os.chmod = real_chmod

folder = TMP / "core"
folder.mkdir()
ms.STATE_FILE, ms.STATE_LOCK = folder / "module-state.json", folder / "module-state.lock"
ms.STATE_LOCK.write_text("", encoding="utf-8")
core_modes = []


def core_atomic(target, payload, *, mode=0o660, default=None):
    core_modes.append(mode)
    Path(target).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


ms.atomic_json = core_atomic
ms.save_state(planted())
check_clean(ms.STATE_FILE, "core save_state")
must(core_modes == [0o644], core_modes)
print("       every state writer cleans a state that is already on disk and leaves other modules, keys and the 0o644 mode alone")

# ---- (E) odd shapes
for odd in ("a string", ["a", "list"], None, 7):
    state = {"schema": 1, "modules": {"weird": {"enabled": True, "source": odd}, "alsoweird": odd}}
    before = json.dumps(state, sort_keys=True)
    for scrub in (ms.scrub_state_sources, v1.scrub_state_sources, v2.scrub_state_sources):
        must(json.dumps(scrub(json.loads(before)), sort_keys=True) == before, f"a source of {odd!r} was changed")
for bad in (None, [], "x", {"modules": []}, {"modules": None}):
    for scrub in (ms.scrub_state_sources, v1.scrub_state_sources, v2.scrub_state_sources):
        scrub(bad)  # never raises
state = {"modules": {"m": {"source": {"repository_url": 5, "other": 1}}, "n": {"source": {"other": 2}}}}
ms.scrub_state_sources(state)
must(state == {"modules": {"m": {"source": {"repository_url": "", "other": 1}}, "n": {"source": {"other": 2}}}}, state)
path = v2_world("v2-corrupt")
path.write_text("{not json", encoding="utf-8")
try:
    v2.set_enabled(["x"], True)
    raise AssertionError("v2 wrote over a corrupt state")
except RuntimeError:
    pass
must(path.read_text(encoding="utf-8") == "{not json", "a corrupt state is left as it was")
try:
    ms.save_state({"_corrupt": True, "modules": {}})
    raise AssertionError("Core saved a corrupt state")
except ms.ModuleStateError:
    pass
print("       odd shapes are not made worse, a non-text URL fails closed to empty, a corrupt state is still refused")

# ---- (F) every state write is preceded by the scrub; the mode stays
FILES = {
    "framwork/tec_tac/module_state.py": (r"atomic_json\(STATE_FILE, payload, mode=0o644\)", 1),
    "scripts/module-v2-job-helper.py": (r"atomic_json\(MODULE_STATE, state, 0o644\)", 1),
    "scripts/module-job-helper.py": (r"atomic_json\(STATE_FILE, state\)", 3),
}
for name, (pattern, expected) in FILES.items():
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    must(len(hits) == expected, f"{name}: {len(hits)} state writes; a new writer needs the scrub (and this test updated)")
    for i in hits:
        must("scrub_state_sources(" in lines[i - 1], f"{name} line {i + 1} writes the state without the scrub")
    must(not any(re.search(r"atomic_json\((STATE_FILE|MODULE_STATE)\b", line) and not re.search(pattern, line) for line in lines), f"{name}: another state write shape")
v1_text = (ROOT / "scripts" / "module-job-helper.py").read_text(encoding="utf-8")
must(v1_text.count("os.chmod(STATE_FILE, 0o644)") == 3, "the v1 0o644 chmod stays")
print("       every state write in the four writers is preceded by the scrub, and 0o644 is unchanged")
print("module-state-source-url-1.17.72: PASS")
