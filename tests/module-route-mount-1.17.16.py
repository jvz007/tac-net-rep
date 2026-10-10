#!/usr/bin/env python3
"""1.17.16 regression: a module's URLs are mounted from the manifest ``routes`` key (CQ47 assumption (a)).

Runs the real registry.py, route_mounting.py, module_manager_v2.py (package inspect parse), bootstrap.py and contracts.py against
stubs for Django's url helpers. Covered: good and bad ``routes`` keys (a prefix that differs from the id, a urlconf outside the
module's own apps, a bad slug, a reportset, unknown keys), the same parse at package inspect, mounting a loaded module under
``api/tfd/<prefix>/``, the compatibility path (a prefix already appended through tec_tac.urls or tacticalrmm.urls is not mounted
twice), a disabled module and a conflicted AD-20 replacement are not mounted, a duplicate prefix mounts the first by sorted id, a
failing urlconf skips only that module, Core's own routes still come first, ``mounted_routes()``, the bootstrap wiring after every
``AppConfig.ready()`` and the contract export skipping a mounted module. The real URL resolver and a real server start are
tests/module-route-mount-runtime-1.17.16.py (a dev-server script).
"""
from __future__ import annotations

import json
import logging
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)
    return module


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)


class URLEntry:
    """What django.urls.path returns: a pattern whose str() is the route, and the thing it includes."""

    def __init__(self, route, include=None):
        self.pattern, self.included = route, include


class Pattern(str):
    pass


def path(route, target):
    return URLEntry(Pattern(route), target)


def include(target):
    return ("include", target)


_stub("django")
_stub("django.urls", path=path, include=include)

from tec_tac import module_manager_v2 as v2, registry  # noqa: E402
from tec_tac import module_category  # noqa: E402
from tec_tac import route_mounting as rm  # noqa: E402

module_category.is_development_server = lambda: True
TMP = Path(tempfile.mkdtemp(prefix="tectac-routes-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP


def write(module_id, root=EXT, **extra):
    folder = root / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension" if root is EXT else "reportset", "version": "1.0.0", "name": module_id}
    payload.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


def reset():
    for root in (EXT, REP):
        for folder in list(root.iterdir()):
            for child in folder.iterdir():
                child.unlink()
            folder.rmdir()


def load(module_id="patching", **extra):
    reset()
    write(module_id, **extra)
    return registry.discover_plugins()[0]


def bad(module_id="patching", **extra):
    try:
        load(module_id, **extra)
    except registry.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"the manifest was accepted: {extra}")


APPS = ["tec_tac_patching.apps.PatchingConfig"]
good = {"django_apps": APPS, "routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}}

# ------------------------------------------------------------------------------------------------ parsing
spec = load(**good)
must(spec.route_prefix == "windows-patching" and spec.route_urlconf == "tec_tac_patching.urls", spec)
must(load(django_apps=APPS, routes={"urlconf": "tec_tac_patching.urls"}).route_prefix == "patching", "the prefix defaults to the module id")
must(load("securityWAF", django_apps=["securityWAF_app.apps.Cfg"], routes={"urlconf": "securityWAF_app.urls"}).route_prefix == "securityWAF", "an id with capitals is a legal default")
must(load("a", django_apps=["pkg.apps.Cfg"], routes={"prefix": "other", "urlconf": "pkg"}).route_urlconf == "pkg", "the app package itself is allowed")
must(load(django_apps=APPS, routes={"prefix": "a" * 64, "urlconf": "tec_tac_patching.sub.urls"}).route_prefix == "a" * 64, "64 characters is the limit")
must(load(django_apps=APPS).route_prefix == "" and load(django_apps=APPS).route_urlconf == "", "no key: both empty, as before")
must(load(django_apps=["pkg.apps"], routes={"urlconf": "pkg.urls"}).route_urlconf == "pkg.urls", "an apps module path works too")
must(load(django_apps=["pkg"], routes={"urlconf": "pkg.urls"}).route_urlconf == "pkg.urls", "a plain package name works too")
# refusals
bad(django_apps=APPS, routes="tec_tac_patching.urls")
bad(django_apps=APPS, routes=[])
bad(django_apps=APPS, routes={})  # urlconf is required
bad(django_apps=APPS, routes={"prefix": "x"})
bad(django_apps=APPS, routes={"urlconf": 5})
bad(django_apps=APPS, routes={"urlconf": "tec_tac_patching.urls", "extra": 1})
for prefix in ("", "Upper", "has space", "a/b", "/a", "a/", "..", "a.b", "-lead", "_lead", "ü", 5, "a" * 65, ["a"]):
    bad(django_apps=APPS, routes={"prefix": prefix, "urlconf": "tec_tac_patching.urls"})
for urlconf in ("", "tec_tac_patching/urls", "tec_tac_patching..urls", ".urls", "tec_tac_patching.", "1abc.urls", "a b.urls", "a-b.urls"):
    bad(django_apps=APPS, routes={"urlconf": urlconf})
# outside the module's own apps: tacticalrmm, tec_tac, another module, a lookalike package
for urlconf in ("tacticalrmm.urls", "tec_tac.urls", "tec_tac.module_manager", "other_module.urls", "tec_tac_patching_evil.urls", "tec_tac_patchin.urls"):
    bad(django_apps=APPS, routes={"urlconf": urlconf})
bad(routes={"urlconf": "tec_tac_patching.urls"})  # no django_apps at all
bad(django_apps=["tacticalrmm.apps.Cfg"], routes={"urlconf": "tacticalrmm.urls"})  # an app inside tacticalrmm cannot be used to reach it
bad(django_apps=["tec_tac.apps.Cfg"], routes={"urlconf": "tec_tac.urls"})
message = bad(django_apps=APPS, routes={"urlconf": "other_module.urls"})
must("tec_tac_patching" in message and "own" in message, message)
# a reportset may not declare routes
reset()
write("patching", django_apps=APPS)
write("patching", root=REP, routes={"urlconf": "x.urls"})
try:
    registry.discover_plugins()
    raise AssertionError("a reportset with routes was accepted")
except registry.RegistryError as exc:
    must("reportset" in str(exc).lower() and "routes" in str(exc), str(exc))
# a manifest key set that is otherwise unknown is still refused
bad(django_apps=APPS, routez={"urlconf": "x"})
must("routes" in registry.SUPPORTED_KEYS and "description" in registry.SUPPORTED_KEYS, "accepted manifest keys")
# PluginSpec still takes every earlier call shape
spec = registry.PluginSpec(plugin_id="x", plugin_type="extension", root=TMP)
must(spec.route_prefix == "" and spec.route_urlconf == "" and spec.description == "", "new fields have defaults")
registry.PluginSpec("x", "extension", TMP, "1.0.0", (), ("a.apps.A",), (), (), "n", "core", False, (), "", (), False)

# ------------------------------------------------------------------------------------------------ package inspect parses the same key
payload = {"id": "patching", "django_apps": APPS, "routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}}
meta = v2._route_and_description_metadata(payload)
must(meta == {"routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}, "description": None}, meta)
must(v2._route_and_description_metadata({"id": "patching", "django_apps": APPS}) == {"routes": None, "description": None}, "absent keys")
for broken in ({"routes": {"urlconf": "tacticalrmm.urls"}}, {"routes": {"prefix": "Bad Prefix", "urlconf": "tec_tac_patching.urls"}}, {"routes": []}):
    try:
        v2._route_and_description_metadata({"id": "patching", "django_apps": APPS, **broken})
        raise AssertionError(f"inspect accepted {broken}")
    except v2.ModuleManagerV2Error:
        pass
reset()
write("patching", **good)
write("p2", django_apps=["p2.apps.Cfg"], routes={"prefix": "p2-x", "urlconf": "p2.urls"})
must(v2._extension_metadata(EXT / "patching")["routes"] == {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}, "extension metadata carries it")


# ------------------------------------------------------------------------------------------------ mounting
class Config:
    def __init__(self, name, cls_name="Config"):
        self.name = name
        self.__class__ = type(cls_name, (Config,), {"__module__": name + ".apps"})


def plug(module_id, prefix=None, urlconf=None, apps=None):
    package = module_id.replace("-", "_")
    return types.SimpleNamespace(plugin_id=module_id, plugin_type="extension", django_apps=tuple(apps if apps is not None else [f"{package}.apps.Config"]),
                                 route_prefix=prefix or "", route_urlconf=urlconf if urlconf is not None else f"{package}.urls")


MODULES = {}


def fake_module(name, patterns=None, broken=False):
    if broken:
        return
    mod = types.ModuleType(name)
    mod.urlpatterns = patterns if patterns is not None else ["a-route"]
    sys.modules[name] = mod
    MODULES[name] = mod


def loaded(*packages):
    return [Config(p) for p in packages]


CORE_ENTRY = URLEntry(Pattern("audit/record/"))
for name in ("alpha.urls", "beta.urls", "gamma.urls", "delta.urls", "pkg_one.urls", "pkg_two.urls"):
    sys.modules.pop(name, None)
fake_module("alpha.urls")
fake_module("beta.urls")
fake_module("gamma.urls")

core_urls, tactical_urls = [CORE_ENTRY], [URLEntry(Pattern("api/tfd/"), "core")]


def mount(plugins, configs, core=None, tactical=None):
    return rm.mount_module_routes(plugins, app_configs=configs, tec_tac_patterns=core_urls if core is None else core,
                                  tactical_patterns=tactical_urls if tactical is None else tactical)


rows = mount([plug("alpha", prefix="alpha-prefix")], loaded("alpha"))
must(rows == [{"prefix": "alpha-prefix", "module": "alpha", "state": "mounted", "reason": "Mounted by Core from the manifest routes key."}], rows)
must(len(core_urls) == 2 and core_urls[0] is CORE_ENTRY, "Core's own routes stay first; the module is appended after them")
entry = core_urls[1]
must(str(entry.pattern) == "alpha-prefix/" and entry.included == ("include", MODULES["alpha.urls"]) and entry._tec_tac_module_route == "alpha", entry.__dict__)
must(rm.mounted_routes() == rows, "mounted_routes() reports it")
rows[0]["state"] = "tampered"
must(rm.mounted_routes()[0]["state"] == "mounted", "the status is a copy")
# the prefix defaults to the module id, and may share a first segment with a Core route (audit)
fake_module("audit_pkg.urls")
del core_urls[1:]
rows = mount([plug("audit", urlconf="audit_pkg.urls", apps=["audit_pkg.apps.Config"])], loaded("audit_pkg"))
must(rows[0]["prefix"] == "audit" and rows[0]["state"] == "mounted" and [str(e.pattern) for e in core_urls] == ["audit/record/", "audit/"], rows)
# running it again does not mount twice
rows = mount([plug("audit", urlconf="audit_pkg.urls", apps=["audit_pkg.apps.Config"])], loaded("audit_pkg"))
must(rows[0]["state"] == "mounted" and [str(e.pattern) for e in core_urls] == ["audit/record/", "audit/"], "idempotent")

# compatibility: the module still appends its own routes the old way
del core_urls[1:]
core_urls.append(URLEntry(Pattern("alpha/"), "own include"))  # appended to tec_tac.urls by the module (licensing, serverhealth ...)
rows = mount([plug("alpha")], loaded("alpha"))
must(rows[0]["state"] == "compat" and len(core_urls) == 2 and core_urls[1].included == "own include", (rows, core_urls))
del core_urls[1:]
tactical_urls.append(URLEntry(Pattern("api/tfd/alpha/"), "own include"))  # appended to tacticalrmm.urls (most modules)
rows = mount([plug("alpha")], loaded("alpha"))
must(rows[0]["state"] == "compat" and len(core_urls) == 1, (rows, core_urls))
del tactical_urls[1:]

# a disabled module (its app is not loaded) is not mounted and is not listed
rows = mount([plug("alpha"), plug("beta")], loaded("beta"))
must([r["module"] for r in rows] == ["beta"] and [str(e.pattern) for e in core_urls] == ["audit/record/", "beta/"], (rows, core_urls))
del core_urls[1:]
# a conflicted replacement Core dropped (not loaded) is not mounted, and does not take the prefix from the module it replaces
fake_module("patching_x.urls")
fake_module("advpatch.urls")
rows = mount([plug("patching", prefix="windows-patching", urlconf="patching_x.urls", apps=["patching_x.apps.Config"]),
              plug("advpatch", prefix="windows-patching", urlconf="advpatch.urls", apps=["advpatch.apps.Config"])], loaded("patching_x"))
must([(r["module"], r["state"]) for r in rows] == [("patching", "mounted")] and len(core_urls) == 2, rows)
del core_urls[1:]
# the replacement alone (the replaced module is off) mounts under the same prefix
rows = mount([plug("patching", prefix="windows-patching", urlconf="patching_x.urls", apps=["patching_x.apps.Config"]),
              plug("advpatch", prefix="windows-patching", urlconf="advpatch.urls", apps=["advpatch.apps.Config"])], loaded("advpatch"))
must([(r["module"], r["state"]) for r in rows] == [("advpatch", "mounted")], rows)
del core_urls[1:]

# a duplicate prefix between two loaded modules: the first by sorted id is mounted, the second is refused
rows = mount([plug("gamma", prefix="shared"), plug("alpha", prefix="shared")], loaded("alpha", "gamma"))
must([(r["module"], r["state"]) for r in rows] == [("alpha", "mounted"), ("gamma", "refused")], rows)
must("alpha" in rows[1]["reason"] and len(core_urls) == 2 and core_urls[1]._tec_tac_module_route == "alpha", (rows, core_urls))
del core_urls[1:]

# a failing urlconf skips only that module: not found, a syntax error and a module with no urlpatterns
sys.modules.pop("broken_one.urls", None)
fake_module("nopatterns.urls", patterns="not a list")
rows = mount([plug("brokenone", urlconf="broken_one.urls", apps=["broken_one.apps.Config"]), plug("nopat", urlconf="nopatterns.urls", apps=["nopatterns.apps.Config"]),
              plug("beta")], loaded("broken_one", "nopatterns", "beta"))
states = {r["module"]: r["state"] for r in rows}
must(states == {"beta": "mounted", "brokenone": "refused", "nopat": "refused"}, states)
must([str(e.pattern) for e in core_urls] == ["audit/record/", "beta/"], "only the good module was mounted")
must(all("urlconf" in r["reason"] for r in rows if r["state"] == "refused") and not any("/" in r["reason"] and "\\" in r["reason"] for r in rows), rows)
del core_urls[1:]
# a module that raises while its urls import is skipped the same way
bad_mod = types.ModuleType("raises.urls")
sys.modules["raises.urls"] = bad_mod
import importlib  # noqa: E402

real_import = importlib.import_module


def exploding(name, package=None):
    if name == "raises.urls":
        raise RuntimeError("boom in module code")
    return real_import(name, package)


importlib.import_module = exploding
rows = mount([plug("raises", urlconf="raises.urls", apps=["raises.apps.Config"]), plug("beta")], loaded("raises", "beta"))
importlib.import_module = real_import
must({r["module"]: r["state"] for r in rows} == {"beta": "mounted", "raises": "refused"}, rows)
del core_urls[1:]

# a module with no routes key is never touched, and tec_tac.urls is not even imported for it
plain = types.SimpleNamespace(plugin_id="plain", plugin_type="extension", django_apps=("plain.apps.Config",), route_prefix="", route_urlconf="")
rows = rm.mount_module_routes([plain], app_configs=loaded("plain"), tec_tac_patterns=core_urls, tactical_patterns=tactical_urls)
must(rows == [] and len(core_urls) == 1, "nothing declares routes")
sys.modules.pop("tec_tac.urls", None)
rows = rm.mount_module_routes([plain])  # no lists given: must not import tec_tac.urls or Django's registry
must(rows == [] and "tec_tac.urls" not in sys.modules, "no import of tec_tac.urls when nothing declares routes")
# a reportset is never mounted even with the attributes set
rep = types.SimpleNamespace(plugin_id="alpha", plugin_type="reportset", django_apps=("alpha.apps.Config",), route_prefix="x", route_urlconf="alpha.urls")
rows = mount([rep], loaded("alpha"))
must(rows == [] and len(core_urls) == 1, rows)
# a failure of the whole step never raises
rows = rm.mount_module_routes(object())
must(rows == [], "an unusable plugin list is logged, not raised")
rows = rm.mount_module_routes([plug("alpha")], app_configs=object(), tec_tac_patterns=core_urls, tactical_patterns=tactical_urls)
must(isinstance(rows, list), "an unusable app list is logged, not raised")

# ------------------------------------------------------------------------------------------------ bootstrap wiring
events = []
calls = []
django_apps_mod = types.ModuleType("django.apps")
registry_mod = types.ModuleType("django.apps.registry")


class FakeApps:
    def populate(self, installed_apps=None):
        events.append("populate")
        return "populated"


registry_mod.Apps = FakeApps
django_apps_mod.apps = FakeApps()
sys.modules["django.apps"], sys.modules["django.apps.registry"] = django_apps_mod, registry_mod
from tec_tac import bootstrap  # noqa: E402

source = (ROOT / "framwork/tec_tac/bootstrap.py").read_text(encoding="utf-8")
must(source.index("settle_reporting_bridge()") < source.index("mount_module_routes()") and "AppConfig.ready()" in source, "mounting runs after the handover, after every ready()")
must("route_mounting" not in (ROOT / "framwork/tec_tac/apps.py").read_text(encoding="utf-8"), "not inside tec_tac's own ready()")
sys.modules["tec_tac.reporting"] = types.ModuleType("tec_tac.reporting")
sys.modules["tec_tac.reporting"].settle_reporting_bridge = lambda: events.append("settle")
fake_rm = types.ModuleType("tec_tac.route_mounting")
fake_rm.mount_module_routes = lambda: events.append("mount")
sys.modules["tec_tac.route_mounting"] = fake_rm
bootstrap.django_apps = django_apps_mod.apps
bootstrap.Apps = FakeApps
bootstrap.get_plugins = lambda: ()
bootstrap.filter_enabled_plugins = lambda plugins: ()
bootstrap.load_extensions()
result = django_apps_mod.apps.populate(["tactical.apps"])
must(result == "populated" and events == ["populate", "settle", "mount"], events)
events.clear()
fake_rm.mount_module_routes = lambda: (_ for _ in ()).throw(RuntimeError("mount failed"))
must(django_apps_mod.apps.populate(["tactical.apps"]) == "populated", "a failing mount never changes the result or raises")
sys.modules["tec_tac.route_mounting"] = rm

# ------------------------------------------------------------------------------------------------ contract export skips a mounted module
import ast  # noqa: E402

contracts_source = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")  # contracts.py needs Django: read its function with ast
tree = ast.parse(contracts_source)
module_ast = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_http_contracts"], type_ignores=[])
ast.fix_missing_locations(module_ast)
contracts_ns = {"__name__": "tec_tac.contracts_under_test", "__package__": "tec_tac", "HTTP_CONTRACT_DETAILS": {}}
exec(compile(module_ast, "contracts.py", "exec"), contracts_ns)
contracts = types.SimpleNamespace(_http_contracts=contracts_ns["_http_contracts"])

fake_urls = types.ModuleType("tec_tac.urls")
own = URLEntry(Pattern("audit/record/"))
own.callback, own.name = None, "core-audit"
mounted = URLEntry(Pattern("windows-patching/"), "include")
mounted._tec_tac_module_route = "patching"
fake_urls.urlpatterns = [own, mounted]
sys.modules["tec_tac.urls"] = fake_urls
import tec_tac  # noqa: E402

tec_tac.urls = fake_urls
routes = [row["route"] for row in contracts._http_contracts()]
must("/api/tfd/audit/record/" in routes and not any("windows-patching" in route for route in routes), routes)
catalog_text = contracts_source
must("mounted_routes" in catalog_text and "module-routes" in catalog_text and "routes" in catalog_text, "the contract lists the key and the status function")
must((ROOT / "docs/module-routes.md").is_file(), "docs/module-routes.md")

print("[TEST] PASS module route mount 1.17.16")
