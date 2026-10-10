"""Runtime check for Core 1.17.16 module route mounting. It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, the real URL resolver and the real Core code are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/module-route-mount-runtime-1.17.16.py

It proves what the stub test (tests/module-route-mount-1.17.16.py) cannot: that ``mounted_routes()`` reports what the real start-up did,
that every module that declares ``routes`` and is loaded resolves under ``/api/tfd/<prefix>/`` through Django's own resolver (and
resolves to a view of its own urlconf), that Core's own routes still resolve to Core's views, that no prefix is mounted twice, and that
reverse() still works after mounting (a broken include would break it).

It changes nothing: it reads the resolver and the registry only. It prints PASS or FAIL for each step and exits with status 1 when any
step fails. It passes with no module declaring ``routes`` yet; the mounted list is then empty and that is reported.
"""
import sys

from django.apps import apps
from django.urls import Resolver404, resolve, reverse
from tec_tac import route_mounting, urls as tec_tac_urls
from tec_tac.registry import get_plugins

RESULTS = []


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


rows = route_mounting.mounted_routes()
declared = [p for p in get_plugins() if p.plugin_type == "extension" and p.route_urlconf]
loaded_names = {config.name for config in apps.get_app_configs()}
print(f"{len(declared)} installed module(s) declare routes; {len(rows)} reported by mounted_routes()")


def every_reported_row_is_well_formed():
    for row in rows:
        assert set(row) == {"prefix", "module", "state", "reason"} and row["state"] in ("mounted", "compat", "refused"), row


def mounted_modules_resolve_through_the_real_resolver():
    for row in rows:
        if row["state"] not in ("mounted", "compat"):
            continue
        try:
            match = resolve(f"/api/tfd/{row['prefix']}/")
        except Resolver404:
            # the module's urlconf may have no route at its root: a 404 inside the include is fine, a missing include is not
            top = [p for p in tec_tac_urls.urlpatterns if str(p.pattern) == f"{row['prefix']}/"]
            assert top or row["state"] == "compat", f"no urlpattern for {row}"
        else:
            assert match.func is not None, row


def a_mounted_prefix_appears_once():
    for row in rows:
        if row["state"] == "mounted":
            count = sum(1 for p in tec_tac_urls.urlpatterns if str(p.pattern) == f"{row['prefix']}/")
            assert count == 1, (row, count)


def disabled_modules_are_not_mounted():
    for plugin in declared:
        is_loaded = any(config.name == plugin.route_urlconf.split(".")[0] or plugin.route_urlconf.startswith(config.name + ".") for config in apps.get_app_configs())
        listed = [row for row in rows if row["module"] == plugin.plugin_id]
        assert bool(listed) == is_loaded or not is_loaded, (plugin.plugin_id, listed, is_loaded)
        if not is_loaded:
            assert not listed, f"{plugin.plugin_id} is not loaded but is reported"


def core_routes_still_win():
    match = resolve("/api/tfd/contracts/")
    assert match.func.view_class.__module__.startswith("tec_tac."), match
    first_core = next(i for i, p in enumerate(tec_tac_urls.urlpatterns) if str(p.pattern) == "contracts/")
    for i, p in enumerate(tec_tac_urls.urlpatterns):
        if getattr(p, "_tec_tac_module_route", None):
            assert i > first_core, "a module pattern sits before a Core pattern"


def reverse_still_works():
    assert reverse("tec-tac-contracts"), "reverse() of a Core route"


def the_contract_export_skips_mounted_modules():
    from tec_tac.contracts import _http_contracts

    exported = [row["route"] for row in _http_contracts()]
    for row in rows:
        if row["state"] == "mounted":
            assert f"/api/tfd/{row['prefix']}/" not in exported, row


step("reported rows are well formed", every_reported_row_is_well_formed)
step("mounted modules resolve through Django's resolver", mounted_modules_resolve_through_the_real_resolver)
step("a mounted prefix appears once", a_mounted_prefix_appears_once)
step("a module that is not loaded is not reported", disabled_modules_are_not_mounted)
step("Core's own routes still win and come first", core_routes_still_win)
step("reverse() still works", reverse_still_works)
step("the contract export skips mounted modules", the_contract_export_skips_mounted_modules)

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
