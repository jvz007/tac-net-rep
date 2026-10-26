#!/usr/bin/env python3
"""1.17.78 regression: agent.command checks the route owner before the send, and a failed audit lookup releases the claim.
Runs without Django: tactical_operations.py and system_commands.py are loaded as one small package with fakes for the cache and the URL resolver.

Covered: the send-command path is owned by OWNER_MODULE in Core's owner table and passes; a path Core owns, or an owner that no longer owns the rule, is refused
function_unavailable and the view is never dispatched; claim() releases the claim when the durable lookup fails, so a retry is not read as a duplicate.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


store = {}


class FakeCache:
    def add(self, key, value, timeout=None):
        if key in store:
            return False
        store[key] = value
        return True

    def delete(self, key):
        store.pop(key, None)


cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = FakeCache()
sys.modules.update({"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"), "django.core.cache": cache_mod})
pkg = types.ModuleType("tt78")
pkg.__path__ = [str(ROOT)]
sys.modules["tt78"] = pkg


def load(name):
    spec = importlib.util.spec_from_file_location(f"tt78.{name}", ROOT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"tt78.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


load("module_category")
to = load("tactical_operations")
sc = load("system_commands")

AID = "x" * 20 + "ABCDEFG"
rule = to._matching_rule(["agents", AID.lower(), "cmd"])
must(rule == ("agents", "{}", "cmd") and sc.OWNER_MODULE in to.ROUTE_OWNERS[rule], "Core's owner table gives agents/{}/cmd to OWNER_MODULE")
path = f"/agents/{AID}/cmd/"
try:
    sc._check_route(path)
    must(True, "the send-command route passes for its owner")
except sc.CommandRefused:
    must(False, "the send-command route passes for its owner")


def refuses():
    try:
        sc._check_route(path)
    except sc.CommandRefused as exc:
        return exc.reason == "function_unavailable"
    return False


sc.OWNER_MODULE = "premium-other"
must(refuses(), "a module that does not own the rule is refused function_unavailable")
sc.OWNER_MODULE = "remote-background"

forbidden = min(to.FORBIDDEN_FIRST_SEGMENTS)
try:
    sc._check_route(f"/{forbidden}/1/cmd/")
    must(False, "a route Core owns is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a route Core owns is refused function_unavailable")

# _send: a refused route dispatches nothing and resolves nothing
dispatched = []
django_urls = types.ModuleType("django.urls")
django_urls.resolve = lambda p: dispatched.append(("resolve", p))
sys.modules["django.urls"] = django_urls
sc._dispatch_view = lambda m, r: dispatched.append(("dispatch", r))
sc.OWNER_MODULE = "premium-other"
try:
    sc._send(AID, {"shell": "cmd", "command": "x", "timeout": 5}, "johan", user=object())
    must(False, "_send refuses before resolve and dispatch")
except sc.CommandRefused:
    must(dispatched == [], "_send refuses before resolve and dispatch; nothing was sent")
sc.OWNER_MODULE = "remote-background"

# claim: a failed durable lookup releases the claim (nothing was sent) and refuses
store.clear()


def broken(a, c):
    raise RuntimeError("db down")


sc._already_recorded = broken
try:
    sc.claim(5, "c1")
    must(False, "a failed lookup refuses")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a failed durable lookup refuses the call (fail closed)")
must(store == {}, "the claim was released: no 24-hour duplicate mark remains")
sc._already_recorded = lambda a, c: False
must(sc.claim(5, "c1") is True, "a retry after the lookup recovers is claimed, not read as a duplicate")
must(sc.claim(5, "c1") is False, "a second claim of the same command is still a duplicate")
sc._already_recorded = lambda a, c: True
store.clear()
must(sc.claim(5, "c2") is False and len(store) == 1, "an earlier audit row still refuses and keeps the claim")

print("\nFAILED: " + ", ".join(FAILED) if FAILED else "\nAll passed")
sys.exit(1 if FAILED else 0)
