#!/usr/bin/env python3
"""1.17.16 regression: the public ``tec_tac.notices.publish`` contract for a module backend or Scheduler run (CQ49 assumption (a)).

The real notices.py runs against stubs for Django, the notice model, the module registry and module state. It covers: a stored
notice carries source = module id, dedupe on the namespaced key without resetting a read notice, refusal of ``core`` and
``tec-tac``, an unknown or disabled module, a reportset, an inactive, installer, agent or dashboard-blocked user, a bad level, an
external or javascript route, an over-long key, and an action label without a route. The database part is
tests/notices-publish-runtime-1.17.16.py (a dev-server script).
"""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


mods = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    return m


# ------------------------------------------------------------------------------------------------ stubs
class _Atomic:
    def __call__(self, fn=None):
        return fn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
USERS = {}


class User:
    def __init__(self, pk, username, *, active=True, installer=False, agent=False, blocked=False):
        self.pk, self.username, self.is_active, self.is_installer_user, self.agent, self.block_dashboard_login = pk, username, active, installer, agent, blocked
        USERS[pk] = self


class _UserQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kw):
        out = list(self.rows)
        for key, value in kw.items():
            if key == "agent__isnull":
                out = [u for u in out if (not u.agent) == value]
            else:
                out = [u for u in out if getattr(u, key) == value]
        return _UserQuery(out)

    def first(self):
        return self.rows[0] if self.rows else None


class _UserManager:
    def filter(self, **kw):
        return _UserQuery(list(USERS.values())).filter(**kw)


User.objects = _UserManager()

ROWS = []


class Notice:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        self.id = len(ROWS) + 1
        self.title = kw.get("title") or ""
        self.created_at = self.updated_at = NOW
        self.read_at = kw.get("read_at")

    def __repr__(self):
        return f"Notice({self.user.username}, {self.client_id}, {self.source})"


class _NoticeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kw):
        out = self.rows
        for key, value in kw.items():
            if key.endswith("__lt") or key.endswith("__isnull"):
                continue
            if key == "user_id":
                out = [r for r in out if r.user.pk == value]
            else:
                out = [r for r in out if getattr(r, key) == value]
        return _NoticeQuery(out)

    def delete(self):
        return (0, {})

    def order_by(self, *a):
        return self

    def values_list(self, *a, **k):
        return []

    def __getitem__(self, item):
        return []


class _NoticeManager:
    def get_or_create(self, user, client_id, defaults):
        for row in ROWS:
            if row.user is user and row.client_id == client_id:
                return row, False
        row = Notice(user=user, client_id=client_id, **defaults)
        ROWS.append(row)
        return row, True

    def filter(self, **kw):
        return _NoticeQuery(ROWS).filter(**kw)


Notice.objects = _NoticeManager()

PLUGINS = {
    "patching": SimpleNamespace(plugin_id="patching", plugin_type="extension"),
    "cyberhoot": SimpleNamespace(plugin_id="cyberhoot", plugin_type="extension"),
    "offmod": SimpleNamespace(plugin_id="offmod", plugin_type="extension"),
    "reports": SimpleNamespace(plugin_id="reports", plugin_type="reportset"),
    "tec-tac": SimpleNamespace(plugin_id="tec-tac", plugin_type="extension"),
    "a" * 40: SimpleNamespace(plugin_id="a" * 40, plugin_type="extension"),
}
ENABLED = {"offmod": False}

mod("django")
mod("django.db", transaction=SimpleNamespace(atomic=_Atomic()))
mod("django.db.models", Q=lambda *a, **k: None)
mod("django.utils")
mod("django.utils.timezone", now=lambda: NOW)
mod("django.contrib")
mod("django.contrib.auth", get_user_model=lambda: User)
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.models", TecTacUserNotice=Notice)
mod("tec_tac.registry", get_plugins=lambda: tuple(PLUGINS.values()))
mod("tec_tac.module_state", load_state=dict, is_enabled=lambda module_id, state=None: ENABLED.get(module_id, True))
sys.modules.update(mods)

spec = importlib.util.spec_from_file_location("tec_tac.notices", APP / "notices.py")
notices = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = notices
spec.loader.exec_module(notices)

alice = User(1, "alice")
bob = User(2, "bob")
User(3, "gone", active=False)
User(4, "installer", installer=True)
User(5, "agentuser", agent=True)
User(6, "blocked", blocked=True)


def refused(*args, **kw):
    try:
        notices.publish(*args, **kw)
    except notices.NoticeError as exc:
        must(isinstance(exc, ValueError), "NoticeError is a ValueError")
        return str(exc)
    raise AssertionError(f"publish was accepted: {args} {kw}")


# ---- a notice is stored with source = module id
del ROWS[:]
result = notices.publish(alice, "scan-done:42", "success", "The patch scan finished.", {"label": "Open Patching", "route": "/patching/runs/42"}, module_id="patching")
must(result["created"] is True and len(ROWS) == 1, result)
note = result["notice"]
must(note["source"] == "patching" and note["level"] == "success" and note["message"] == "The patch scan finished.", note)
must(note["action"] == {"label": "Open Patching", "route": "/patching/runs/42"} and note["read"] is False, note)
must(ROWS[0].client_id == "patching:scan-done:42" and ROWS[0].source == "patching", ROWS[0].client_id)
# a username works, and no action is fine
result = notices.publish("bob", "k1", "info", "Hello.", module_id="cyberhoot")
must(result["created"] and result["notice"]["action"] is None and ROWS[-1].user is bob, result)

# ---- dedupe on the namespaced key; a read notice is never reset
count = len(ROWS)
again = notices.publish(alice, "scan-done:42", "error", "Other text.", module_id="patching")
must(again["created"] is False and len(ROWS) == count and again["notice"]["message"] == "The patch scan finished.", again)
ROWS[0].read_at = NOW
again = notices.publish(alice, "scan-done:42", "success", "The patch scan finished.", module_id="patching")
must(again["created"] is False and again["notice"]["read"] is True and ROWS[0].read_at == NOW, "a read notice stays read")
# the same client_id from another module is another notice; the same module for another user is another notice
must(notices.publish(alice, "scan-done:42", "info", "Mine.", module_id="cyberhoot")["created"] is True, "namespaced by module")
must(notices.publish(bob, "scan-done:42", "info", "Yours.", module_id="patching")["created"] is True, "once per user")

# ---- module refusals
for name in ("core", "Core", "tec-tac", "TEC-TAC", " core "):
    refused(alice, "k", "info", "m", module_id=name)
refused(alice, "k", "info", "m", module_id="nosuchmodule")
refused(alice, "k", "info", "m", module_id="offmod")  # disabled
refused(alice, "k", "info", "m", module_id="reports")  # a reportset is not a module backend
for bad in ("", "  ", None, 5, ["patching"]):
    refused(alice, "k", "info", "m", module_id=bad)
try:
    notices.publish(alice, "k", "info", "m")
    raise AssertionError("module_id is required")
except TypeError:
    pass
# a registry failure is a refusal, not a crash
saved = mods["tec_tac.registry"].get_plugins
mods["tec_tac.registry"].get_plugins = lambda: (_ for _ in ()).throw(RuntimeError("broken"))
refused(alice, "k", "info", "m", module_id="patching")
mods["tec_tac.registry"].get_plugins = saved

# ---- user refusals
for who in (USERS[3], USERS[4], USERS[5], USERS[6], "gone", "installer", "agentuser", "blocked", "nobody", "", None, 5, SimpleNamespace(), SimpleNamespace(pk=99)):
    refused(who, "k", "info", "m", module_id="patching")
# a stale object is looked up again: an object that says it is active, but the database says no
stale = SimpleNamespace(pk=3, is_active=True, username="gone")
refused(stale, "k", "info", "m", module_id="patching")

# ---- level, text and key
for level in ("", "INFO", "critical", None, 5, "info "):
    refused(alice, "k", level, "m", module_id="patching")
refused(alice, "k", "info", "", module_id="patching")
refused(alice, "k", "info", "   ", module_id="patching")
refused(alice, "k", "info", None, module_id="patching")
refused(alice, "k", "info", "x" * 1001, module_id="patching")
must(notices.publish(alice, "k-max", "info", "x" * 1000, module_id="patching")["created"], "1000 characters is the limit")
for key in ("", "  ", None, 5, "bad key", "has/slash", "new\nline", "ü"):
    refused(alice, key, "info", "m", module_id="patching")
# "patching:" is 9 characters, so a key of 56 fits and 57 does not
must(notices.publish(alice, "k" * 55, "info", "m", module_id="patching")["created"], "55 + 9 = 64 fits")
refused(alice, "k" * 56, "info", "m", module_id="patching")
refused(alice, "k" * 30, "info", "m", module_id="a" * 40)  # 40 + 1 + 30 = 71

# ---- action rules
for action in ("/x", ["a"], 5, {"label": "L"}, {"label": "L", "route": ""}, {"label": "L", "route": "https://evil.example/x"},
               {"label": "L", "route": "//evil.example/x"}, {"label": "L", "route": "javascript:alert(1)"}, {"label": "L", "route": "relative/path"},
               {"label": "L", "route": "/ok\nx"}, {"label": "L", "route": "/ok", "extra": 1}, {"label": "x" * 61, "route": "/ok"},
               {"label": 5, "route": "/ok"}, {"label": "L", "route": 5}, {"route": "/x" * 300}):
    refused(alice, "k-act", "info", "m", action, module_id="patching")
ok = notices.publish(alice, "k-route-only", "info", "m", {"route": "/patching"}, module_id="patching")
must(ok["notice"]["action"] == {"label": "", "route": "/patching"}, ok)
must(notices.publish(alice, "k-none", "info", "m", {}, module_id="patching")["notice"]["action"] is None, "an empty action is no action")

# ---- never over HTTP, never from a browser
views_source = (APP / "notice_views.py").read_text(encoding="utf-8")
must("publish(" not in views_source.replace("publish_system_notice", "").replace("def publish", ""), "no view calls publish")
urls_source = (APP / "urls.py").read_text(encoding="utf-8")
must("notices.publish" not in urls_source, "no route")

# ---- the existing system-notice recipients still use the same filter
must(notices._interactive_users().filter(username="alice").first() is alice, "shared filter")
must(notices._interactive_users().filter(username="blocked").first() is None, "blocked users are excluded")

print("[TEST] PASS notices publish 1.17.16")
