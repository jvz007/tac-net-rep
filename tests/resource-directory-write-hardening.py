#!/usr/bin/env python3
"""Behavioral M16/L44/L45 regression for the Tactical Resource adapter."""
from __future__ import annotations

import contextlib
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"

# Minimal Django stubs needed to load the real adapter.
django = types.ModuleType("django")
sys.modules["django"] = django
core = types.ModuleType("django.core")
exceptions = types.ModuleType("django.core.exceptions")
class ValidationError(Exception): pass
exceptions.ValidationError = ValidationError
sys.modules["django.core"] = core
sys.modules["django.core.exceptions"] = exceptions

db = types.ModuleType("django.db")
class IntegrityError(Exception): pass
class _Transaction:
    @staticmethod
    def atomic(): return contextlib.nullcontext()
db.IntegrityError = IntegrityError
db.transaction = _Transaction()
sys.modules["django.db"] = db
models_mod = types.ModuleType("django.db.models")
class Q:
    def __init__(self, *args, **kwargs): self.args=args; self.kwargs=kwargs
    def __or__(self, other): return self
models_mod.Q = Q
sys.modules["django.db.models"] = models_mod

spec = importlib.util.spec_from_file_location("resource_adapter_real", PKG / "resources_adapter.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)

CLIENTS = []
SITES = []

class Relation:
    def __init__(self, values=()): self.values=list(values)
    def exists(self): return bool(self.values)
    def all(self): return list(self.values)
    def add(self, value):
        if value not in self.values: self.values.append(value)
    def filter(self, pk=None, pk__in=None):
        vals=self.values
        if pk is not None: vals=[v for v in vals if getattr(v,"pk",v)==pk]
        if pk__in is not None: vals=[v for v in vals if getattr(v,"pk",v) in set(pk__in)]
        return Relation(vals)

class Role:
    is_superuser=False
    def __init__(self):
        self.can_view_clients=Relation()
        self.can_view_sites=Relation([object()])  # restricted role
class User:
    is_superuser=False
    is_authenticated=True
    username="operator"
    def __init__(self): self.role=Role()
    def get_and_set_role_cache(self): return self.role

class Query:
    def __init__(self, rows): self.rows=list(rows)
    def all(self): return Query(self.rows)
    def filter(self, **kwargs):
        rows=self.rows
        for key,val in kwargs.items():
            if key == "pk": rows=[r for r in rows if r.pk==val]
            elif key == "client_id": rows=[r for r in rows if r.client_id==val]
            elif key == "pk__in": rows=[r for r in rows if r.pk in set(val)]
        return Query(rows)
    def select_for_update(self): return self
    def first(self): return self.rows[0] if self.rows else None
    def exists(self): return bool(self.rows)
    def count(self): return len(self.rows)
    def values(self, *fields):
        return [{f: getattr(r, f) for f in fields} for r in self.rows]
    def values_list(self, *fields, flat=False):
        if flat: return [getattr(r, fields[0]) for r in self.rows]
        return [tuple(getattr(r, f) for f in fields) for r in self.rows]

class Manager:
    def __init__(self, source): self.source=source
    def all(self): return Query(self.source)
    def filter(self, **kwargs): return Query(self.source).filter(**kwargs)
    def select_for_update(self): return Query(self.source)

class Client:
    objects=Manager(CLIENTS)
    def __init__(self, name):
        self.pk=None; self.name=name; self.modified_by=None; self.modified_time=None; self.last_update_fields=None
    def full_clean(self, **kwargs):
        if self.name == "INVALID": raise ValidationError("bad client")
    def save(self, update_fields=None):
        self.last_update_fields=update_fields
        if self.pk is None:
            self.pk=(max([c.pk for c in CLIENTS], default=0)+1); CLIENTS.append(self)
        self.modified_by="operator"
    def __repr__(self): return f"Client({self.pk})"

class Site:
    objects=Manager(SITES)
    def __init__(self, client=None, client_id=None, name=""):
        self.pk=None; self.name=name; self.client=client
        self.client_id=client.pk if client is not None else client_id
        self.modified_by=None; self.modified_time=None; self.last_update_fields=None
    def full_clean(self, **kwargs):
        if self.name == "INVALID": raise ValidationError("bad site")
    def save(self, update_fields=None):
        self.last_update_fields=update_fields
        if self.pk is None:
            self.pk=(max([s.pk for s in SITES], default=0)+1); SITES.append(self)
        self.modified_by="operator"

class Agent: pass
adapter._models=lambda: (Client, Site, Agent)
adapter.site_write_in_scope=lambda *, user, site_id: any(s.pk == site_id for s in SITES)

user=User()
created=adapter.create_client_row(user=user, name="Gamma")
assert created["name"] == "Gamma"
client=CLIENTS[0]
assert len(SITES) == 1 and SITES[0].client_id == client.pk and SITES[0].name == "Default Site"
assert client in user.role.can_view_clients.values, "restricted creator was not added to new client scope"

# Client update keeps Tactical BaseAuditModel fields in update_fields.
updated=adapter.update_client_row(user=user, client_id=client.pk, name="Gamma Renamed")
assert updated["name"] == "Gamma Renamed"
assert set(client.last_update_fields) == {"name", "modified_by", "modified_time"}

# Last site cannot be moved away from its source client.
target=Client("Target"); target.save()
try:
    adapter.update_site_row(user=user, site_id=SITES[0].pk, client_id=target.pk)
    raise AssertionError("last site moved away from client")
except adapter.TacticalResourceValidationError as exc:
    assert "retain at least one site" in str(exc)

# Once source has another site, move is allowed and audit fields are persisted.
second=Site(client=client, name="Second"); second.save()
# Scope the existing site for the restricted role.
user.role.can_view_sites=Relation([SITES[0], second])
moved=adapter.update_site_row(user=user, site_id=SITES[0].pk, client_id=target.pk)
assert moved["client_id"] == target.pk
assert {"client", "modified_by", "modified_time"}.issubset(set(SITES[0].last_update_fields))

# Tactical model validation becomes stable adapter validation instead of a raw 500.
try:
    adapter.create_site_row(client_id=client.pk, name="INVALID")
    raise AssertionError("ValidationError leaked from adapter")
except adapter.TacticalResourceValidationError:
    pass

print("[TEST] PASS Resource Directory write hardening")
