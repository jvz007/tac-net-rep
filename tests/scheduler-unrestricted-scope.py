#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = ROOT / 'framwork/tec_tac/resources_adapter.py'

# Minimal Django stubs: this regression exercises only adapter scope logic.
django = types.ModuleType('django'); sys.modules['django'] = django
db = types.ModuleType('django.db'); db.IntegrityError = type('IntegrityError',(Exception,),{}); db.transaction = types.SimpleNamespace(atomic=lambda: None); sys.modules['django.db'] = db
models = types.ModuleType('django.db.models')
class Q:
    def __init__(self,*a,**k): pass
    def __or__(self,other): return self
models.Q = Q; sys.modules['django.db.models'] = models

spec = importlib.util.spec_from_file_location('resources_adapter_scope_test', TARGET)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class Values(list):
    def values_list(self, field, flat=False):
        assert field == 'pk' and flat
        return [row['pk'] for row in self]
    def exists(self): return bool(self)

class Relation:
    def __init__(self, ids): self.ids=set(ids)
    def exists(self): return bool(self.ids)
    def filter(self, **kwargs):
        ids = kwargs.get('pk__in')
        if ids is not None: return Values([{'pk': i} for i in self.ids if i in set(ids)])
        pk = kwargs.get('pk')
        return Values([{'pk': pk}]) if pk in self.ids else Values([])

class ClientQS:
    existing={1,2,3}
    def filter(self, **kwargs):
        ids=kwargs.get('pk__in')
        if ids is not None: return Values([{'pk':i} for i in self.existing if i in set(ids)])
        pk=kwargs.get('pk')
        return Values([{'pk':pk}]) if pk in self.existing else Values([])
class Client: objects=ClientQS()

class SiteValues(list):
    def values(self, *fields): return self
    def first(self): return self[0] if self else None
    def exists(self): return bool(self)
class SiteQS:
    rows={10:1,20:2,30:3}
    def filter(self, **kwargs):
        pk=kwargs.get('pk')
        if pk in self.rows: return SiteValues([{'pk':pk,'client_id':self.rows[pk]}])
        return SiteValues([])
class Site: objects=SiteQS()
class Agent: pass
mod._models=lambda:(Client,Site,Agent)

class Role:
    def __init__(self, clients=(), sites=(), superuser=False):
        self.can_view_clients=Relation(clients); self.can_view_sites=Relation(sites); self.is_superuser=superuser
class User:
    is_superuser=False
    def __init__(self, role): self.role=role
    def get_and_set_role_cache(self): return self.role

# No client or site restrictions => full Tactical scope.
unrestricted=User(Role())
assert mod._role_scope_unrestricted(user=unrestricted)
assert mod.explicit_client_target_ids_in_scope(user=unrestricted, client_ids=[1,2,999]) == {1,2}
assert mod.client_write_in_scope(user=unrestricted, client_id=1)
assert mod.site_write_in_scope(user=unrestricted, site_id=10)

# A site-only role is restricted; parent-client visibility is not whole-client authority.
site_only=User(Role(sites=[10]))
assert not mod._role_scope_unrestricted(user=site_only)
assert mod.explicit_client_target_ids_in_scope(user=site_only, client_ids=[1]) == set()
assert not mod.client_write_in_scope(user=site_only, client_id=1)
assert mod.site_write_in_scope(user=site_only, site_id=10)
assert not mod.site_write_in_scope(user=site_only, site_id=20)

# Explicit client scope authorizes that client and all its sites, but nothing else.
client_only=User(Role(clients=[2]))
assert mod.explicit_client_target_ids_in_scope(user=client_only, client_ids=[1,2]) == {2}
assert mod.client_write_in_scope(user=client_only, client_id=2)
assert not mod.client_write_in_scope(user=client_only, client_id=1)
assert mod.site_write_in_scope(user=client_only, site_id=20)
assert not mod.site_write_in_scope(user=client_only, site_id=10)

print('scheduler unrestricted Tactical scope: PASS')
