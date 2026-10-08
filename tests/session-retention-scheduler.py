#!/usr/bin/env python3
"""D4 regression: the existing Scheduler tick invokes Core session retention."""
from __future__ import annotations
import importlib.util, sys, types
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/'framwork'/'tec_tac'/'management'/'commands'/'tec_tac_scheduler_tick.py'

base=types.ModuleType('django.core.management.base')
class Out:
    def __init__(self): self.lines=[]
    def write(self, value): self.lines.append(str(value))
class BaseCommand:
    def __init__(self): self.stdout=Out(); self.stderr=Out()
base.BaseCommand=BaseCommand
sys.modules['django']=types.ModuleType('django')
sys.modules['django.core']=types.ModuleType('django.core')
sys.modules['django.core.management']=types.ModuleType('django.core.management')
sys.modules['django.core.management.base']=base

pkg=types.ModuleType('tec_tac'); pkg.__path__=[str(ROOT/'framwork'/'tec_tac')]; sys.modules['tec_tac']=pkg
scheduler=types.ModuleType('tec_tac.scheduler')
scheduler.dispatch_due_schedules=lambda: {'checked':2,'queued':['q'],'skipped':[],'cleaned':0,'now':'test-now'}
sys.modules['tec_tac.scheduler']=scheduler
calls=[]
security=types.ModuleType('tec_tac.session_security')
def cleanup(): calls.append('cleanup'); return {'ran':True}
security.cleanup_session_history_if_due=cleanup
security.sweep_expired_sessions=lambda: {'revoked':0,'skipped_no_digest':0,'orphan_tokens_deleted':0}
sys.modules['tec_tac.session_security']=security

spec=importlib.util.spec_from_file_location('tec_tac.management.commands.tec_tac_scheduler_tick', MODULE)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
cmd=mod.Command(); cmd.handle()
assert calls == ['cleanup'], calls
assert any('session_history_cleanup=ran' in line for line in cmd.stdout.lines), cmd.stdout.lines

# Failure must not take down the general scheduler tick and must be visible.
def fail_cleanup(): calls.append('failed'); raise RuntimeError('db unavailable')
security.cleanup_session_history_if_due=fail_cleanup
mod.cleanup_session_history_if_due=fail_cleanup
cmd2=mod.Command(); cmd2.handle()
assert any('session_history_cleanup=error' in line for line in cmd2.stdout.lines), cmd2.stdout.lines
assert any('retrying next tick' in line for line in cmd2.stderr.lines), cmd2.stderr.lines
assert any('session_expiry_sweep=ran' in line for line in cmd.stdout.lines), cmd.stdout.lines

# 1.17.1: a failing expiry sweep is isolated the same way.
def fail_sweep(): raise RuntimeError('sweep down')
mod.sweep_expired_sessions=fail_sweep
cmd3=mod.Command(); cmd3.handle()
assert any('session_expiry_sweep=error' in line for line in cmd3.stdout.lines), cmd3.stdout.lines

print('[TEST] PASS D4 scheduler tick invokes retention and isolates cleanup failures')
