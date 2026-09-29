#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import ast
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]

def load(name, rel):
    spec=importlib.util.spec_from_file_location(name, ROOT/rel); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def must(cond,msg):
    if not cond: raise AssertionError(msg)

# F4: modules can read Tactical UI values from the real UI-context helper payload.
source=(ROOT/'framwork/tec_tac/account_self_service.py').read_text()
tree=ast.parse(source)
fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='tactical_ui_context')
module=ast.Module(body=[fn], type_ignores=[]); ast.fix_missing_locations(module)
ns={'Any':object,'_can_run_url_actions':lambda user: bool(getattr(user.role,'can_run_urlactions',False))}
exec(compile(module,'tactical_ui_context','exec'),ns)
user=SimpleNamespace(agent_dblclick_action='urlaction', url_action_id=77, role=SimpleNamespace(can_run_urlactions=True))
ctx=ns['tactical_ui_context'](user)
must(ctx=={'agent_dblclick_action':'urlaction','url_action_id':77,'can_run_url_actions':True}, f'wrong Tactical UI context: {ctx}')
views=(ROOT/'framwork/tec_tac/views.py').read_text()
must('"tactical_ui": tactical_ui_context(request.user)' in views, 'UiContextView does not publish Tactical UI values')

# F11: every /api/tfd endpoint receives a deterministic Swagger group, including modules.
api=load('openapi169','framwork/tec_tac/openapi.py')
schema={'tags':[{'name':'Tactical'}],'paths':{
 '/api/tfd/scheduler/schedules/':{'get':{'tags':['old']},'post':{}},
 '/api/tfd/resources/clients/':{'get':{}},
 '/api/tfd/alerts/events/':{'get':{'tags':['Alerts']}},
 '/api/v3/agents/':{'get':{'tags':['Agents']}},
}}
out=api.postprocess_tec_tac_groups(schema)
must(out['paths']['/api/tfd/scheduler/schedules/']['get']['tags']==['Tec-Tac · Scheduler'],'scheduler group missing')
must(out['paths']['/api/tfd/resources/clients/']['get']['tags']==['Tec-Tac · Clients, Sites & Agents'],'resource group missing')
must(out['paths']['/api/tfd/alerts/events/']['get']['tags']==['Tec-Tac Module · alerts'],'module group missing')
must(out['paths']['/api/v3/agents/']['get']['tags']==['Agents'],'Tactical endpoint tag was changed')
names={x['name'] for x in out['tags']}
must({'Tactical','Tec-Tac · Scheduler','Tec-Tac · Clients, Sites & Agents','Tec-Tac Module · alerts'} <= names,'top-level Swagger tag catalogue incomplete')
settings=SimpleNamespace(SPECTACULAR_SETTINGS={'TITLE':'Tactical RMM API'})
api.install_openapi_grouping(settings)
hooks=settings.SPECTACULAR_SETTINGS['POSTPROCESSING_HOOKS']
must(api.DEFAULT_ENUM_HOOK in hooks and api.GROUP_HOOK in hooks,'Swagger grouping did not preserve enum hook or install Tec-Tac hook')
print('[TEST] PASS F4 UI-context + F11 Swagger grouping')
