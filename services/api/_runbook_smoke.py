import sys, uuid
sys.path.insert(0, '.')
from app.api.v1.endpoints.runbook import router, get_runbook
from app.api.v1.deps import DBSession
print('ROUTER_MOUNTS:', list(getattr(router, 'routes', []))[:1])
print('FUNC_NAME:', get_runbook.__name__)
print('DB_ALIAS_CHECK:', DBSession.__class__.__name__)
print('SMOKE_DONE')