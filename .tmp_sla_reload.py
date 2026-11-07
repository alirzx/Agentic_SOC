#!/usr/bin/env python3
from __future__ import annotations

import sys
import time

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    remote = r"""
set -euo pipefail
API=$(docker ps -qf name=aisoc-demo-api | head -1)
WEB=$(docker ps -qf name=aisoc-demo-web | head -1)
docker cp /home/api/Agentic_SOC/services/api/app/services/sla.py "$API":/app/app/services/sla.py
docker cp /home/api/Agentic_SOC/services/api/app/api/v1/endpoints/sla.py "$API":/app/app/api/v1/endpoints/sla.py
docker cp /home/api/Agentic_SOC/apps/web/src/components/sla/SLADashboard.tsx "$WEB":/app/apps/web/src/components/sla/SLADashboard.tsx 2>/dev/null \
  || docker cp /home/api/Agentic_SOC/apps/web/src/components/sla/SLADashboard.tsx "$WEB":/app/src/components/sla/SLADashboard.tsx 2>/dev/null \
  || echo WEB_path_skip
docker restart "$API"
docker restart "$WEB" || true
echo restarted
for i in $(seq 1 25); do
  ST=$(docker inspect -f '{{.State.Status}}' "$API")
  echo api_$i=$ST
  if [ "$ST" = running ]; then
    sleep 5
    ST2=$(docker inspect -f '{{.State.Status}}' "$API")
    [ "$ST2" = running ] && break
  fi
  sleep 2
done
# hit metrics via curl inside compose network if possible
docker exec "$API" python - <<'PY'
import urllib.request
try:
    # health
    print('health', urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status)
except Exception as e:
    print('health_err', e)
PY
docker logs --tail 15 "$API" 2>&1 | tail -15
echo DONE
"""
    _stdin, stdout, stderr = client.exec_command(remote, timeout=300)
    while True:
        line = stdout.readline()
        if not line:
            break
        sys.stdout.write(line)
        sys.stdout.flush()
    err = stderr.read().decode("utf-8", errors="replace")
    if err:
        sys.stderr.write(err)
    raise SystemExit(stdout.channel.recv_exit_status())


if __name__ == "__main__":
    main()
