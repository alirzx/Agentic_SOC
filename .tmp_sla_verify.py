#!/usr/bin/env python3
from __future__ import annotations

import sys
import time

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"

CHECK_PY = r'''
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import uuid
from app.services.sla import durations_from_alert, compute_sla_metrics
print("doc_has_prefer", "Prefer" in (compute_sla_metrics.__doc__ or ""))
detected = datetime.now(UTC) - timedelta(hours=3)
alert = SimpleNamespace(
    id=uuid.uuid4(),
    severity="high",
    status="resolved",
    first_seen=detected,
    created_at=detected,
    event_time=detected,
    first_seen_at=detected + timedelta(minutes=8),
    assigned_at=detected + timedelta(minutes=8),
    resolved_at=detected + timedelta(minutes=40),
    updated_at=detected + timedelta(minutes=40),
)
print("durations", durations_from_alert(alert))

import asyncio
from sqlalchemy import text
from app.db.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text(
            "SELECT tenant_id::text, count(*) FROM alerts GROUP BY tenant_id ORDER BY count(*) DESC LIMIT 1"
        ))).first()
        if not row:
            print("NO_ALERTS")
            return
        tid, cnt = row[0], row[1]
        print("tenant", tid, "alerts", cnt)
        metrics = await compute_sla_metrics(db, uuid.UUID(tid), days=30)
        o = metrics["overall"]
        print(
            "metrics_total", o.get("total_alerts"),
            "breaches", o.get("total_breaches"),
            "mttd", o.get("mttd_avg"),
            "mttr", o.get("mttr_avg"),
            "source", o.get("data_source"),
        )
        for sev, s in metrics["per_severity"].items():
            if s["total"]:
                print(f"sev {sev} total={s['total']} breaches={s['breaches']} mttd={s['mttd_avg']} mttr={s['mttr_avg']}")

asyncio.run(main())
'''


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    sftp = client.open_sftp()
    with sftp.file("/tmp/aisoc_sla_check.py", "w") as f:
        f.write(CHECK_PY)
    sftp.close()

    # Ensure files in container again without full restart if already running
    remote = r"""
set -euo pipefail
API=$(docker ps -qf name=aisoc-demo-api | head -1)
echo API=$API status=$(docker inspect -f '{{.State.Status}}' "$API")
# force-copy critical modules again
docker cp /home/api/Agentic_SOC/services/api/app/services/sla.py "$API":/app/app/services/sla.py
docker cp /home/api/Agentic_SOC/services/api/app/api/v1/endpoints/sla.py "$API":/app/app/api/v1/endpoints/sla.py
docker cp /home/api/Agentic_SOC/services/api/app/services/splunk_notable.py "$API":/app/app/services/splunk_notable.py
docker cp /home/api/Agentic_SOC/services/api/app/api/v1/endpoints/alerts.py "$API":/app/app/api/v1/endpoints/alerts.py
docker cp /tmp/aisoc_sla_check.py "$API":/tmp/aisoc_sla_check.py
# verify hydrate exists
docker exec "$API" grep -c 'def hydrate_alert_for_detail' /app/app/services/splunk_notable.py || true
docker exec "$API" grep -c hybrid_alerts_and_sla_events /app/app/services/sla.py || true
# if not running, restart
ST=$(docker inspect -f '{{.State.Status}}' "$API")
if [ "$ST" != running ]; then docker start "$API"; sleep 8; fi
# wait healthy
for i in $(seq 1 20); do
  ST=$(docker inspect -f '{{.State.Status}}' "$API")
  echo wait=$i $ST
  [ "$ST" = running ] && break
  sleep 2
done
docker exec -e PYTHONPATH=/app -w /app "$API" python /tmp/aisoc_sla_check.py
echo DONE
"""
    _stdin, stdout, stderr = client.exec_command(remote, timeout=240)
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
