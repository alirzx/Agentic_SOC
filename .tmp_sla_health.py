#!/usr/bin/env python3
from __future__ import annotations

import sys

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"

CHECK = r'''
import asyncio, traceback, uuid
from sqlalchemy import text
from app.db.database import AsyncSessionLocal
from app.services.sla import compute_sla_metrics

async def main():
    async with AsyncSessionLocal() as db:
        tid = (await db.execute(text("SELECT tenant_id FROM alerts LIMIT 1"))).scalar()
        print("tid", tid)
        m = await compute_sla_metrics(db, tid, days=30)
        print("OK", m["overall"])

try:
    asyncio.run(main())
except Exception:
    traceback.print_exc()
    raise
'''


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    sftp = client.open_sftp()
    with sftp.file("/tmp/aisoc_sla_m.py", "w") as f:
        f.write(CHECK)
    sftp.close()
    remote = r"""
set -euo pipefail
API=$(docker ps -qf name=aisoc-demo-api | head -1)
docker cp /tmp/aisoc_sla_m.py "$API":/tmp/aisoc_sla_m.py
docker exec -e PYTHONPATH=/app -w /app "$API" python /tmp/aisoc_sla_m.py
echo DONE
"""
    _stdin, stdout, stderr = client.exec_command(remote, timeout=180)
    sys.stdout.write(stdout.read().decode("utf-8", errors="replace"))
    sys.stderr.write(stderr.read().decode("utf-8", errors="replace"))
    raise SystemExit(stdout.channel.recv_exit_status())


if __name__ == "__main__":
    main()
