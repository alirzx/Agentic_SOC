#!/usr/bin/env python3
"""Restore alerts + splunk_notable from image so API boots; keep hybrid SLA modules."""

from __future__ import annotations

import sys
from pathlib import Path

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"
ROOT = Path(__file__).resolve().parent


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)

    sftp = client.open_sftp()
    for local, remote in {
        ROOT / "services/api/app/services/sla.py": "/tmp/aisoc_sla_svc_sla.py",
        ROOT / "services/api/app/api/v1/endpoints/sla.py": "/tmp/aisoc_sla_ep_sla.py",
        ROOT / "apps/web/src/components/sla/SLADashboard.tsx": "/tmp/aisoc_sla_SLADashboard.tsx",
        ROOT / "services/api/app/services/splunk_notable.py": "/tmp/aisoc_splunk_notable.py",
        ROOT / "services/api/app/api/v1/endpoints/alerts.py": "/tmp/aisoc_alerts_local.py",
    }.items():
        print("PUT", remote)
        sftp.put(str(local), remote)
    sftp.close()

    # Use bash -s with password via SUDO_ASKPASS-less stdin carefully:
    remote = r"""
set -euo pipefail
cd /home/api/Agentic_SOC
API=$(docker ps -aqf name=aisoc-demo-api | head -1)
echo API=$API
# Prefer local workspace files that match each other (alerts + splunk_notable + sla)
printf '%s\n' "$PASS" | sudo -S cp /tmp/aisoc_alerts_local.py services/api/app/api/v1/endpoints/alerts.py
printf '%s\n' "$PASS" | sudo -S cp /tmp/aisoc_splunk_notable.py services/api/app/services/splunk_notable.py
printf '%s\n' "$PASS" | sudo -S cp /tmp/aisoc_sla_svc_sla.py services/api/app/services/sla.py
printf '%s\n' "$PASS" | sudo -S cp /tmp/aisoc_sla_ep_sla.py services/api/app/api/v1/endpoints/sla.py
printf '%s\n' "$PASS" | sudo -S chown api:api \
  services/api/app/api/v1/endpoints/alerts.py \
  services/api/app/services/splunk_notable.py \
  services/api/app/services/sla.py \
  services/api/app/api/v1/endpoints/sla.py
printf '%s\n' "$PASS" | sudo -S cp /tmp/aisoc_sla_SLADashboard.tsx apps/web/src/components/sla/SLADashboard.tsx || true

# Restore alert_queue from image (local may be fine but keep VM-compatible)
IMG=$(docker inspect -f '{{.Image}}' "$API")
CID=$(docker create "$IMG")
docker cp "$CID":/app/app/services/alert_queue.py /tmp/alert_queue_from_image.py
docker rm "$CID" >/dev/null
printf '%s\n' "$PASS" | sudo -S cp /tmp/alert_queue_from_image.py services/api/app/services/alert_queue.py
printf '%s\n' "$PASS" | sudo -S chown api:api services/api/app/services/alert_queue.py

docker cp services/api/app/api/v1/endpoints/alerts.py "$API":/app/app/api/v1/endpoints/alerts.py
docker cp services/api/app/services/splunk_notable.py "$API":/app/app/services/splunk_notable.py
docker cp services/api/app/services/sla.py "$API":/app/app/services/sla.py
docker cp services/api/app/api/v1/endpoints/sla.py "$API":/app/app/api/v1/endpoints/sla.py
docker cp services/api/app/services/alert_queue.py "$API":/app/app/services/alert_queue.py
docker restart "$API"
echo API_restarted
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  ST=$(docker inspect -f '{{.State.Status}}' "$API")
  EC=$(docker inspect -f '{{.State.ExitCode}}' "$API")
  echo wait_$i=$ST exit=$EC
  if [ "$ST" = running ]; then
    sleep 2
    ST2=$(docker inspect -f '{{.State.Status}}' "$API")
    if [ "$ST2" = running ]; then break; fi
  fi
  sleep 2
done
docker logs --tail 40 "$API" 2>&1 | tail -40
echo DONE
"""
    # Set PASS env for remote
    _stdin, stdout, stderr = client.exec_command(
        f"export PASS={PASSWORD!r}; bash -s <<'EOS'\n{remote}\nEOS",
        timeout=240,
    )
    # The above quoting is messy. Use channel with env instead:
    # Simpler: write script and run with env PASS=
    raise SystemExit("use_v2")


if __name__ == "__main__":
    # rewrite simpler
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    sftp = client.open_sftp()
    for local, remote in {
        ROOT / "services/api/app/services/sla.py": "/tmp/aisoc_sla_svc_sla.py",
        ROOT / "services/api/app/api/v1/endpoints/sla.py": "/tmp/aisoc_sla_ep_sla.py",
        ROOT / "apps/web/src/components/sla/SLADashboard.tsx": "/tmp/aisoc_sla_SLADashboard.tsx",
        ROOT / "services/api/app/services/splunk_notable.py": "/tmp/aisoc_splunk_notable.py",
        ROOT / "services/api/app/api/v1/endpoints/alerts.py": "/tmp/aisoc_alerts_local.py",
    }.items():
        print("PUT", remote)
        sftp.put(str(local), remote)
    script = """#!/bin/bash
set -euo pipefail
cd /home/api/Agentic_SOC
API=$(docker ps -aqf name=aisoc-demo-api | head -1)
echo API=$API
sudo -n true 2>/dev/null || true
sudo cp /tmp/aisoc_alerts_local.py services/api/app/api/v1/endpoints/alerts.py
sudo cp /tmp/aisoc_splunk_notable.py services/api/app/services/splunk_notable.py
sudo cp /tmp/aisoc_sla_svc_sla.py services/api/app/services/sla.py
sudo cp /tmp/aisoc_sla_ep_sla.py services/api/app/api/v1/endpoints/sla.py
sudo chown api:api services/api/app/api/v1/endpoints/alerts.py services/api/app/services/splunk_notable.py services/api/app/services/sla.py services/api/app/api/v1/endpoints/sla.py
sudo cp /tmp/aisoc_sla_SLADashboard.tsx apps/web/src/components/sla/SLADashboard.tsx || true
IMG=$(docker inspect -f '{{.Image}}' "$API")
CID=$(docker create "$IMG")
docker cp "$CID":/app/app/services/alert_queue.py /tmp/alert_queue_from_image.py
docker rm "$CID" >/dev/null
sudo cp /tmp/alert_queue_from_image.py services/api/app/services/alert_queue.py
sudo chown api:api services/api/app/services/alert_queue.py
docker cp services/api/app/api/v1/endpoints/alerts.py "$API":/app/app/api/v1/endpoints/alerts.py
docker cp services/api/app/services/splunk_notable.py "$API":/app/app/services/splunk_notable.py
docker cp services/api/app/services/sla.py "$API":/app/app/services/sla.py
docker cp services/api/app/api/v1/endpoints/sla.py "$API":/app/app/api/v1/endpoints/sla.py
docker cp services/api/app/services/alert_queue.py "$API":/app/app/services/alert_queue.py
docker restart "$API"
echo API_restarted
for i in $(seq 1 20); do
  ST=$(docker inspect -f '{{.State.Status}}' "$API")
  EC=$(docker inspect -f '{{.State.ExitCode}}' "$API")
  echo wait_$i=$ST exit=$EC
  if [ "$ST" = running ]; then sleep 3; ST2=$(docker inspect -f '{{.State.Status}}' "$API"); [ "$ST2" = running ] && break; fi
  sleep 2
done
docker logs --tail 50 "$API" 2>&1 | tail -50
echo DONE
"""
    with sftp.file("/tmp/aisoc_sla_bootfix.sh", "w") as f:
        f.write(script)
    sftp.chmod("/tmp/aisoc_sla_bootfix.sh", 0o755)
    sftp.close()

    # sudo needs password - use echo | sudo -S
    cmd = f"echo {PASSWORD!r} | sudo -S bash /tmp/aisoc_sla_bootfix.sh"
    # Better: printf
    cmd = "printf '%s\\n' " + repr(PASSWORD) + " | sudo -S bash /tmp/aisoc_sla_bootfix.sh"
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=300)
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
