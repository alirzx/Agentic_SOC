#!/usr/bin/env python3
"""Sync SLA Tracking fixes to the lab VM and restart API/web containers."""

from __future__ import annotations

import sys
from pathlib import Path

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"
ROOT = Path(__file__).resolve().parent

MAPPING = {
    "services/api/app/services/sla.py": "/tmp/aisoc_sla_svc_sla.py",
    "services/api/app/api/v1/endpoints/sla.py": "/tmp/aisoc_sla_ep_sla.py",
    "services/api/app/services/alert_queue.py": "/tmp/aisoc_sla_alert_queue.py",
    "services/api/app/api/v1/endpoints/alerts.py": "/tmp/aisoc_sla_alerts.py",
    "apps/web/src/components/sla/SLADashboard.tsx": "/tmp/aisoc_sla_SLADashboard.tsx",
    "services/api/tests/services/test_sla.py": "/tmp/aisoc_sla_test_sla.py",
}


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    sftp = client.open_sftp()
    for rel, tmp in MAPPING.items():
        print(f"PUT {rel} -> {tmp}")
        sftp.put(str(ROOT / rel), tmp)
    sftp.close()

    lines = [
        "set -euo pipefail",
        "cd /home/api/Agentic_SOC",
        f"echo '{PASSWORD}' | sudo -S true >/dev/null",
    ]
    for rel, tmp in MAPPING.items():
        lines.append(f"sudo cp {tmp} {rel}")
        lines.append(f"sudo chown api:api {rel}")
    lines.extend(
        [
            'API=$(docker ps -qf name=aisoc-demo-api | head -1)',
            'WEB=$(docker ps -qf name=aisoc-demo-web | head -1)',
            'echo "API=$API WEB=$WEB"',
            '[ -n "$API" ]',
            'docker cp services/api/app/services/sla.py "$API":/app/app/services/sla.py',
            'docker cp services/api/app/api/v1/endpoints/sla.py "$API":/app/app/api/v1/endpoints/sla.py',
            'docker cp services/api/app/services/alert_queue.py "$API":/app/app/services/alert_queue.py',
            'docker cp services/api/app/api/v1/endpoints/alerts.py "$API":/app/app/api/v1/endpoints/alerts.py',
            'docker restart "$API"',
            'echo API_restarted',
            'if [ -n "$WEB" ]; then',
            '  docker cp apps/web/src/components/sla/SLADashboard.tsx "$WEB":/app/apps/web/src/components/sla/SLADashboard.tsx 2>/dev/null \\',
            '    || docker cp apps/web/src/components/sla/SLADashboard.tsx "$WEB":/app/src/components/sla/SLADashboard.tsx 2>/dev/null \\',
            '    || echo WEB_dashboard_path_unknown',
            '  docker restart "$WEB" || true',
            '  echo WEB_restarted',
            'fi',
            'sleep 12',
            'docker exec -i "$API" python - <<\'PY\'',
            "from datetime import UTC, datetime, timedelta",
            "from types import SimpleNamespace",
            "import uuid",
            "from app.services.sla import durations_from_alert, DEFAULT_SLA_TARGETS, compute_sla_metrics",
            "detected = datetime.now(UTC) - timedelta(hours=3)",
            "alert = SimpleNamespace(",
            "    id=uuid.uuid4(), severity='high', status='resolved',",
            "    first_seen=detected, created_at=detected, event_time=detected,",
            "    first_seen_at=detected + timedelta(minutes=8),",
            "    assigned_at=detected + timedelta(minutes=8),",
            "    resolved_at=detected + timedelta(minutes=40),",
            "    updated_at=detected + timedelta(minutes=40),",
            ")",
            "d = durations_from_alert(alert)",
            "assert d['mttd'] == 8 and d['mttr'] == 40, d",
            "print('durations_from_alert OK', d)",
            "print('DEFAULT critical MTTD', DEFAULT_SLA_TARGETS['critical']['mttd_target'])",
            "print('hybrid_fn', compute_sla_metrics.__name__)",
            "print('SLA modules loaded OK')",
            "PY",
            "echo DONE",
        ]
    )
    remote_script = "\n".join(lines) + "\n"
    _stdin, stdout, stderr = client.exec_command(remote_script, timeout=300)
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
