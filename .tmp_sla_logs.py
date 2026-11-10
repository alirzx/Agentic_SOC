#!/usr/bin/env python3
from __future__ import annotations

import sys

import paramiko

HOST, USER, PASSWORD = "192.168.0.55", "api", "Tow3e@kmha%$#"

REMOTE = r"""
set +e
API=$(docker ps -aqf name=aisoc-demo-api | head -1)
echo API=$API
docker ps -a --filter name=aisoc-demo-api --format '{{.ID}} {{.Status}}'
echo '--- logs ---'
docker logs --tail 80 "$API" 2>&1
echo DONE
"""


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20, allow_agent=False, look_for_keys=False)
    _stdin, stdout, stderr = client.exec_command(REMOTE, timeout=60)
    sys.stdout.write(stdout.read().decode("utf-8", errors="replace"))
    sys.stderr.write(stderr.read().decode("utf-8", errors="replace"))
    raise SystemExit(stdout.channel.recv_exit_status())


if __name__ == "__main__":
    main()
