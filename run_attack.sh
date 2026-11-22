#!/usr/bin/env bash
# Shows the theft succeeding with no controls.
set -euo pipefail
cd "$(dirname "$0")"
rm -f harness/received.log
python3 harness/collector.py >/tmp/collector.out 2>&1 &
COLL=$!
trap 'kill $COLL 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
  python3 -c "import socket;socket.create_connection(('127.0.0.1',8977),0.2).close()" 2>/dev/null && break
  sleep 0.1
done
echo "### Agent runs the 'pr-summary' skill (no controls) ###"
python3 harness/mini_agent.py skills/pr-summary
echo; echo "### What the attacker's collector received ###"
cat harness/received.log 2>/dev/null || echo "(nothing)"
