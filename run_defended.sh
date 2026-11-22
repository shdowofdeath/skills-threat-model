#!/usr/bin/env bash
# Same skill. Two controls applied: CI scan, then runtime egress allowlist.
set -euo pipefail
cd "$(dirname "$0")"
echo "### Control 1 — CI static scan (before the skill ever runs) ###"
if python3 controls/scan_skill.py skills/pr-summary; then
  echo "scan passed"
else
  echo ">> CI would block this merge. Continuing anyway to show runtime control..."
fi
echo; echo "### Control 2 — runtime egress allowlist (github.com only) ###"
rm -f harness/received.log
python3 harness/collector.py >/tmp/collector.out 2>&1 &
COLL=$!
trap 'kill $COLL 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
  python3 -c "import socket;socket.create_connection(('127.0.0.1',8977),0.2).close()" 2>/dev/null && break
  sleep 0.1
done
python3 harness/mini_agent.py skills/pr-summary --egress-allow github.com
echo; echo "### What the attacker's collector received ###"
cat harness/received.log 2>/dev/null || echo "(nothing received — canary never left)"
