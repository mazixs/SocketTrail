#!/usr/bin/env bash
# Smoke: the server starts and the API responds. Arguments are the launch command, e.g.
# packaging/smoke.sh target/release/sockettrail or packaging/smoke.sh wine sockettrail.exe
set -euo pipefail
PORT=${PORT:-8799}
URL=http://127.0.0.1:$PORT

"$@" --no-open --port "$PORT" &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  curl -sf "$URL/api/ping" >/dev/null && break
  kill -0 $PID 2>/dev/null || { echo "process exited before the server started"; exit 1; }
  sleep 1
done
curl -sf "$URL/api/ping" | grep '"sockettrail"' >/dev/null
curl -sf "$URL/api/state" >/dev/null
curl -sf "$URL/api/procs" | grep '"total"' >/dev/null
curl -sf "$URL/" | grep -i '<html' >/dev/null
echo "smoke ok"
