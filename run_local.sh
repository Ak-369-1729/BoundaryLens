#!/usr/bin/env bash
# Start the two demo configurations and the scanner backend locally (no Docker).
set -euo pipefail
cd "$(dirname "$0")"
set -a; [ -f .env ] && . ./.env; set +a
PY=".venv/bin/python"
export PYTHONPATH="$PWD/scanner:$PWD/demo_app"
mkdir -p .run
LEDGERLY_MODE=vulnerable $PY -m uvicorn ledgerly.app:create_app --factory --host 127.0.0.1 --port 8081 --log-level warning &
echo $! > .run/vuln.pid
LEDGERLY_MODE=fixed $PY -m uvicorn ledgerly.app:create_app --factory --host 127.0.0.1 --port 8082 --log-level warning &
echo $! > .run/fixed.pid
$PY -m uvicorn boundarylens.app:app --host "${BL_HOST:-127.0.0.1}" --port "${BL_PORT:-8080}" --log-level warning &
echo $! > .run/backend.pid
echo "BoundaryLens dashboard: http://${BL_HOST:-127.0.0.1}:${BL_PORT:-8080}"
echo "Stop with: ./stop_local.sh"
wait
