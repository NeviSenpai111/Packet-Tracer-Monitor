#!/usr/bin/env bash
# Launch the packet tracer. Packet capture needs raw-socket privileges, so this
# runs uvicorn under sudo using the venv's Python.
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "venv not found. Run: python -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

HOST="${PT_HOST:-127.0.0.1}"
PORT="${PT_PORT:-8000}"

echo "Starting Packet Tracer on http://${HOST}:${PORT} (sudo required for capture)…"
exec sudo -E "$PY" -m uvicorn packettracer.server:app --host "$HOST" --port "$PORT"
