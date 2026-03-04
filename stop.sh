#!/usr/bin/env bash
set -euo pipefail

# Mirage - Stop Script (bash)
# Stops: Docker containers + local frontend dev server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "========================================"
echo "  MIRAGE - Stopping Services"
echo "========================================"
echo

# Step 1: Stop frontend dev server (port 3000)
echo "[1/3] Stopping frontend dev server..."
if command -v lsof >/dev/null 2>&1; then
  pids=$(lsof -ti:3000 || true)
  if [[ -n "${pids:-}" ]]; then
    kill -9 $pids 2>/dev/null || true
    echo "  Frontend stopped"
  else
    echo "  Frontend was not running"
  fi
else
  echo "  lsof not found; skipping port-based frontend shutdown"
fi

# Also kill any node processes from this project (best-effort)
if command -v pgrep >/dev/null 2>&1; then
  pgrep -f "bb-agent.*node" >/dev/null 2>&1 && pkill -f "bb-agent.*node" || true
fi

# Step 2: Stop Docker containers
echo "[2/3] Stopping Docker containers..."
docker compose down >/dev/null 2>&1 || true
echo "  Containers stopped"

# Step 3: Free port 8443 if still held
echo "[3/3] Cleaning up ports..."
if command -v lsof >/dev/null 2>&1; then
  pids8443=$(lsof -ti:8443 || true)
  if [[ -n "${pids8443:-}" ]]; then
    kill -9 $pids8443 2>/dev/null || true
    echo "  Port 8443 freed"
  else
    echo "  Ports clean"
  fi
else
  echo "  lsof not found; skipping backend port cleanup"
fi

# Clean up log files
rm -f "$SCRIPT_DIR/frontend-dev.log" "$SCRIPT_DIR/frontend-dev-err.log"

echo
echo "========================================"
echo "  ALL SERVICES STOPPED"
echo "========================================"
echo

