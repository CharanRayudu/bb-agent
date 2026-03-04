#!/usr/bin/env bash
set -euo pipefail

# Mirage - Start Script (bash)
# Starts: Docker containers (backend, db, sandbox) + local frontend dev server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "========================================"
echo "  MIRAGE - Starting Services"
echo "========================================"
echo

# Step 1: Build the sandbox tools image
echo "[1/4] Building mirage-tools image..."
if ! build_out=$(docker build -t mirage-tools:latest -f build/tools/Dockerfile . 2>&1); then
  echo "  FAILED to build mirage-tools"
  printf '%s\n' "$build_out"
  echo
  echo "  Tip: If the error is about 'fetch oauth token' or 'connection closed',"
  echo "  Docker cannot reach Docker Hub (network/firewall/VPN). Try:"
  echo "  - Retry in a few minutes"
  echo "  - Disable VPN or check firewall"
  echo "  - docker pull kalilinux/kali-rolling   (to test connectivity)"
  exit 1
fi
echo "  OK"

# Step 2: Start Docker containers (db, backend, sandbox)
echo "[2/4] Starting Docker containers..."
export DOCKER_BUILDKIT=0
if ! docker compose up -d --build >/dev/null 2>&1; then
  echo "  FAILED to start containers"
  exit 1
fi
echo "  OK"

# Step 3: Wait for backend health
echo "[3/4] Waiting for backend..."
retries=0
max_retries=30
while (( retries < max_retries )); do
  if curl -sf "http://localhost:8443/api/flows" >/dev/null 2>&1; then
    echo "  Backend is ready"
    break
  fi
  sleep 2
  retries=$((retries + 1))
done
if (( retries >= max_retries )); then
  echo "  Backend did not respond in time"
fi

# Step 4: Start frontend dev server locally
echo "[4/4] Starting frontend dev server..."

# Kill any existing process on port 3000
if command -v lsof >/dev/null 2>&1; then
  pids=$(lsof -ti:3000 || true)
  if [[ -n "${pids:-}" ]]; then
    echo "  Killing processes on port 3000..."
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
fi

# Install deps if needed
if [[ ! -d "frontend/node_modules" ]]; then
  echo "  Installing npm dependencies..."
  (cd frontend && npm install >/dev/null 2>&1)
fi

# Start Vite dev server in background
echo "  Launching Vite dev server..."
(
  cd frontend
  npm run dev >"$SCRIPT_DIR/frontend-dev.log" 2>"$SCRIPT_DIR/frontend-dev-err.log"
) &

sleep 3
echo "  Frontend running at http://localhost:3000"

echo
echo "========================================"
echo "  ALL SERVICES RUNNING"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8443"
echo "========================================"
echo

echo "Tailing backend logs (Ctrl+C to stop)..."
docker logs -f mirage-backend

