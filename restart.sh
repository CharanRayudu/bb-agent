#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NO_CACHE=0
if [[ "${1:-}" == "--no-cache" ]]; then
  NO_CACHE=1
fi

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

echo
echo "========================================"
echo "  MIRAGE - Full Restart"
echo "========================================"
echo

echo "[1/6] Stopping frontend dev server..."
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

if command -v pgrep >/dev/null 2>&1; then
  pgrep -f "bb-agent.*node" >/dev/null 2>&1 && pkill -f "bb-agent.*node" || true
fi

rm -f "$SCRIPT_DIR/frontend-dev.log" "$SCRIPT_DIR/frontend-dev-err.log"

echo "[2/6] Stopping Docker containers..."
docker compose down --remove-orphans >/dev/null 2>&1 || true
echo "  Containers stopped"

echo "[3/6] Rebuilding mirage-tools image..."
if (( NO_CACHE == 1 )); then
  if ! docker build --no-cache -t mirage-tools:latest -f build/tools/Dockerfile . >/dev/null; then
    if image_exists "mirage-tools:latest"; then
      echo "  Rebuild failed, but existing mirage-tools:latest image is available. Reusing it."
    else
      echo "  FAILED to rebuild mirage-tools and no local fallback image exists"
      exit 1
    fi
  else
    echo "  mirage-tools rebuilt"
  fi
else
  if ! docker build -t mirage-tools:latest -f build/tools/Dockerfile . >/dev/null; then
    if image_exists "mirage-tools:latest"; then
      echo "  Rebuild failed, but existing mirage-tools:latest image is available. Reusing it."
    else
      echo "  FAILED to rebuild mirage-tools and no local fallback image exists"
      exit 1
    fi
  else
    echo "  mirage-tools rebuilt"
  fi
fi

echo "[4/6] Rebuilding backend and recreating containers..."
if (( NO_CACHE == 1 )); then
  docker compose build --no-cache backend >/dev/null
fi
docker compose up -d --build --force-recreate >/dev/null 2>&1
docker image prune -f >/dev/null 2>&1 || true
echo "  Containers recreated with fresh backend image"

echo "[5/6] Waiting for backend..."
retries=0
max_retries=45
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
  exit 1
fi

echo "[6/6] Restarting frontend dev server..."
if [[ ! -d "frontend/node_modules" ]]; then
  echo "  Installing npm dependencies..."
  (cd frontend && npm install >/dev/null 2>&1)
fi

(
  cd frontend
  npm run dev >"$SCRIPT_DIR/frontend-dev.log" 2>"$SCRIPT_DIR/frontend-dev-err.log"
) &

sleep 3
echo "  Frontend running at http://localhost:3000"

echo
echo "========================================"
echo "  FULL RESTART COMPLETE"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8443"
if (( NO_CACHE == 1 )); then
  echo "  Build Mode: no-cache"
else
  echo "  Build Mode: cached rebuild"
fi
echo "========================================"
echo

echo "Tailing backend logs (Ctrl+C to stop)..."
docker logs -f mirage-backend
