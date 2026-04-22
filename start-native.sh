#!/bin/bash
# start-native.sh — starts the full Mirage stack natively (no Docker Compose needed)
# Use this when running in environments where Docker Compose is unavailable.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | grep -v '^$' | xargs)
fi

echo "=== Mirage Native Stack ==="

# ── 1. PostgreSQL ─────────────────────────────────────────────
echo "[1/4] PostgreSQL..."
if ! pg_isready -h localhost -p 5432 -q; then
  service postgresql start
  until pg_isready -h localhost -p 5432 -q; do sleep 1; done
fi
echo "      PostgreSQL OK"

# ── 2. Docker daemon ──────────────────────────────────────────
echo "[2/4] Docker daemon..."
if ! docker info -f "{{.ServerVersion}}" &>/dev/null; then
  dockerd \
    --host=unix:///var/run/docker.sock \
    --iptables=false \
    --ip-masq=false \
    --bridge=none \
    --data-root=/var/lib/docker \
    > /tmp/dockerd.log 2>&1 &
  until docker info -f "{{.ServerVersion}}" &>/dev/null; do sleep 1; done
fi
echo "      Docker OK ($(docker info -f '{{.ServerVersion}}' 2>/dev/null))"

# ── 3. Backend ────────────────────────────────────────────────
echo "[3/4] Backend..."
pkill -f "/tmp/mirage$" 2>/dev/null || true
sleep 1
go build -o /tmp/mirage ./cmd/mirage/ 2>&1

export DATABASE_URL="${DATABASE_URL:-postgres://mirage:mirage@localhost:5432/miragedb?sslmode=disable}"
export SERVER_PORT="${SERVER_PORT:-8443}"
export SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
export DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
export SANDBOX_IMAGE="${SANDBOX_IMAGE:-mirage-tools:latest}"
export CODEX_HOME="${CODEX_HOME:-/root/.codex}"
export OPENAI_MODEL="${OPENAI_MODEL:-gpt-5.4}"
export OPENAI_TEMPERATURE="${OPENAI_TEMPERATURE:-0.1}"
export AUTH_REQUIRED="${AUTH_REQUIRED:-false}"

/tmp/mirage > /tmp/mirage-backend.log 2>&1 &
BACKEND_PID=$!
until curl -sf http://localhost:${SERVER_PORT}/api/health &>/dev/null; do sleep 1; done
echo "      Backend OK (PID $BACKEND_PID)"

# ── 4. Frontend ───────────────────────────────────────────────
echo "[4/4] Frontend..."
pkill -f "vite" 2>/dev/null || true
sleep 1
cd frontend
VITE_API_URL="localhost:${SERVER_PORT}" \
VITE_WS_URL="ws://localhost:${SERVER_PORT}/ws" \
  npm run dev > /tmp/mirage-frontend.log 2>&1 &
FRONTEND_PID=$!
until grep -q "ready in" /tmp/mirage-frontend.log 2>/dev/null; do sleep 1; done
echo "      Frontend OK (PID $FRONTEND_PID)"
cd ..

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Mirage is running                       ║"
echo "║  Dashboard  →  http://localhost:3000      ║"
echo "║  API        →  http://localhost:8443      ║"
echo "║  WS         →  ws://localhost:8443/ws     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Logs:"
echo "  Backend  → /tmp/mirage-backend.log"
echo "  Frontend → /tmp/mirage-frontend.log"
echo "  Docker   → /tmp/dockerd.log"
echo ""
echo "To stop:  pkill -f '/tmp/mirage'; pkill -f vite"
