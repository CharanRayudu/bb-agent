# Mirage - Start Script
# Starts: Docker containers (backend, db, sandbox) + local frontend dev server

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MIRAGE - Starting Services" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build the sandbox tools image
Write-Host "[1/4] Building mirage-tools image..." -ForegroundColor Yellow
$buildOut = docker build -t mirage-tools:latest -f build/tools/Dockerfile . 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to build mirage-tools" -ForegroundColor Red
    Write-Host $buildOut -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Tip: If the error is about 'fetch oauth token' or 'connection closed'," -ForegroundColor Yellow
    Write-Host "  Docker cannot reach Docker Hub (network/firewall/VPN). Try:" -ForegroundColor Yellow
    Write-Host "  - Retry in a few minutes" -ForegroundColor White
    Write-Host "  - Disable VPN or check firewall" -ForegroundColor White
    Write-Host "  - docker pull kalilinux/kali-rolling (to test connectivity)" -ForegroundColor White
    exit 1
}
Write-Host "  OK" -ForegroundColor Green

# Step 2: Start Docker containers (db, backend, sandbox)
Write-Host "[2/4] Starting Docker containers..." -ForegroundColor Yellow
$env:DOCKER_BUILDKIT = 0
docker compose up -d --build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to start containers" -ForegroundColor Red
    exit 1
}
Write-Host "  OK" -ForegroundColor Green

# Step 3: Wait for backend health
Write-Host "[3/4] Waiting for backend..." -ForegroundColor Yellow
$retries = 0
$maxRetries = 30
while ($retries -lt $maxRetries) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8443/api/flows" -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "  Backend is ready" -ForegroundColor Green
            break
        }
    }
    catch {
        Start-Sleep -Seconds 2
        $retries++
    }
}
if ($retries -ge $maxRetries) {
    Write-Host "  Backend did not respond in time" -ForegroundColor Red
}

# Step 4: Start frontend dev server locally
Write-Host "[4/4] Starting frontend dev server..." -ForegroundColor Yellow

# Kill any existing process on port 3000
$existing = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($existing) {
    $existing | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
}

# Install deps if needed
if (-not (Test-Path "frontend/node_modules")) {
    Write-Host "  Installing npm dependencies..." -ForegroundColor Yellow
    Push-Location frontend
    npm install 2>&1 | Out-Null
    Pop-Location
}

# Start Vite dev server in background
Start-Process -NoNewWindow -FilePath "cmd" -ArgumentList "/c", "cd frontend && npm run dev" -WorkingDirectory $PSScriptRoot -RedirectStandardOutput "frontend-dev.log" -RedirectStandardError "frontend-dev-err.log"
Start-Sleep -Seconds 3
Write-Host "  Frontend running at http://localhost:3000" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ALL SERVICES RUNNING" -ForegroundColor Green
Write-Host "  Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "  Backend:  http://localhost:8443" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Tail backend logs
Write-Host "Tailing backend logs (Ctrl+C to stop)..." -ForegroundColor DarkGray
docker logs -f mirage-backend
