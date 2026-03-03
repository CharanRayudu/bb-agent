$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   🚀 Starting Mirage Platform 🚀" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Building & Starting Docker Services (Database, Backend, Sandbox)..." -ForegroundColor Yellow
docker-compose up -d --build postgres backend sandbox

Write-Host "`n[2/2] Starting Frontend Development Server..." -ForegroundColor Yellow

# Check for lingering processes on port 3000
$port3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($port3000) {
    Write-Host "⚠️  Port 3000 is occupied. Cleaning up..." -ForegroundColor Yellow
    Stop-Process -Id $port3000.OwningProcess -Force -ErrorAction SilentlyContinue
}

Set-Location -Path "frontend"
if (-Not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Gray
    npm install
}

Write-Host "`n✅ Mirage is starting up! The frontend will be available at http://localhost:3000" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the frontend server.`n" -ForegroundColor DarkGray

npm run dev
