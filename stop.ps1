$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   🛑 Stopping Mirage Platform 🛑" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Write-Host "`nStopping and removing Docker containers..." -ForegroundColor Yellow
docker-compose down --timeout 5

Write-Host "Killing any lingering Node.js/Vite processes..." -ForegroundColor Yellow
Stop-Process -Name node -Force -ErrorAction SilentlyContinue

Write-Host "✅ All services completely stopped." -ForegroundColor Green
