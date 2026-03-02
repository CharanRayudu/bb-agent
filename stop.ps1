$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   🛑 Stopping Mirage Platform 🛑" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Write-Host "`nStopping and removing Docker containers..." -ForegroundColor Yellow
docker-compose down

Write-Host "`n✅ All backend services completely stopped." -ForegroundColor Green
