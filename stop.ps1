# Mirage - Stop Script
# Stops: Docker containers + local frontend dev server

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MIRAGE - Stopping Services" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Stop frontend dev server (port 3000)
Write-Host "[1/3] Stopping frontend dev server..." -ForegroundColor Yellow
$frontendProcs = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($frontendProcs) {
    $frontendProcs | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  Frontend stopped" -ForegroundColor Green
}
else {
    Write-Host "  Frontend was not running" -ForegroundColor DarkGray
}

# Also kill any node processes from this project
Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*bb-agent*" -or $_.CommandLine -like "*bb-agent*"
} | Stop-Process -Force -ErrorAction SilentlyContinue

# Step 2: Stop Docker containers
Write-Host "[2/3] Stopping Docker containers..." -ForegroundColor Yellow
docker compose down 2>&1 | Out-Null
Write-Host "  Containers stopped" -ForegroundColor Green

# Step 3: Free port 8443 if still held
Write-Host "[3/3] Cleaning up ports..." -ForegroundColor Yellow
$backendProcs = Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue
if ($backendProcs) {
    $backendProcs | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  Port 8443 freed" -ForegroundColor Green
}
else {
    Write-Host "  Ports clean" -ForegroundColor DarkGray
}

# Clean up log files
Remove-Item -Path "frontend-dev.log" -ErrorAction SilentlyContinue
Remove-Item -Path "frontend-dev-err.log" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ALL SERVICES STOPPED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
