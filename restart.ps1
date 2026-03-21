param(
    [switch]$NoCache
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MIRAGE - Full Restart" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

function Stop-Frontend {
    Write-Host "[1/6] Stopping frontend dev server..." -ForegroundColor Yellow

    $frontendConns = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
    if ($frontendConns) {
        $frontendConns | ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  Frontend stopped" -ForegroundColor Green
    }
    else {
        Write-Host "  Frontend was not running" -ForegroundColor DarkGray
    }

    Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*bb-agent*" -or $_.CommandLine -like "*bb-agent*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue

    Remove-Item -Path "frontend-dev.log" -ErrorAction SilentlyContinue
    Remove-Item -Path "frontend-dev-err.log" -ErrorAction SilentlyContinue
}

function Stop-BackendPorts {
    $backendConns = Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue
    if ($backendConns) {
        $backendConns | ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-CmdQuiet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    cmd /c "$Command >nul 2>nul"
    return $LASTEXITCODE
}

function Test-DockerImageExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Image
    )

    Invoke-CmdQuiet "docker image inspect $Image"
    return ($LASTEXITCODE -eq 0)
}

Stop-Frontend

Write-Host "[2/6] Stopping Docker containers..." -ForegroundColor Yellow
Invoke-CmdQuiet "docker compose down --remove-orphans" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to stop containers" -ForegroundColor Red
    exit 1
}
Write-Host "  Containers stopped" -ForegroundColor Green

Stop-BackendPorts

Write-Host "[3/6] Rebuilding mirage-tools image..." -ForegroundColor Yellow
$toolsCommand = "docker build -t mirage-tools:latest -f build/tools/Dockerfile"
if ($NoCache) {
    $toolsCommand += " --no-cache"
}
$toolsCommand += " ."
Invoke-CmdQuiet $toolsCommand | Out-Null
if ($LASTEXITCODE -ne 0) {
    if (Test-DockerImageExists "mirage-tools:latest") {
        Write-Host "  Rebuild failed, but existing mirage-tools:latest image is available. Reusing it." -ForegroundColor Yellow
    }
    else {
        Write-Host "  FAILED to rebuild mirage-tools and no local fallback image exists" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "  mirage-tools rebuilt" -ForegroundColor Green
}

Write-Host "[4/6] Rebuilding backend and recreating containers..." -ForegroundColor Yellow
if ($NoCache) {
    Invoke-CmdQuiet "docker compose build --no-cache backend" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED to rebuild backend with no cache" -ForegroundColor Red
        exit 1
    }
}
Invoke-CmdQuiet "docker compose up -d --build --force-recreate" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAILED to recreate containers" -ForegroundColor Red
    exit 1
}
Invoke-CmdQuiet "docker image prune -f" | Out-Null
Write-Host "  Containers recreated with fresh backend image" -ForegroundColor Green

Write-Host "[5/6] Waiting for backend..." -ForegroundColor Yellow
$retries = 0
$maxRetries = 45
$backendReady = $false
while ($retries -lt $maxRetries) {
    try {
        curl.exe -fsS --max-time 2 "http://localhost:8443/api/health" | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Backend is ready" -ForegroundColor Green
            $backendReady = $true
            break
        }
    }
    catch {
    }
    Start-Sleep -Seconds 2
    $retries++
}
if (-not $backendReady) {
    Write-Host "  Backend did not respond in time" -ForegroundColor Red
    exit 1
}

Write-Host "[6/6] Restarting frontend dev server..." -ForegroundColor Yellow
if (-not (Test-Path "frontend/node_modules")) {
    Write-Host "  Installing npm dependencies..." -ForegroundColor Yellow
    Push-Location frontend
    npm install 2>&1 | Out-Null
    Pop-Location
}

Start-Process -NoNewWindow -FilePath "cmd" -ArgumentList "/c", "cd frontend && npm run dev" -WorkingDirectory $scriptDir -RedirectStandardOutput "frontend-dev.log" -RedirectStandardError "frontend-dev-err.log"
Start-Sleep -Seconds 3
Write-Host "  Frontend running at http://localhost:3000" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  FULL RESTART COMPLETE" -ForegroundColor Green
Write-Host "  Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "  Backend:  http://localhost:8443" -ForegroundColor White
if ($NoCache) {
    Write-Host "  Build Mode: no-cache" -ForegroundColor White
}
else {
    Write-Host "  Build Mode: cached rebuild" -ForegroundColor White
}
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Tailing backend logs (Ctrl+C to stop)..." -ForegroundColor DarkGray
docker logs -f mirage-backend
