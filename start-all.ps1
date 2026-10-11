# Start AIOps API/Dashboard and the dedicated VM MCP edge on Windows.
# Run from any directory: .\start-all.ps1 [-ApiPort 8000] [-VmMcpPort 9105]
[CmdletBinding()]
param(
    [ValidateRange(1,65535)][int]$ApiPort = 8000,
    [ValidateRange(1,65535)][int]$VmMcpPort = 9105,
    [ValidateSet('127.0.0.1','0.0.0.0')][string]$ApiHost = '127.0.0.1'
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$RuntimeRoot = Join-Path $ProjectRoot '.runtime'
$StatePath = Join-Path $RuntimeRoot 'processes.json'
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

function Get-ProcessInfoById {
    param([int]$ProcessId)
    try {
        return Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
}

function Get-ProcessCreationStamp {
    param($ProcessInfo)
    if ($null -eq $ProcessInfo -or -not $ProcessInfo.CreationDate) { return '' }
    return ([datetime]$ProcessInfo.CreationDate).ToUniversalTime().ToString('o')
}

function Test-TrackedProcess {
    param($Entry)
    if ($null -eq $Entry -or -not $Entry.Pid -or -not $Entry.CreatedAt -or -not $Entry.Module -or -not $Entry.Port) {
        return $false
    }
    $info = Get-ProcessInfoById -ProcessId ([int]$Entry.Pid)
    if ($null -eq $info -or -not $info.CommandLine) { return $false }
    if ((Get-ProcessCreationStamp $info) -ne [string]$Entry.CreatedAt) { return $false }
    $command = [string]$info.CommandLine
    $moduleText = [string]$Entry.Module
    $portPattern = '--port\s+' + [regex]::Escape([string]$Entry.Port) + '(?:\s|$)'
    return ($command.IndexOf($moduleText, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            [regex]::IsMatch($command, $portPattern))
}

function Test-PortInUse {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connection = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $connection.AsyncWaitHandle.WaitOne(400)) { return $false }
        $client.EndConnect($connection)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Save-State {
    $payload = [ordered]@{
        UpdatedAt = (Get-Date).ToString('o')
        AIOps = $State.AIOps
        VMMcp = $State.VMMcp
    }
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Test-ServiceHealth {
    param($Service)
    try {
        $body = Invoke-RestMethod -Method Get -Uri $Service.HealthUrl -TimeoutSec 2 -ErrorAction Stop
        if ($Service.Key -eq 'VMMcp') {
            return ($body.status -eq 'ok' -and $body.provider -eq 'vm')
        }
        return ($body.status -eq 'alive')
    } catch {
        return $false
    }
}

function Wait-ServiceHealth {
    param($Service, $Entry)
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-TrackedProcess -Entry $Entry)) { break }
        if (Test-ServiceHealth -Service $Service) { return $true }
        Start-Sleep -Milliseconds 600
    }
    return $false
}

function Start-ManagedService {
    param($Service)
    $existing = $State[$Service.Key]
    if (Test-TrackedProcess -Entry $existing) {
        if (-not (Test-ServiceHealth -Service $Service)) {
            throw ("{0} is tracked on PID {1} but its health endpoint is not ready. Check the logs or run .\stop-all.ps1." -f $Service.Name, $existing.Pid)
        }
        Write-Host ("[RUNNING] {0}: PID {1}" -f $Service.Name, $existing.Pid) -ForegroundColor Green
        return
    }
    if ($null -ne $existing) {
        Write-Warning ("Stale state for {0}; the old PID will not be stopped or reused." -f $Service.Name)
        $State[$Service.Key] = $null
        Save-State
    }
    if (Test-PortInUse -Port ([int]$Service.Port)) {
        throw ("Port {0} is already in use; refusing to start {1} over another process." -f $Service.Port, $Service.Name)
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $stdout = Join-Path $RuntimeRoot ("{0}-{1}.out.log" -f $Service.Key, $stamp)
    $stderr = Join-Path $RuntimeRoot ("{0}-{1}.err.log" -f $Service.Key, $stamp)
    $args = "-m uvicorn $($Service.Module) --host $($Service.Host) --port $($Service.Port)"
    $previous = @{}
    $process = $null
    Write-Host ("[STARTING] {0} on {1}:{2}" -f $Service.Name, $Service.Host, $Service.Port) -ForegroundColor Cyan
    try {
        foreach ($key in $Service.Environment.Keys) {
            $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
            [Environment]::SetEnvironmentVariable($key, [string]$Service.Environment[$key], 'Process')
        }
        $process = Start-Process -FilePath $Python -ArgumentList $args -WorkingDirectory $ProjectRoot -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    } finally {
        foreach ($key in $previous.Keys) {
            [Environment]::SetEnvironmentVariable($key, $previous[$key], 'Process')
        }
    }

    $info = Get-ProcessInfoById -ProcessId ([int]$process.Id)
    if ($null -eq $info) {
        throw ("{0} exited immediately. Check {1}" -f $Service.Name, $stderr)
    }
    $entry = [pscustomobject]@{
        Name = $Service.Name
        Pid = [int]$process.Id
        CreatedAt = Get-ProcessCreationStamp $info
        Module = $Service.Module
        Port = [int]$Service.Port
        StdoutLog = $stdout
        StderrLog = $stderr
        StartedAt = (Get-Date).ToString('o')
    }
    if (-not $entry.CreatedAt) {
        throw ("Cannot verify creation time of PID {0}; refusing to track it." -f $entry.Pid)
    }
    $State[$Service.Key] = $entry
    Save-State

    if (-not (Wait-ServiceHealth -Service $Service -Entry $entry)) {
        $tail = ''
        if (Test-Path -LiteralPath $stderr -PathType Leaf) {
            $tail = (Get-Content -LiteralPath $stderr -Tail 15 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        }
        throw ("{0} did not become healthy. Process is tracked for .\stop-all.ps1.`nLog: {1}`n{2}" -f $Service.Name, $stderr, $tail)
    }
    Write-Host ("[STARTED] {0}: PID {1}" -f $Service.Name, $entry.Pid) -ForegroundColor Green
}

if ($ApiPort -eq $VmMcpPort) { throw 'API and VM MCP must use different TCP ports.' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Missing .venv\Scripts\python.exe. Create a Python 3.12 virtual environment and install requirements.txt.'
}
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot '.env') -PathType Leaf)) {
    throw 'Missing .env. Copy .env.example to .env, then configure DB, MCP_BEARER_TOKEN, and SSH settings.'
}
New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null

# The same token must authenticate the API MCP client and the VM edge.
# Do not start an unauthenticated VM edge, even in development.
Push-Location $ProjectRoot
try {
    & $Python -c "import uvicorn; from domain.contracts.config import settings; import sys; sys.exit(0 if (settings.MCP_BEARER_TOKEN or '').strip() else 2)"
    if ($LASTEXITCODE -ne 0) {
        throw 'Python configuration check failed. Install requirements, validate .env and set MCP_BEARER_TOKEN to a non-empty secret.'
    }
} finally {
    Pop-Location
}

# Fail early with a safe explanation rather than starting a 'live' API that
# returns 503 on Zabbix signals / dashboard summary due to schema drift.
# This is strictly read-only: upgrades require a separately verified backup.
Push-Location $ProjectRoot
try {
    & $Python -m scripts.check_database_migrations
    $migrationPreflightExit = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($migrationPreflightExit -ne 0) {
    throw 'AIOps startup blocked: database migration preflight failed. Follow the commands above; no migration was applied automatically.'
}

$State = @{ AIOps = $null; VMMcp = $null }
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    try {
        $saved = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $State.AIOps = $saved.AIOps
        $State.VMMcp = $saved.VMMcp
    } catch {
        throw "Cannot read $StatePath. Inspect it before retrying to avoid duplicate processes."
    }
}

# AIOps itself never receives SSH privileges. Only the VM edge does.
$vm = [pscustomobject]@{
    Key = 'VMMcp'
    Name = 'VM MCP'
    Module = 'apps.mcp_server.main:app'
    Host = '127.0.0.1'
    Port = $VmMcpPort
    HealthUrl = "http://127.0.0.1:$VmMcpPort/health"
    Environment = @{
        MCP_SERVER_PROVIDER = 'vm'
        MCP_SERVER_REQUIRE_AUTH = 'true'
        SSH_ENABLED = 'true'
    }
}
$api = [pscustomobject]@{
    Key = 'AIOps'
    Name = 'AIOps API / Dashboard / Chatbot'
    Module = 'apps.api.main:app'
    Host = $ApiHost
    Port = $ApiPort
    HealthUrl = "http://127.0.0.1:$ApiPort/api/v1/health/live"
    Environment = @{
        SSH_ENABLED = 'false'
        VM_MCP_URL = "http://127.0.0.1:$VmMcpPort/mcp"
    }
}

# Start the dependency before the API. Existing tracked services are not duplicated.
Start-ManagedService $vm
Start-ManagedService $api

Write-Host ''
Write-Host 'AIOps and VM MCP are running.' -ForegroundColor Green
Write-Host "Dashboard : http://127.0.0.1:$ApiPort/dashboard"
Write-Host "Chatbot   : http://127.0.0.1:$ApiPort/chatbot"
Write-Host "Swagger   : http://127.0.0.1:$ApiPort/docs"
Write-Host "VM MCP    : http://127.0.0.1:$VmMcpPort/mcp"
Write-Host "Logs/state: $RuntimeRoot"
Write-Host 'Stop with : .\stop-all.ps1'
