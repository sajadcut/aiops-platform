[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$RuntimeRoot = Join-Path $ProjectRoot '.runtime'
$StatePath = Join-Path $RuntimeRoot 'processes.json'
$LocalConfigPath = Join-Path $ProjectRoot 'start-all.local.ps1'
$ExampleConfigPath = Join-Path $ProjectRoot 'start-all.local.ps1.example'

New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null

function Get-ProcessInfoById {
    param([int]$ProcessId)

    try {
        $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        return $processInfo
    }
    catch {
        return $null
    }
}

function Test-TrackedProcess {
    param($Entry)

    if ($null -eq $Entry -or -not $Entry.Pid -or [string]::IsNullOrWhiteSpace([string]$Entry.MatchText)) {
        return $false
    }

    $processInfo = Get-ProcessInfoById -ProcessId ([int]$Entry.Pid)
    if ($null -eq $processInfo -or [string]::IsNullOrWhiteSpace([string]$processInfo.CommandLine)) {
        return $false
    }

    return $processInfo.CommandLine.IndexOf([string]$Entry.MatchText, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Test-TcpPortInUse {
    param([int]$Port)

    if ($Port -le 0) { return $false }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne(300)) {
            return $false
        }

        $client.EndConnect($asyncResult)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Resolve-ExecutablePath {
    param([string]$Executable)

    if (Test-Path -LiteralPath $Executable -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Executable).Path
    }

    $command = Get-Command $Executable -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [string]$command.Source
    }

    throw "Executable not found: $Executable"
}

function Save-ProcessState {
    $payload = [ordered]@{
        UpdatedAt = (Get-Date).ToString('o')
        AIOps = $State.AIOps
        VMMcp = $State.VMMcp
    }

    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Start-ManagedService {
    param($Service)

    $existing = $State[$Service.Key]
    if (Test-TrackedProcess -Entry $existing) {
        Write-Host ("[RUNNING] {0} is already running (PID {1})." -f $Service.Name, $existing.Pid) -ForegroundColor Green
        return
    }

    if ($null -ne $existing) {
        Write-Warning ("Saved PID for {0} is stale or no longer matches; refreshing its state." -f $Service.Name)
        $State[$Service.Key] = $null
        Save-ProcessState
    }

    if (-not (Test-Path -LiteralPath $Service.WorkingDirectory -PathType Container)) {
        throw ("Working directory for {0} does not exist: {1}" -f $Service.Name, $Service.WorkingDirectory)
    }

    $resolvedExecutable = Resolve-ExecutablePath -Executable ([string]$Service.Executable)
    if ([string]::IsNullOrWhiteSpace([string]$Service.Arguments)) {
        throw ("No command-line arguments configured for {0}." -f $Service.Name)
    }

    if ([string]$Service.MatchText -match 'REPLACE_WITH') {
        throw ("Update MatchText for {0} in start-all.local.ps1 before running." -f $Service.Name)
    }

    if (Test-TcpPortInUse -Port ([int]$Service.TcpPort)) {
        throw ("Port {0} is already accepting connections. Check whether {1} is already running." -f $Service.TcpPort, $Service.Name)
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stdoutPath = Join-Path $RuntimeRoot ("{0}-{1}.out.log" -f $Service.Key, $stamp)
    $stderrPath = Join-Path $RuntimeRoot ("{0}-{1}.err.log" -f $Service.Key, $stamp)

    Write-Host ("[STARTING] {0}" -f $Service.Name) -ForegroundColor Cyan
    Write-Host ("  Directory: {0}" -f $Service.WorkingDirectory)
    Write-Host ("  Command:   {0} {1}" -f $resolvedExecutable, $Service.Arguments)

    $process = Start-Process -FilePath $resolvedExecutable -ArgumentList ([string]$Service.Arguments) -WorkingDirectory ([string]$Service.WorkingDirectory) -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

    Start-Sleep -Seconds 3

    $entry = [pscustomobject]@{
        Name = [string]$Service.Name
        Pid = [int]$process.Id
        Executable = $resolvedExecutable
        WorkingDirectory = [string]$Service.WorkingDirectory
        Arguments = [string]$Service.Arguments
        MatchText = [string]$Service.MatchText
        TcpPort = [int]$Service.TcpPort
        StdoutLog = $stdoutPath
        StderrLog = $stderrPath
        StartedAt = (Get-Date).ToString('o')
    }

    if (-not (Test-TrackedProcess -Entry $entry)) {
        $stderrTail = ''
        if (Test-Path -LiteralPath $stderrPath) {
            $stderrTail = (Get-Content -LiteralPath $stderrPath -Tail 30 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        }

        throw ("{0} did not remain running. Review log: {1}{2}{3}" -f $Service.Name, $stderrPath, [Environment]::NewLine, $stderrTail)
    }

    $State[$Service.Key] = $entry
    Save-ProcessState
    Write-Host ("[STARTED] {0} (PID {1})" -f $Service.Name, $process.Id) -ForegroundColor Green
    Write-Host ("  Logs: {0} | {1}" -f $stdoutPath, $stderrPath)
}

if (-not (Test-Path -LiteralPath $LocalConfigPath -PathType Leaf)) {
    if (Test-Path -LiteralPath $ExampleConfigPath -PathType Leaf) {
        Copy-Item -LiteralPath $ExampleConfigPath -Destination $LocalConfigPath
        Write-Host "Created local configuration: $LocalConfigPath" -ForegroundColor Yellow
        Write-Host 'Edit the VM MCP folder, executable, arguments, and MatchText, then run start-all.ps1 again.'
        return
    }

    throw "Missing VM MCP config: $LocalConfigPath"
}

. $LocalConfigPath
$configVariable = Get-Variable -Name VMMcpConfig -ErrorAction SilentlyContinue
if ($null -eq $configVariable -or $null -eq $configVariable.Value) {
    throw 'start-all.local.ps1 must define $VMMcpConfig.'
}
$VMMcpConfig = $configVariable.Value

if (-not [bool]$VMMcpConfig.Enabled) {
    throw 'VM MCP is disabled in start-all.local.ps1. Set Enabled = $true to start both projects.'
}

if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot '.venv\Scripts\python.exe') -PathType Leaf)) {
    throw "AIOps Python was not found at .venv\Scripts\python.exe. Create the project's Python 3.12 virtual environment first."
}

if ([string]$VMMcpConfig.WorkingDirectory -match 'REPLACE_WITH' -or -not (Test-Path -LiteralPath ([string]$VMMcpConfig.WorkingDirectory) -PathType Container)) {
    throw "Set WorkingDirectory in start-all.local.ps1 to the actual VM MCP project folder."
}
if ([string]$VMMcpConfig.Executable -match 'REPLACE_WITH') {
    throw "Set Executable in start-all.local.ps1 to the actual VM MCP runtime, such as its .venv\Scripts\python.exe."
}
if ([string]$VMMcpConfig.Arguments -match 'REPLACE_WITH') {
    throw "Replace the sample Arguments in start-all.local.ps1 with the actual VM MCP startup command."
}
if ([string]$VMMcpConfig.MatchText -match 'REPLACE_WITH') {
    throw "Set MatchText in start-all.local.ps1 to a unique substring of the VM MCP command line."
}

$State = @{ AIOps = $null; VMMcp = $null }
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    try {
        $previousState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $State.AIOps = $previousState.AIOps
        $State.VMMcp = $previousState.VMMcp
    }
    catch {
        Write-Warning 'Previous process state could not be read; a new state file will be created.'
    }
}

$AIOpsService = [pscustomobject]@{
    Key = 'AIOps'
    Name = 'AIOps API + Web'
    WorkingDirectory = $ProjectRoot
    Executable = (Join-Path $ProjectRoot '.venv\Scripts\python.exe')
    Arguments = '-m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000'
    MatchText = 'apps.api.main:app'
    TcpPort = 8000
}

$McpService = [pscustomobject]@{
    Key = 'VMMcp'
    Name = [string]$VMMcpConfig.Name
    WorkingDirectory = [string]$VMMcpConfig.WorkingDirectory
    Executable = [string]$VMMcpConfig.Executable
    Arguments = [string]$VMMcpConfig.Arguments
    MatchText = [string]$VMMcpConfig.MatchText
    TcpPort = [int]$VMMcpConfig.TcpPort
}

# Start VM MCP first so the API's external tool dependency is available early.
Start-ManagedService -Service $McpService
Start-ManagedService -Service $AIOpsService

Write-Host ''
Write-Host 'All configured projects are running.' -ForegroundColor Green
Write-Host 'AIOps dashboard: http://127.0.0.1:8000/dashboard'
Write-Host 'AIOps API docs:  http://127.0.0.1:8000/docs'
Write-Host ("Process state:   {0}" -f $StatePath)
Write-Host 'Use .\stop-all.ps1 to stop the processes started by this script.'
