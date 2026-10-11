[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$RuntimeRoot = Join-Path $ProjectRoot '.runtime'
$StatePath = Join-Path $RuntimeRoot 'processes.json'

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

function Save-ProcessState {
    param($State)

    $payload = [ordered]@{
        UpdatedAt = (Get-Date).ToString('o')
        AIOps = $State.AIOps
        VMMcp = $State.VMMcp
    }

    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    Write-Host 'No process state was found. Nothing started by start-all.ps1 is tracked.' -ForegroundColor Yellow
    return
}

try {
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
}
catch {
    throw "Cannot read process state at $StatePath. Inspect or remove the file manually only after checking which services are running."
}

$State = @{ AIOps = $saved.AIOps; VMMcp = $saved.VMMcp }
$TaskkillPath = Join-Path $env:SystemRoot 'System32\taskkill.exe'
$StillTracked = $false

# Stop in reverse startup order: API first, then VM MCP.
foreach ($key in @('AIOps', 'VMMcp')) {
    $entry = $State[$key]
    if ($null -eq $entry -or -not $entry.Pid) {
        continue
    }

    $pidValue = [int]$entry.Pid
    $processInfo = Get-ProcessInfoById -ProcessId $pidValue

    if ($null -eq $processInfo) {
        Write-Host ("[ALREADY STOPPED] {0} (PID {1})" -f $entry.Name, $pidValue) -ForegroundColor DarkGray
        $State[$key] = $null
        continue
    }

    $matchText = [string]$entry.MatchText
    $commandLine = [string]$processInfo.CommandLine
    if ([string]::IsNullOrWhiteSpace($matchText) -or [string]::IsNullOrWhiteSpace($commandLine) -or $commandLine.IndexOf($matchText, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Write-Warning ("Not stopping PID {0}: its command line no longer matches tracked service '{1}'. This prevents killing an unrelated process if a PID was reused." -f $pidValue, $entry.Name)
        $StillTracked = $true
        continue
    }

    Write-Host ("[STOPPING] {0} (PID {1})" -f $entry.Name, $pidValue) -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $TaskkillPath -PathType Leaf)) {
        throw "taskkill.exe was not found at $TaskkillPath"
    }

    & $TaskkillPath /PID $pidValue /T /F | Out-Null
    $taskkillExitCode = $LASTEXITCODE
    Start-Sleep -Milliseconds 700

    $remaining = Get-ProcessInfoById -ProcessId $pidValue
    if ($null -eq $remaining -or $taskkillExitCode -eq 0) {
        Write-Host ("[STOPPED] {0}" -f $entry.Name) -ForegroundColor Green
        $State[$key] = $null
    }
    else {
        Write-Warning ("Could not confirm that {0} stopped. Check PID {1} and the process log." -f $entry.Name, $pidValue)
        $StillTracked = $true
    }
}

if ($StillTracked) {
    Save-ProcessState -State $State
    Write-Warning ("Some entries were retained in {0}; inspect the warning above." -f $StatePath)
}
else {
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    Write-Host 'All tracked project processes have been stopped.' -ForegroundColor Green
}

Write-Host ("Logs remain in: {0}" -f $RuntimeRoot)
