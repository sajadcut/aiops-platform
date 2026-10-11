# Stop only the AIOps API and VM MCP processes tracked by start-all.ps1.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RuntimeRoot = Join-Path $PSScriptRoot '.runtime'
$StatePath = Join-Path $RuntimeRoot 'processes.json'

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
    param($Entry, $Info)
    if ($null -eq $Entry -or $null -eq $Info -or -not $Entry.CreatedAt -or -not $Entry.Module -or -not $Entry.Port) {
        return $false
    }
    if ((Get-ProcessCreationStamp $Info) -ne [string]$Entry.CreatedAt) { return $false }
    $command = [string]$Info.CommandLine
    if ([string]::IsNullOrWhiteSpace($command)) { return $false }
    $portPattern = '--port\s+' + [regex]::Escape([string]$Entry.Port) + '(?:\s|$)'
    return ($command.IndexOf([string]$Entry.Module, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            [regex]::IsMatch($command, $portPattern))
}

function Save-State {
    param($Current)
    $payload = [ordered]@{
        UpdatedAt = (Get-Date).ToString('o')
        AIOps = $Current.AIOps
        VMMcp = $Current.VMMcp
    }
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    Write-Host 'No managed processes are tracked; nothing to stop.' -ForegroundColor Yellow
    return
}

try {
    $saved = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Cannot read $StatePath. No processes were stopped; inspect the file manually."
}

$State = @{ AIOps = $saved.AIOps; VMMcp = $saved.VMMcp }

# Reverse startup order. Never kill by image name or port alone.
foreach ($key in @('AIOps', 'VMMcp')) {
    $entry = $State[$key]
    if ($null -eq $entry -or -not $entry.Pid) { continue }

    $processId = [int]$entry.Pid
    $info = Get-ProcessInfoById -ProcessId $processId
    if ($null -eq $info) {
        Write-Host ("[ALREADY STOPPED] {0} (PID {1})" -f $entry.Name, $processId)
        $State[$key] = $null
        Save-State $State
        continue
    }
    if (-not (Test-TrackedProcess -Entry $entry -Info $info)) {
        Write-Warning ("PID {0} no longer matches the saved identity of {1}. It will NOT be killed." -f $processId, $entry.Name)
        $State[$key] = $null
        Save-State $State
        continue
    }

    Write-Host ("[STOPPING] {0} (PID {1})" -f $entry.Name, $processId) -ForegroundColor Cyan
    try {
        Stop-Process -Id $processId -ErrorAction Stop
    } catch {
        Write-Warning ("Failed to stop PID {0}: {1}" -f $processId, $_.Exception.Message)
    }

    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Get-ProcessInfoById -ProcessId $processId)) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq (Get-ProcessInfoById -ProcessId $processId)) {
        Write-Host ("[STOPPED] {0}" -f $entry.Name) -ForegroundColor Green
        $State[$key] = $null
    } else {
        Write-Warning ("PID {0} is still running. It remains tracked; check permissions." -f $processId)
    }
    Save-State $State
}

if ($null -eq $State.AIOps -and $null -eq $State.VMMcp) {
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    Write-Host 'All tracked services have stopped.' -ForegroundColor Green
} else {
    Write-Warning "Some services remain tracked in $StatePath"
}
Write-Host "Logs remain in: $RuntimeRoot"
