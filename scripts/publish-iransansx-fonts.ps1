# Optional: publish the owner's local IRANSansX files to this public GitHub repository.
# This script never downloads, generates or supplies licensed font binaries.
# Requires explicit confirmation that PUBLIC REDISTRIBUTION is permitted by the license.
[CmdletBinding()]
param(
    [switch]$ConfirmPublicRedistribution,
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fontDirectory = Join-Path $root 'font'
$weights = @('Thin','UltraLight','Light','Regular','Medium','DemiBold','Bold','ExtraBold','Black')
$names = @($weights | ForEach-Object { "IRANSansX$($_).ttf" })

function Run-Git {
    param([string[]]$Arguments)
    & git -C $root @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("git failed (exit {0}): {1}" -f $LASTEXITCODE, ($Arguments -join ' '))
    }
}

if (-not $ConfirmPublicRedistribution) {
    throw 'Refusing publication: IRANSansX may be commercially licensed. Verify the license explicitly permits PUBLIC SOURCE redistribution, then pass -ConfirmPublicRedistribution.'
}

$remote = (& git -C $root remote get-url origin 2>&1) -join ''
if ($LASTEXITCODE -ne 0 -or $remote -notmatch '(?i)github\.com[:/]sajadcut/aiops-platform(?:\.git)?$') {
    throw 'Refusing to publish: origin does not point to github.com/sajadcut/aiops-platform.'
}
$currentBranch = (& git -C $root branch --show-current 2>&1) -join ''
if ($LASTEXITCODE -ne 0 -or $currentBranch -ne 'main') {
    throw 'Refusing to publish: check out main and pull latest origin/main first.'
}
$staged = @(& git -C $root diff --cached --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect staging area.' }
if ($staged.Count -gt 0) {
    throw 'Refusing to commit unrelated staged changes. Unstage them and retry.'
}

foreach ($name in $names) {
    $file = Join-Path $fontDirectory $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required font file is missing: $file"
    }
    $info = Get-Item -LiteralPath $file
    if ($info.Length -lt 10000 -or $info.Length -gt 10000000) {
        throw "Font size outside expected bounds: $name"
    }
    $stream = [System.IO.File]::OpenRead($file)
    try {
        $magic = New-Object byte[] 4
        if ($stream.Read($magic, 0, 4) -ne 4) {
            throw "Unrecognized font header: $name"
        }
        $isTrueType = $magic[0] -eq 0 -and $magic[1] -eq 1 -and $magic[2] -eq 0 -and $magic[3] -eq 0
        $isTrueType = $isTrueType -or ([System.Text.Encoding]::ASCII.GetString($magic) -eq 'true')
        if (-not $isTrueType) {
            throw "Not a TrueType font: $name"
        }
    } finally {
        $stream.Dispose()
    }
}

Write-Host '[OK] Public redistribution rights affirmed and all nine TrueType font files validated.' -ForegroundColor Green
$relative = @($names | ForEach-Object { "font/$_" })
Run-Git -Arguments (@('add', '--') + $relative)

& git -C $root diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host '[OK] The nine font files are already committed (no staged differences).' -ForegroundColor Green
} elseif ($LASTEXITCODE -eq 1) {
    Run-Git -Arguments @('commit', '-m', 'assets(font): add licensed IRANSansX font binaries')
} else {
    throw 'Could not inspect staged font changes.'
}
if ($Push) {
    # Fast-forward only; never force-push over other developers.
    Run-Git -Arguments @('push', 'origin', 'main')
    Write-Host '[OK] Licensed font files pushed to origin/main.' -ForegroundColor Green
} else {
    Write-Host '[INFO] Fonts committed locally. Rerun with -Push to publish to GitHub.' -ForegroundColor Yellow
}
