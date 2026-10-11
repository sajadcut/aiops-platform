# Verify the actual running API serves IRANSansX to the browser.
# Read-only: does not alter git, databases, application files or processes.
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:8000'
)
$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
$names = @(
    'IRANSansXThin.ttf', 'IRANSansXUltraLight.ttf', 'IRANSansXLight.ttf',
    'IRANSansXRegular.ttf', 'IRANSansXMedium.ttf', 'IRANSansXDemiBold.ttf',
    'IRANSansXBold.ttf', 'IRANSansXExtraBold.ttf', 'IRANSansXBlack.ttf'
)
$failed = 0
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Request-Asset {
    param([string]$Path, [string]$ExpectedMime)
    $url = "$BaseUrl$Path"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -Headers @{
            'Cache-Control' = 'no-cache'
        }
        $mime = [string]$response.Headers['Content-Type']
        if ($response.StatusCode -ne 200 -or $mime -notlike "$ExpectedMime*") {
            Write-Host "[FAIL] $($response.StatusCode) $mime $url" -ForegroundColor Red
            $script:failed++
            return $null
        }
        Write-Host "[OK]   $($response.StatusCode) $mime $url" -ForegroundColor Green
        return $response
    } catch {
        Write-Host "[FAIL] $url : $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
        return $null
    }
}

Write-Host "Checking the running AIOps server at $BaseUrl ..."
$page = Request-Asset -Path '/dashboard' -ExpectedMime 'text/html'
if ($null -ne $page -and $page.Content -notmatch '/dashboard/fonts\.css\?v=2') {
    Write-Host '[FAIL] Dashboard HTML does not reference the current v2 font stylesheet. Restart the API, verify its port and pull main.' -ForegroundColor Red
    $failed++
}
$css = Request-Asset -Path '/dashboard/fonts.css?v=2' -ExpectedMime 'text/css'
if ($null -ne $css) {
    if ($css.Content -notmatch 'IRANSansXRegular.ttf' -or $css.Content -notmatch 'font-display:\s*swap') {
        Write-Host '[FAIL] Unexpected font CSS content. The running API may be serving a different checkout.' -ForegroundColor Red
        $failed++
    }
}
foreach ($name in $names) {
    $response = Request-Asset -Path "/assets/fonts/$($name)?v=2" -ExpectedMime 'font/ttf'
    if ($null -ne $response -and $response.RawContentLength -lt 10000) {
        Write-Host "[FAIL] Font response too small to be a valid TTF: $name" -ForegroundColor Red
        $failed++
    }
}
$missing = @($names | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root "font/$_") -PathType Leaf) })
if ($missing.Count -gt 0) {
    Write-Host "[WARN] Missing local font files: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host '[INFO] Check git sparse-checkout / skip-worktree before changing any local files.' -ForegroundColor Yellow
    & git -C $root ls-files -v -- font/IRANSansXDemiBold.ttf
}
if ($failed -gt 0) {
    Write-Host "[FAIL] $failed UI font checks failed. Check the URL in the browser, API logs and asset responses above." -ForegroundColor Red
    exit 1
}
Write-Host '[OK] All nine font assets and the current stylesheet are served by the running API.' -ForegroundColor Green
Write-Host 'Next: In the browser, Ctrl+Shift+R, then DevTools > Network > Font. Verify IRANSansX and inspect computed font-family.' -ForegroundColor Cyan
