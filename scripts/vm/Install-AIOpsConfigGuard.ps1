<#
.SYNOPSIS
Installs the repository-pinned AIOps config guard on a monitored Linux VM.
.DESCRIPTION
Run from a trusted Windows AIOps deployment checkout. Uses the SAME SSH login
user for scp, SSH and sudo. No root SSH, Python, sudoers rewrite, remote curl,
or privileged LLM-generated shell commands. Requires explicit operator action
and that the SSH identity already has authorization to run sudo install/stat.
This is intentionally NOT called by the incident validation endpoint.
.EXAMPLE
.\scripts\vm\Install-AIOpsConfigGuard.ps1 -Target 10.248.16.82 -SshUser szendehnam
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
    [string]$SshUser
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'aiops-config-guard'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw 'Trusted config guard source not found in the deployment checkout.'
}
if (-not (Get-Command ssh -ErrorAction SilentlyContinue) -or
    -not (Get-Command scp -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH ssh and scp are required on the deployment workstation.'
}
# Git for Windows may have checked out the POSIX helper with CRLF. Ensure
# the deployed script has a Linux-compatible LF shebang, no UTF-8 BOM, and a
# digest covering EXACTLY the bytes copied to the VM.
$normalized = [IO.File]::ReadAllText($source).Replace("`r`n", "`n")
if (-not $normalized.StartsWith("#!/bin/sh`n")) {
    throw 'The trusted root guard does not have a valid POSIX shebang.'
}
$tempSource = Join-Path ([IO.Path]::GetTempPath()) (
    'aiops-guard-' + [Guid]::NewGuid().ToString('N') + '.sh')
[IO.File]::WriteAllText($tempSource, $normalized, [Text.UTF8Encoding]::new($false))
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tempSource).Hash.ToLowerInvariant()
$remote = "$SshUser@$Target"
$stage = '.aiops-config-guard.' + [Guid]::NewGuid().ToString('N') + '.stage'
$targetFile = '/usr/local/sbin/aiops-config-guard'

try {
    # The payload is taken ONLY from this checked-out, trusted repository.
    & scp -q -o StrictHostKeyChecking=yes -- $tempSource "${remote}:./$stage"
    if ($LASTEXITCODE -ne 0) { throw 'Secure copy to monitored VM failed.' }

    $stageCheck = & ssh -o StrictHostKeyChecking=yes -- $remote "chmod 600 -- $stage && sh -n -- $stage && sha256sum -- $stage" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not ($stageCheck -match "^$hash\s")) {
        throw 'Staged helper syntax/hash verification failed; nothing was installed.'
    }

    Write-Host "Trusted source verified (SHA-256: $hash). SSH user: $SshUser"
    Write-Host 'Sudo may request the password of that same SSH user.'
    # Never use root SSH or an unrestricted `sudo su` process.
    $remoteCommand = "sudo test -d /usr/local/sbin && sudo test ! -L /usr/local/sbin && sudo test ! -L $targetFile && sudo install -o root -g root -m 0750 -- $stage $targetFile && sudo stat -c '%u:%g:%a' -- $targetFile && sudo sha256sum -- $targetFile"
    $installed = & ssh -tt -o StrictHostKeyChecking=yes -- $remote $remoteCommand 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Privileged installation failed; verify the SSH user's authorized sudo policy."
    }
    $installedText = ($installed -join "`n")
    if ($installedText -notmatch '(?m)^0:0:750\s*$' -or
        $installedText -notmatch "(?m)^$hash\s") {
        throw 'Installed file metadata or SHA-256 differs from the audited artifact.'
    }
    Write-Host 'AIOps config guard installed and verified as root:root, mode 0750.'
    Write-Host 'Now retry Validate configuration in the Incident Room.'
}
finally {
    # Best effort unprivileged cleanup. Never delete the production helper.
    & ssh -o StrictHostKeyChecking=yes -- $remote "rm -f -- $stage" 2>$null | Out-Null
    Remove-Item -LiteralPath $tempSource -Force -ErrorAction SilentlyContinue
}
