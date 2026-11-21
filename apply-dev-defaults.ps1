#Requires -Version 5.1
# apply-dev-defaults.ps1 [-Apply] - apply the safe defaults from safe-defaults/ for the
# CURRENT Windows user. Dry run by default: prints what it would change. Backs up files it edits.
param([switch]$Apply)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Invoke-Step([scriptblock]$Block, [string]$Description) {
    if ($Apply) {
        Write-Host "+ $Description"
        & $Block
    } else {
        Write-Host "(dry run) $Description"
    }
}

# npm
if (Get-Command npm -ErrorAction SilentlyContinue) {
    $cur = & npm config get ignore-scripts 2>$null
    if ($cur -ne "true") {
        Invoke-Step { & npm config set ignore-scripts true --location=user } "npm config set ignore-scripts true --location=user"
    }
    $listed = & npm config ls -l 2>$null | Out-String
    if ($listed -match '(?m)^min-release-age') {
        $age = & npm config get min-release-age 2>$null
        if ($age -ne "1") {
            Invoke-Step { & npm config set min-release-age 1 --location=user } "npm config set min-release-age 1 --location=user"
        }
    } else {
        $ver = & npm --version
        Write-Host "npm $ver has no min-release-age; upgrade npm to get it."
    }
}

# yarn berry
if (Get-Command yarn -ErrorAction SilentlyContinue) {
    $yv = & yarn --version 2>$null
    if ($yv -and $yv -notmatch '^1\.') {
        Invoke-Step { & yarn config set enableScripts false --home } "yarn config set enableScripts false --home"
    }
}

# VS Code-family user settings: insert keys only if missing; never rewrite existing JSONC.
$apps = @("Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf")
$wanted = @(
    '"task.allowAutomaticTasks": "off"',
    '"security.workspace.trust.enabled": true',
    '"security.workspace.trust.untrustedFiles": "open"',
    '"security.workspace.trust.emptyWindow": false',
    '"security.workspace.trust.startupPrompt": "always"',
    '"extensions.autoUpdate": false',
    '"extensions.autoCheckUpdates": false'
)
foreach ($app in $apps) {
    $dir = Join-Path $env:APPDATA (Join-Path $app "User")
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    $f = Join-Path $dir "settings.json"
    if (-not (Test-Path -LiteralPath $f)) {
        Invoke-Step { "{`r`n}`r`n" | Set-Content -LiteralPath $f -Encoding utf8 } "create empty $f"
    }
    $content = ""
    if (Test-Path -LiteralPath $f) { $content = Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue }
    $add = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $wanted) {
        $key = ($kv -split ":", 2)[0]
        if ($content -and ($content.Contains($key))) {
            if (-not $content.Contains($kv)) {
                $val = (($kv -split ":", 2)[1]).Trim()
                Write-Host "NOTE ${app}: $key is set to a different value; change it by hand to $val"
            }
        } else {
            [void]$add.Add("  $kv,")
        }
    }
    if ($add.Count -gt 0) {
        $block = ($add -join "`n") + "`n"
        if ($Apply) {
            if (Test-Path -LiteralPath $f) {
                $stamp = Get-Date -Format "yyyyMMddHHmmss"
                Copy-Item -LiteralPath $f -Destination "$f.bak.$stamp"
            }
            if (-not (Test-Path -LiteralPath $f) -or [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue))) {
                "{`n$block}`n" | Set-Content -LiteralPath $f -Encoding utf8
            } else {
                $raw = Get-Content -LiteralPath $f -Raw
                $updated = [regex]::Replace($raw, '\{', "{`n$block", 1)
                # utf8 in Windows PowerShell 5.1 writes a BOM, which VS Code accepts.
                $utf8 = New-Object System.Text.UTF8Encoding $false
                [System.IO.File]::WriteAllText($f, $updated, $utf8)
            }
            Write-Host "+ updated $f (backup next to it)"
        } else {
            Write-Host "(dry run) add to ${f}:"
            Write-Host $block
        }
    }
}

# git hooks + fsck
$hooksTarget = ((Join-Path $HOME ".polinrider-guard\hooks") -replace '\\', '/')
$cur = $null
try { $cur = & git config --global core.hooksPath 2>$null } catch { $cur = $null }
if ($cur -ne $hooksTarget) {
    $hookScript = Join-Path $Here "install-hooks.ps1"
    Invoke-Step { & $hookScript } $hookScript
}

if (-not $Apply) {
    Write-Host "Dry run only. Re-run with -Apply to make these changes."
}
