#Requires -Version 5.1
# Windows: same as install-hooks.sh. Git for Windows runs the bash hooks itself.
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = Join-Path $HOME ".polinrider-guard"
if ($Uninstall) { git config --global --unset core.hooksPath; Write-Host "Removed global core.hooksPath."; exit 0 }
$cur = (git config --global core.hooksPath) 2>$null
$target = (Join-Path $Dest "hooks") -replace '\\', '/'
if ($cur -and $cur -ne $target) { Write-Error "core.hooksPath already set to $cur; not overwriting." }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
foreach ($d in @("hooks", "lib", "iocs")) {
    $p = Join-Path $Dest $d; if (Test-Path $p) { Remove-Item -Recurse -Force $p }
    Copy-Item -Recurse (Join-Path $Here $d) $p
}
Copy-Item (Join-Path $Here "*.sh"), (Join-Path $Here "*.ps1") $Dest -Force
git config --global core.hooksPath $target
git config --global transfer.fsckObjects true
git config --global fetch.fsckObjects true
Write-Host "Installed to $Dest. Global hooks: $(git config --global core.hooksPath)"
