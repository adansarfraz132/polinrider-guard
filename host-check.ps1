#Requires -Version 5.1
# host-check.ps1 - read-only check of THIS Windows PC for artifacts of the researched
# developer-targeted malware (see THREATS.md). Changes nothing. Exit 2 if anything is found.
$ErrorActionPreference = "SilentlyContinue"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ioc = Join-Path $Here "iocs"
$script:found = $false
function Hit($what, $why) { Write-Host "HIGH  $what" -ForegroundColor Red; Write-Host "      $why"; $script:found = $true }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$homes = @($HOME)
if ($isAdmin) { $homes = @(Get-ChildItem "C:\Users" -Directory | ForEach-Object FullName) }

# 1. Files/folders from host-artifacts.txt (BeaverTail/InvisibleFerret, SEAL persistence paths)
foreach ($line in Get-Content (Join-Path $Ioc "host-artifacts.txt")) {
    if (-not $line -or $line.StartsWith("#")) { continue }
    $parts = $line.Split("|", 2); $rel = $parts[0].Trim(); $why = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
    if ($rel.StartsWith("/")) { continue }
    foreach ($h in $homes) {
        $p = Join-Path $h ($rel -replace "/", "\")
        Get-Item -Path $p -Force | ForEach-Object { Hit $_.FullName $why }
    }
}
# 2. Scheduled task + Defender exclusions used by the Contagious Interview miner (SEAL 2026-01)
Get-ScheduledTask | Where-Object { $_.TaskName -eq "Runtime Broker" -or (($_.Actions.Execute + " " + $_.Actions.Arguments) -match '\\\.(n2|n3|nlp|npl|pyp)\b|\\\.npm\\') } |
    ForEach-Object { Hit "Scheduled task '$($_.TaskName)'" "$($_.Actions.Execute) $($_.Actions.Arguments)" }
if ($isAdmin) {
    $pref = Get-MpPreference
    @($pref.ExclusionPath) + @($pref.ExclusionProcess) | Where-Object { $_ -match '\\\.(n2|n3|nlp|npl|npm)|AppData\\(Roaming|Local)\\Microsoft\\Windows\\Applications' } |
        ForEach-Object { Hit "Defender exclusion $_" "Contagious Interview persistence (SEAL)" }
}
# 3. VS Code-family extensions vs known-malicious list (GlassWorm)
$bad = Get-Content (Join-Path $Ioc "vscode-extensions.txt") | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object { $_.ToLowerInvariant() }
foreach ($h in $homes) {
    foreach ($d in @(".vscode\extensions", ".vscode-insiders\extensions", ".cursor\extensions", ".windsurf\extensions")) {
        Get-ChildItem (Join-Path $h $d) -Directory | ForEach-Object {
            if ($_.Name -match '^(.+?)-(\d[\w.+-]*)$') {
                $id = $Matches[1].ToLowerInvariant(); $ver = $Matches[2]
                if ($bad -contains $id -or $bad -contains "$id@$ver") { Hit $_.FullName "known-malicious extension (GlassWorm)" }
            }
        }
    }
}
# 4. Running node/python processes whose command line matches the loaders
Get-CimInstance Win32_Process | Where-Object {
    ($_.Name -match '^(node|bun|python|pythonw)(\.exe)?$' -and $_.CommandLine -match '\.woff2?|spellright\.dict|\\\.n2\\|\\\.npl|\\\.nlp|\\\.pyp\\|bun_environment\.js|\\\.npm\\scoped_dir') -or
    ($_.Name -eq 'msedge.exe' -and $_.ExecutablePath -and $_.ExecutablePath -notmatch 'Program Files')
} | ForEach-Object { Hit "Process $($_.Name) pid $($_.ProcessId)" "$($_.CommandLine)" }
# 5. Connections to known C2 IPs/ports (snapshot)
$ips = Get-Content (Join-Path $Ioc "ips-high.txt") | Where-Object { $_ -and -not $_.StartsWith("#") }
Get-NetTCPConnection -State Established | Where-Object { $ips -contains $_.RemoteAddress -or @(1224, 2242, 5918, 5978) -contains $_.RemotePort } |
    ForEach-Object { Hit "Connection to $($_.RemoteAddress):$($_.RemotePort)" "owning pid $($_.OwningProcess)" }
# 6. npm defaults
if (Get-Command npm -ErrorAction SilentlyContinue) {
    if ((npm config get ignore-scripts) -ne "true") { Write-Host "INFO  npm ignore-scripts is OFF for this user (see safe-defaults\README.md)." }
}
if ($script:found) {
    Write-Host "`nSomething matched. Disconnect from the network, rotate GitHub/npm/cloud/SSH credentials from a different clean device, and tell your security team. SEAL recommends a full OS reinstall for Contagious Interview infections on Windows." -ForegroundColor Red
    exit 2
}
Write-Host "No known artifacts found on this PC (snapshot IOCs; not a guarantee)." -ForegroundColor Green
exit 0
