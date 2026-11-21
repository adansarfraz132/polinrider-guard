#Requires -Version 5.1
<#
.SYNOPSIS
  Static "is this repo safe to install/open?" check for Windows.
.DESCRIPTION
  Preferred path: runs scan-repo.sh through Git for Windows' bash (which ships perl),
  so Windows gets exactly the same checks as macOS/Linux.
  Fallback (no Git Bash): a native PowerShell subset of the checks.
  Never executes, imports, or installs anything from the scanned folder.
  Exit codes: 0 clean, 1 review MEDIUM, 2 HIGH (stop), 3 error.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan-repo.ps1 C:\code\some-repo
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Path = ".",
    [switch]$Deep,
    [switch]$WithTools,
    [switch]$Native
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$IocDir = if ($env:IOC_DIR) { $env:IOC_DIR } else { Join-Path $Here "iocs" }
$Root = (Resolve-Path -LiteralPath $Path).Path

if (-not $Native) {
    $bashCandidates = @(
        (Join-Path $env:ProgramFiles "Git\bin\bash.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Git\bin\bash.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Git\bin\bash.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }
    if ($bashCandidates) {
        $bash = @($bashCandidates)[0]
        $toPosix = { param($p) ($p -replace '\\', '/') -replace '^([A-Za-z]):', { '/' + $_.Groups[1].Value.ToLower() } }
        $script = & $toPosix (Join-Path $Here "scan-repo.sh")
        $target = & $toPosix $Root
        $argsList = @($script)
        if ($Deep) { $argsList += "--deep" }
        if ($WithTools) { $argsList += "--with-tools" }
        $argsList += $target
        & $bash @argsList
        exit $LASTEXITCODE
    }
    Write-Host "Git for Windows bash not found; using the native PowerShell subset." -ForegroundColor Yellow
}

# ------------------------------------------------------------------ native subset
function Read-List([string]$Name) {
    $p = Join-Path $IocDir $Name
    if (-not (Test-Path $p)) { return @() }
    Get-Content -LiteralPath $p | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
}
$StrHigh = @(Read-List "strings-high.txt" | ForEach-Object { $_.ToLowerInvariant() })
$RxHigh  = @(Read-List "regex-high.txt" | ForEach-Object { $_ -replace '\[\[:space:\]\]', '\s' -replace '\[\^\[:space:\]\]', '\S' })
$DomHigh = @(Read-List "domains-high.txt")
$IpHigh  = @(Read-List "ips-high.txt")
$NpmAny = @{}; $NpmVer = @{}
foreach ($l in Read-List "npm-packages.txt") {
    if ($l -match '^(@?[^@]+)@(.+)$') { $NpmVer[$l.ToLowerInvariant()] = 1 } else { $NpmAny[$l.ToLowerInvariant()] = 1 }
}
$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Sev, $Check, $Loc, $Detail) {
    $d = ($Detail -replace '[^\x20-\x7e]', '?') -replace ' {6,}', ' [many spaces] '
    if ($d.Length -gt 180) { $d = $d.Substring(0, 180) + "..." }
    $Findings.Add([pscustomobject]@{ Sev = $Sev; Check = $Check; Loc = $Loc; Detail = $d })
}
$SusCmd = '(node\s+-e\b|node\s+\S+\.(woff2?|ttf|otf|eot|dict|png|jpe?g|svg|ico|txt|css)\b|curl\s|wget\s|\|\s*(ba|z)?sh\b|bash\s+-c|powershell|pwsh|iex\b|Invoke-Expression|Invoke-WebRequest|\birm\b|\biwr\b|base64|atob\(|eval\(|https?://|setup_bun\.js|bun_environment\.js|telemetry\.js|\.vercel\.app|certutil|mshta|rundll32)'
$Prune = @('.git', '.hg', '.svn')
if (-not $Deep) { $Prune += @('node_modules', '.venv', 'venv', 'bower_components') }
$selfFull = (Resolve-Path $Here).Path

function Get-Files([string]$Dir) {
    foreach ($item in Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue) {
        if ($item.PSIsContainer) {
            if ($Prune -contains $item.Name) { continue }
            if ($item.FullName -eq $selfFull) { continue }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            Get-Files $item.FullName
        } else { $item }
    }
}
$files = @(Get-Files $Root)
$utf8 = New-Object System.Text.UTF8Encoding($false, $false)
$fontExt = @('.woff', '.woff2', '.ttf', '.otf', '.eot')
foreach ($f in $files) {
    $rp = $f.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
    $name = $f.Name; $ext = $f.Extension.ToLowerInvariant()
    if ($name -eq 'temp_auto_push.bat') { Add-Finding HIGH ioc-filename $rp 'PolinRider propagation script' }
    if ($name -in @('setup_bun.js', 'bun_environment.js')) { Add-Finding HIGH ioc-filename $rp 'Shai-Hulud 2.0 file' }
    if ($f.Length -gt 25MB) { continue }
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $isText = ([Array]::IndexOf($bytes[0..([Math]::Min(8191, [Math]::Max(0, $bytes.Length - 1)))], [byte]0) -lt 0)
    $head = if ($bytes.Length -ge 4) { [Text.Encoding]::ASCII.GetString($bytes, 0, 4) } else { "" }
    if ($fontExt -contains $ext -and $head -notmatch '^(wOFF|wOF2|true|OTTO|ttcf)' -and -not ($bytes.Length -ge 4 -and $bytes[0] -eq 0 -and $bytes[1] -eq 1 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0) -and $ext -ne '.eot') {
        Add-Finding HIGH fake-asset $rp "'$ext' file has no font signature (fake-font loader trick)"
    }
    if ($head -match '^(\x7fELF|MZ)' -and $rp -notmatch '(^|/)node_modules/') { Add-Finding MEDIUM binary $rp 'executable binary committed to the repo' }
    if (-not $isText) { continue }
    $c = $utf8.GetString($bytes)
    $lc = $c.ToLowerInvariant()
    foreach ($s in $StrHigh) { if ($lc.Contains($s)) { Add-Finding HIGH ioc-string $rp "known malware marker: $s" } }
    foreach ($d in $DomHigh) { if ($lc.Contains($d.ToLowerInvariant())) { Add-Finding HIGH ioc-domain $rp "known malicious host: $d" } }
    foreach ($ip in $IpHigh) { if ($c -match ('(?<![\d.])' + [regex]::Escape($ip) + '(?![\d])')) { Add-Finding HIGH ioc-ip $rp "known C2 IP: $ip" } }
    $codeExt = $ext -in @('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.json')
    foreach ($rx in $RxHigh) {
        if ($rx -match '\{200,\}' -and -not $codeExt) { continue }
        $m = [regex]::Match($c, $rx); if ($m.Success) { Add-Finding HIGH loader-pattern $rp "PolinRider-style loader pattern: $($m.Value)" }
    }
    if ([regex]::IsMatch($c, '(?:\uDB40[\uDD00-\uDDEF]|[\uFE00-\uFE0F]){8,}')) { Add-Finding HIGH invisible-unicode $rp 'run of 8+ Unicode variation selectors (GlassWorm-style hidden code)' }
    $isCfg = ($name -match '^[\w.-]+\.config\.(js|cjs|mjs|ts|cts|mts)$') -or ($name -in @('truffle.js', '.eslintrc.js', '.babelrc.js', 'vue.config.js'))
    if ($isCfg) {
        $i = 0
        foreach ($line in ($c -split "`n")) {
            $i++
            if ($line.Length -gt 400) { Add-Finding $(if ($line.Length -gt 1000) { 'HIGH' } else { 'MEDIUM' }) config-long-line "${rp}:$i" "line is $($line.Length) chars in a build config" }
            if ($line -match '\S[ \t]{50,}\S') { Add-Finding HIGH config-hidden-tail "${rp}:$i" 'code after 50+ spaces on one line' }
        }
        if ($c -match '(\beval\s*\(|new\s+Function\s*\(|child_process|\batob\s*\(|fromCharCode|\bglobal\s*\[|\bglobal\.\w+\s*=)') { Add-Finding HIGH config-dangerous-api $rp "build config uses $($Matches[1])" }
    }
    if ($rp -match '(^|/)\.vscode/tasks\.json$' -or $name -like '*.code-workspace') {
        if ($c -match '"runOn"\s*:\s*"folderOpen"') { Add-Finding HIGH vscode-autorun $rp 'task runs automatically on folder open' }
        foreach ($m in [regex]::Matches($c, '"command"\s*:\s*"((?:[^"\\]|\\.)*)"')) { if ($m.Groups[1].Value -match $SusCmd) { Add-Finding HIGH vscode-task-command $rp "task command looks like a loader: $($m.Groups[1].Value)" } }
    }
    if ($rp -match '(^|/)\.vscode/settings\.json$' -and $c -match '"task\.allowAutomaticTasks"\s*:\s*"on"') { Add-Finding HIGH vscode-settings $rp 'workspace turns automatic tasks ON' }
    if ($name -eq 'package.json') {
        try { $j = $c | ConvertFrom-Json } catch { $j = $null }
        if ($j) {
            foreach ($hook in @('preinstall', 'install', 'postinstall', 'preprepare', 'prepare', 'postprepare')) {
                $cmd = $null
                if ($j.scripts) { $cmd = $j.scripts.$hook }
                if ($cmd) { Add-Finding $(if ($cmd -match $SusCmd) { 'HIGH' } else { 'MEDIUM' }) lifecycle-script $rp "scripts.$hook runs on install: $cmd" }
            }
            foreach ($sect in @('dependencies', 'devDependencies', 'optionalDependencies')) {
                if (-not $j.$sect) { continue }
                foreach ($p in $j.$sect.PSObject.Properties) {
                    $n = $p.Name.ToLowerInvariant(); $v = ("" + $p.Value).TrimStart('=', 'v')
                    if ($NpmAny.ContainsKey($n)) { Add-Finding HIGH malicious-package $rp "known-malicious package $($p.Name)" }
                    if ($NpmVer.ContainsKey("$n@$v")) { Add-Finding HIGH malicious-package $rp "hijacked version $($p.Name)@$v" }
                }
            }
        }
    }
    if ($name -in @('package-lock.json', 'npm-shrinkwrap.json')) {
        $key = ''
        foreach ($line in ($c -split "`n")) {
            if ($line -match '^\s*"((?:node_modules/)?[^"]+)":\s*\{\s*$') { $key = $Matches[1] -replace '^.*node_modules/', '' }
            elseif ($line -match '^\s*"version":\s*"([^"]+)"' -and $key) {
                $k = $key.ToLowerInvariant(); $v = $Matches[1]
                if ($NpmAny.ContainsKey($k)) { Add-Finding HIGH malicious-package $rp "lockfile has known-malicious $key@$v" }
                if ($NpmVer.ContainsKey("$k@$v")) { Add-Finding HIGH malicious-package $rp "lockfile has hijacked $key@$v" }
            }
            elseif ($line -match '^\s*"resolved":\s*"([^"]+)"' -and $Matches[1] -notmatch '^https://registry\.npmjs\.org/') { Add-Finding MEDIUM lockfile-source $rp "resolved outside registry.npmjs.org: $($Matches[1])" }
        }
    }
}

$order = @{ HIGH = 0; MEDIUM = 1; LOW = 2; INFO = 3 }
$uniq = $Findings | Sort-Object @{ e = { $order[$_.Sev] } }, Check, Loc, Detail -Unique
$high = @($uniq | Where-Object Sev -eq 'HIGH').Count
$med = @($uniq | Where-Object Sev -eq 'MEDIUM').Count
Write-Host "Repo scan (native subset): $Root"
Write-Host "Files checked: $($files.Count)   HIGH: $high   MEDIUM: $med"
foreach ($x in $uniq) {
    $col = switch ($x.Sev) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }
    Write-Host ("{0,-6} {1,-22} {2}" -f $x.Sev, $x.Check, $x.Loc) -ForegroundColor $col
    Write-Host ("       {0}" -f $x.Detail)
}
if ($high -gt 0) {
    Write-Host "STOP. Do not install, open in VS Code/Cursor as trusted, or run anything from this repo. Send this output to your security team." -ForegroundColor Red
    exit 2
}
if ($med -gt 0) { Write-Host "Review MEDIUM items. Install with: npm ci --ignore-scripts" -ForegroundColor Yellow; exit 1 }
Write-Host "No known-bad patterns found (first pass, not a guarantee)." -ForegroundColor Green
exit 0
