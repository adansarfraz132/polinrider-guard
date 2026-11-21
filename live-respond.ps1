#Requires -Version 5.1
<#
.SYNOPSIS
  Live response for PolinRider on Windows (also runs on PowerShell 7 for Linux/macOS, which is how CI tests it).
.DESCRIPTION
  Finds PolinRider activity running now (detached node -e loaders, the python stealer, the
  temp_auto_push git amend/force-push helper) and the places it can start again from
  (~\.node_modules, folderOpen tasks, Startup folder, Run keys, scheduled tasks, injected
  config files, global git hooks). Default is REPORT ONLY.
    -Kill        stop matched processes and their children
    -Quarantine  MOVE matched files to ~\.polinrider-quarantine\<time>\ with a manifest (path + sha256)
    -Restore DIR -Yes  put quarantined items back
    -Watch       re-check every -Interval seconds, kill/quarantine what reappears (if -Kill/-Quarantine)
  Nothing is ever deleted. Ends with "SAFE TO ROTATE CREDENTIALS" or "NOT SAFE YET", then the rotation checklist.
  Exit codes: 0 safe, 2 not safe yet, 3 error.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File live-respond.ps1 -Kill -Quarantine
#>
[CmdletBinding()]
param(
    [switch]$Kill, [switch]$Quarantine, [string]$Restore, [switch]$Yes, [switch]$Force,
    [switch]$Watch, [int]$Interval = 30, [int]$MaxCycles = 0,
    [string[]]$ScanDir = @(), [string[]]$HomeDir = @(), [string[]]$Accept = @(),
    [switch]$NoRepos, [switch]$NoHistory, [switch]$Isolated, [string]$QuarantineRoot
)
$ErrorActionPreference = "SilentlyContinue"
$Version = "0.2.0"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$IocDir = if ($env:IOC_DIR) { $env:IOC_DIR } else { Join-Path $Here "iocs" }
$IsWin = ($PSVersionTable.PSEdition -ne 'Core') -or ($IsWindows -eq $true)
$Sep = [IO.Path]::DirectorySeparatorChar

# ------------------------------------------------------------------ IOC lists (same files as the bash tools)
function Read-List($name) {
    $p = Join-Path $IocDir $name
    if (-not (Test-Path $p)) { return @() }
    @(Get-Content $p | Where-Object { $_ -and $_.Trim() -and -not $_.TrimStart().StartsWith("#") })
}
function Bound($vals) {
    $v = @($vals | Where-Object { $_ })
    if (-not $v) { return $null }
    [regex]::new('(?<![A-Za-z0-9_.-])(?:' + (($v | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![A-Za-z0-9_-])', 'IgnoreCase')
}
$StrHigh = @(Read-List "strings-high.txt" | ForEach-Object { $_.ToLowerInvariant() })
$RxHigh = @(Read-List "regex-high.txt" | ForEach-Object { try { [regex]::new(($_ -replace '\[\^\[:space:\]\]', '\S' -replace '\[\[:space:\]\]', '\s')) } catch { } } | Where-Object { $_ })
$RxDomHigh = Bound (Read-List "domains-high.txt")
$RxDomMed = Bound (Read-List "domains-medium.txt")
$RxIp = Bound (Read-List "ips-high.txt")
$HostArt = @(Read-List "host-artifacts.txt")
$ArtPath = [regex]::new('(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/home/[^/\s"'']+|/Users/[^/\s"'']+|[A-Za-z]:\\Users\\[^\\\s"'']+)[/\\]\.(?:n2|n3|npl|nlp|pyp|npm[/\\](?:scoped_dir|vhost\.ctl|npm-compiler\.log))')
$ChainRx = [regex]::new('temp_auto_push|tmp7A863DD1|bun_environment\.js|spellright\.dict', 'IgnoreCase')

function Ioc-Hit($t) {
    if (-not $t) { return $null }
    $lt = $t.ToLowerInvariant()
    foreach ($s in $StrHigh) { if ($lt.Contains($s)) { return "campaign marker '$s'" } }
    foreach ($rx in $RxHigh) { if ($rx.IsMatch($t)) { return "PolinRider loader pattern" } }
    if ($RxDomHigh -and $RxDomHigh.IsMatch($t)) { return "known C2 host" }
    if ($RxIp -and $RxIp.IsMatch($t)) { return "known C2 IP address" }
    $null
}
function Node-Bad($c) {
    if (-not $c) { return $null }
    $r = Ioc-Hit $c; if ($r) { return $r }
    $rpc = $RxDomMed -and $RxDomMed.IsMatch($c)
    if ($rpc -and $c -match '\beval\s*\(|new\s+Function|\bFunction\s*\(|/(?:0/)?boot\b|\b_p_t\b') { return "blockchain RPC lookup combined with eval or a /boot fetch (dead-drop loader)" }
    if ($c -match 'https?://\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}/(?:0/)?boot\b') { return "fetches /boot from a raw IP:port (loader stage)" }
    if ($c -match '\.node_modules' -and $c -match 'axios|socket\.io') { return "inline script uses the private npm prefix .node_modules with axios or socket.io" }
    if ($c -match '/(?:0/)?boot\b' -and $c -match '\beval\s*\(' -and $c -match 'https?|fetch|\.get\(|request') { return "fetches /boot and evals the response" }
    $null
}
function Node-Review($c) {
    if ($c -match '\beval\s*\(' -and $c -match 'https?\.get\(|\bfetch\(|axios\.get|\brequest\(') { return "inline script evals data it fetched from the network" }
    $null
}
function File-Bad($t) {
    if (-not $t) { return $null }
    $r = Node-Bad $t; if ($r) { return $r }
    if ($ChainRx.IsMatch($t)) { return "references the PolinRider git auto-push / stealer helper" }
    if ($ArtPath.IsMatch($t)) { return "runs from a known malware artifact directory" }
    if ($t -match '(?i)\bnode(?:\.exe)?\s+[^\r\n;|&]*\.(?:woff2?|dict)\b') { return "runs node on a font or dictionary file" }
    $null
}
function Strip-JsonComments($s) {
    $sb = New-Object System.Text.StringBuilder; $inStr = $false; $i = 0; $n = $s.Length
    while ($i -lt $n) {
        $ch = $s[$i]
        if ($inStr) { [void]$sb.Append($ch); if ($ch -eq '\' -and $i + 1 -lt $n) { [void]$sb.Append($s[$i + 1]); $i += 2; continue }; if ($ch -eq '"') { $inStr = $false }; $i++; continue }
        if ($ch -eq '"') { $inStr = $true; [void]$sb.Append($ch); $i++; continue }
        if ($ch -eq '/' -and $i + 1 -lt $n -and $s[$i + 1] -eq '/') { while ($i -lt $n -and $s[$i] -ne "`n") { $i++ }; continue }
        if ($ch -eq '/' -and $i + 1 -lt $n -and $s[$i + 1] -eq '*') { $e = $s.IndexOf('*/', $i + 2); if ($e -lt 0) { $i = $n } else { $i = $e + 2 }; continue }
        [void]$sb.Append($ch); $i++
    }
    $sb.ToString() -replace ',(\s*[\]}])', '$1'
}
function Flat($v) {
    if ($null -eq $v) { return '' }
    if ($v -is [string]) { return $v }
    if ($v -is [System.Collections.IEnumerable]) { return (@($v | ForEach-Object { Flat $_ }) -join ' ') }
    if ($v -is [pscustomobject]) { return (@($v.PSObject.Properties | ForEach-Object { Flat $_.Value }) -join ' ') }
    "$v"
}
# Returns @(severity, reason) or $null. Only folderOpen tasks are considered.
function Tasks-Verdict($text) {
    if (-not $text -or $text -notmatch 'folderOpen') { return $null }
    $json = $null
    try { $json = (Strip-JsonComments $text) | ConvertFrom-Json } catch { }
    if (-not $json -or -not $json.tasks) {
        $r = File-Bad $text
        if (-not $r -and $text -match '(?i)\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|iwr|irm|iex)\b') { $r = 'downloads or runs a script' }
        if ($r) { return @('HIGH', "folderOpen task (unparseable file) that $r") }
        return @('REVIEW', 'folderOpen task in a file that could not be parsed')
    }
    $worst = ''; $why = ''; $rank = @{ '' = 0; 'REVIEW' = 1; 'HIGH' = 2 }
    foreach ($t in @($json.tasks)) {
        if (-not $t.runOptions -or $t.runOptions.runOn -ne 'folderOpen') { continue }
        $cmd = (Flat $t.command) + ' ' + (Flat $t.args) + ' ' + (Flat $t.windows) + ' ' + (Flat $t.linux) + ' ' + (Flat $t.osx)
        $hidden = ($t.presentation -and ($t.presentation.reveal -in @('never', 'silent') -or $t.presentation.close -eq $true))
        $sev = ''; $r = $null
        $x = File-Bad $cmd
        if ($x) { $sev = 'HIGH'; $r = "folderOpen task: $x" }
        elseif ($cmd -match '(?i)\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|iex|Invoke-Expression)\b' -or $cmd -match '(?i)\b(?:bash|sh|zsh|cmd(?:\.exe)?)\b.*(?:\s-c\b|\s/c\b)' -or $cmd -match '(?i)\b(?:node|nodejs|bun)(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b' -or $cmd -match '(?i)\bpython3?(?:\.exe)?\s+-c\b') { $sev = 'HIGH'; $r = 'folderOpen task downloads or runs inline code' }
        elseif ($cmd -match '(?i)\b(?:node|nodejs|bun|python3?|ruby|perl)(?:\.exe)?\s+\S' -or $cmd -match '(?i)\.(?:bat|cmd|ps1|sh|vbs)\b') {
            if ($hidden) { $sev = 'HIGH'; $r = 'folderOpen task silently runs a script (hidden terminal)' } else { $sev = 'REVIEW'; $r = 'folderOpen task runs a script; check that you wrote it' }
        }
        if ($sev -and $rank[$sev] -gt $rank[$worst]) { $worst = $sev; $why = $r }
    }
    if ($worst) { return @($worst, $why) }
    $null
}
function Clean-Cmd($s, $max = 160) {
    if ($null -eq $s) { return '' }
    $s = [regex]::Replace($s, '[^\x20-\x7e]', '?'); $s = [regex]::Replace($s, ' {6,}', ' [many spaces] ')
    if ($s.Length -gt $max) { $s = $s.Substring(0, $max) + '...' }
    $s
}
function Read-Text($p, $max = 2097152) {
    try {
        $fs = [IO.File]::OpenRead($p); try { $n = [int][Math]::Min($fs.Length, $max); $buf = New-Object byte[] $n; [void]$fs.Read($buf, 0, $n) } finally { $fs.Dispose() }
        [Text.Encoding]::UTF8.GetString($buf)
    } catch { $null }
}
function Sha($p) { try { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() } catch { $null } }
function Col($name) { if ([Console]::IsOutputRedirected) { '' } else { $e = [char]27; switch ($name) { 'R' { "$e[31m" } 'Y' { "$e[33m" } 'G' { "$e[32m" } 'B' { "$e[1m" } 'N' { "$e[0m" } } } }
$R = Col R; $Y = Col Y; $G = Col G; $B = Col B; $N = Col N

# ------------------------------------------------------------------ homes and options
$IsAdmin = $false
if ($IsWin) { $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
$Homes = @($HomeDir | Where-Object { $_ -and (Test-Path $_) })
if (-not $Homes) {
    $Homes = @($HOME)
    if ($IsAdmin -and -not $Isolated) { $Homes = @(Get-ChildItem "C:\Users" -Directory | ForEach-Object FullName) }
}
$TmpDirs = @()
if (-not $Isolated) { $TmpDirs = @($env:TEMP, $env:TMP, "C:\Windows\Temp", $(if (-not $IsWin) { "/tmp" }), $env:TMPDIR) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique }
if (-not $QuarantineRoot) { $QuarantineRoot = Join-Path $Homes[0] ".polinrider-quarantine" }

# ------------------------------------------------------------------ restore mode
function Do-Restore($dir) {
    $mf = Join-Path $dir "manifest.json"
    if (-not (Test-Path $mf)) { Write-Host "No manifest.json in $dir"; return 3 }
    $m = Get-Content $mf -Raw | ConvertFrom-Json
    Write-Host "Restoring from $dir ($(@($m.entries).Count) item(s))."
    Write-Host "${Y}WARNING: these items were quarantined because they look like malware. Restoring puts them back and can re-arm them.${N}"
    if (-not $Yes) { Write-Host "Re-run with -Yes to confirm."; return 3 }
    $ok = 0; $bad = 0
    foreach ($e in @($m.entries)) {
        switch ($e.type) {
            'move' {
                if (-not (Test-Path -LiteralPath $e.quarantined)) { Write-Host "  not in quarantine any more (already restored?): $($e.quarantined)"; $bad++; continue }
                if (Test-Path -LiteralPath $e.original) { Write-Host "  ${Y}skip${N} $($e.original) already exists (not overwriting)"; $bad++; continue }
                New-Item -ItemType Directory -Force -Path (Split-Path $e.original) | Out-Null
                Move-Item -LiteralPath $e.quarantined -Destination $e.original -Force
                if (Test-Path -LiteralPath $e.original) { Write-Host "  restored $($e.original)"; $ok++ } else { Write-Host "  ${R}failed${N} $($e.original)"; $bad++ }
            }
            'edit' {
                $cur = if (Test-Path -LiteralPath $e.original) { Sha $e.original } else { '' }
                if ($cur -ne $e.new_sha256 -and -not $Force) { Write-Host "  ${Y}skip${N} $($e.original) changed after quarantine (use -Force to overwrite)"; $bad++; continue }
                Copy-Item -LiteralPath $e.backup -Destination $e.original -Force; Write-Host "  restored $($e.original)"; $ok++
            }
            'regvalue' {
                if ($IsWin) { New-Item -Path $e.key -Force | Out-Null; Set-ItemProperty -Path $e.key -Name $e.name -Value $e.data; Write-Host "  restored registry value $($e.key)\$($e.name)"; $ok++ } else { $bad++ }
            }
            'task' {
                if ($IsWin) { Register-ScheduledTask -Xml (Get-Content $e.backup -Raw) -TaskName $e.name -Force | Out-Null; Write-Host "  restored scheduled task $($e.name)"; $ok++ } else { $bad++ }
            }
        }
    }
    Write-Host "Restored $ok item(s), $bad not restored."
    if ($bad) { return 2 } else { return 0 }
}
if ($Restore) { exit (Do-Restore $Restore) }

# ------------------------------------------------------------------ processes
function Get-Procs {
    if ($IsWin) {
        Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ Pid = [int]$_.ProcessId; PPid = [int]$_.ParentProcessId; Cmd = [string]$_.CommandLine; Name = [string]$_.Name } }
    } else {
        ps -axww -o pid= -o ppid= -o command= 2>$null | ForEach-Object { if ($_ -match '^\s*(\d+)\s+(\d+)\s+(.*?)\s*$') { [pscustomobject]@{ Pid = [int]$Matches[1]; PPid = [int]$Matches[2]; Cmd = $Matches[3]; Name = '' } } }
    }
}
function Split-Exe($cmd) {
    if (-not $cmd) { return @('', '') }
    if ($cmd.StartsWith('"')) { $e = $cmd.IndexOf('"', 1); if ($e -gt 0) { return @($cmd.Substring(1, $e - 1), $cmd.Substring($e + 1).Trim()) } }
    $i = $cmd.IndexOfAny(@(' ', "`t")); if ($i -lt 0) { return @($cmd, '') }
    @($cmd.Substring(0, $i), $cmd.Substring($i + 1).Trim())
}
function Proc-Class($exe) {
    $b = [IO.Path]::GetFileName(($exe -replace '\\', '/')).ToLowerInvariant() -replace '\.exe$', ''
    if ($b -in @('node', 'nodejs', 'bun')) { return 'node' }
    if ($b -match '^pythonw?[\d.]*$') { return 'python' }
    if ($b -in @('sh', 'bash', 'zsh', 'dash', 'fish', 'cmd', 'powershell', 'pwsh')) { return 'shell' }
    if ($b -in @('curl', 'wget')) { return 'fetch' }
    if ($b -eq 'git') { return 'git' }
    ''
}
function Node-Args($a) {
    $t = @($a -split '\s+' | Where-Object { $_ })
    $takes = @('-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions', '--input-type', '--title', '--env-file')
    for ($i = 0; $i -lt $t.Count; $i++) {
        $x = $t[$i]
        if ($x -in @('-e', '--eval', '-p', '--print', '-pe', '-ep')) { return @('inline', ($t[($i + 1)..($t.Count - 1)] -join ' ')) }
        if ($x -match '^--(?:eval|print)=(.*)$') { return @('inline', $Matches[1] + ' ' + ($t[($i + 1)..($t.Count - 1)] -join ' ')) }
        if ($takes -contains $x) { $i++; continue }
        if ($x.StartsWith('-')) { continue }
        return @('script', $x)
    }
    @('none', '')
}
$BadScript = [regex]::new('(?:^|[/\\])\.(?:n2|n3|npl|nlp|pyp)(?:[/\\]|$)|[/\\]\.npm[/\\]scoped_dir|bun_environment\.js|spellright\.dict|\.woff2?$')
$script:ProcTable = @{}
function Classify-Proc($p) {
    $sp = Split-Exe $p.Cmd; $exe = $sp[0]; $args_ = $sp[1]
    $cls = Proc-Class $exe
    if (-not $cls) { return $null }
    switch ($cls) {
        'node' {
            $na = Node-Args $args_
            if ($na[0] -eq 'inline') {
                $r = Node-Bad $na[1]; if ($r) { return @('HIGH', "node -e loader: $r") }
                $r = Node-Review $na[1]; if ($r) { return @('REVIEW', "node -e: $r") }
                return $null
            }
            if ($na[0] -eq 'script') {
                if ($BadScript.IsMatch($na[1])) { return @('HIGH', "node is running a file from a malware artifact path ($($na[1]))") }
                $r = Ioc-Hit $args_; if ($r) { return @('HIGH', "node command line: $r") }
                if ($args_ -match '(?i)temp_auto_push|tmp7A863DD1') { return @('HIGH', 'node is running the PolinRider helper') }
            }
            return $null
        }
        'python' {
            if ($args_ -match '(?i)tmp7A863DD1') { return @('HIGH', 'python process tied to the PolinRider stealer lock file') }
            $r = Ioc-Hit $args_; if ($r) { return @('HIGH', "python command line: $r") }
            if ($args_ -match '[/\\]\.(?:n2|n3|npl|nlp|pyp)(?:[/\\]|\s|$)|[/\\]\.npm[/\\]scoped_dir') { return @('HIGH', 'python is running from a malware artifact directory') }
            if ($args_ -match 'nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa' -or ($args_ -match '\.git-credentials' -and $args_ -match '(?i)zipfile|requests\.post|urllib|sqlite3|Login Data')) { return @('HIGH', 'python code that touches wallet extensions or git credentials') }
            return $null
        }
        'shell' {
            if ($args_ -match '(?i)temp_auto_push') { return @('HIGH', 'shell is running the PolinRider git auto-push script') }
            if ($args_ -match 'commit\s+--amend' -and $args_ -match '\bpush\b' -and $args_ -match '(?:\s-\w*f\w*\b|--force)' -and $args_ -match '--no-verify') { return @('HIGH', 'shell one-liner amends the last commit and force-pushes with --no-verify (temp_auto_push.bat behaviour)') }
            if ($args_ -match '(?i)(?:\s-c\b|\s/c\b|-Command|-EncodedCommand|-enc\b)') {
                $r = Node-Bad $args_; if ($r) { return @('HIGH', "shell command: $r") }
                if ($ArtPath.IsMatch($args_)) { return @('HIGH', 'shell command runs a script from a malware artifact directory') }
                if ($args_ -match '(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest)\b' -and $args_ -match '(?i)\|\s*(?:(?:ba|z)?sh|node|iex|Invoke-Expression)\b' -and (($RxDomHigh -and $RxDomHigh.IsMatch($args_)) -or ($RxIp -and $RxIp.IsMatch($args_)))) { return @('HIGH', 'shell pipes a download from a known C2 host into an interpreter') }
            }
            return $null
        }
        'fetch' { if (($RxDomHigh -and $RxDomHigh.IsMatch($args_)) -or ($RxIp -and $RxIp.IsMatch($args_))) { return @('HIGH', 'download from a known C2 host or IP') }; return $null }
        'git' {
            $forced = $args_ -match '\bpush\b' -and $args_ -match '(?:\s-\w*f\w*\b|--force)' -and $args_ -match '--no-verify'
            $amend = $args_ -match '\bcommit\b' -and $args_ -match '--amend' -and $args_ -match '--no-verify'
            if (-not ($forced -or $amend)) { return $null }
            $par = $script:ProcTable[$p.PPid]
            $what = if ($forced) { 'git force-push' } else { 'git commit --amend' }
            if ($par) {
                $pc = Proc-Class (Split-Exe $par.Cmd)[0]
                if ($pc -in @('node', 'python') -or $par.Cmd -match '(?i)temp_auto_push|auto[_-]?push') { return @('HIGH', "$what with --no-verify started by an interpreter or the auto-push script") }
            }
            return @('NOTE', "$what with --no-verify (normal if you typed it; the malware does this from a script)")
        }
    }
    $null
}
function Short-Proc($id) { $p = $script:ProcTable[$id]; if (-not $p) { return "pid $id (gone)" }; "pid $id ``$(Clean-Cmd $p.Cmd 80)``" }
function Detect-Processes {
    $script:ProcTable = @{}; $children = @{}
    foreach ($p in (Get-Procs)) { $script:ProcTable[$p.Pid] = $p; if (-not $children.ContainsKey($p.PPid)) { $children[$p.PPid] = @() }; $children[$p.PPid] += $p.Pid }
    $script:Children = $children
    $anc = @{}; $x = $PID; while ($x -and -not $anc[$x]) { $anc[$x] = $true; $x = if ($script:ProcTable[$x]) { $script:ProcTable[$x].PPid } else { 0 } }
    $script:Ancestors = $anc
    $out = @()
    foreach ($p in ($script:ProcTable.Values | Sort-Object Pid)) {
        if ($anc[$p.Pid] -or $p.Pid -le 1) { continue }
        $c = Classify-Proc $p
        if ($c) { $out += [pscustomobject]@{ Kind = 'process'; Sev = $c[0]; Pid = $p.Pid; PPid = $p.PPid; Cmd = $p.Cmd; Why = $c[1]; Key = "proc:$($p.Pid)"; Path = $null; Action = $null } }
    }
    if ($IsWin -and -not $Isolated) {
        $ips = Read-List "ips-high.txt"
        Get-NetTCPConnection -State Established | Where-Object { $ips -contains $_.RemoteAddress -or @(1224, 2242, 5918, 5978) -contains $_.RemotePort } | ForEach-Object {
            $op = $script:ProcTable[[int]$_.OwningProcess]
            if ($op -and (Proc-Class (Split-Exe $op.Cmd)[0]) -in @('node', 'python') -and -not $anc[$op.Pid] -and -not ($out | Where-Object Pid -eq $op.Pid)) {
                $out += [pscustomobject]@{ Kind = 'process'; Sev = 'HIGH'; Pid = $op.Pid; PPid = $op.PPid; Cmd = $op.Cmd; Why = "interpreter has an open connection to $($_.RemoteAddress):$($_.RemotePort) (known C2 IP or port)"; Key = "proc:$($op.Pid)"; Path = $null; Action = $null }
            }
        }
    }
    $out
}
function Get-Descendants($id, $seen) { foreach ($c in @($script:Children[$id])) { if ($c -and -not $seen.ContainsKey($c) -and -not $script:Ancestors[$c]) { $seen[$c] = $true; Get-Descendants $c $seen } } }

# ------------------------------------------------------------------ persistence
function PF($sev, $path, $why, $action) { [pscustomobject]@{ Kind = 'persist'; Sev = $sev; Path = $path; Why = $why; Action = $action; Key = "persist:${path}:$(if ($action) { $action.type })"; Pid = $null; PPid = $null; Cmd = $null } }
function Dir-Has($d, $n) { (Test-Path (Join-Path $d "node_modules$Sep$n")) -or (Test-Path (Join-Path $d "lib${Sep}node_modules$Sep$n")) -or (Test-Path (Join-Path $d $n)) }
function Bad-Lines($text) {
    $out = @(); $i = 0
    foreach ($l in ($text -split "`n")) { $i++; if ($l.TrimStart().StartsWith('#')) { continue }; $r = File-Bad $l; if ($r) { $out += , @($i, $r) } }
    $out
}
function Detect-HomeArtifacts($h) {
    $f = @()
    foreach ($l in $HostArt) {
        $parts = $l.Split('|', 2); $rel = $parts[0].Trim(); $why = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
        if ($rel -eq '.node_modules') { continue }
        if ($rel.StartsWith('/')) { continue }
        if ($rel.StartsWith('AppData') -and -not $IsWin) { continue }
        $p = Join-Path $h ($rel -replace '/', $Sep)
        Get-Item -Path $p -Force | ForEach-Object { $f += PF 'HIGH' $_.FullName "malware artifact: $why" @{ type = 'move' } }
    }
    $nm = Join-Path $h ".node_modules"
    if (Test-Path -LiteralPath $nm) {
        if ((Dir-Has $nm 'axios') -and (Dir-Has $nm 'socket.io-client')) { $f += PF 'HIGH' $nm '~\.node_modules holds axios and socket.io-client (private npm prefix of the PolinRider stealer stage)' @{ type = 'move' } }
        else { $f += PF 'REVIEW' $nm '~\.node_modules exists. Normal only if you chose it as your npm prefix (check: npm config get prefix)' @{ type = 'move' } }
    }
    $f
}
function Detect-HomePersistence($h) {
    $f = @()
    # PowerShell profiles and Unix shell startup files: comment out matching lines only
    $rcs = @("Documents\PowerShell\profile.ps1", "Documents\PowerShell\Microsoft.PowerShell_profile.ps1", "Documents\WindowsPowerShell\profile.ps1", "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1", ".config/powershell/profile.ps1", ".bashrc", ".zshrc", ".profile", ".bash_profile") | ForEach-Object { Join-Path $h ($_ -replace '\\', $Sep) }
    foreach ($rc in $rcs) {
        if (-not (Test-Path -LiteralPath $rc -PathType Leaf)) { continue }
        $t = Read-Text $rc; if (-not $t) { continue }
        $b = @(Bad-Lines $t); if ($b.Count -eq 0) { continue }
        $f += PF 'HIGH' $rc ("startup file runs malware: line " + (($b | ForEach-Object { $_[0] }) -join ', ') + " ($($b[0][1]))") @{ type = 'edit' }
    }
    # Startup folder
    foreach ($sd in @((Join-Path $h "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | ForEach-Object { $_ -replace '\\', $Sep }), (Join-Path $h ".config/autostart"))) {
        if (-not (Test-Path $sd)) { continue }
        Get-ChildItem $sd -File -Force | ForEach-Object {
            $t = $null
            if ($_.Extension -in @('.bat', '.cmd', '.ps1', '.vbs', '.pyw', '.py', '.js', '.desktop')) { $t = Read-Text $_.FullName 262144 }
            elseif ($_.Extension -eq '.lnk' -and $IsWin) { try { $s = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName); $t = "$($s.TargetPath) $($s.Arguments)" } catch { } }
            $r = if ($t) { File-Bad $t } else { $null }
            if (-not $r -and $_.Name -eq 'Windows Update Script.pyw') { $r = 'known Contagious Interview startup script name (SEAL)' }
            if ($r) { $f += PF 'HIGH' $_.FullName "startup entry runs malware ($r)" @{ type = 'move' } }
        }
    }
    # Global git hooks
    foreach ($gc in @((Join-Path $h ".gitconfig"), (Join-Path $h ".config/git/config"))) {
        if (-not (Test-Path $gc) -or -not (Get-Command git -ErrorAction SilentlyContinue)) { continue }
        $hp = (& git config --file $gc --get core.hooksPath 2>$null)
        if (-not $hp) { continue }
        $dir = $hp -replace '^~', $h
        $own = $dir -match '[/\\]\.polinrider-guard[/\\]hooks[/\\]?$'
        if (-not (Test-Path $dir)) { if (-not $own) { $f += PF 'REVIEW' $gc "global core.hooksPath points at a folder that does not exist ($hp)" $null }; continue }
        $inHome = $dir.StartsWith($h + $Sep)
        if (($dir -match '^(?:/tmp|/var/tmp)/|\\Temp\\' -and -not $inHome) -or $dir -match '[/\\]\.(?:n2|n3|npl|nlp|pyp)(?:[/\\]|$)') { $f += PF 'REVIEW' $dir "global core.hooksPath is in a temp or hidden malware-style folder ($hp)" $null }
        Get-ChildItem $dir -File -Force | Where-Object { $_.Name -notmatch '^\.|\.sample$' } | ForEach-Object {
            $t = Read-Text $_.FullName; if (-not $t) { return }
            if ($OwnHooks[(Sha $_.FullName)]) { return }
            $r = File-Bad $t
            if ($r) { $f += PF 'HIGH' $_.FullName "global git hook runs malware ($r)" @{ type = 'move' } }
            elseif (-not $own -and $t -match '(?i)\b(?:curl|wget|Invoke-WebRequest|iwr)\b|\bnode\s+-e\b|\bbase64\s+(?:-d|--decode)\b|python3?\s+-c\b') { $f += PF 'REVIEW' $_.FullName 'global git hook downloads or runs inline code; confirm you installed it' $null }
        }
    }
    # User-level VS Code / Cursor tasks.json
    foreach ($tj in @("AppData\Roaming\Code\User\tasks.json", "AppData\Roaming\Cursor\User\tasks.json", ".config/Code/User/tasks.json", "Library/Application Support/Code/User/tasks.json")) {
        $p = Join-Path $h ($tj -replace '\\', $Sep)
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $v = Tasks-Verdict (Read-Text $p); if ($v) { $f += PF $v[0] $p $v[1] @{ type = 'move' } }
    }
    $f
}
function Detect-WindowsPersistence {
    $f = @()
    if (-not $IsWin -or $Isolated) { return $f }
    foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
        $item = Get-Item -Path $k; if (-not $item) { continue }
        foreach ($n in $item.GetValueNames()) {
            $d = [string]$item.GetValue($n)
            $r = File-Bad $d
            if ($r) { $f += PF 'HIGH' "$k\$n" "Run key runs malware ($r): $(Clean-Cmd $d 100)" @{ type = 'regvalue'; key = $k; name = $n; data = $d } }
        }
    }
    foreach ($t in (Get-ScheduledTask)) {
        $txt = (@($t.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
        $r = File-Bad $txt
        if (-not $r -and $t.TaskName -eq 'Runtime Broker' -and $txt -notmatch '(?i)C:\\Windows\\System32') { $r = 'task named Runtime Broker that does not run the Windows binary (SEAL: Contagious Interview miner)' }
        if (-not $r -and $txt -match '\\\.(n2|n3|nlp|npl|pyp)\b|\\\.npm\\') { $r = 'runs from a malware artifact directory' }
        if ($r) { $f += PF 'HIGH' "ScheduledTask:$($t.TaskPath)$($t.TaskName)" "scheduled task runs malware ($r): $(Clean-Cmd $txt 100)" @{ type = 'task'; name = $t.TaskName; path = $t.TaskPath } }
    }
    if ($IsAdmin) {
        $pref = Get-MpPreference
        @($pref.ExclusionPath) + @($pref.ExclusionProcess) | Where-Object { $_ -match '\\\.(n2|n3|nlp|npl|npm)|AppData\\(Roaming|Local)\\Microsoft\\Windows\\Applications' } | ForEach-Object { $f += PF 'REVIEW' "DefenderExclusion:$_" "Defender exclusion used by Contagious Interview persistence (SEAL). Remove it with Remove-MpPreference after reviewing." $null }
    }
    $f
}
function Detect-TempFiles {
    $f = @()
    $dirs = @($TmpDirs) + @($Homes)
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { continue }
        $depth = if ($Homes -contains $d) { 2 } else { 3 }
        Get-ChildItem $d -File -Recurse -Depth $depth -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^temp_auto_push\.[A-Za-z0-9]+$' -or $_.Name -eq 'config.bat' } | Where-Object { $_.FullName -notmatch '[/\\](?:node_modules|\.git)[/\\]' } | ForEach-Object {
            if ($_.Name -eq 'config.bat') {
                $gi = Read-Text (Join-Path $_.DirectoryName '.gitignore')
                if ($gi -match '(?m)^\s*config\.bat\s*$') { $f += PF 'HIGH' $_.FullName 'config.bat listed in .gitignore next to it (PolinRider hides its helper this way)' @{ type = 'move' } }
                else { $f += PF 'REVIEW' $_.FullName 'config.bat found; a lone config.bat is often harmless' @{ type = 'move' } }
            } else { $f += PF 'HIGH' $_.FullName 'PolinRider git amend / force-push helper script' @{ type = 'move' } }
        }
    }
    $f
}
$script:Roots = @(); $script:DirtyRoots = @{}
function Discover-Roots($h) {
    $prune = @('node_modules', 'Library', 'Applications', 'snap', 'AppData', 'Pictures', 'Music', 'Movies', 'Videos', 'Public', 'venv', '__pycache__', 'anaconda3', 'miniconda3', 'dist', 'build', 'target')
    $roots = @()
    function Walk($d, $depth) {
        if ($depth -gt 6) { return }
        foreach ($e in (Get-ChildItem $d -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
            if ($e.Name.StartsWith('.') -or $prune -contains $e.Name -or ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
            if ((Test-Path (Join-Path $e.FullName '.git')) -or (Test-Path (Join-Path $e.FullName 'package.json')) -or (Test-Path (Join-Path $e.FullName '.vscode/tasks.json'))) { $script:found += $e.FullName; continue }
            Walk $e.FullName ($depth + 1)
        }
    }
    $script:found = @(); Walk $h 1; $script:found
}
$RepoChecks = @('ioc-string', 'ioc-hash', 'ioc-domain', 'ioc-ip', 'ioc-filename', 'config-hidden-tail', 'loader-pattern', 'config-dangerous-api', 'config-long-line', 'fake-asset', 'vscode-task-command')
function Scan-Root($root) {
    $f = @(); $seen = @{}
    $scan = Join-Path $Here "scan-repo.ps1"
    $lines = & $scan -Path $root 6>&1 2>$null | ForEach-Object { "$_" }
    foreach ($l in $lines) {
        if ($l -match '^HIGH\s+(\S+)\s+(.+?)\s*$' -and $RepoChecks -contains $Matches[1]) {
            $chk = $Matches[1]; $loc = ($Matches[2] -replace ':\d+$', '')
            $abs = if ([IO.Path]::IsPathRooted($loc)) { $loc } else { Join-Path $root $loc }
            if ($seen[$abs] -or -not (Test-Path -LiteralPath $abs)) { continue }
            $seen[$abs] = $true
            $f += PF 'HIGH' $abs "project file with malware ($chk)" @{ type = 'move'; root = $root }
        }
    }
    $tj = Join-Path $root ".vscode/tasks.json"
    if ((Test-Path -LiteralPath $tj) -and -not $seen[$tj]) { $v = Tasks-Verdict (Read-Text $tj); if ($v) { $f += PF $v[0] $tj $v[1] @{ type = 'move'; root = $root } } }
    $hooks = Join-Path $root ".git/hooks"
    if (Test-Path $hooks) {
        Get-ChildItem $hooks -File -Force | Where-Object { $_.Name -notmatch '\.sample$' } | ForEach-Object { $t = Read-Text $_.FullName; $r = File-Bad $t; if ($r) { $f += PF 'HIGH' $_.FullName "repository git hook runs malware ($r)" @{ type = 'move'; root = $root } } }
    }
    $f
}
function Detect-Repos($only) {
    if ($NoRepos) { return @() }
    $f = @()
    if (-not $only) {
        $script:Roots = @()
        foreach ($d in $ScanDir) { if (Test-Path $d) { $script:Roots += (Resolve-Path $d).Path } }
        if (-not $ScanDir) { foreach ($h in $Homes) { $script:Roots += @(Discover-Roots $h) } }
        $only = $script:Roots
    }
    foreach ($r in @($only)) { if (-not $r -or -not (Test-Path $r)) { continue }; $x = @(Scan-Root $r); if ($x.Count) { $script:DirtyRoots[$r] = $true }; $f += $x }
    $f
}
function Detect-Persistence([switch]$Light, $Roots) {
    $f = @()
    foreach ($h in $Homes) { $f += Detect-HomeArtifacts $h; $f += Detect-HomePersistence $h }
    $f += Detect-WindowsPersistence; $f += Detect-TempFiles
    if (-not $Light) { $f += Detect-Repos $Roots }
    $seen = @{}; $f | Where-Object { if ($_.Path -and (Test-Path -LiteralPath $_.Path) -and (Under-Kit $_.Path)) { $false } elseif ($seen[$_.Key]) { $false } else { $seen[$_.Key] = $true; $true } }
}
function Is-Accepted($f) { if (-not $f.Path) { return $false }; foreach ($a in $Accept) { if ($f.Path -eq $a -or $f.Path.StartsWith($a + $Sep)) { return $true } }; $false }
function Is-Blocking($f) { $f.Sev -eq 'HIGH' -or ($f.Sev -eq 'REVIEW' -and -not (Is-Accepted $f)) }

# ------------------------------------------------------------------ quarantine
$script:QDir = $null; $script:Entries = @(); $script:QN = 0
$Kit = try { (Resolve-Path $Here).Path } catch { $Here }
function Under-Kit($p) { try { $r = (Resolve-Path -LiteralPath $p).Path } catch { $r = $p }; ($r -eq $Kit) -or $r.StartsWith($Kit + $Sep) }
$OwnHooks = @{}
Get-ChildItem (Join-Path $Kit 'hooks') -File -Force | ForEach-Object { $OwnHooks[(Sha $_.FullName)] = $true }
function Q-Init {
    if ($script:QDir) { return }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'; $d = Join-Path $QuarantineRoot $ts; $i = 1
    while (Test-Path $d) { $i++; $d = Join-Path $QuarantineRoot "$ts-$i" }
    New-Item -ItemType Directory -Force -Path (Join-Path $d 'items') | Out-Null
    $script:QDir = $d
}
function Write-Manifest {
    if (-not $script:QDir) { return }
    $m = [ordered]@{ tool = 'polinrider-guard'; version = $Version; created = (Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'); host = [Environment]::MachineName; user = [Environment]::UserName; entries = @($script:Entries) }
    ($m | ConvertTo-Json -Depth 8) | Set-Content -Path (Join-Path $script:QDir 'manifest.json') -Encoding UTF8
}
function Hash-Tree($path) {
    $it = Get-Item -LiteralPath $path -Force
    if ($it.PSIsContainer) {
        $files = @(Get-ChildItem -LiteralPath $path -Recurse -File -Force | Select-Object -First 20000 | ForEach-Object { @{ rel = $_.FullName.Substring($path.Length).TrimStart('\', '/'); sha256 = (Sha $_.FullName) } })
        return @{ kind = 'dir'; files = $files }
    }
    @{ kind = 'file'; sha256 = (Sha $path) }
}
function Q-Item($f) {
    $a = $f.Action
    if ($f.Path -and (Test-Path -LiteralPath $f.Path) -and (Under-Kit $f.Path)) { Write-Host "  refusing to move a file of this kit itself: $($f.Path)"; return }
    Q-Init
    $script:QN++; $id = '{0:D4}' -f $script:QN
    $dest = Join-Path (Join-Path $script:QDir 'items') $id
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    switch ($a.type) {
        'move' {
            $info = Hash-Tree $f.Path
            $target = Join-Path $dest (Split-Path $f.Path -Leaf)
            Move-Item -LiteralPath $f.Path -Destination $target -Force
            if (Test-Path -LiteralPath $f.Path) { Write-Host "  ${R}could not move $($f.Path)${N}"; return }
            $e = [ordered]@{ id = $id; type = 'move'; original = $f.Path; quarantined = $target; reason = $f.Why; kind = $info.kind }
            if ($info.sha256) { $e.sha256 = $info.sha256 }; if ($info.files) { $e.files = $info.files }
            $script:Entries += $e
            Write-Host "  moved  $($f.Path)`n         -> $target"
        }
        'edit' {
            $text = [IO.File]::ReadAllText($f.Path)
            $backup = Join-Path $dest ((Split-Path $f.Path -Leaf) + '.orig')
            [IO.File]::WriteAllText($backup, $text)
            $lines = $text -split "`n"; $done = @()
            for ($i = 0; $i -lt $lines.Count; $i++) { if (-not $lines[$i].TrimStart().StartsWith('#') -and (File-Bad $lines[$i])) { $done += ($i + 1); $lines[$i] = "# polinrider-guard disabled: " + $lines[$i] } }
            [IO.File]::WriteAllText($f.Path, ($lines -join "`n"))
            $script:Entries += [ordered]@{ id = $id; type = 'edit'; original = $f.Path; backup = $backup; backup_sha256 = (Sha $backup); new_sha256 = (Sha $f.Path); lines = $done; reason = $f.Why }
            Write-Host "  commented out line(s) $($done -join ',') in $($f.Path) (original saved: $backup)"
        }
        'regvalue' {
            Remove-ItemProperty -Path $a.key -Name $a.name
            $script:Entries += [ordered]@{ id = $id; type = 'regvalue'; original = "$($a.key)\$($a.name)"; key = $a.key; name = $a.name; data = $a.data; reason = $f.Why }
            Write-Host "  removed Run value $($a.key)\$($a.name) (saved in the manifest)"
        }
        'task' {
            $xml = Export-ScheduledTask -TaskName $a.name -TaskPath $a.path
            $backup = Join-Path $dest 'task.xml'; $xml | Set-Content -Path $backup -Encoding UTF8
            Unregister-ScheduledTask -TaskName $a.name -TaskPath $a.path -Confirm:$false
            $script:Entries += [ordered]@{ id = $id; type = 'task'; original = "ScheduledTask:$($a.path)$($a.name)"; name = $a.name; backup = $backup; reason = $f.Why }
            Write-Host "  unregistered scheduled task $($a.name) (XML saved: $backup)"
        }
    }
    Write-Manifest
}
function Do-Kill($procs) {
    $kill = @{}
    foreach ($p in ($procs | Where-Object { $_.Sev -eq 'HIGH' })) { $kill[$p.Pid] = $true; $d = @{}; Get-Descendants $p.Pid $d; foreach ($k in $d.Keys) { $kill[$k] = $true } }
    foreach ($k in @($kill.Keys)) { if ($script:Ancestors[$k]) { $kill.Remove($k) } }
    if ($kill.Count -eq 0) { return }
    Write-Host "${B}Stopping matched processes${N}"
    foreach ($id in ($kill.Keys | Sort-Object)) {
        $d = if ($script:ProcTable[$id]) { Clean-Cmd $script:ProcTable[$id].Cmd 80 } else { '' }
        try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host "  stopped pid $id ``$d``" } catch { Write-Host "  ${R}cannot stop pid $id (permission or already gone)${N}" }
    }
    Start-Sleep -Milliseconds 800
}
function Do-Actions($found) {
    if ($Kill) { Do-Kill @($found | Where-Object Kind -eq 'process') }
    if ($Quarantine) {
        $q = @($found | Where-Object { $_.Kind -eq 'persist' -and $_.Action -and $_.Sev -eq 'HIGH' })
        if ($q.Count) { Write-Host "${B}Quarantine${N}"; foreach ($x in $q) { Q-Item $x } }
    }
}

# ------------------------------------------------------------------ report
function Show-Findings($found) {
    $proc = @($found | Where-Object Kind -eq 'process'); $per = @($found | Where-Object Kind -eq 'persist')
    Write-Host "${B}Running processes${N}"
    if (-not $proc) { Write-Host "  none matched" }
    foreach ($p in $proc) {
        $c = if ($p.Sev -eq 'HIGH') { $R } else { $Y }
        Write-Host ("  {0}{1,-6}{2} pid {3}  parent {4}" -f $c, $p.Sev, $N, $p.Pid, (Short-Proc $p.PPid))
        Write-Host "         cmd: $(Clean-Cmd $p.Cmd 160)"; Write-Host "         why: $($p.Why)"
    }
    Write-Host "${B}Persistence and re-run points${N}"
    if (-not $per) { Write-Host "  none matched" }
    foreach ($p in $per) {
        $c = if ($p.Sev -eq 'HIGH') { $R } elseif ($p.Sev -eq 'REVIEW') { $Y } else { '' }
        $acc = if (Is-Accepted $p) { ' (accepted by you)' } else { '' }
        Write-Host ("  {0}{1,-6}{2} {3}{4}" -f $c, $p.Sev, $N, (Clean-Cmd $p.Path 200), $acc); Write-Host "         why: $($p.Why)"
    }
}
function Show-Verdict($found) {
    $block = @($found | Where-Object { Is-Blocking $_ })
    Write-Host "`n${B}Verdict${N}"
    if ($block.Count -eq 0) {
        Write-Host "${G}${B}SAFE TO ROTATE CREDENTIALS${N}"
        Write-Host "  No active PolinRider process and no re-run point was found after the actions above."
        Write-Host "  This is a snapshot against published indicators, not proof. See the caveats below."
        return 0
    }
    Write-Host "${R}${B}NOT SAFE YET${N}"
    $np = @($block | Where-Object Kind -eq 'process').Count; $ne = @($block | Where-Object Kind -eq 'persist').Count
    Write-Host "  Still present: $np running process(es), $ne persistence item(s)."
    foreach ($x in $block) {
        $what = if ($x.Kind -eq 'process') { "pid $($x.Pid): $(Clean-Cmd $x.Cmd 70)" } else { Clean-Cmd $x.Path 120 }
        $why = if ($x.Kind -eq 'process') { if (-not $Kill) { ' (re-run with -Kill)' } else { ' (could not be stopped: try as Administrator)' } }
        elseif ($x.Sev -eq 'REVIEW') { ' (needs your review; use -Accept PATH once you have checked it)' }
        elseif (-not $x.Action) { ' (cannot be moved by this tool: remove it by hand as Administrator)' }
        elseif (-not $Quarantine) { ' (re-run with -Quarantine)' } else { ' (could not be moved)' }
        Write-Host "   - [$($x.Sev)] $what$why"
    }
    Write-Host "  Do not rotate credentials on this machine yet: a re-run would steal the new ones."
    2
}
function Show-Checklist($ok) {
    Write-Host "`n${B}What this does not tell you${N}"
    Write-Host "  - It cannot undo anything already stolen (browser passwords, cookies, wallet data, .env keys, git credentials)."
    Write-Host "  - Indicators rotate and a rootkit or a renamed process would not match. If in doubt, reinstall the operating system."
    Write-Host "  - Other copies of an infected repo (other machines, forks, CI caches) can re-infect you. Check them too."
    Write-Host "  - On Windows with WSL: the loader can start node.exe on the Windows side. Run this script on the Windows host and live-respond.sh inside each WSL distro."
    $hdr = if ($ok) { '' } else { ' (do this only after the verdict is SAFE)' }
    Write-Host "`n${B}Rotation checklist$hdr${N}"
    Write-Host "  Do it from a different, clean device if you can. Revoke first, then create new ones."
    Write-Host "   1. GitHub: personal access tokens, OAuth apps, SSH and GPG keys, deploy keys, and review recent sessions and security log."
    Write-Host "   2. Delete ~/.git-credentials and clear Windows Credential Manager git entries; sign out of the GitHub CLI, then log in again."
    Write-Host "   3. npm: revoke tokens (npm token list), turn on 2FA, check .npmrc for _authToken lines."
    Write-Host "   4. Cloud and CI keys: AWS, GCP, Azure, Vercel, Supabase, Docker, Fly, Netlify, Cloudflare; any key in a .env or profile script."
    Write-Host "   5. SSH: replace every private key in ~/.ssh that lived on this machine and remove the old public keys from servers and GitHub."
    Write-Host "   6. Browsers: change passwords saved in the browser, sign out of all sessions, rotate the password-manager master password if its extension was installed."
    Write-Host "   7. Wallets: move funds to a wallet created on a clean device; the old seed phrase is burned."
    Write-Host "   8. Email and chat accounts that had saved sessions (Google, Slack, Discord, Telegram)."
    Write-Host "  If you are unsure the machine is clean, reinstall the operating system before you sign in to anything. SEAL recommends this for Contagious Interview infections on Windows."
}
function Recheck { @(Detect-Processes) + @(Detect-Persistence -Roots @($script:DirtyRoots.Keys)) }

# ------------------------------------------------------------------ main
$mode = if ($Kill -or $Quarantine) { 'ACTIONS ENABLED: ' + ((@('kill', 'quarantine') | Where-Object { Get-Variable -Name ($_.Substring(0, 1).ToUpper() + $_.Substring(1)) -ValueOnly }) -join ' ') } else { 'report only (no changes)' }
Write-Host "${B}PolinRider Guard live response $Version${N}  $mode"
Write-Host "  homes: $($Homes -join ', ')"
$found = @(Detect-Processes) + @(Detect-Persistence)
Show-Findings $found
$actionable = @($found | Where-Object { $_.Sev -ne 'NOTE' })
if ($actionable.Count -and ($Kill -or $Quarantine)) {
    Do-Actions $found
    $found = @(Recheck)
    Write-Host "`n${B}After actions${N}"; Show-Findings $found
} elseif ($actionable.Count) { Write-Host "`nNothing was changed. Re-run with -Kill and/or -Quarantine to act on the HIGH items." }
$rc = Show-Verdict $found
Show-Checklist ($rc -eq 0)
if ($script:QDir) { Write-Host "`nQuarantine folder: $($script:QDir)`n  Restore with: live-respond.ps1 -Restore '$($script:QDir)' -Yes" }

# git history report through Git for Windows' bash (same engine as history-report.sh)
if (-not $NoHistory -and -not $NoRepos) {
    $bash = $null
    if ($IsWin) { foreach ($c in @((Join-Path $env:ProgramFiles "Git\bin\bash.exe"), (Join-Path ${env:ProgramFiles(x86)} "Git\bin\bash.exe"), (Join-Path $env:LOCALAPPDATA "Programs\Git\bin\bash.exe"))) { if ($c -and (Test-Path $c)) { $bash = $c; break } } }
    else { $bash = (Get-Command bash -ErrorAction SilentlyContinue).Source }
    Write-Host ""
    if ($bash) {
        $toPosix = { param($p) if ($IsWin) { ($p -replace '\\', '/') -replace '^([A-Za-z]):', { '/' + $_.Groups[1].Value.ToLower() } } else { $p } }
        $args2 = @((& $toPosix (Join-Path $Here 'history-report.sh')))
        foreach ($r in $script:Roots) { $args2 += (& $toPosix $r) }
        & $bash @args2
    } else { Write-Host "Git history report skipped: it needs Git for Windows (bash and perl). Install it and run history-report.sh." }
}

if ($Watch) {
    Write-Host "`n${B}Watching${N} every ${Interval}s. Ctrl-C to stop."
    $cycle = 0
    while ($true) {
        Start-Sleep -Seconds $Interval
        $cycle++
        $w = @(Detect-Processes) + @(Detect-Persistence -Light:($cycle % 10 -ne 0))
        $hi = @($w | Where-Object Sev -eq 'HIGH')
        $ts = Get-Date -Format 'HH:mm:ss'
        if ($hi.Count) {
            Write-Host "$([char]7)${R}[$ts] ALERT: $($hi.Count) PolinRider item(s) present${N}"
            Show-Findings $w
            if ($Kill -or $Quarantine) { Do-Actions $w }
        } elseif ($MaxCycles -gt 0 -or $cycle % 10 -eq 0) { Write-Host "[$ts] clean (check $cycle)" }
        if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) { break }
    }
    $last = @(Detect-Processes) + @(Detect-Persistence -Light)
    Write-Host "`nStopped watching."
    $rc = Show-Verdict $last
}
exit $rc
