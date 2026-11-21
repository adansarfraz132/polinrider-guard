#!/usr/bin/env perl
# live-core.pl - live response engine behind live-respond.sh (Linux and macOS).
#
# Finds PolinRider activity that is running right now and the places it can start
# again from. Default is REPORT ONLY. Changes happen only with --kill, --quarantine,
# --restore. Nothing is ever deleted: files are MOVED to a timestamped quarantine
# folder with a manifest (original path, sha256, mode) so --restore can put them back.
# Only core Perl modules are used.
use strict;
use warnings;
no warnings 'recursion';
use FindBin ();
use lib "$FindBin::Bin";
use PRG qw(load_iocs ioc_hit node_bad node_review file_bad tasks_verdict read_file_text sha256_file clean_cmd
  @HOST_ART $RX_DOM_MED $RX_IP_HIGH $RX_DOM_HIGH $ART_PATH_RX $CHAIN_RX);
use Getopt::Long qw(GetOptions);
use File::Path qw(make_path);
use File::Basename qw(basename dirname);
use File::Find ();
use POSIX qw(strftime);
use JSON::PP ();

$| = 1;
my $VERSION = '0.2.0';
my %o = (interval => 30, 'max-cycles' => 0, history => 1, 'repo-depth' => 6);
my (@homes, @scan_dirs, @tmp_dirs, @accept);
GetOptions(\%o, 'kill!', 'quarantine!', 'restore=s', 'yes!', 'force!', 'watch!', 'interval=i', 'max-cycles=i',
  'home=s' => \@homes, 'scan-dir=s' => \@scan_dirs, 'tmp-dir=s' => \@tmp_dirs, 'accept=s' => \@accept,
  'ioc-dir=s', 'quarantine-root=s', 'deep!', 'no-repos!', 'isolated!', 'history!', 'self=s', 'repo-depth=i',
  'help|h!') or die "bad arguments (see --help)\n";
if ($o{help}) { print usage(); exit 0 }

sub usage {
  return <<'USAGE';
live-respond.sh - find running PolinRider activity and its re-run points (default: report only)

  live-respond.sh                         report only (changes nothing)
  live-respond.sh --kill                  also terminate matched processes (and their children)
  live-respond.sh --quarantine            also MOVE matched files to ~/.polinrider-quarantine/<time>/
  live-respond.sh --kill --quarantine     the recommended first step on a suspect machine
  live-respond.sh --restore DIR --yes     move quarantined files back (re-arms them: only if you must)
  live-respond.sh --watch [--interval N]  keep re-checking every N seconds (default 30), Ctrl-C to stop

Options
  --scan-dir DIR    scan this folder as a project root (repeatable). Default: git/npm projects under ~
  --home DIR        check this home directory (repeatable; default $HOME, or all homes when run as root)
  --no-repos        skip the project-folder scan (processes and per-user persistence only)
  --deep            also scan node_modules/ inside projects (slow)
  --accept PATH     treat one REVIEW item (by path) as checked by you; it no longer blocks the verdict
  --no-history      skip the git history report at the end (history-report.sh runs it on its own)
  --max-cycles N    stop --watch after N checks (default: run until Ctrl-C)

Exit codes: 0 = SAFE TO ROTATE CREDENTIALS, 2 = NOT SAFE YET, 3 = error.
USAGE
}

my $SCRIPT_DIR = "$FindBin::Bin/..";
my $IOC_DIR = $o{'ioc-dir'} || $ENV{IOC_DIR} || "$SCRIPT_DIR/iocs";
load_iocs($IOC_DIR);
my $ISO = $o{isolated} ? 1 : 0;
my $IS_ROOT = ($> == 0);
my $HOME = $ENV{HOME} || (getpwuid($>))[7] || '';
if (!@homes) {
  @homes = ($HOME);
  if ($IS_ROOT && !$ISO) { for my $h (glob('/home/*'), glob('/Users/*')) { push @homes, $h if -d $h && $h ne $HOME } }
}
@homes = grep { defined $_ && length $_ && -d $_ } @homes;
if (!@tmp_dirs && !$ISO) { @tmp_dirs = grep { -d $_ } ('/tmp', '/var/tmp', ($ENV{TMPDIR} // '')) ; my %s; @tmp_dirs = grep { !$s{$_}++ } @tmp_dirs }
my ($R, $Y, $G, $N, $B) = -t STDOUT ? ("\e[31m", "\e[33m", "\e[32m", "\e[0m", "\e[1m") : ('', '', '', '', '');
my $QROOT = $o{'quarantine-root'} || "$HOME/.polinrider-quarantine";
my $JSON = JSON::PP->new->canonical->pretty;

# ------------------------------------------------------------------ restore mode
if (defined $o{restore}) { exit do_restore($o{restore}) }

# ------------------------------------------------------------------ process table
my (%P, %CH);          # pid => {ppid, cmd}, ppid => [pids]
my %ancestors;         # pids we must never touch
sub read_ps {
  %P = (); %CH = ();
  my @lines = `ps -axww -o pid= -o ppid= -o command= 2>/dev/null`;
  for my $l (@lines) {
    next unless $l =~ /^\s*(\d+)\s+(\d+)\s+(.*?)\s*$/;
    $P{$1} = { pid => $1, ppid => $2, cmd => $3 };
    push @{ $CH{$2} }, $1;
  }
  %ancestors = ();
  my $p = $$;
  while ($p && !$ancestors{$p}) { $ancestors{$p} = 1; $p = $P{$p} ? $P{$p}{ppid} : 0 }
  $ancestors{1} = 1;
}

# Split "exe args..." even when the executable path contains spaces (macOS .app bundles).
sub split_exe {
  my ($cmd) = @_;
  if ($cmd =~ m{^(/[^\n]*?\.app/[^\n]*?/(?:node|bun|nodejs|python[\d.]*))(?:\s+(.*))?$}) { return ($1, $2 // '') }
  if ($cmd =~ /^(\S+)(?:\s+(.*))?$/) { return ($1, $2 // '') }
  return ($cmd, '');
}

sub proc_class {
  my ($exe) = @_;
  my $b = lc basename($exe);
  $b =~ s/\.exe$//;
  return 'node'   if $b =~ /^(?:node|nodejs|bun)$/;
  return 'python' if $b =~ /^pythonw?[\d.]*$/;
  return 'shell'  if $b =~ /^(?:sh|bash|zsh|dash|fish|ksh|csh|tcsh|cmd|powershell|pwsh)$/;
  return 'fetch'  if $b =~ /^(?:curl|wget)$/;
  return 'git'    if $b eq 'git';
  return '';
}

# Inline code (-e/--eval/-p) or script path for node. Returns (mode, text).
sub node_args {
  my ($args) = @_;
  my @t = split ' ', $args;
  my %takes = map { $_ => 1 } qw(-r --require --import --loader --experimental-loader -C --conditions --input-type --title --env-file);
  for (my $i = 0; $i < @t; $i++) {
    my $a = $t[$i];
    if ($a =~ /^(?:-e|--eval|-p|--print|-pe|-ep)$/) { return ('inline', join ' ', @t[$i + 1 .. $#t]) }
    if ($a =~ /^--(?:eval|print)=(.*)$/) { return ('inline', join ' ', $1, @t[$i + 1 .. $#t]) }
    if ($takes{$a}) { $i++; next }
    next if $a =~ /^-/;
    return ('script', $a);
  }
  return ('none', '');
}

my $BAD_SCRIPT_RX = qr{(?:^|[/\\])\.(?:n2|n3|npl|nlp|pyp)(?:[/\\]|$)|[/\\]\.npm[/\\]scoped_dir|bun_environment\.js|spellright\.dict|\.woff2?$};

sub classify_process {
  my ($p) = @_;
  my ($exe, $args) = split_exe($p->{cmd});
  my $cls = proc_class($exe);
  return () unless $cls;
  if ($cls eq 'node') {
    my ($mode, $text) = node_args($args);
    if ($mode eq 'inline') {
      if (my $r = node_bad($text)) { return ('HIGH', "node -e loader: $r") }
      if (my $r = node_review($text)) { return ('REVIEW', "node -e: $r") }
      return ();
    }
    if ($mode eq 'script') {
      if ($text =~ $BAD_SCRIPT_RX) { return ('HIGH', "node is running a file from a malware artifact path ($text)") }
      if (my $r = ioc_hit($args)) { return ('HIGH', "node command line: $r") }
      return ('HIGH', 'node is running the PolinRider helper') if $args =~ /temp_auto_push|tmp7A863DD1/i;
    }
    return ();
  }
  if ($cls eq 'python') {
    my $full = $args;
    return ('HIGH', "python process tied to the PolinRider stealer lock file") if $full =~ /tmp7A863DD1/i;
    if (my $r = ioc_hit($full)) { return ('HIGH', "python command line: $r") }
    return ('HIGH', 'python is running from a malware artifact directory') if $full =~ m{[/\\]\.(?:n2|n3|npl|nlp|pyp)(?:[/\\]|\s|$)|[/\\]\.npm[/\\]scoped_dir};
    # Public extension IDs the stealer targets: MetaMask, Phantom, plus the git-credentials file.
    return ('HIGH', 'python code that touches wallet extensions or git credentials') if $full =~ /nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa/
      || ($full =~ /\.git-credentials/ && $full =~ /zipfile|requests\.post|urllib|sqlite3|Login Data/i);
    return ();
  }
  if ($cls eq 'shell') {
    if ($args =~ /temp_auto_push/i) { return ('HIGH', 'shell is running the PolinRider git auto-push script') }
    if ($args =~ /commit\s+--amend/ && $args =~ /\bpush\b/ && $args =~ /(?:\s-\w*f\w*\b|--force)/ && $args =~ /--no-verify/) {
      return ('HIGH', 'shell one-liner amends the last commit and force-pushes with --no-verify (temp_auto_push.bat behaviour)');
    }
    if ($args =~ /(?:\s-c\b|\s\/c\b|-Command|-EncodedCommand|-enc\b)/i) {
      if (my $r = node_bad($args)) { return ('HIGH', "shell command: $r") }
      return ('HIGH', 'shell command runs a script from a malware artifact directory') if $args =~ $ART_PATH_RX;
      return ('HIGH', "shell pipes a download from a known C2 host into an interpreter")
        if $args =~ /\b(?:curl|wget)\b/ && $args =~ /\|\s*(?:ba|z)?sh\b|\|\s*node\b/ && (($RX_DOM_HIGH && $args =~ $RX_DOM_HIGH) || ($RX_IP_HIGH && $args =~ $RX_IP_HIGH));
    }
    return ();
  }
  if ($cls eq 'fetch') {
    return ('HIGH', 'download from a known C2 host or IP') if ($RX_DOM_HIGH && $args =~ $RX_DOM_HIGH) || ($RX_IP_HIGH && $args =~ $RX_IP_HIGH);
    return ();
  }
  if ($cls eq 'git') {
    my $forced = $args =~ /\bpush\b/ && $args =~ /(?:\s-\w*f\w*\b|--force)/ && $args =~ /--no-verify/;
    my $amend  = $args =~ /\bcommit\b/ && $args =~ /--amend/ && $args =~ /--no-verify/;
    return () unless $forced || $amend;
    # A person in a terminal sometimes does this. The malware does it from a script or an interpreter.
    my $par = $P{ $p->{ppid} };
    my ($pexe, $pargs) = $par ? split_exe($par->{cmd}) : ('', '');
    my $pc = proc_class($pexe);
    if ($par && ($pc =~ /^(?:node|python)$/ || $par->{cmd} =~ /temp_auto_push|auto[_-]?push/i)) {
      return ('HIGH', 'git ' . ($forced ? 'force-push' : 'commit --amend') . ' with --no-verify started by an interpreter or the auto-push script');
    }
    return ('NOTE', 'git ' . ($forced ? 'force-push' : 'commit --amend') . ' with --no-verify (normal if you typed it; the malware does this from a script)');
  }
  return ();
}

sub short_proc { my ($pid) = @_; my $p = $P{$pid} or return "pid $pid (gone)"; return "pid $pid `" . clean_cmd($p->{cmd}, 80) . '`' }

my %conn;   # pid => "ip:port"
sub read_connections {
  %conn = ();
  return if $ISO;
  my @rows;
  if (system('command -v lsof >/dev/null 2>&1') == 0) { @rows = `lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null` }
  for my $l (@rows) {
    next unless $l =~ /^\S+\s+(\d+)\s+.*->(\d+\.\d+\.\d+\.\d+):(\d+)\s+\(ESTABLISHED\)/;
    my ($pid, $ip, $port) = ($1, $2, $3);
    if (($RX_IP_HIGH && $ip =~ $RX_IP_HIGH) || $port =~ /^(?:1224|2242|5918|5978)$/) { $conn{$pid} = "$ip:$port" }
  }
}

sub detect_processes {
  read_ps();
  read_connections();
  my @f;
  for my $pid (sort { $a <=> $b } keys %P) {
    next if $ancestors{$pid};
    my $p = $P{$pid};
    my ($sev, $why) = classify_process($p);
    if (!$sev && $conn{$pid}) {
      my ($exe) = split_exe($p->{cmd});
      my $c = proc_class($exe);
      if ($c =~ /^(?:node|python)$/) { ($sev, $why) = ('HIGH', "interpreter has an open connection to $conn{$pid} (known C2 IP or port)") }
    }
    next unless $sev;
    push @f, { kind => 'process', sev => $sev, pid => $pid, ppid => $p->{ppid}, cmd => $p->{cmd}, why => $why, key => "proc:$pid" };
  }
  return @f;
}

sub descendants {
  my ($pid, $seen) = @_;
  $seen ||= {};
  for my $c (@{ $CH{$pid} || [] }) { next if $seen->{$c}++ || $ancestors{$c}; descendants($c, $seen) }
  return keys %$seen;
}

# ------------------------------------------------------------------ persistence
my %seen_path;
# The kit's own files quote the markers on purpose. Never report or move them.
my $KIT = do { require Cwd; Cwd::abs_path($SCRIPT_DIR) // $SCRIPT_DIR };
sub under_kit { my ($p) = @_; my $r = Cwd::abs_path($p) // $p; return ($r eq $KIT || index($r, "$KIT/") == 0) ? 1 : 0 }
my %OWN_HOOK = map { (sha256_file($_) // '') => 1 } grep { -f $_ } glob("$KIT/hooks/*");
$SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /^Can't opendir|^Can't stat|^Can't lstat|Permission denied/ };
sub pf {   # persistence finding
  my (%a) = @_;
  $a{kind} = 'persist';
  $a{key} = "persist:$a{path}:" . ($a{action} ? $a{action}{type} : '');
  return \%a;
}

sub dir_has { my ($d, $n) = @_; return -d "$d/node_modules/$n" || -d "$d/lib/node_modules/$n" || -d "$d/$n" }

sub detect_home_artifacts {
  my ($h) = @_;
  my @f;
  for my $l (@HOST_ART) {
    my ($path, $note) = split /\s*\|\s*/, $l, 2;
    $path =~ s/\s+$//;
    next if $path =~ /^AppData/ || $path eq '.node_modules';
    my @hits;
    if ($path =~ m{^/}) { next if $ISO; @hits = glob($path) }
    else { @hits = glob("$h/$path") }
    for my $p (@hits) {
      next unless -e $p || -l $p;
      push @f, pf(sev => 'HIGH', path => $p, why => "malware artifact: " . ($note // ''), action => { type => 'move' });
    }
  }
  # Private npm prefix used by the Node stealer stage (SafeDep): axios + socket.io-client.
  my $nm = "$h/.node_modules";
  if (-d $nm) {
    if (dir_has($nm, 'axios') && dir_has($nm, 'socket.io-client')) {
      push @f, pf(sev => 'HIGH', path => $nm, why => '~/.node_modules holds axios and socket.io-client (private npm prefix of the PolinRider stealer stage)', action => { type => 'move' });
    } else {
      push @f, pf(sev => 'REVIEW', path => $nm, why => '~/.node_modules exists. Normal only if you chose it as your npm prefix (check: npm config get prefix)', action => { type => 'move' });
    }
  }
  return @f;
}

sub rc_files { my ($h) = @_; return grep { -f $_ } map { "$h/$_" } qw(.bashrc .zshrc .bash_profile .profile .zprofile .zshenv .zlogin .config/fish/config.fish) }

sub bad_lines {
  my ($text) = @_;
  my @bad;
  my @l = split /\n/, $text, -1;
  for my $i (0 .. $#l) {
    next if $l[$i] =~ /^\s*#/;
    if (my $r = file_bad($l[$i])) { push @bad, [$i + 1, $r] }
    elsif ($l[$i] =~ /sudo shutdown -h 0/) { push @bad, [$i + 1, 'campaign marker (s1ngularity sabotage line)'] }
  }
  return @bad;
}

sub detect_home_persistence {
  my ($h) = @_;
  my @f;
  # Shell startup files: comment out only the matching lines.
  for my $rc (rc_files($h)) {
    my $t = read_file_text($rc) // next;
    my @b = bad_lines($t) or next;
    push @f, pf(sev => 'HIGH', path => $rc, why => 'startup file runs malware: line ' . join(', ', map { $_->[0] } @b) . ' (' . $b[0][1] . ')', action => { type => 'edit' });
  }
  # systemd user units, XDG autostart, macOS LaunchAgents.
  for my $dir ("$h/.config/systemd/user", "$h/.config/autostart", "$h/Library/LaunchAgents") {
    next unless -d $dir;
    opendir my $dh, $dir or next;
    for my $e (sort readdir $dh) {
      next if $e =~ /^\./;
      my $p = "$dir/$e";
      next unless -f $p && !-l $p;
      my $t = read_file_text($p) // next;
      my $r = file_bad($t) // next;
      push @f, pf(sev => 'HIGH', path => $p, why => "auto-start entry runs malware ($r)", action => { type => 'move', service => 1 });
    }
    closedir $dh;
  }
  # Global git configuration: hooks that run on every commit, clone and checkout.
  for my $gc ("$h/.gitconfig", "$h/.config/git/config") {
    next unless -f $gc;
    my $hp = `git config --file '$gc' --get core.hooksPath 2>/dev/null`;
    chomp $hp;
    next unless length $hp;
    (my $dir = $hp) =~ s{^~(?=/|$)}{$h};
    my $own = $dir =~ m{/\.polinrider-guard/hooks/?$};
    if (!-d $dir) { push @f, pf(sev => 'REVIEW', path => $gc, why => "global core.hooksPath points at a folder that does not exist ($hp)") unless $own; next }
    my $in_home = grep { index($dir, "$_/") == 0 } @homes;
    if (($dir =~ m{^(?:/tmp|/var/tmp|/dev/shm)/} && !$in_home) || $dir =~ m{/\.(?:n2|n3|npl|nlp|pyp)(?:/|$)}) {
      push @f, pf(sev => 'REVIEW', path => $dir, why => "global core.hooksPath is in a temp or hidden malware-style folder ($hp)");
    }
    opendir my $dh, $dir or next;
    for my $e (sort readdir $dh) {
      my $p = "$dir/$e";
      next if $e =~ /^\./ || $e =~ /\.sample$/ || !-f $p || -l $p;
      my $t = read_file_text($p) // next;
      next if $OWN_HOOK{ sha256_file($p) // '-' };    # an unmodified copy of this kit's own hook
      if (my $r = file_bad($t)) {
        push @f, pf(sev => 'HIGH', path => $p, why => "global git hook runs malware ($r)", action => { type => 'move' });
      } elsif (!$own && $t =~ /\b(?:curl|wget|Invoke-WebRequest|iwr)\b|\bnode\s+-e\b|\bbase64\s+(?:-d|--decode)\b|python3?\s+-c\b/) {
        push @f, pf(sev => 'REVIEW', path => $p, why => 'global git hook downloads or runs inline code; confirm you installed it');
      }
    }
    closedir $dh;
  }
  # User-level VS Code / Cursor tasks.json (applies to every folder).
  for my $tj ("$h/.config/Code/User/tasks.json", "$h/.config/Cursor/User/tasks.json", "$h/Library/Application Support/Code/User/tasks.json", "$h/Library/Application Support/Cursor/User/tasks.json") {
    next unless -f $tj;
    my $t = read_file_text($tj) // next;
    my ($sev, $why) = tasks_verdict($t);
    push @f, pf(sev => $sev, path => $tj, why => $why, action => { type => 'move' }) if $sev;
  }
  return @f;
}

sub detect_crontab {
  return () if $ISO && !$ENV{PRG_TEST_CRONTAB};
  my $t = `crontab -l 2>/dev/null`;
  return () unless defined $t && length $t;
  my @b = bad_lines($t) or return ();
  return (pf(sev => 'HIGH', path => 'crontab', why => 'cron entry runs malware: line ' . join(', ', map { $_->[0] } @b) . ' (' . $b[0][1] . ')', action => { type => 'crontab' }));
}

sub detect_system_persistence {
  return () if $ISO;
  my @f;
  my @dirs = ('/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/systemd/system', '/usr/lib/systemd/user', '/etc/xdg/autostart', '/Library/LaunchAgents', '/Library/LaunchDaemons');
  for my $d (@dirs) {
    next unless -d $d && -r $d;
    opendir my $dh, $d or next;
    for my $e (sort readdir $dh) {
      my $p = "$d/$e";
      next unless -f $p && !-l $p && -r $p && $e !~ /^\./;
      my $t = read_file_text($p, 256 * 1024) // next;
      my $r = file_bad($t) // next;
      push @f, pf(sev => 'HIGH', path => $p, why => "system-wide auto-start runs malware ($r). Needs root to remove: this tool leaves system files alone unless you run it as root", action => $IS_ROOT ? { type => 'move', service => 1 } : undef);
    }
    closedir $dh;
  }
  return @f;
}

sub find_named {
  my ($dir, $depth) = @_;
  my @hits;
  return @hits unless -d $dir;
  my $base_depth = ($dir =~ tr{/}{});
  File::Find::find({ no_chdir => 1, follow => 0,
    preprocess => sub { @_ },
    wanted => sub {
      my $p = $File::Find::name;
      my $d = ($p =~ tr{/}{}) - $base_depth;
      if (-d $p && !-l $p) { $File::Find::prune = 1 if $d >= $depth || basename($p) =~ /^(?:node_modules|\.git|\.cache|snap|Library|\.npm)$/ && $p ne $dir; return }
      return unless -f $p && !-l $p;
      push @hits, $p if basename($p) =~ /^temp_auto_push\.[A-Za-z0-9]+$/i || basename($p) eq 'config.bat';
    } }, $dir);
  return @hits;
}

sub detect_temp_files {
  my @f;
  my @dirs = @tmp_dirs;
  for my $h (@homes) { push @dirs, $h; }
  for my $d (@dirs) {
    my $depth = (grep { $_ eq $d } @homes) ? 2 : 3;
    for my $p (find_named($d, $depth)) {
      my $b = basename($p);
      if ($b eq 'config.bat') {
        my $gi = read_file_text(dirname($p) . '/.gitignore') // '';
        if ($gi =~ /^\s*config\.bat\s*$/m) { push @f, pf(sev => 'HIGH', path => $p, why => 'config.bat listed in .gitignore next to it (PolinRider hides its helper this way)', action => { type => 'move' }) }
        else { push @f, pf(sev => 'REVIEW', path => $p, why => 'config.bat found; PolinRider adds it to .gitignore, but a lone config.bat is often harmless', action => { type => 'move' }) }
      } else {
        push @f, pf(sev => 'HIGH', path => $p, why => 'PolinRider git amend / force-push helper script', action => { type => 'move' });
      }
    }
  }
  return @f;
}

# ------------------------------------------------------------------ project roots
my %PRUNE = map { $_ => 1 } qw(node_modules Library Applications snap AppData Pictures Music Movies Videos Public venv __pycache__ anaconda3 miniconda3 dist build target);
sub discover_roots {
  my ($home) = @_;
  my @roots;
  my $walk; $walk = sub {
    my ($d, $depth) = @_;
    return if $depth > $o{'repo-depth'};
    opendir my $dh, $d or return;
    my @e = sort grep { $_ ne '.' && $_ ne '..' } readdir $dh;
    closedir $dh;
    for my $e (@e) {
      next if $e =~ /^\./ || $PRUNE{$e};
      my $p = "$d/$e";
      next if -l $p || !-d $p;
      if (-e "$p/.git" || -f "$p/package.json" || -f "$p/.vscode/tasks.json") { push @roots, $p; next }
      $walk->($p, $depth + 1);
    }
  };
  $walk->($home, 1);
  return @roots;
}

my @ROOTS;
my %DIRTY_ROOTS;

my $CHECKS = qr/^(?:ioc-string|ioc-hash|ioc-domain|ioc-ip|ioc-filename|config-hidden-tail|loader-pattern|config-dangerous-api|config-long-line|fake-asset|vscode-task-command)$/;

# Another copy of this kit (a second clone) quotes the markers on purpose.
sub kit_copy_file {
  my ($root, $abs) = @_;
  return 0 unless -f "$root/lib/scan-core.pl" && -f "$root/iocs/strings-high.txt";
  my $rel = substr($abs, length($root) + 1);
  return ($rel =~ m{^(?:iocs|lib|hooks|tests|docs|extras|safe-defaults)/} || $rel =~ m{^[^/]+\.(?:sh|ps1|md)$}) ? 1 : 0;
}

sub scan_root {
  my ($root) = @_;
  my @f;
  my @self = ();
  my $sd = eval { require Cwd; Cwd::abs_path($SCRIPT_DIR) } // $SCRIPT_DIR;
  push @self, ('--self', $sd) if index("$sd/", "$root/") == 0;
  my @cmd = ('perl', "$FindBin::Bin/scan-core.pl", '--root', $root, '--ioc-dir', $IOC_DIR, @self, $o{deep} ? '--deep' : '--no-deep');
  open(my $olderr, '>&', \*STDERR);
  open(STDERR, '>', '/dev/null');
  my $opened = open my $ph, '-|', @cmd;
  open(STDERR, '>&', $olderr);
  return @f unless $opened;
  my %seen;
  while (my $l = <$ph>) {
    chomp $l;
    my ($sev, $chk, $loc, $det) = split /\t/, $l, 4;
    next unless defined $det && $sev eq 'HIGH' && $chk =~ $CHECKS;
    (my $rel = $loc) =~ s/:\d+$//;
    my $abs = $rel =~ m{^/} ? $rel : ($rel eq '.' ? $root : "$root/$rel");
    next if $seen{$abs}++ || !-e $abs || kit_copy_file($root, $abs);
    push @f, pf(sev => 'HIGH', path => $abs, why => "project file with malware ($chk: $det)", action => { type => 'move', repo_file => 1, root => $root });
  }
  close $ph;
  # tasks.json that runs on folder open
  for my $tj ("$root/.vscode/tasks.json") {
    next unless -f $tj;
    my $t = read_file_text($tj) // next;
    my ($sev, $why) = tasks_verdict($t);
    next unless $sev;
    next if $seen{$tj}++;
    push @f, pf(sev => $sev, path => $tj, why => $why, action => { type => 'move', repo_file => 1, root => $root });
  }
  # Git hooks and config inside the repository.
  if (-d "$root/.git/hooks") {
    opendir my $dh, "$root/.git/hooks";
    for my $e (sort readdir $dh) {
      my $p = "$root/.git/hooks/$e";
      next if $e =~ /^\./ || $e =~ /\.sample$/ || !-f $p || -l $p;
      my $t = read_file_text($p) // next;
      my $r = file_bad($t) // next;
      push @f, pf(sev => 'HIGH', path => $p, why => "repository git hook runs malware ($r)", action => { type => 'move', repo_file => 1, root => $root });
    }
    closedir $dh;
  }
  if (-f "$root/.git/config") {
    my $t = read_file_text("$root/.git/config") // '';
    if (my @b = bad_lines($t)) {
      push @f, pf(sev => 'HIGH', path => "$root/.git/config", why => 'repository git config contains a malware line (' . $b[0][1] . ')', action => { type => 'edit', repo_file => 1, root => $root });
    }
  }
  return @f;
}

sub detect_repos {
  my (@only) = @_;
  return () if $o{'no-repos'};
  my @f;
  if (!@only) {
    @ROOTS = ();
    my %s;
    for my $d (@scan_dirs) { my $a = eval { require Cwd; Cwd::abs_path($d) } // $d; push @ROOTS, $a unless $s{$a}++ }
    if (!@scan_dirs) { for my $h (@homes) { for my $r (discover_roots($h)) { push @ROOTS, $r unless $s{$r}++ } } }
    @only = @ROOTS;
    print STDERR "  scanning " . scalar(@only) . " project folder(s)...\n" if @only > 2 && !$o{_quiet};
  }
  for my $r (@only) {
    next unless -d $r;
    my @x = scan_root($r);
    $DIRTY_ROOTS{$r} = 1 if @x;
    push @f, @x;
  }
  return @f;
}

sub detect_persistence {
  my (%a) = @_;
  my @f;
  for my $h (@homes) { push @f, detect_home_artifacts($h), detect_home_persistence($h) }
  push @f, detect_crontab(), detect_system_persistence(), detect_temp_files();
  push @f, detect_repos(@{ $a{roots} || [] }) unless $a{light};
  # de-duplicate by key
  my (%s, @u);
  for my $x (@f) { next if $x->{path} && $x->{path} ne 'crontab' && -e $x->{path} && under_kit($x->{path}); push @u, $x unless $s{ $x->{key} }++ }
  return @u;
}

# ------------------------------------------------------------------ accepted review items
sub is_accepted {
  my ($f) = @_;
  return 0 unless $f->{path};
  for my $a (@accept) { return 1 if $f->{path} eq $a || index($f->{path}, "$a/") == 0 }
  return 0;
}
sub blocking { my ($f) = @_; return ($f->{sev} eq 'HIGH' || ($f->{sev} eq 'REVIEW' && !is_accepted($f))) }

# ------------------------------------------------------------------ quarantine
my ($QDIR, @ENTRIES, $QN);
sub qdir_init {
  return if $QDIR;
  my $ts = strftime('%Y%m%d-%H%M%S', localtime);
  my $d = "$QROOT/$ts";
  my $i = 1;
  while (-e $d) { $d = "$QROOT/$ts-" . ++$i }
  make_path("$d/items", { mode => 0700 });
  chmod 0700, $QROOT, $d;
  $QDIR = $d; $QN = 0;
}
sub write_manifest {
  return unless $QDIR;
  my $m = { tool => 'polinrider-guard', version => $VERSION, created => strftime('%Y-%m-%dT%H:%M:%S%z', localtime),
    host => (`hostname 2>/dev/null` =~ s/\s+$//r), user => scalar(getpwuid($>)), entries => \@ENTRIES };
  open my $fh, '>', "$QDIR/manifest.json" or return;
  print $fh $JSON->encode($m);
  close $fh;
  chmod 0600, "$QDIR/manifest.json";
}
sub hash_tree {
  my ($path) = @_;
  my @files;
  if (-d $path && !-l $path) {
    my $cnt = 0;
    File::Find::find({ no_chdir => 1, follow => 0, wanted => sub {
      my $p = $File::Find::name;
      return if -d $p && !-l $p;
      return if ++$cnt > 20000;
      my $rel = substr($p, length($path) + 1);
      my @st = lstat $p;
      if (-l $p) { push @files, { rel => $rel, link => readlink($p) } }
      else { push @files, { rel => $rel, sha256 => ((-s $p) < 200 * 1024 * 1024 ? sha256_file($p) : undef), mode => $st[2] & 07777 } }
    } }, $path);
    return { kind => 'dir', files => \@files, truncated => $cnt > 20000 ? JSON::PP::true : JSON::PP::false };
  }
  if (-l $path) { return { kind => 'symlink', link => readlink($path) } }
  my @st = stat $path;
  return { kind => 'file', sha256 => sha256_file($path), mode => $st[2] & 07777 };
}
sub strip_exec {
  my ($p) = @_;
  my @all;
  if (-d $p && !-l $p) { File::Find::find({ no_chdir => 1, follow => 0, wanted => sub { push @all, $File::Find::name } }, $p) } else { @all = ($p) }
  for my $x (@all) { next if -l $x; my @st = stat $x; next unless @st; chmod(($st[2] & 07777) & ~0111 | (-d $x ? 0700 : 0), $x) }
}

sub q_item {
  my ($f) = @_;
  my $a = $f->{action};
  if ($f->{path} && $f->{path} ne 'crontab' && under_kit($f->{path})) { print "  refusing to move a file of this kit itself: $f->{path}\n"; return 0 }
  qdir_init();
  my $id = sprintf '%04d', ++$QN;
  my $dest = "$QDIR/items/$id";
  make_path($dest, { mode => 0700 });
  my $reason = $f->{why};
  if ($a->{type} eq 'move') {
    my $path = $f->{path};
    my $info = hash_tree($path);
    my $target = "$dest/" . basename($path);
    if ($a->{service} && !$ENV{PRG_NO_SERVICE_CTL}) {
      # Stop the service first so it is not restarted from a file that is about to move.
      if ($path =~ m{/systemd/(?:user|system)/([^/]+)$}) { my $u = $1; system('systemctl', ($path =~ m{/user/} ? '--user' : ()), 'disable', '--now', $u); }
      if ($path =~ m{/Library/Launch(?:Agents|Daemons)/}) { system('launchctl', 'unload', '-w', $path) }
    }
    system('mv', '--', $path, $target) == 0 or do { print "  ${R}could not move $path${N}\n"; return 0 };
    strip_exec($target);
    push @ENTRIES, { id => $id, type => 'move', original => $path, quarantined => $target, reason => $reason, %$info };
    print "  moved  $path\n         -> $target\n";
    write_manifest();
    return 1;
  }
  if ($a->{type} eq 'edit') {
    my $path = $f->{path};
    my $text = read_file_text($path, 64 * 1024 * 1024);
    defined $text or return 0;
    my @st = stat $path;
    my $backup = "$dest/" . basename($path) . '.orig';
    open my $bo, '>:raw', $backup or return 0; print $bo $text; close $bo; chmod 0600, $backup;
    my @l = split /\n/, $text, -1;
    my @done;
    for my $i (0 .. $#l) {
      next if $l[$i] =~ /^\s*#/;
      if (file_bad($l[$i]) || $l[$i] =~ /sudo shutdown -h 0/) { push @done, $i + 1; $l[$i] = "# polinrider-guard disabled: $l[$i]" }
    }
    my $new = join "\n", @l;
    my $tmp = "$path.polinrider-tmp";
    open my $no, '>:raw', $tmp or return 0; print $no $new; close $no; chmod $st[2] & 07777, $tmp;
    rename $tmp, $path or do { unlink $tmp; return 0 };
    push @ENTRIES, { id => $id, type => 'edit', original => $path, backup => $backup, backup_sha256 => sha256_file($backup),
      new_sha256 => sha256_file($path), mode => $st[2] & 07777, lines => \@done, reason => $reason };
    print "  commented out line(s) " . join(',', @done) . " in $path (original saved: $backup)\n";
    write_manifest();
    return 1;
  }
  if ($a->{type} eq 'crontab') {
    my $text = `crontab -l 2>/dev/null`;
    my $backup = "$dest/crontab.orig";
    open my $bo, '>:raw', $backup or return 0; print $bo $text; close $bo; chmod 0600, $backup;
    my @l = split /\n/, $text, -1;
    my @done;
    for my $i (0 .. $#l) { next if $l[$i] =~ /^\s*#/; if (file_bad($l[$i])) { push @done, $i + 1; $l[$i] = "# polinrider-guard disabled: $l[$i]" } }
    my $tmp = "$dest/crontab.new";
    open my $no, '>:raw', $tmp or return 0; print $no join("\n", @l); close $no;
    system('crontab', $tmp) == 0 or do { print "  ${R}could not install the cleaned crontab${N}\n"; return 0 };
    push @ENTRIES, { id => $id, type => 'crontab', original => 'crontab', backup => $backup, backup_sha256 => sha256_file($backup), lines => \@done, reason => $reason };
    print "  commented out crontab line(s) " . join(',', @done) . " (original saved: $backup)\n";
    write_manifest();
    return 1;
  }
  return 0;
}

sub do_restore {
  my ($dir) = @_;
  my $mf = "$dir/manifest.json";
  -f $mf or do { print STDERR "No manifest.json in $dir\n"; return 3 };
  my $m = eval { JSON::PP->new->decode(read_file_text($mf)) } or do { print STDERR "Cannot read manifest\n"; return 3 };
  print "Restoring from $dir (" . scalar(@{ $m->{entries} }) . " item(s)).\n";
  print "${Y}WARNING: these files were quarantined because they look like malware. Restoring puts them back in place and can re-arm them.${N}\n";
  if (!$o{yes}) { print "Re-run with --yes to confirm.\n"; return 3 }
  my ($ok, $bad) = (0, 0);
  for my $e (@{ $m->{entries} }) {
    if ($e->{type} eq 'move') {
      my ($src, $dst) = ($e->{quarantined}, $e->{original});
      if (!-e $src && !-l $src) { print "  not in quarantine any more (already restored?): $src\n"; $bad++; next }
      if (-e $dst || -l $dst) { print "  ${Y}skip${N} $dst already exists (not overwriting)\n"; $bad++; next }
      if (($e->{sha256}) && -f $src && (sha256_file($src) // '') ne $e->{sha256}) { print "  ${Y}warning${N}: $src changed since quarantine (sha256 mismatch)\n" }
      make_path(dirname($dst));
      system('mv', '--', $src, $dst) == 0 or do { print "  ${R}failed${N} $dst\n"; $bad++; next };
      if (($e->{files}) ) { for my $f (@{ $e->{files} }) { next if $f->{link} || !defined $f->{mode}; chmod $f->{mode}, "$dst/$f->{rel}" } }
      elsif (defined $e->{mode} && !-l $dst) { chmod $e->{mode}, $dst }
      print "  restored $dst\n"; $ok++;
    } elsif ($e->{type} eq 'edit') {
      my ($bk, $dst) = ($e->{backup}, $e->{original});
      -f $bk or do { print "  missing backup $bk\n"; $bad++; next };
      my $cur = -f $dst ? sha256_file($dst) : '';
      if ($cur ne ($e->{new_sha256} // '') && !$o{force}) { print "  ${Y}skip${N} $dst changed after quarantine (use --force to overwrite)\n"; $bad++; next }
      my $txt = read_file_text($bk, 64 * 1024 * 1024);
      open my $fh, '>:raw', $dst or do { $bad++; next }; print $fh $txt; close $fh; chmod $e->{mode}, $dst if defined $e->{mode};
      print "  restored $dst\n"; $ok++;
    } elsif ($e->{type} eq 'crontab') {
      system('crontab', $e->{backup}) == 0 ? do { print "  restored crontab\n"; $ok++ } : do { print "  ${R}failed to restore crontab${N}\n"; $bad++ };
    }
  }
  print "Restored $ok item(s), $bad not restored.\n";
  return $bad ? 2 : 0;
}

# ------------------------------------------------------------------ reporting
sub trunc_note { return $_[0] }
sub print_findings {
  my (@f) = @_;
  my @proc = grep { $_->{kind} eq 'process' } @f;
  my @per  = grep { $_->{kind} eq 'persist' } @f;
  print "${B}Running processes${N}\n";
  if (!@proc) { print "  none matched\n" }
  for my $p (@proc) {
    my $col = $p->{sev} eq 'HIGH' ? $R : $Y;
    printf "  %s%-6s%s pid %d  parent %s\n", $col, $p->{sev}, $N, $p->{pid}, short_proc($p->{ppid});
    print "         cmd: " . clean_cmd($p->{cmd}, 160) . "\n";
    print "         why: $p->{why}\n";
  }
  print "${B}Persistence and re-run points${N}\n";
  if (!@per) { print "  none matched\n" }
  for my $p (@per) {
    my $col = $p->{sev} eq 'HIGH' ? $R : ($p->{sev} eq 'REVIEW' ? $Y : '');
    my $acc = is_accepted($p) ? ' (accepted by you)' : '';
    printf "  %s%-6s%s %s%s\n", $col, $p->{sev}, $N, clean_cmd($p->{path}, 200), $acc;
    print "         why: $p->{why}\n";
  }
}

sub do_kill {
  my (@proc) = @_;
  my %kill;
  for my $p (grep { $_->{sev} eq 'HIGH' } @proc) {
    $kill{ $p->{pid} } = 1;
    $kill{$_} = 1 for descendants($p->{pid});
  }
  for my $pid (keys %kill) { delete $kill{$pid} if $ancestors{$pid} }
  return 0 unless %kill;
  print "${B}Stopping matched processes${N}\n";
  my $n = 0;
  for my $pid (sort { $a <=> $b } keys %kill) {
    my $d = $P{$pid} ? clean_cmd($P{$pid}{cmd}, 80) : '';
    if (kill('TERM', $pid)) { print "  sent TERM to pid $pid `$d`\n"; $n++ } else { print "  ${R}cannot signal pid $pid (permission or already gone)${N}\n" }
  }
  select(undef, undef, undef, 0.8);
  for my $pid (sort { $a <=> $b } keys %kill) {
    if (kill(0, $pid)) {
      # A zombie still answers kill(0). Only escalate if it is a live process.
      my $st = `ps -o stat= -p $pid 2>/dev/null`; $st =~ s/\s+//g;
      next if $st =~ /^Z/ || $st eq '';
      kill('KILL', $pid); print "  sent KILL to pid $pid\n";
    }
  }
  select(undef, undef, undef, 0.4);
  return $n;
}

sub do_actions {
  my (@f) = @_;
  if ($o{kill}) { do_kill(grep { $_->{kind} eq 'process' } @f) }
  if ($o{quarantine}) {
    my @q = grep { $_->{kind} eq 'persist' && $_->{action} && ($_->{sev} eq 'HIGH') } @f;
    # Review items are never moved automatically.
    if (@q) { print "${B}Quarantine${N}\n"; q_item($_) for @q }
  }
}

sub recheck {
  my @pr = detect_processes();
  my @ps = detect_persistence(roots => [keys %DIRTY_ROOTS]);
  return (@pr, @ps);
}

sub verdict {
  my (@f) = @_;
  my @block = grep { blocking($_) } @f;
  print "\n${B}Verdict${N}\n";
  if (!@block) {
    print "${G}${B}SAFE TO ROTATE CREDENTIALS${N}\n";
    print "  No active PolinRider process and no re-run point was found after the actions above.\n";
    print "  This is a snapshot against published indicators, not proof. See the caveats below.\n";
    return 0;
  }
  print "${R}${B}NOT SAFE YET${N}\n";
  my @pr = grep { $_->{kind} eq 'process' } @block;
  my @pe = grep { $_->{kind} eq 'persist' } @block;
  print "  Still present: " . scalar(@pr) . " running process(es), " . scalar(@pe) . " persistence item(s).\n";
  for my $x (@block) {
    my $what = $x->{kind} eq 'process' ? "pid $x->{pid}: " . clean_cmd($x->{cmd}, 70) : clean_cmd($x->{path}, 120);
    my $why = '';
    if ($x->{kind} eq 'process' && !$o{kill}) { $why = ' (re-run with --kill)' }
    elsif ($x->{kind} eq 'process') { $why = ' (could not be stopped: try as the owning user or root)' }
    elsif ($x->{sev} eq 'REVIEW') { $why = ' (needs your review; use --accept PATH once you have checked it)' }
    elsif (!$x->{action}) { $why = ' (cannot be moved by this tool: remove it by hand as root)' }
    elsif (!$o{quarantine}) { $why = ' (re-run with --quarantine)' }
    else { $why = ' (could not be moved)' }
    print "   - [$x->{sev}] $what$why\n";
  }
  print "  Do not rotate credentials on this machine yet: a re-run would steal the new ones.\n";
  return 2;
}

sub caveats_and_checklist {
  my ($ok) = @_;
  if (-r '/proc/version' && (read_file_text('/proc/version', 4096) // '') =~ /microsoft/i) {
    print "\n${Y}WSL detected.${N} The loader can also start node.exe on the Windows side. Run live-respond.ps1 on the Windows host too.\n";
  }
  print "\n${B}What this does not tell you${N}\n";
  print "  - It cannot undo anything already stolen (browser passwords, cookies, wallet data, .env keys, git credentials).\n";
  print "  - Indicators rotate and a rootkit or a renamed process would not match. If in doubt, reinstall the operating system.\n";
  print "  - Other copies of an infected repo (other machines, forks, CI caches) can re-infect you. Check them too.\n";
  print "\n${B}Rotation checklist" . ($ok ? '' : ' (do this only after the verdict is SAFE)') . "${N}\n";
  print "  Do it from a different, clean device if you can. Revoke first, then create new ones.\n";
  print "   1. GitHub: personal access tokens, OAuth apps, SSH and GPG keys, deploy keys, and review recent sessions and security log.\n";
  print "   2. Delete ~/.git-credentials; sign out of git credential helpers and the GitHub CLI, then log in again.\n";
  print "   3. npm: revoke tokens (npm token list), turn on 2FA, check ~/.npmrc for _authToken lines.\n";
  print "   4. Cloud and CI keys: AWS, GCP, Azure, Vercel, Supabase, Docker, Fly, Netlify, Cloudflare; any key in a .env or shell profile.\n";
  print "   5. SSH: replace every private key in ~/.ssh that lived on this machine and remove the old public keys from servers and GitHub.\n";
  print "   6. Browsers: change passwords saved in the browser, sign out of all sessions, rotate password-manager master password if its extension was installed.\n";
  print "   7. Wallets: move funds to a wallet created on a clean device; the old seed phrase is burned.\n";
  print "   8. Email and chat accounts that had saved sessions (Google, Slack, Discord, Telegram).\n";
  print "  If you are unsure the machine is clean, reinstall the operating system before you sign in to anything.\n";
}

# ------------------------------------------------------------------ main
print "${B}PolinRider Guard live response $VERSION${N}  " . ($o{kill} || $o{quarantine} ? 'ACTIONS ENABLED: ' . join(' ', grep { $o{$_} } qw(kill quarantine)) : 'report only (no changes)') . "\n";
print "  homes: " . join(', ', @homes) . "\n";
my @found = (detect_processes(), detect_persistence());
print_findings(@found);
my @actionable = grep { $_->{sev} ne 'NOTE' } @found;
if (@actionable && ($o{kill} || $o{quarantine})) {
  do_actions(@found);
  @found = recheck();
  print "\n${B}After actions${N}\n";
  print_findings(@found);
} elsif (@actionable) {
  print "\nNothing was changed. Re-run with --kill and/or --quarantine to act on the HIGH items.\n";
}
my $rc = verdict(@found);
caveats_and_checklist($rc == 0);
if ($QDIR) { print "\nQuarantine folder: $QDIR\n  Restore with: live-respond.sh --restore '$QDIR' --yes\n" }

if ($o{history} && !$o{'no-repos'} && (@scan_dirs || @ROOTS)) {
  my @repo_args;
  push @repo_args, ('--scan-dir', $_) for (@scan_dirs ? @scan_dirs : @ROOTS);
  push @repo_args, ('--isolated') if $ISO;
  print "\n";
  system('perl', "$FindBin::Bin/history-core.pl", '--ioc-dir', $IOC_DIR, '--embedded', @repo_args);
}

if ($o{watch}) {
  my $sig = 0;
  $SIG{INT} = $SIG{TERM} = sub { $sig = 1 };
  print "\n${B}Watching${N} every $o{interval}s" . ($o{kill} ? ', killing reappearing processes' : ', alert only (add --kill to stop them)') . ($o{quarantine} ? ', quarantining reappearing files' : '') . ". Ctrl-C to stop.\n";
  my $cycle = 0;
  my %announced;
  while (!$sig) {
    my $secs = $o{interval};
    for (my $t = 0; $t < $secs && !$sig; $t++) { select(undef, undef, undef, 1) }
    last if $sig;
    $cycle++;
    my $full = ($cycle % 10 == 0);
    my @w = (detect_processes(), detect_persistence(light => !$full));
    my @hi = grep { $_->{sev} eq 'HIGH' } @w;
    my $ts = strftime('%H:%M:%S', localtime);
    if (@hi) {
      print "\a${R}[$ts] ALERT: " . scalar(@hi) . " PolinRider item(s) present${N}\n";
      print_findings(@w);
      do_actions(@w) if $o{kill} || $o{quarantine};
      %announced = ();
    } elsif ($cycle % 10 == 0 || $o{'max-cycles'}) {
      print "[$ts] clean (check $cycle)\n";
    }
    last if $o{'max-cycles'} && $cycle >= $o{'max-cycles'};
  }
  my @last = (detect_processes(), detect_persistence(light => 1));
  print "\nStopped watching.\n";
  $rc = verdict(@last);
}
exit $rc;
