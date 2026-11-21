#!/usr/bin/env perl
# history-core.pl - git history forensics for PolinRider, behind history-report.sh.
#
# For each git repository it finds the FIRST commit that introduced infected code
# (with author and committer dates and date-mismatch flags), every commit and ref that
# carries it, whether HEAD is still infected, and a summary across repositories.
# With --github owner/repo it also looks at that repository's public forks and runs a
# GitHub code search for the loader fingerprint. Read-only: it never changes a repository.
# Only core Perl modules and the curl command are used.
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin";
use PRG qw(load_iocs ioc_hit file_bad tasks_verdict read_file_text clean_cmd @HOST_ART);
use Getopt::Long qw(GetOptions);
use File::Basename qw(basename dirname);
use File::Temp qw(tempdir);
use POSIX qw(strftime);
use JSON::PP ();

$| = 1;
my $VERSION = '0.2.0';
my %o = ('max-commits' => 50000, 'max-forks' => 100, 'repo-depth' => 6, 'raw-tasks' => 1);
my (@homes, @scan_dirs, @fingerprints);
GetOptions(\%o, 'ioc-dir=s', 'scan-dir=s' => \@scan_dirs, 'home=s' => \@homes, 'isolated!', 'embedded!', 'json=s',
  'max-commits=i', 'github=s', 'max-forks=i', 'fingerprint=s' => \@fingerprints, 'no-code-search!', 'help|h!', 'repo-depth=i')
  or die "bad arguments (see --help)\n";
my @paths = @ARGV;
if ($o{help}) { print usage(); exit 0 }
sub usage {
  return <<'USAGE';
history-report.sh - find when and where PolinRider code entered your git history (read-only)

  history-report.sh [PATH...]                 each PATH is a repo, or a folder containing repos
  history-report.sh                           repos found under your home directory
  history-report.sh --github owner/repo       also check that repo's public forks and run code search

Options
  --json FILE         write the full result as JSON
  --max-commits N     history walk limit per repo (default 50000)
  --github OWNER/REPO check up to --max-forks forks (default 100) for the same code
  --fingerprint STR   extra code-search fingerprint (repeatable); markers found in your own repos are added automatically
  --no-code-search    skip the GitHub code search
  GITHUB_TOKEN        (environment) used for the GitHub API if set; works without it at a much lower rate limit

Exit codes: 0 = no infected content in history, 1 = infected only in history (HEAD clean), 2 = a repo is infected now, 3 = error.
USAGE
}
my $SCRIPT_DIR = "$FindBin::Bin/..";
my $IOC_DIR = $o{'ioc-dir'} || $ENV{IOC_DIR} || "$SCRIPT_DIR/iocs";
load_iocs($IOC_DIR);
my ($R, $Y, $G, $N, $B) = -t STDOUT ? ("\e[31m", "\e[33m", "\e[32m", "\e[0m", "\e[1m") : ('', '', '', '', '');
my $HOME = $ENV{HOME} || '';
@homes = ($HOME) if !@homes && $HOME;

# ------------------------------------------------------------------ helpers
my @GITC = ('git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.pager=cat', '-c', 'protocol.ext.allow=never', '--no-pager');
sub git_lines {
  my ($repo, @args) = @_;
  open my $ph, '-|', @GITC, '-C', $repo, @args or return ();
  my @l;
  while (my $x = <$ph>) { chomp $x; push @l, $x }
  close $ph;
  return @l;
}
sub git_one { my @l = git_lines(@_); return defined $l[0] ? $l[0] : '' }

# Paths that mention markers on purpose: documentation, this kit's own IOC lists and tests.
sub skip_path {
  my ($p, $self_repo) = @_;
  return 1 if $p =~ /\.(?:md|markdown|txt|csv|tsv|rst|lock|svg|map|snap)$/i;
  return 1 if $self_repo && $p =~ m{^(?:iocs|tests|docs|lib|hooks|extras|safe-defaults)/};
  return 1 if $self_repo && $p =~ m{^[^/]+\.(?:sh|ps1)$};
  return 0;
}
sub is_self_repo { my ($repo) = @_; return (-f "$repo/lib/scan-core.pl" && -f "$repo/iocs/strings-high.txt") ? 1 : 0 }

sub line_hit {
  my ($l) = @_;
  return undef if length($l) < 8;
  return ioc_hit(length($l) > 3_000_000 ? substr($l, 0, 3_000_000) : $l);
}

sub discover {
  my (@roots) = @_;
  my @repos;
  my %seen;
  my $walk; $walk = sub {
    my ($d, $depth) = @_;
    return if $depth > $o{'repo-depth'};
    if (-e "$d/.git") { my $a = eval { require Cwd; Cwd::abs_path($d) } // $d; push @repos, $a unless $seen{$a}++; return }
    opendir my $dh, $d or return;
    my @e = sort grep { $_ ne '.' && $_ ne '..' } readdir $dh;
    closedir $dh;
    for my $e (@e) {
      next if $e eq 'node_modules' || $e =~ /^\./ && $depth > 0 && $e ne '.git';
      next if $e eq 'Library' || $e eq 'Applications' || $e eq 'snap';
      my $p = "$d/$e";
      next if -l $p || !-d $p;
      $walk->($p, $depth + 1);
    }
  };
  for my $r (@roots) { $walk->($r, 0) if -d $r }
  return @repos;
}

# ------------------------------------------------------------------ per-repo analysis
my %MARKERS;     # loader fingerprints seen in added lines (e.g. global.i value)
sub analyze_repo {
  my ($repo) = @_;
  my $self_repo = is_self_repo($repo);
  my %res = (path => $repo, commits_scanned => 0, introducing => [], infected_refs => [], head_infected => JSON::PP::false,
    worktree_infected => JSON::PP::false, status => 'CLEAN');
  my $head = git_one($repo, 'rev-parse', '--verify', '-q', 'HEAD');
  if (!length $head && !git_lines($repo, 'for-each-ref', '--format=%(refname)')) { $res{status} = 'EMPTY'; return \%res }

  # 1. Walk history oldest to newest and inspect every added line.
  my (%ct_of, %at_of, @order, %C);
  my $fmt = "\x01C\x01%H\x01%P\x01%an\x01%ae\x01%aI\x01%cI\x01%at\x01%ct\x01%s";
  open my $ph, '-|', @GITC, '-C', $repo, 'log', '--all', '--reverse', '--topo-order', '-p', '-U0', '--no-color', '--no-ext-diff',
    '--no-textconv', '--no-renames', "--max-count=$o{'max-commits'}", "--format=$fmt" or die "git log failed\n";
  my ($cur, $file);
  while (my $l = <$ph>) {
    chomp $l;
    if (substr($l, 0, 3) eq "\x01C\x01") {
      my ($sha, $par, $an, $ae, $ai, $ci, $at, $ct, $subj) = split /\x01/, substr($l, 3), 9;
      $cur = { sha => $sha, parents => [split ' ', $par // ''], author => $an, email => $ae, author_date => $ai, committer_date => $ci,
        at => $at, ct => $ct, subject => $subj // '', files => {} };
      $ct_of{$sha} = $ct; $at_of{$sha} = $at; push @order, $sha; $C{$sha} = $cur;
      $res{commits_scanned}++;
      $file = undef;
      next;
    }
    next unless $cur;
    if ($l =~ m{^\+\+\+ b/(.*)$}) {
      $file = $1;
      if (basename($file) =~ /^temp_auto_push\.[A-Za-z0-9]+$/i && !skip_path($file, $self_repo)) { $cur->{files}{$file} ||= 'PolinRider auto-push helper file' }
      next;
    }
    next unless defined $file && substr($l, 0, 1) eq '+' && substr($l, 0, 3) ne '+++';
    next if skip_path($file, $self_repo);
    my $body = substr($l, 1);
    if (my $r = line_hit($body)) {
      $cur->{files}{$file} ||= $r;
      if ($body =~ /global\.[oi]\s*=\s*['"](A?\d+-[0-9A-Za-z*-]+)['"]/) { $MARKERS{$1} = 1 }
    }
  }
  close $ph;
  my @hits = grep { %{ $C{$_}{files} } } @order;
  for my $sha (@hits) {
    my $c = $C{$sha};
    my @flags;
    my ($at, $ct) = ($c->{at}, $c->{ct});
    if ($ct - $at > 86400) { push @flags, sprintf('committer date is %.1f days after the author date (amend, rebase, or clock rewind)', ($ct - $at) / 86400) }
    elsif ($at - $ct > 86400) { push @flags, sprintf('author date is %.1f days after the committer date (unusual)', ($at - $ct) / 86400) }
    for my $p (@{ $c->{parents} }) {
      next unless defined $ct_of{$p};
      if ($at + 60 < $ct_of{$p}) { push @flags, sprintf('dated %.1f days BEFORE its own parent %s (clock rewind or history rewrite; PolinRider rewinds the clock)', ($ct_of{$p} - $at) / 86400, substr($p, 0, 7)); last }
    }
    my @refs = git_lines($repo, 'for-each-ref', '--contains', $sha, '--format=%(refname:short)', 'refs/heads', 'refs/remotes', 'refs/tags');
    @refs = grep { $_ !~ m{/HEAD$} } @refs;
    push @{ $res{introducing} }, { sha => $sha, author => $c->{author}, email => $c->{email}, author_date => $c->{author_date},
      committer_date => $c->{committer_date}, subject => $c->{subject}, files => { %{ $c->{files} } }, flags => \@flags,
      contained_in => \@refs };
  }
  # reflog hint: PolinRider amends the latest commit
  my @rl = git_lines($repo, 'reflog', '--format=%gs');
  $res{reflog_amends} = scalar grep { /^commit \(amend\)/ } @rl;

  # 2. What is infected NOW: every branch, remote branch, tag and the working tree.
  my ($sf, $rf) = write_pattern_files();
  my @refs = grep { length && $_ !~ m{/HEAD$} } git_lines($repo, 'for-each-ref', '--format=%(refname)', 'refs/heads', 'refs/remotes', 'refs/tags');
  $res{refs_total} = scalar @refs;
  my %tree_cache;
  my $head_tree = length $head ? git_one($repo, 'rev-parse', "$head^{tree}") : '';
  for my $ref (@refs[0 .. ($#refs > 299 ? 299 : $#refs)]) {
    my $tree = git_one($repo, 'rev-parse', '--verify', '-q', "$ref^{tree}");
    next unless length $tree;
    my $files = $tree_cache{$tree} //= tree_infected($repo, $ref, $sf, $rf, $self_repo);
    push @{ $res{infected_refs} }, { ref => $ref, files => $files } if %$files;
  }
  if (length $head && $head_tree) {
    my $files = $tree_cache{$head_tree} //= tree_infected($repo, 'HEAD', $sf, $rf, $self_repo);
    if (%$files) { $res{head_infected} = JSON::PP::true; $res{head_files} = $files }
  }
  # working tree (tracked and untracked, ignoring .gitignore)
  {
    my %wt;
    for my $mode (['-F', $sf], ['-E', $rf]) {
      for my $f (git_lines($repo, 'grep', '-I', '-l', '-i', '--untracked', $mode->[0], '-f', $mode->[1], '--', '.')) {
        next if skip_path($f, $self_repo);
        $wt{$f} = 'matches IOC patterns';
      }
    }
    for my $f (git_lines($repo, 'ls-files', '--cached', '--others')) { $wt{$f} = 'PolinRider auto-push helper file' if basename($f) =~ /^temp_auto_push\.[A-Za-z0-9]+$/i && !skip_path($f, $self_repo) }
    if (%wt) { $res{worktree_infected} = JSON::PP::true; $res{worktree_files} = \%wt }
  }
  my $ever = @{ $res{introducing} } > 0;
  my $now = $res{head_infected} || @{ $res{infected_refs} } || $res{worktree_infected};
  $res{status} = $res{head_infected} ? 'INFECTED (HEAD)' : $now ? 'INFECTED (other refs or working tree)' : $ever ? 'HISTORY ONLY (clean now)' : 'CLEAN';
  if ($ever) { $res{first} = $res{introducing}[0] }
  return \%res;
}

my $PATDIR;
sub write_pattern_files {
  $PATDIR ||= tempdir('prg-hist.XXXXXX', TMPDIR => 1, CLEANUP => 1);
  my $sf = "$PATDIR/strings.txt"; my $rf = "$PATDIR/regex.txt";
  if (!-f $sf) {
    open my $a, '>', $sf; print $a "$_\n" for grep { length } map { $_ } do { my @s; open my $fh, '<', "$IOC_DIR/strings-high.txt"; while (<$fh>) { chomp; next if /^\s*(#|$)/; push @s, $_ } @s }; close $a;
    open my $b, '>', $rf; open my $fh2, '<', "$IOC_DIR/regex-high.txt"; while (<$fh2>) { chomp; next if /^\s*(#|$)/; print $b "$_\n" } close $b;
  }
  return ($sf, $rf);
}
sub tree_infected {
  my ($repo, $ref, $sf, $rf, $self_repo) = @_;
  my %f;
  for my $mode (['-F', $sf], ['-E', $rf]) {
    for my $l (git_lines($repo, 'grep', '-I', '-l', '-i', $mode->[0], '-f', $mode->[1], $ref, '--', '.')) {
      my $p = $l; $p =~ s/^\Q$ref\E://;
      next if skip_path($p, $self_repo);
      $f{$p} = 'matches IOC patterns';
    }
  }
  for my $p (git_lines($repo, 'ls-tree', '-r', '--name-only', $ref)) {
    $f{$p} = 'PolinRider auto-push helper file' if basename($p) =~ /^temp_auto_push\.[A-Za-z0-9]+$/i && !skip_path($p, $self_repo);
  }
  return \%f;
}

sub short_date { my ($d) = @_; return $d // '' }

sub print_repo {
  my ($r) = @_;
  my $col = $r->{status} =~ /^INFECTED/ ? $R : $r->{status} =~ /^HISTORY/ ? $Y : $G;
  print "${B}Repo${N} $r->{path}\n";
  if ($r->{status} eq 'EMPTY') { print "  empty repository\n"; return }
  print "  commits scanned: $r->{commits_scanned}   status: ${col}$r->{status}${N}\n";
  if ($r->{first}) {
    my $f = $r->{first};
    print "  ${B}First commit with infected code${N}\n";
    print "    commit    $f->{sha}\n";
    print "    author    $f->{author} <$f->{email}>\n";
    print "    authored  $f->{author_date}\n";
    print "    committed $f->{committer_date}\n";
    print "    message   " . clean_cmd($f->{subject}, 100) . "\n";
    print "    files     " . join(', ', map { clean_cmd($_, 80) } sort keys %{ $f->{files} }) . "\n";
    print "    ${Y}date flag${N}  $_\n" for @{ $f->{flags} };
    print "    (no date flag: PolinRider keeps the original timestamp on an amended commit, so a clean date does not prove the commit is genuine)\n" unless @{ $f->{flags} };
    my $n = @{ $r->{introducing} };
    print "  ${B}Commits that introduced infected code${N}: $n\n";
    my $i = 0;
    for my $c (@{ $r->{introducing} }) {
      last if ++$i > 15;
      print "    " . substr($c->{sha}, 0, 10) . "  $c->{author_date}  $c->{author}  [" . join(', ', map { clean_cmd($_, 50) } sort keys %{ $c->{files} }) . "]" . (@{ $c->{flags} } ? "  ${Y}DATE FLAG${N}" : '') . "\n";
      my @in = @{ $c->{contained_in} };
      print "        in refs: " . join(', ', @in[0 .. ($#in > 5 ? 5 : $#in)]) . (@in > 6 ? ", ... (+" . (@in - 6) . ")" : '') . "\n" if @in;
    }
    print "    ... and " . ($n - 15) . " more\n" if $n > 15;
  } else {
    print "  no commit in history added any known infected pattern\n";
  }
  print "  ${B}Infected now${N}\n";
  print "    HEAD: " . ($r->{head_infected} ? "${R}YES${N} (" . join(', ', map { clean_cmd($_, 60) } sort keys %{ $r->{head_files} }) . ")" : "no") . "\n";
  my @ir = @{ $r->{infected_refs} };
  print "    refs carrying it: " . scalar(@ir) . " of $r->{refs_total}" . (@ir ? ': ' . join(', ', map { $_->{ref} } @ir[0 .. ($#ir > 9 ? 9 : $#ir)]) . (@ir > 10 ? ', ...' : '') : '') . "\n";
  print "    working tree: " . ($r->{worktree_infected} ? "${R}YES${N} (" . join(', ', map { clean_cmd($_, 60) } sort keys %{ $r->{worktree_files} }) . ")" : "no") . "\n";
  print "    local reflog shows $r->{reflog_amends} 'commit (amend)' entries (PolinRider amends the latest commit; people do too)\n" if $r->{reflog_amends};
}

# ------------------------------------------------------------------ GitHub
my $API = $ENV{POLINRIDER_GITHUB_API} || 'https://api.github.com';
my $RAW = $ENV{POLINRIDER_GITHUB_RAW} || 'https://raw.githubusercontent.com';
my $TOKEN = $ENV{GITHUB_TOKEN} // '';
my %rl = (remaining => undef, reset => undef, stopped => '');
my $gh_calls = 0;
sub urlenc { my ($s) = @_; $s =~ s/([^A-Za-z0-9_.~-])/sprintf('%%%02X', ord $1)/ge; return $s }

sub http_get {
  my ($url, %opt) = @_;
  $PATDIR ||= tempdir('prg-hist.XXXXXX', TMPDIR => 1, CLEANUP => 1);
  my ($hf, $bf) = ("$PATDIR/h.txt", "$PATDIR/b.txt");
  unlink $hf, $bf;
  my @cmd = ('curl', '-sS', '-L', '--proto', '=https,http', '-m', '30', '-D', $hf, '-o', $bf, '-H', 'User-Agent: polinrider-guard/' . $VERSION);
  push @cmd, ('-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28') if $opt{api};
  push @cmd, ('--max-filesize', $opt{max} || 3000000);
  if ($opt{api} && length $TOKEN) {
    # The token goes to curl on stdin so it never shows in a process list or in output.
    push @cmd, ('-K', '-');
    open my $c, '|-', @cmd, $url or return (0, {}, undef);
    print $c qq{header = "Authorization: Bearer $TOKEN"\n};
    close $c;
  } else {
    system(@cmd, $url);
  }
  $gh_calls++ if $opt{api};
  my %h; my $status = 0;
  if (open my $fh, '<', $hf) {
    while (my $l = <$fh>) { $l =~ s/\r?\n$//; if ($l =~ m{^HTTP/\S+\s+(\d+)}) { $status = $1; %h = () } elsif ($l =~ /^([^:]+):\s*(.*)$/) { $h{ lc $1 } = $2 } }
    close $fh;
  }
  my $body = -f $bf ? read_file_text($bf, 20_000_000) : undef;
  if ($opt{api}) {
    $rl{remaining} = $h{'x-ratelimit-remaining'} if defined $h{'x-ratelimit-remaining'};
    $rl{reset} = $h{'x-ratelimit-reset'} if defined $h{'x-ratelimit-reset'};
    if (($status == 403 || $status == 429) && (($h{'x-ratelimit-remaining'} // '1') eq '0' || defined $h{'retry-after'} || ($body // '') =~ /rate limit/i)) {
      $rl{stopped} = 'GitHub rate limit reached' . (defined $rl{reset} ? ' (resets at ' . strftime('%Y-%m-%d %H:%M:%S %Z', localtime($rl{reset})) . ')' : '');
    }
  }
  return ($status, \%h, $body);
}
sub api_get {
  my ($path) = @_;
  return (0, {}, undef) if $rl{stopped};
  if (defined $rl{remaining} && $rl{remaining} <= 1) {
    $rl{stopped} = 'stopped before the rate limit was exhausted (' . $rl{remaining} . ' calls left)' . (defined $rl{reset} ? ', resets at ' . strftime('%Y-%m-%d %H:%M:%S %Z', localtime($rl{reset})) : '');
    return (0, {}, undef);
  }
  my ($s, $h, $b) = http_get("$API$path", api => 1);
  my $j = eval { JSON::PP->new->decode($b // '') };
  return ($s, $h, $j);
}

my $LONG_SPACE_TAIL = qr/[^\s][ ]{200,}\S/;
sub check_raw_file {
  my ($base, $branch, $path) = @_;
  my ($s, $h, $body) = http_get("$RAW/$base/$branch/" . join('/', map { urlenc($_) } split m{/}, $path));
  return undef unless $s == 200 && defined $body;
  if ($path =~ m{(?:^|/)\.vscode/tasks\.json$}) { my ($sev, $why) = tasks_verdict($body); return $why if $sev eq 'HIGH' }
  if (my $r = ioc_hit($body)) { return $r }
  if ($path =~ /\.woff2?$/i && $body !~ /^wOF[F2]/ && $body =~ /\b(?:require|function|module\.exports|global)\b/) { return 'a .woff/.woff2 file that is really JavaScript' }
  if ($path =~ /\.dict$/i && $body =~ /\b(?:require|function|module\.exports|global)\b.*[(=]/s && $body =~ /eval|require|global/) { return 'a .dict file that holds JavaScript' }
  return undef;
}

sub candidate_files {
  my (@paths) = @_;
  my @c;
  for my $p (@paths) {
    my $b = basename($p);
    if ($b =~ /^temp_auto_push\.[A-Za-z0-9]+$/i) { push @c, [$p, 'name'] ; next }
    if ($b =~ /^(?:postcss|tailwind|next|vite|webpack|eslint|rollup|babel|jest|nuxt|astro|vitest|hardhat|truffle|svelte|vue|metro|gridsome)(?:[.-]config)?\.(?:js|cjs|mjs|ts|cts|mts)$/i
        || $b =~ /^[\w.-]+\.config\.(?:js|cjs|mjs|ts|cts|mts)$/i || $b =~ /^\.eslintrc\.c?js$/ || $p =~ m{(?:^|/)\.vscode/tasks\.json$}
        || $b eq 'spellright.dict' || $b =~ /\.woff2?$/i) { push @c, [$p, 'file'] }
  }
  return @c;
}

sub check_github_repo {
  my ($full, $branch) = @_;
  my %r = (repo => $full, url => "https://github.com/$full", infected => JSON::PP::false, checked => JSON::PP::false);
  my ($s, $h);
  $branch //= 'main';
  $r{default_branch} = $branch;
  ($s, $h, my $tree) = api_get("/repos/$full/git/trees/" . urlenc($branch) . '?recursive=1');
  if ($s != 200 || ref $tree ne 'HASH') { $r{error} = $rl{stopped} || "file list not readable (HTTP $s)"; return \%r }
  $r{truncated} = $tree->{truncated} ? JSON::PP::true : JSON::PP::false;
  my @paths = map { $_->{path} } grep { ($_->{type} // '') eq 'blob' } @{ $tree->{tree} || [] };
  my @cand = candidate_files(@paths);
  $r{files_checked} = 0;
  my @why;
  for my $c (@cand[0 .. ($#cand > 39 ? 39 : $#cand)]) {
    my ($p, $kind) = @$c;
    if ($kind eq 'name') { push @why, "$p: PolinRider auto-push helper file"; next }
    my $why = check_raw_file($full, $branch, $p);
    $r{files_checked}++;
    push @why, "$p: $why" if $why;
  }
  $r{checked} = JSON::PP::true;
  if (@why) { $r{infected} = JSON::PP::true; $r{evidence} = \@why }
  return \%r;
}

sub github_report {
  my ($repo) = @_;
  my %g = (repo => $repo, forks => [], code_search => []);
  print "\n${B}GitHub: $repo${N}\n";
  print "  token: " . (length $TOKEN ? 'GITHUB_TOKEN is set (used for API calls only)' : 'none (unauthenticated: low rate limit, code search unavailable)') . "\n";
  my ($s, $h, $meta) = api_get("/repos/$repo");
  if ($s != 200 || ref $meta ne 'HASH') { print "  cannot read $repo (HTTP $s)" . ($rl{stopped} ? ": $rl{stopped}" : '') . "\n"; $g{error} = "HTTP $s"; return \%g }
  $g{forks_count} = $meta->{forks_count} // 0;
  $g{stars} = $meta->{stargazers_count};
  $g{private} = $meta->{private} ? 1 : 0;
  $g{default_branch} = $meta->{default_branch};
  print "  default branch: $meta->{default_branch}, public forks reported by GitHub: $g{forks_count}\n";
  # the repo itself
  my $self = check_github_repo($repo, $meta->{default_branch});
  $g{self} = $self;
  print "  $repo default branch: " . ($self->{infected} ? "${R}INFECTED${N}" : $self->{checked} ? 'no known pattern' : 'not checked (' . ($self->{error} // '?') . ')') . "\n";
  print "      $_\n" for @{ $self->{evidence} || [] };
  # forks
  my @forks;
  my $page = 1;
  while (@forks < $o{'max-forks'} && !$rl{stopped}) {
    my ($fs, $fh, $list) = api_get("/repos/$repo/forks?per_page=100&sort=newest&page=$page");
    last unless $fs == 200 && ref $list eq 'ARRAY' && @$list;
    push @forks, @$list;
    last if @$list < 100;
    $page++;
  }
  splice(@forks, $o{'max-forks'}) if @forks > $o{'max-forks'};
  $g{forks_listed} = scalar @forks;
  my ($inf, $clean, $unk) = (0, 0, 0);
  for my $f (@forks) {
    my $name = $f->{full_name} // next;
    if ($rl{stopped}) { $unk++; push @{ $g{forks} }, { repo => $name, url => "https://github.com/$name", checked => JSON::PP::false, error => $rl{stopped} }; next }
    my $r = check_github_repo($name, $f->{default_branch});
    push @{ $g{forks} }, $r;
    if ($r->{infected}) { $inf++ } elsif ($r->{checked}) { $clean++ } else { $unk++ }
  }
  print "  forks listed: " . scalar(@forks) . " (limit $o{'max-forks'}), checked: " . ($inf + $clean) . ", not checked: $unk\n";
  print "  ${R}forks whose default branch carries the pattern: $inf${N}\n" if $inf;
  print "  forks whose default branch shows no known pattern: $clean\n";
  for my $r (grep { $_->{infected} } @{ $g{forks} }) { print "    $r->{url}\n      $_\n" for @{ $r->{evidence} } }
  print "  note: $g{forks_count} public forks exist but only " . scalar(@forks) . " were listed (limit)\n" if $g{forks_count} > @forks;
  print "  ${Y}stopped early: $rl{stopped}${N}\n" if $rl{stopped};
  $g{forks_infected} = $inf; $g{forks_clean} = $clean; $g{forks_unchecked} = $unk;
  # code search
  if (!$o{'no-code-search'}) {
    my @fp = (@fingerprints, sort keys %MARKERS);
    my %s; @fp = grep { !$s{$_}++ } @fp;
    if (!@fp) {
      # No marker from a local repo in this run: fall back to the published wallets and the shuffle-table marker.
      if (open my $fh, '<', "$IOC_DIR/strings-high.txt") { while (<$fh>) { chomp; push @fp, $_ if /^0x[0-9a-fA-F]{40}$/ } close $fh }
      push @fp, 'rmcej%otb%';
    }
    print "  ${B}Code search${N} (estimate of other public repositories carrying the same code)\n";
    if (!length $TOKEN) {
      print "    skipped: GitHub code search needs authentication. Set GITHUB_TOKEN to a token with no special scopes and re-run.\n";
      $g{code_search_skipped} = 'needs GITHUB_TOKEN';
    } else {
      for my $fp (@fp[0 .. ($#fp > 5 ? 5 : $#fp)]) {
        last if $rl{stopped};
        my ($cs, $ch, $res) = api_get('/search/code?per_page=5&q=' . urlenc("\"$fp\""));
        if ($cs == 401 || $cs == 403) { print "    skipped: code search refused (HTTP $cs)" . ($rl{stopped} ? ": $rl{stopped}" : '') . "\n"; last }
        if ($cs != 200 || ref $res ne 'HASH') { print "    query for fingerprint failed (HTTP $cs)\n"; next }
        my @urls = map { $_->{html_url} } @{ $res->{items} || [] };
        push @{ $g{code_search} }, { fingerprint => $fp, total_count => $res->{total_count}, sample_urls => \@urls };
        print "    \"" . clean_cmd($fp, 60) . "\": $res->{total_count} file match(es) reported by GitHub\n";
        print "       $_\n" for @urls;
        select(undef, undef, undef, 2.5);
      }
    }
  }
  print "  ${B}Limits${N}\n";
  print "    - Private repositories, plain clones, downloaded ZIPs and local copies are invisible to this check.\n";
  print "    - Only each fork's default branch is checked, and only config, task, font and dictionary files (up to 40 per repository); an infection elsewhere is missed.\n";
  print "    - Code search counts files, not people. It includes security write-ups and IOC lists, and GitHub indexes only part of public code. Treat it as a rough hint, never as a count of victims.\n";
  print "    - Each fork costs one API call; unauthenticated limits stop the run early (reported above).\n";
  return \%g;
}

# ------------------------------------------------------------------ main
my @targets = (@paths, @scan_dirs);
my @repos;
if (@targets) { @repos = discover(@targets) } elsif (@homes) { @repos = discover(@homes) }
print "${B}PolinRider Guard history report $VERSION${N}\n" unless $o{embedded};
print "${B}Git history report${N}\n" if $o{embedded};
print "  " . scalar(@repos) . " git repositor" . (@repos == 1 ? 'y' : 'ies') . " found\n\n";
my @results;
for my $r (@repos) { my $x = analyze_repo($r); push @results, $x; print_repo($x); print "\n" }

my ($n_head, $n_now, $n_hist) = (0, 0, 0);
print "${B}Summary${N}\n";
if (!@results) { print "  nothing to report (no repositories found)\n" }
for my $r (@results) {
  next if $r->{status} eq 'EMPTY';
  $n_head++ if $r->{head_infected};
  $n_now++ if $r->{status} =~ /^INFECTED/;
  $n_hist++ if $r->{status} =~ /^HISTORY/;
  my $since = $r->{first} ? "since $r->{first}{author_date} (first commit " . substr($r->{first}{sha}, 0, 10) . ')' : '';
  printf "  %-34s %-38s %s\n", clean_cmd($r->{path}, 34), $r->{status}, $since if $r->{status} ne 'CLEAN';
}
my $clean = grep { $_->{status} eq 'CLEAN' } @results;
print "  repositories scanned: " . scalar(@results) . "   infected now: $n_now (HEAD: $n_head)   history only: $n_hist   clean: $clean\n";
print "  ${Y}Dates come from commit metadata that the malware can rewrite. Treat them as leads, not proof.${N}\n" if $n_now || $n_hist;

my $gh;
$gh = github_report($o{github}) if $o{github};

if ($o{json}) {
  open my $jf, '>', $o{json} or die "cannot write $o{json}\n";
  print $jf JSON::PP->new->canonical->pretty->encode({ tool => 'polinrider-guard', version => $VERSION, repos => \@results, github => $gh });
  close $jf;
}
exit($n_now ? 2 : $n_hist ? 1 : 0);
