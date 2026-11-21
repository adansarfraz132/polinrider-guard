# PRG.pm - shared IOC loading and text classification for live-core.pl and history-core.pl.
# Read-only helpers. Nothing here executes or evaluates scanned content.
# Only core Perl modules are used.
package PRG;
use strict;
use warnings;
use JSON::PP ();
use Digest::SHA ();
use Exporter 'import';
our @EXPORT_OK = qw(load_iocs ioc_hit node_bad node_review file_bad tasks_verdict read_file_text
  sha256_file clean_cmd strip_json_comments @HOST_ART $RX_DOM_MED $RX_IP_HIGH $RX_DOM_HIGH $ART_PATH_RX $CHAIN_RX);

our (@STR_HIGH, @RX_HIGH, @DOM_HIGH, @DOM_MED, @IP_HIGH, @HOST_ART);
our ($RX_DOM_HIGH, $RX_DOM_MED, $RX_IP_HIGH);

# Paths the malware family leaves under a home directory (also in iocs/host-artifacts.txt).
our $ART_PATH_RX = qr{(?:~|\$HOME|\$\{HOME\}|/home/[^/\s"']+|/Users/[^/\s"']+|[A-Za-z]:\\Users\\[^\\\s"']+)[/\\]\.(?:n2|n3|npl|nlp|pyp|npm[/\\](?:scoped_dir|vhost\.ctl|npm-compiler\.log))};
# Things that mark the git amend / force-push loop (temp_auto_push.bat and look-alikes).
our $CHAIN_RX = qr/temp_auto_push|tmp7A863DD1|bun_environment\.js|spellright\.dict/i;

sub read_list {
  my ($dir, $f) = @_;
  my @out;
  my $p = "$dir/$f";
  return @out unless -f $p;
  open my $fh, '<', $p or return @out;
  while (my $l = <$fh>) {
    $l =~ s/\r?\n$//;
    next if $l =~ /^\s*(#|$)/;
    push @out, $l;
  }
  close $fh;
  return @out;
}

sub bound_rx {
  my @v = @_;
  return undef unless @v;
  my $j = join '|', map { quotemeta } @v;
  return qr/(?<![A-Za-z0-9_.-])(?:$j)(?![A-Za-z0-9_-])/i;
}

sub load_iocs {
  my ($dir) = @_;
  @STR_HIGH = map { lc } read_list($dir, 'strings-high.txt');
  @RX_HIGH  = map { qr/$_/ } read_list($dir, 'regex-high.txt');
  @DOM_HIGH = map { lc } read_list($dir, 'domains-high.txt');
  @DOM_MED  = map { lc } read_list($dir, 'domains-medium.txt');
  @IP_HIGH  = read_list($dir, 'ips-high.txt');
  @HOST_ART = read_list($dir, 'host-artifacts.txt');
  $RX_DOM_HIGH = bound_rx(@DOM_HIGH);
  $RX_DOM_MED  = bound_rx(@DOM_MED);
  $RX_IP_HIGH  = bound_rx(@IP_HIGH);
  return 1;
}

# Fingerprints that are specific to the campaign (published markers, wallets, C2 hosts/IPs).
sub ioc_hit {
  my ($t) = @_;
  return undef unless defined $t && length $t;
  my $lt = lc $t;
  for my $s (@STR_HIGH) { return "campaign marker '$s'" if index($lt, $s) >= 0 }
  for my $rx (@RX_HIGH) { return "PolinRider loader pattern" if $t =~ $rx }
  return "known C2 host" if $RX_DOM_HIGH && $t =~ $RX_DOM_HIGH;
  return "known C2 IP address" if $RX_IP_HIGH && $t =~ $RX_IP_HIGH;
  return undef;
}

# Inline node code or a node command line: specific loader behaviour only.
sub node_bad {
  my ($c) = @_;
  return undef unless defined $c && length $c;
  my $r = ioc_hit($c);
  return $r if $r;
  my $rpc = ($RX_DOM_MED && $c =~ $RX_DOM_MED) ? 1 : 0;
  return "blockchain RPC lookup combined with eval or a /boot fetch (dead-drop loader)"
    if $rpc && $c =~ /\beval\s*\(|new\s+Function|\bFunction\s*\(|\/(?:0\/)?boot\b|\b_p_t\b/;
  return "fetches /boot from a raw IP:port (loader stage)"
    if $c =~ m{https?://\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}/(?:0/)?boot\b};
  return "inline script uses the private npm prefix ~/.node_modules with axios or socket.io"
    if $c =~ /\.node_modules/ && $c =~ /axios|socket\.io/;
  return "fetches /boot and evals the response"
    if $c =~ m{/(?:0/)?boot\b} && $c =~ /\beval\s*\(/ && $c =~ /https?|fetch|\.get\(|request/;
  return undef;
}

# Weaker signals: worth a human look, never killed or quarantined automatically.
sub node_review {
  my ($c) = @_;
  return undef unless defined $c;
  return "inline script evals data it fetched from the network"
    if $c =~ /\beval\s*\(/ && $c =~ /https?\.get\(|\bfetch\(|axios\.get|\brequest\(/;
  return undef;
}

# Text of a persistence file (cron line, unit file, shell rc line, git hook).
sub file_bad {
  my ($t) = @_;
  return undef unless defined $t && length $t;
  my $r = node_bad($t);
  return $r if $r;
  return "references the PolinRider git auto-push / stealer helper" if $t =~ $CHAIN_RX;
  return "runs from a known malware artifact directory" if $t =~ $ART_PATH_RX;
  return "runs node on a font or dictionary file" if $t =~ /\bnode(?:\.exe)?\s+[^\n;|&]*\.(?:woff2?|dict)\b/i;
  return undef;
}

sub read_file_text {
  my ($p, $max) = @_;
  $max ||= 2 * 1024 * 1024;
  open my $fh, '<:raw', $p or return undef;
  local $/;
  my $buf = '';
  read($fh, $buf, $max);
  close $fh;
  return $buf;
}

sub sha256_file {
  my ($p) = @_;
  open my $fh, '<:raw', $p or return undef;
  my $d = Digest::SHA->new(256);
  $d->addfile($fh);
  close $fh;
  return $d->hexdigest;
}

sub clean_cmd {
  my ($s, $max) = @_;
  $s //= '';
  $max ||= 160;
  $s =~ s/[^\x20-\x7e]/?/g;
  $s =~ s/ {6,}/ [many spaces] /g;
  $s = substr($s, 0, $max) . '...' if length $s > $max;
  return $s;
}

# tasks.json allows comments and trailing commas. Remove comments without touching strings.
sub strip_json_comments {
  my ($s) = @_;
  my $out = '';
  my $n = length $s;
  my ($i, $in_str) = (0, 0);
  while ($i < $n) {
    my $ch = substr($s, $i, 1);
    if ($in_str) {
      $out .= $ch;
      if ($ch eq '\\' && $i + 1 < $n) { $out .= substr($s, $i + 1, 1); $i += 2; next }
      $in_str = 0 if $ch eq '"';
      $i++; next;
    }
    if ($ch eq '"') { $in_str = 1; $out .= $ch; $i++; next }
    if ($ch eq '/' && substr($s, $i, 2) eq '//') { $i++ while $i < $n && substr($s, $i, 1) ne "\n"; next }
    if ($ch eq '/' && substr($s, $i, 2) eq '/*') {
      my $e = index($s, '*/', $i + 2);
      $i = $e < 0 ? $n : $e + 2;
      next;
    }
    $out .= $ch; $i++;
  }
  return $out;
}

sub flatten_strings {
  my ($v) = @_;
  return '' unless defined $v;
  if (ref $v eq 'ARRAY') { return join ' ', map { flatten_strings($_) } @$v }
  if (ref $v eq 'HASH')  { return join ' ', map { flatten_strings($v->{$_}) } sort keys %$v }
  return "$v";
}

# Classify a .vscode/tasks.json text. Returns (severity, reason) or ().
# Only tasks that run automatically on folder open are considered. A plain
# "npm run dev" style task is normal and is not reported.
sub tasks_verdict {
  my ($text) = @_;
  return () unless defined $text && $text =~ /folderOpen/;
  my $json = eval { JSON::PP->new->relaxed->decode(strip_json_comments($text)) };
  my @tasks = ($json && ref $json eq 'HASH' && ref $json->{tasks} eq 'ARRAY') ? @{ $json->{tasks} } : ();
  my ($worst, $why) = ('', '');
  my $rank = sub { return { HIGH => 2, REVIEW => 1 }->{ $_[0] } // 0 };
  my $note = sub { my ($s, $r) = @_; if ($rank->($s) > $rank->($worst)) { ($worst, $why) = ($s, $r) } };
  if (!@tasks) {
    # Unparseable: fall back to the raw text.
    my $r = file_bad($text) // (($text =~ /\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|iwr|irm|iex)\b/i) ? 'downloads or runs a script' : undef);
    return $r ? ('HIGH', "folderOpen task (unparseable file) that $r") : ('REVIEW', 'folderOpen task in a file that could not be parsed');
  }
  for my $t (@tasks) {
    next unless ref $t eq 'HASH';
    my $ro = $t->{runOptions};
    next unless ref $ro eq 'HASH' && defined $ro->{runOn} && $ro->{runOn} eq 'folderOpen';
    my $cmd = join ' ', flatten_strings($t->{command}), flatten_strings($t->{args}),
      map { flatten_strings($t->{$_}) } grep { $_ =~ /^(windows|linux|osx)$/ } keys %$t;
    my $pres = ref $t->{presentation} eq 'HASH' ? $t->{presentation} : {};
    my $hidden = (($pres->{reveal} // '') =~ /^(never|silent)$/) || (($pres->{echo} // 1) eq '0') || $pres->{close} ? 1 : 0;
    if (my $r = file_bad($cmd)) { $note->('HIGH', "folderOpen task: $r"); next }
    if ($cmd =~ /\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|iex|Invoke-Expression)\b/i
        || $cmd =~ /\b(?:bash|sh|zsh|cmd(?:\.exe)?)\b.*(?:\s-c\b|\s\/c\b)/i
        || $cmd =~ /\b(?:node|nodejs|bun)(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b/i
        || $cmd =~ /\bpython3?(?:\.exe)?\s+-c\b/i) {
      $note->('HIGH', 'folderOpen task downloads or runs inline code'); next;
    }
    if ($cmd =~ /\b(?:node|nodejs|bun|python3?|ruby|perl)(?:\.exe)?\s+\S/i || $cmd =~ /\.(?:bat|cmd|ps1|sh|vbs)\b/i) {
      $note->($hidden ? 'HIGH' : 'REVIEW',
        $hidden ? 'folderOpen task silently runs a script (hidden terminal)' : 'folderOpen task runs a script; check that you wrote it');
      next;
    }
  }
  return $worst ? ($worst, $why) : ();
}

1;
