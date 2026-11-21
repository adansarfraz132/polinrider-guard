#!/usr/bin/env perl
# scan-core.pl - static, read-only repo scanner used by scan-repo.sh.
# It never executes, imports, or evaluates anything from the scanned tree.
# Output: one finding per line, TAB separated: SEVERITY CHECK LOCATION DETAIL
# Only core Perl modules are used (File::Find, JSON::PP, Digest::SHA, Digest::MD5).
use strict;
use warnings;
no warnings 'recursion';
use File::Find ();
use File::Spec;
use JSON::PP ();
use Digest::SHA ();
use Digest::MD5 ();
use Getopt::Long qw(GetOptions);

my ($root, $ioc_dir, $self_dir, $deep, $max_mb, $long_cfg) = ('.', '', '', 0, 25, 400);
my @skip_rel;
GetOptions(
  'skip=s'     => \@skip_rel,
  'root=s'     => \$root,
  'ioc-dir=s'  => \$ioc_dir,
  'self=s'     => \$self_dir,
  'deep!'      => \$deep,
  'max-mb=i'   => \$max_mb,
  'long-cfg=i' => \$long_cfg,
) or die "bad args\n";
$root =~ s{/+$}{} unless $root eq '/';
my $max_bytes = $max_mb * 1024 * 1024;

# ---------------------------------------------------------------- IOC load
sub read_list {
  my ($f) = @_;
  my @out;
  my $p = "$ioc_dir/$f";
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
my @str_high  = map { lc } read_list('strings-high.txt');
my @rx_high   = map { qr/$_/ } read_list('regex-high.txt');
my @rx_med    = map { qr/$_/ } read_list('regex-medium.txt');
my @dom_high  = map { lc } read_list('domains-high.txt');
my @dom_med   = map { lc } read_list('domains-medium.txt');
my @ip_high   = read_list('ips-high.txt');
my (%hash_ioc);   # "algo:hash" => note
for my $l (read_list('hashes.txt')) {
  my ($algo, $h, $note) = $l =~ /^(\w+)\s+([0-9a-fA-F]+)\s*(?:\|\s*(.*))?$/ or next;
  $hash_ioc{lc("$algo:$h")} = $note // '';
}
my (%npm_any, %npm_ver);
for my $l (read_list('npm-packages.txt')) {
  $l =~ s/\s+.*$//;
  if ($l =~ /^(\@?[^@]+)\@(.+)$/) { $npm_ver{lc "$1\@$2"} = 1 } else { $npm_any{lc $l} = 1 }
}
my (%ext_any, %ext_ver);
for my $l (read_list('vscode-extensions.txt')) {
  if ($l =~ /^([^@]+)\@(.+)$/) { $ext_ver{lc "$1\@$2"} = 1; $ext_any{lc $1} ||= 0 } else { $ext_any{lc $l} = 1 }
}
# Optional public feed snapshot (data only). Generic services are skipped.
my %feed_generic = map { $_ => 1 } qw(discord.com webhook.site dns.google ipfs.io git.disroot.org rentry.co
  relay.damus.io relay.nostr.com github.com raw.githubusercontent.com api.github.com registry.npmjs.org pypi.org
  files.pythonhosted.org vercel.app workers.dev ngrok-free.dev mypinata.cloud);
my (@feed_dom, @feed_ip);
my $feed = "$ioc_dir/feeds/safedep-ioc.csv";
if (-f $feed && open my $ff, '<', $feed) {
  while (my $l = <$ff>) {
    my ($kind, $val) = $l =~ /^"([^"]*)","([^"]*)"/ or next;
    $val = lc $val;
    if ($kind =~ /^(sha256|sha1|md5)$/ && $val =~ /^[0-9a-f]+$/) { $hash_ioc{"$kind:$val"} //= 'SafeDep feed' }
    elsif ($kind eq 'domain' && !$feed_generic{$val} && length($val) > 4) { push @feed_dom, $val }
    elsif ($kind eq 'ipv4' && $val =~ /^\d+\.\d+\.\d+\.\d+$/
           && $val !~ /^(1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9)$/ && $val !~ /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|2(2[4-9]|[3-5]\d)\.)/) { push @feed_ip, $val }
  }
  close $ff;
}
my $want_sha1 = grep { /^sha1:/ } keys %hash_ioc;
my $want_md5  = grep { /^md5:/ } keys %hash_ioc;
sub bound_rx { my @v = @_; return undef unless @v; my $j = join '|', map { quotemeta } @v; return qr/(?<![A-Za-z0-9_.-])(?:$j)(?![A-Za-z0-9_-])/i }
my $rx_dom_high = bound_rx(@dom_high);
my $rx_dom_med  = bound_rx(@dom_med);
my $rx_ip_high  = bound_rx(@ip_high);
my $rx_feed_dom = bound_rx(@feed_dom);
my $rx_feed_ip  = bound_rx(@feed_ip);

# ---------------------------------------------------------------- output
my %seen_count;
sub clean { my ($s) = @_; $s //= ''; $s =~ s/[^\x20-\x7e]/?/g; $s =~ s/ {6,}/ [many spaces] /g; $s = substr($s, 0, 180) . '...' if length $s > 180; return $s }
sub finding {
  my ($sev, $check, $loc, $detail) = @_;
  my ($file) = $loc =~ /^(.*?)(?::\d+)?$/;
  my $k = "$check|$file";
  $seen_count{$k}++;
  return if $seen_count{$k} > 3;
  print join("\t", $sev, $check, $loc, clean($detail)), "\n";
}

# ---------------------------------------------------------------- helpers
my @cfg_exact = qw(truffle.js truffle-config.js .eslintrc.js .eslintrc.cjs .babelrc.js gridsome.config.js vue.config.js
  svelte.config.js metro.config.js);
my %cfg_exact = map { $_ => 1 } @cfg_exact;
sub is_config {
  my ($b) = @_;
  return 1 if $cfg_exact{$b};
  return 1 if $b =~ /^[\w.-]+\.config\.(js|cjs|mjs|ts|cts|mts)$/i;
  return 1 if $b =~ /^(hardhat|astro|nuxt|vite|vitest|webpack|rollup|babel|jest|postcss|tailwind|eslint|next)\.config\./i;
  return 0;
}
my %code_ext = map { $_ => 1 } qw(js mjs cjs jsx ts tsx mts cts json jsonc sh bash zsh ps1 psm1 py bat cmd vbs rb php go rs java kt yml yaml toml);
my %font_ext = map { $_ => 1 } qw(woff woff2 ttf otf eot ttc);
my %img_ext  = map { $_ => 1 } qw(png jpg jpeg gif ico webp bmp);
my %script_ext = map { $_ => 1 } qw(bat cmd vbs vbe jse wsf hta scr lnk ps1 psm1 msi);

sub unescape_js {
  my ($s) = @_;
  $s =~ s/\\u([0-9a-fA-F]{4})/chr(hex($1))/ge;
  $s =~ s/\\x([0-9a-fA-F]{2})/chr(hex($1))/ge;
  return $s;
}
# True if the match at $pos sits after // on its line, or inside a /* */ block.
sub in_js_comment {
  my ($s, $pos) = @_;
  return 0 if $pos < 0;
  my $line_start = $pos == 0 ? 0 : rindex($s, "\n", $pos - 1) + 1;
  my $prefix = substr($s, $line_start, $pos - $line_start);
  return 1 if $prefix =~ m{//};
  my $before = substr($s, 0, $pos);
  my $opens = () = $before =~ m{/\*}g;
  my $closes = () = $before =~ m{\*/}g;
  return $opens > $closes;
}

sub rel { my ($p) = @_; my $r = $p; $r =~ s/^\Q$root\E\/?//; return $r eq '' ? '.' : $r }
sub ext { my ($b) = @_; return $b =~ /\.([^.\/]+)$/ ? lc $1 : '' }
sub looks_like_js { my ($c) = @_; return $c =~ /(\brequire\s*\(|\bfunction\s*\(|\beval\s*\(|=>|\bvar\s+\w+\s*=|\bconst\s+\w+\s*=|module\.exports|child_process|global\[)/ }

sub magic_kind {
  my ($head) = @_;
  return 'elf'   if $head =~ /^\x7fELF/;
  return 'pe'    if $head =~ /^MZ/;
  return 'macho' if $head =~ /^(\xfe\xed\xfa[\xce\xcf]|[\xce\xcf]\xfa\xed\xfe)/;
  return 'fat'   if $head =~ /^\xca\xfe\xba\xbe/;
  return '';
}
sub font_ok {
  my ($head, $e, $c) = @_;
  return 1 if $head =~ /^(wOFF|wOF2|\x00\x01\x00\x00|true|OTTO|ttcf|typ1)/;
  return 1 if $e eq 'eot' && length($c) > 35 && substr($c, 34, 2) eq "LP";
  return 0;
}
sub img_ok {
  my ($head, $e) = @_;
  return $head =~ /^(\x89PNG|\xff\xd8\xff|GIF8|\x00\x00\x01\x00|RIFF|BM)/ ? 1 : 0;
}

my $sus_cmd = qr/(\bnode\s+-e\b|\bnode\s+[^\s|;&]+\.(woff2?|ttf|otf|eot|dict|png|jpe?g|gif|svg|ico|txt|css)\b|curl\s|wget\s|\|\s*(ba|z)?sh\b|bash\s+-c|sh\s+-c|powershell|pwsh|iex\b|Invoke-Expression|Invoke-WebRequest|\birm\b|\biwr\b|base64|atob\(|eval\(|https?:\/\/|setup_bun\.js|bun_environment\.js|telemetry\.js|bundle\.js|\.vercel\.app|python[23]?\s+-c|certutil|mshta|rundll32|regsvr32)/i;

# ---------------------------------------------------------------- per-file content checks
sub scan_text {
  my ($rp, $base, $e, $c, $in_nm) = @_;
  my $lc = lc $c;
  for my $s (@str_high) {
    my $i = index($lc, $s);
    next if $i < 0;
    my $ln = 1 + (substr($c, 0, $i) =~ tr/\n//);
    finding('HIGH', 'ioc-string', "$rp:$ln", "known malware marker: $s");
  }
  if ($code_ext{$e} || is_config($base)) {
    my $dec = lc unescape_js($c);
    if ($dec ne $lc) {
      for my $s (@str_high) {
        next if index($lc, $s) >= 0;
        my $i = index($dec, $s);
        next if $i < 0;
        my $ln = 1 + (substr($dec, 0, $i) =~ tr/\n//);
        finding('HIGH', 'ioc-string', "$rp:$ln", "known malware marker (javascript-escaped): $s");
      }
    }
  }
  if ($rx_dom_high && $c =~ $rx_dom_high) { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('HIGH', 'ioc-domain', "$rp:$ln", "known malicious host: $m") }
  if ($rx_ip_high  && $c =~ $rx_ip_high)  { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('HIGH', 'ioc-ip', "$rp:$ln", "known C2 IP: $m") }
  if (!$in_nm) {
    if ($rx_feed_dom && $c =~ $rx_feed_dom) { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'feed-domain', "$rp:$ln", "host listed in SafeDep IOC feed: $m") }
    if ($rx_feed_ip  && $c =~ $rx_feed_ip)  { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'feed-ip', "$rp:$ln", "IP listed in SafeDep IOC feed: $m") }
    if ($rx_dom_med  && $c =~ $rx_dom_med)  { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'blockchain-deaddrop', "$rp:$ln", "blockchain API used as a C2 dead drop by PolinRider: $m (normal only in web3 code)") }
  }
  for my $rx (@rx_high) {
    # The long-whitespace rule only makes sense in code (markdown tables pad with spaces).
    next if "$rx" =~ /\{200,\}/ && $e !~ /^(js|mjs|cjs|jsx|ts|tsx|mts|cts|json)$/;
    if ($c =~ $rx) { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('HIGH', 'loader-pattern', "$rp:$ln", "PolinRider-style loader pattern: $m") }
  }
  my $minified = ($base =~ /\.(min|bundle|chunk)\.(js|mjs|cjs)$/ || $rp =~ m{(^|/)(dist|build|vendor|out|\.next|coverage)/});
  if (!$in_nm && !$minified && $code_ext{$e}) {
    for my $rx (@rx_med) {
      if ($c =~ $rx) { my $m = $&; my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'obfuscation-heuristic', "$rp:$ln", "review: $m") }
    }
  }
  # invisible / deceptive unicode (raw UTF-8 bytes, no decoding)
  if ($code_ext{$e} || $e eq '' || $e eq 'md') {
    if ($c =~ /(?:\xF3\xA0[\x84-\x87][\x80-\xBF]|\xEF\xB8[\x80-\x8F]){8,}/) { my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('HIGH', 'invisible-unicode', "$rp:$ln", 'run of 8+ Unicode variation selectors (GlassWorm-style hidden code)') }
    if ($c =~ /(?:\xF3\xA0[\x80-\x81][\x80-\xBF]){8,}/) { my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('HIGH', 'invisible-unicode', "$rp:$ln", 'run of 8+ Unicode tag characters (hidden text)') }
    if ($c =~ /(?:\xEE[\x80-\xBF][\x80-\xBF]|\xEF[\x80-\xA3][\x80-\xBF]){16,}/) { my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'invisible-unicode', "$rp:$ln", 'run of 16+ Private Use Area characters') }
    if ($code_ext{$e} && $c =~ /\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/) { my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'bidi-unicode', "$rp:$ln", 'bidirectional control character in code (Trojan Source, CVE-2021-42574)') }
    if ($code_ext{$e} && $c =~ /(?:\xE2\x80[\x8B-\x8D]|\xE2\x81\xA0){8,}/) { my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'invisible-unicode', "$rp:$ln", 'run of 8+ zero-width characters') }
  }
  # config-file injection (PolinRider appends to build configs)
  if (is_config($base) || $base =~ /^(App|app|index)\.(js|jsx|ts|tsx|mjs)$/) {
    my $cfg = is_config($base);
    my $ln = 0;
    for my $line (split /\n/, $c) {
      $ln++;
      my $len = length $line;
      if ($cfg) {
        if ($len > $long_cfg) { finding($len > 1000 ? 'HIGH' : 'MEDIUM', 'config-long-line', "$rp:$ln", "line is $len chars in a config/entry file (PolinRider appends a one-line payload)") }
      } elsif ($len > 2000) {
        # index.js / App.js often contain long SVG or data lines. HIGH only if the
        # line also looks like an appended loader, or is as long as those payloads.
        my $payloady = ($line =~ /\S[ \t]{50,}\S/ || $len > 8000
          || $line =~ /(\beval\s*\(|global\[['"](!|_V)['"]\]|global\.(o|i)\s*=|_\$_[0-9a-f]{4}=)/);
        finding($payloady ? 'HIGH' : 'MEDIUM', 'config-long-line', "$rp:$ln", "line is $len chars in a config/entry file (PolinRider appends a one-line payload)");
      }
      if ($line =~ /\S[ \t]{50,}\S/) { finding('HIGH', 'config-hidden-tail', "$rp:$ln", 'code after 50+ spaces on one line (payload pushed off-screen)') }
    }
    if ($cfg) {
      my $api_rx = qr/(\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['"]|child_process|\batob\s*\(|fromCharCode|Buffer\.from\([^)]*base64|\bglobal\s*\[|\bglobal\.\w+\s*=)/;
      my ($strong_m, $strong_ln, $weak_m, $weak_ln);
      while ($c =~ /$api_rx/g) {
        my $m = $1; my $pos = $-[0];
        next if in_js_comment($c, $pos);
        my $ln2 = 1 + (substr($c, 0, $pos) =~ tr/\n//);
        if ($m =~ /(eval\s*\(|new\s+Function|Function\s*\(|atob\s*\(|fromCharCode|Buffer\.from|global\s*\[|global\.\w+\s*=)/) {
          $strong_m = $m; $strong_ln = $ln2; last;
        }
        if (!$weak_m) { $weak_m = $m; $weak_ln = $ln2; }
      }
      if ($strong_m) {
        finding('HIGH', 'config-dangerous-api', "$rp:$strong_ln", "build config uses $strong_m (no reason for a config to do this)");
      } elsif ($weak_m) {
        finding('MEDIUM', 'config-dangerous-api', "$rp:$weak_ln", "build config uses $weak_m (review; often a test helper, but unusual in app configs)");
      }
      if ($c =~ /\b(https?\.get|https?\.request|net\.connect|XMLHttpRequest|\bfetch\s*\(|axios)/) { my $m = $1; my $ln2 = 1 + (substr($c,0,$-[0]) =~ tr/\n//); finding('MEDIUM', 'config-network', "$rp:$ln2", "build config makes network calls ($m)") }
      if ($base =~ /^(postcss|tailwind)\.config\./ && $c =~ /createRequire/) { finding('MEDIUM', 'config-createRequire', $rp, 'createRequire preamble in postcss/tailwind config (injected by PolinRider variant)') }
      if ($base =~ /^postcss\.config\./ && length($c) > 3500) { finding('MEDIUM', 'config-size', $rp, sprintf('postcss config is %d bytes (typical 80-200; infected ~5000)', length $c)) }
    }
  }
}

sub check_package_json {
  my ($rp, $c, $in_nm) = @_;
  my $j = eval { JSON::PP->new->relaxed->decode($c) };
  if (!$j || ref $j ne 'HASH') { finding('LOW', 'package-json', $rp, 'could not parse package.json'); return }
  my $s = ref $j->{scripts} eq 'HASH' ? $j->{scripts} : {};
  for my $hook (qw(preinstall install postinstall preprepare prepare postprepare prepublish)) {
    next unless defined $s->{$hook};
    my $cmd = "$s->{$hook}";
    my $sev = $cmd =~ $sus_cmd ? 'HIGH' : ($in_nm ? 'LOW' : 'MEDIUM');
    $sev = 'LOW' if !$in_nm && $sev eq 'MEDIUM' && $cmd =~ /^\s*(husky( install)?|npm run build|tsc|svelte-kit sync|nuxt prepare|panda codegen|lefthook install|simple-git-hooks|npx only-allow (pnpm|yarn|npm|bun)|patch-package)\s*$/;
    finding($sev, 'lifecycle-script', $rp, "scripts.$hook runs automatically on install: $cmd");
  }
  for my $k (keys %$s) {
    next unless defined $s->{$k};
    finding('HIGH', 'lifecycle-script', $rp, "scripts.$k references a known worm file: $s->{$k}") if $s->{$k} =~ /(setup_bun\.js|bun_environment\.js)/;
  }
  for my $sect (qw(dependencies devDependencies optionalDependencies peerDependencies)) {
    my $d = $j->{$sect};
    next unless ref $d eq 'HASH';
    for my $n (sort keys %$d) {
      my $v = "$d->{$n}";
      finding('HIGH', 'malicious-package', $rp, "$sect has known-malicious package $n") if $npm_any{lc $n};
      (my $pin = $v) =~ s/^[=v]//;
      finding('HIGH', 'malicious-package', $rp, "$sect pins hijacked version $n\@$pin") if $npm_ver{lc "$n\@$pin"};
      next if ($v =~ /^(file|link|portal):/ && $v !~ m{://} && $v !~ /\.(tgz|tar\.gz)$/) || $v =~ /^(workspace|catalog|npm):/;
      if ($v =~ /^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)|^[\w.-]+\/[\w.-]+(#.*)?$/) {
        finding($in_nm ? 'LOW' : 'MEDIUM', 'non-registry-dependency', $rp, "$sect.$n comes from outside the npm registry: $v");
      }
    }
  }
}

sub check_lock_npm {
  my ($rp, $c) = @_;
  my ($key, $ver, $res) = ('', '', '');
  my ($nonreg, $noint, @scripts) = (0, 0);
  my $ln = 0;
  my $flush = sub {
    return unless $key;
    my $name = $key; $name =~ s{^.*node_modules/}{};
    if ($name && $ver) {
      finding('HIGH', 'malicious-package', $rp, "lockfile contains known-malicious package $name\@$ver") if $npm_any{lc $name};
      finding('HIGH', 'malicious-package', $rp, "lockfile contains hijacked version $name\@$ver") if $npm_ver{lc "$name\@$ver"};
    }
  };
  for my $line (split /\n/, $c) {
    $ln++;
    if ($line =~ /^\s*"((?:node_modules\/)?[^"]+)":\s*\{\s*$/) { $flush->(); $key = $1; $ver = ''; next }
    if ($line =~ /^\s*"version":\s*"([^"]+)"/) { $ver = $1; $flush->(); next }
    if ($line =~ /^\s*"resolved":\s*"([^"]+)"/) {
      my $u = $1;
      if ($u !~ m{^https://registry\.npmjs\.org/}) { $nonreg++; finding('MEDIUM', 'lockfile-source', "$rp:$ln", "package resolved outside registry.npmjs.org: $u") }
    }
    if ($line =~ /^\s*"hasInstallScript":\s*true/) { my $n = $key; $n =~ s{^.*node_modules/}{}; push @scripts, $n }
  }
  $flush->();
  if (@scripts) { finding('INFO', 'install-scripts', $rp, scalar(@scripts) . ' locked packages have install scripts (blocked if ignore-scripts is on): ' . join(', ', @scripts[0 .. ($#scripts < 11 ? $#scripts : 11)])) }
  my $res_count = () = $c =~ /"resolved":/g;
  my $int_count = () = $c =~ /"integrity":/g;
  if ($res_count > $int_count) { finding('MEDIUM', 'lockfile-integrity', $rp, ($res_count - $int_count) . ' resolved entries have no integrity hash') }
}

sub check_lock_text {
  my ($rp, $base, $c) = @_;
  my $ln = 0;
  my $cur = '';
  for my $line (split /\n/, $c) {
    $ln++;
    if ($base eq 'pnpm-lock.yaml') {
      if ($line =~ /^\s{2}'?\/?(\@?[^@\s'(]+)\@([0-9][^:'(\s]*)/) {
        my ($n, $v) = ($1, $2);
        finding('HIGH', 'malicious-package', "$rp:$ln", "lockfile contains known-malicious package $n\@$v") if $npm_any{lc $n};
        finding('HIGH', 'malicious-package', "$rp:$ln", "lockfile contains hijacked version $n\@$v") if $npm_ver{lc "$n\@$v"};
      }
      finding('MEDIUM', 'lockfile-source', "$rp:$ln", "non-registry resolution: $1") if $line =~ /(tarball:\s*\S+|repo:\s*\S+)/ && $line !~ m{registry\.npmjs\.org};
      finding('INFO', 'install-scripts', "$rp:$ln", 'package with requiresBuild: true') if $line =~ /requiresBuild:\s*true/;
    } else {   # yarn.lock
      if ($line =~ /^"?(\@?[^@\s"]+)\@/) { $cur = $1 }
      if ($line =~ /^\s+version:?\s+"?([^"\s]+)"?/ && $cur) {
        my $v = $1;
        finding('HIGH', 'malicious-package', "$rp:$ln", "lockfile contains known-malicious package $cur\@$v") if $npm_any{lc $cur};
        finding('HIGH', 'malicious-package', "$rp:$ln", "lockfile contains hijacked version $cur\@$v") if $npm_ver{lc "$cur\@$v"};
      }
      if ($line =~ /^\s+(resolved|resolution):?\s+"?([^"\s]+)"?/) {
        my $u = $2;
        finding('MEDIUM', 'lockfile-source', "$rp:$ln", "non-registry source: $u") if $u =~ m{^(https?|git|file|github)[:+]} && $u !~ m{^https://registry\.(yarnpkg\.com|npmjs\.org)/};
      }
    }
  }
}

sub check_vscode {
  my ($rp, $base, $c) = @_;
  if ($base eq 'tasks.json' || $base =~ /\.code-workspace$/) {
    if ($c =~ /"runOn"\s*:\s*"folderOpen"/) {
      my $ln = 1 + (substr($c,0,$-[0]) =~ tr/\n//);
      finding('HIGH', 'vscode-autorun', "$rp:$ln", 'task runs automatically when the folder is opened (runOn: folderOpen) - used by PolinRider and Contagious Interview');
    }
    while ($c =~ /"(command|args)"\s*:\s*("(?:[^"\\]|\\.)*"|\[[^\]]*\])/g) {
      my $v = $2; my $pos = $-[0];
      if ($v =~ $sus_cmd) { my $ln = 1 + (substr($c,0,$pos) =~ tr/\n//); finding('HIGH', 'vscode-task-command', "$rp:$ln", "task command looks like a downloader/loader: $v") }
    }
    if ($c =~ /"reveal"\s*:\s*"never"/ && $c =~ /runOn/) { finding('MEDIUM', 'vscode-autorun', $rp, 'autorun task hides its terminal (presentation.reveal: never)') }
  }
  if ($base eq 'settings.json' && $rp =~ m{(^|/)\.vscode/}) {
    finding('HIGH', 'vscode-settings', $rp, 'workspace turns automatic tasks ON (task.allowAutomaticTasks: on)') if $c =~ /"task\.allowAutomaticTasks"\s*:\s*"on"/;
    finding('MEDIUM', 'vscode-settings', $rp, 'workspace tries to change workspace-trust settings') if $c =~ /"security\.workspace\.trust/;
    finding('MEDIUM', 'vscode-settings', $rp, "workspace overrides a tool path: $1") if $c =~ /"((?:[\w.]+\.)?(?:path|executablePath|nodePath|serverPath|interpreterPath)|terminal\.integrated\.(?:shell|profiles|env)[\w.]*)"\s*:/;
  }
  if ($base eq 'extensions.json' && $rp =~ m{(^|/)\.vscode/}) {
    while ($c =~ /"([A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+)"/g) {
      my $id = lc $1;
      finding('HIGH', 'malicious-extension', $rp, "recommends known-malicious extension $id") if exists $ext_any{$id};
    }
  }
  if ($base eq 'devcontainer.json') {
    while ($c =~ /"(initializeCommand|onCreateCommand|postCreateCommand|postStartCommand|postAttachCommand|updateContentCommand)"\s*:\s*("(?:[^"\\]|\\.)*"|\[[^\]]*\]|\{[^}]*\})/g) {
      my ($k, $v) = ($1, $2);
      finding(($k eq 'initializeCommand' || $v =~ $sus_cmd) ? 'HIGH' : 'MEDIUM', 'devcontainer-command', $rp, "$k runs " . ($k eq 'initializeCommand' ? 'on the HOST' : 'in the container') . ": $v");
    }
  }
  if ($base eq 'mcp.json' || ($base eq 'settings.json' && $c =~ /"mcp"\s*:/)) {
    finding('MEDIUM', 'mcp-server', $rp, 'project defines MCP servers that launch local commands when an AI agent starts') if $c =~ /"command"\s*:/;
  }
}

# ---------------------------------------------------------------- walker
my @files;
my %prune = map { $_ => 1 } ('.git', '.hg', '.svn');
my %prune_nondeep = map { $_ => 1 } ('node_modules', '.venv', 'venv', '.tox', 'bower_components');
my $self_abs = $self_dir ? File::Spec->rel2abs($self_dir) : '';
File::Find::find({
  no_chdir => 1,
  preprocess => sub { sort @_ },
  wanted => sub {
    my $p = $File::Find::name;
    my $b = $_; $b =~ s{.*/}{};
    if (-d $p && !-l $p) {
      if ($p ne $root && ($prune{$b} || (!$deep && $prune_nondeep{$b}) || ($self_abs && File::Spec->rel2abs($p) eq $self_abs))) {
        $File::Find::prune = 1;
      }
      if ($b eq '.git' && $p ne $root) { $File::Find::prune = 1 }
      return;
    }
    return if -l $p;
    if (@skip_rel) { my $rel = substr($p, length($root) + 1); for my $s (@skip_rel) { return if $rel eq $s } }
    push @files, $p if -f _;
  },
}, $root);

my $has_pkg = 0; my $has_lock = 0; my $gitignore_cfgbat = 0; my %bat_seen;
for my $p (@files) {
  my $rp = rel($p);
  my $base = $p; $base =~ s{.*/}{};
  my $e = ext($base);
  my $in_nm = $rp =~ m{(^|/)node_modules/} ? 1 : 0;
  my $size = -s $p // 0;

  # name-based IOCs
  finding('HIGH', 'ioc-filename', $rp, 'temp_auto_push.bat: PolinRider propagation script (amends + force-pushes back-dated commits)') if $base eq 'temp_auto_push.bat';
  finding('HIGH', 'ioc-filename', $rp, 'Shai-Hulud 2.0 stager/payload file') if $base eq 'setup_bun.js' || $base eq 'bun_environment.js';
  finding('HIGH', 'ioc-filename', $rp, 'Shai-Hulud workflow file') if $base =~ /^shai-hulud/i;
  finding('HIGH', 'ioc-filename', $rp, 'Contagious Interview artifact (.vscode/argv.exe, p.zi/p8.zi)') if $rp =~ m{(^|/)\.vscode/argv\.exe$} || $base =~ /^p8?\.zi$/;
  $bat_seen{cfg} = $rp if $base eq 'config.bat';
  if ($script_ext{$e} && !$in_nm) { finding('LOW', 'script-file', $rp, "Windows/script file in repo (.$e) - review before running anything") }
  if ($e eq 'node' && !$in_nm) { finding('MEDIUM', 'native-addon', $rp, 'prebuilt native Node addon (.node) committed to the repo (GlassWorm used native loaders)') }

  next if $size > $max_bytes;
  open my $fh, '<:raw', $p or next;
  local $/;
  my $c = <$fh> // '';
  close $fh;
  my $head = substr($c, 0, 8);

  # hashes
  if (%hash_ioc) {
    my $h = lc Digest::SHA::sha256_hex($c);
    finding('HIGH', 'ioc-hash', $rp, "sha256 matches known malware ($hash_ioc{\"sha256:$h\"})") if exists $hash_ioc{"sha256:$h"};
    if ($e =~ /^(js|mjs|cjs)$/) {
      if ($want_sha1) { my $h1 = Digest::SHA::sha1_hex($c); finding('HIGH', 'ioc-hash', $rp, "sha1 matches known malware ($hash_ioc{\"sha1:$h1\"})") if exists $hash_ioc{"sha1:$h1"} }
      if ($want_md5)  { my $h5 = Digest::MD5::md5_hex($c); finding('HIGH', 'ioc-hash', $rp, "md5 matches known malware ($hash_ioc{\"md5:$h5\"})") if exists $hash_ioc{"md5:$h5"} }
    }
  }

  # binaries / disguised files
  my $mk = magic_kind($head);
  if ($mk && !$in_nm) { finding('MEDIUM', 'binary', $rp, "executable binary ($mk) committed to the repo") }
  my $is_text = index(substr($c, 0, 8192), "\0") < 0;
  if ($font_ext{$e} && !font_ok($head, $e, $c)) {
    finding('HIGH', 'fake-asset', $rp, ($is_text && looks_like_js($c)) ? "'.$e' file is actually JavaScript (PolinRider/Contagious Interview fake font)" : "'.$e' file does not have a font signature");
  }
  if ($img_ext{$e} && !img_ok($head, $e) && $is_text && looks_like_js($c)) { finding('HIGH', 'fake-asset', $rp, "'.$e' image is actually JavaScript") }
  if ($base =~ /\.dict$/ && $is_text && looks_like_js($c)) { finding('HIGH', 'fake-asset', $rp, 'dictionary file contains JavaScript (spellright.dict trick)') }
  next unless $is_text;

  # package manager files
  if ($base eq 'package.json') { $has_pkg++ unless $in_nm; check_package_json($rp, $c, $in_nm) }
  if (!$in_nm && $base =~ /^(package-lock\.json|npm-shrinkwrap\.json)$/) { $has_lock++; check_lock_npm($rp, $c) }
  if (!$in_nm && ($base eq 'pnpm-lock.yaml' || $base eq 'yarn.lock')) { $has_lock++; check_lock_text($rp, $base, $c) }
  if (!$in_nm && $base =~ /^(bun\.lockb?|bun\.lock)$/) { $has_lock++ }
  if (!$in_nm) {
    if ($base eq '.npmrc') {
      finding('MEDIUM', 'npmrc', $rp, 'repo .npmrc turns install scripts back on') if $c =~ /^\s*ignore-scripts\s*=\s*false/m;
      finding('MEDIUM', 'npmrc', $rp, "repo .npmrc points at a non-default registry: $1") if $c =~ /^\s*(?:\@[\w-]+:)?registry\s*=\s*(\S+)/m && $1 !~ m{registry\.npmjs\.org};
      finding('MEDIUM', 'npmrc', $rp, 'repo .npmrc contains an auth token (leaked secret?)') if $c =~ /_authToken\s*=/;
    }
    finding('MEDIUM', 'yarn-exec', $rp, "yarnPath runs a repo-supplied JS file on every yarn command: $1") if $base eq '.yarnrc.yml' && $c =~ /^\s*yarnPath:\s*(\S+)/m;
    finding('MEDIUM', 'pnpmfile', $rp, '.pnpmfile.cjs hooks run code during pnpm install') if $base =~ /^\.?pnpmfile\.c?js$/;
    finding('MEDIUM', 'pnpm-builds', $rp, 'pnpm-workspace.yaml allows every dependency build script') if $base eq 'pnpm-workspace.yaml' && $c =~ /dangerouslyAllowAllBuilds:\s*true/;
    finding('MEDIUM', 'bun-preload', $rp, 'bunfig.toml preloads a script') if $base eq 'bunfig.toml' && $c =~ /preload\s*=/;
    if ($base =~ /^requirements.*\.txt$|^constraints.*\.txt$|^pip\.conf$|^Pipfile$/) {
      finding('MEDIUM', 'python-index', $rp, "extra/alternate package index (dependency-confusion risk): $1") if $c =~ /(--extra-index-url\s+\S+|--index-url\s+\S+|extra-index-url\s*=\s*\S+)/;
      finding('LOW', 'python-source', $rp, "dependency installed straight from a URL/VCS: $1") if $c =~ /^\s*((?:git\+|https?:\/\/)\S+)/m;
    }
    if ($base eq 'setup.py' && $c =~ /\b(urllib|requests\.|socket\.|subprocess|os\.system|base64|exec\(|eval\()/) { finding('MEDIUM', 'python-setup', $rp, "setup.py runs at pip install time and uses $1") }
    finding('MEDIUM', 'python-pth', $rp, '.pth file in repo (auto-executes when placed in site-packages)') if $e eq 'pth';
    $gitignore_cfgbat = 1 if $base eq '.gitignore' && $c =~ /(^|\/)config\.bat\s*$/m;
    finding('HIGH', 'ioc-filename', $rp, '.gitignore hides temp_auto_push.bat (PolinRider)') if $base eq '.gitignore' && $c =~ /temp_auto_push\.bat/;
    if ($rp =~ m{(^|/)\.github/workflows/[^/]+\.ya?ml$} && $c =~ /pull_request_target/ && $c =~ /github\.event\.pull_request\.head\.(sha|ref)/) {
      finding('MEDIUM', 'ci-workflow', $rp, 'pull_request_target workflow checks out untrusted PR code (secrets exposure)');
    }
    check_vscode($rp, $base, $c) if $rp =~ m{(^|/)\.(vscode|devcontainer|cursor)/} || $base =~ /\.code-workspace$|^devcontainer\.json$|^mcp\.json$/;
  }
  if ($size > 5 * 1024 * 1024 && $e =~ /^(js|mjs|cjs)$/ && !$in_nm && $rp !~ m{(^|/)(dist|build|out)/}) {
    finding('MEDIUM', 'large-js', $rp, sprintf('%.1f MB JavaScript file outside build output (bun_environment.js was ~10 MB)', $size / 1048576));
  }
  scan_text($rp, $base, $e, $c, $in_nm);
}
if ($bat_seen{cfg}) { finding($gitignore_cfgbat ? 'HIGH' : 'MEDIUM', 'ioc-filename', $bat_seen{cfg}, $gitignore_cfgbat ? 'config.bat listed in .gitignore next to it (PolinRider evidence)' : 'config.bat present (generic name; PolinRider used it)') }
elsif ($gitignore_cfgbat) { finding('MEDIUM', 'ioc-filename', '.gitignore', '.gitignore lists config.bat (PolinRider evidence; check history)') }
if ($has_pkg && !$has_lock) { finding('LOW', 'no-lockfile', '.', 'package.json without a lockfile: installs are not reproducible') }
print "#files\t", scalar(@files), "\n";
