#!/usr/bin/perl
#
# Approval by Cloudflare Turnstile, the option beside the proof of work
# (inc/snif-auth-captcha.php), through the real endpoint,
# secure_html/snif-auth.php, served by the PHP CLI's web server on a scratch
# CA proxy tree. Cloudflare's siteverify is a stand-in, also under php -S, so
# no request leaves the host:
#   - with etc/turnstile.secret alone: a token Cloudflare accepts, in
#     X-SNIF-Captcha or the cf-turnstile-response form field, approves the
#     name (202) and records "1"; one it refuses, or no answer from it, is
#     403; no token is 401; there is no proof of work (?pow is 501); the
#     check sends the secret and the token, and not the client's address;
#   - the authorization page is told "&sitekey=<key>" only with
#     etc/turnstile.sitekey too;
#   - a repeat answers 202 without asking Cloudflare; the quotas apply, and
#     the address's counter is keyed by the Turnstile secret;
#   - with etc/pow.secret as well, the proof of work is the one used: the
#     page is told "&pow=1", and a Turnstile token approves nothing and is
#     not checked;
#   - per domain: an empty etc/<base>.pow.secret puts that domain on
#     Turnstile, and etc/<base>.turnstile.sitekey and .secret are its own.
#
#   perl ca-proxy/test/turnstile.t [path/to/ca-proxy]
#
# Needs php (cli). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use POSIX qw(strftime);
use Digest::SHA qw(hmac_sha256_hex);
use HTTP::Tiny;
use IO::Socket::INET;
use Socket qw(inet_aton);
use JSON::PP;
use FindBin;

my $Src = shift || "$FindBin::Bin/..";
$Src = Cwd::abs_path($Src) if eval { require Cwd; 1 };
$| = 1;
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}
die "turnstile.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{TURNSTILE_KEEP});
print "# tree $T\n" if $ENV{TURNSTILE_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) || die "port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}
my @Pids;
END { kill('TERM', @Pids) if @Pids; }
sub serve {
    my ($port, $root, $log, @php) = @_;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
	open(STDOUT, '>', $log);
	open(STDERR, '>&', \*STDOUT);
	exec('php', '-d', 'display_errors=stderr', @php, '-S', "127.0.0.1:$port", '-t', $root);
	exit 127;
    }
    push @Pids, $pid;
    for (1 .. 50) {
	last if IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
	select(undef, undef, undef, 0.1);
    }
}

# The stand-in for Cloudflare's siteverify: it logs each check, one JSON line,
# and accepts a token that starts with "good-" for the secret in its tree.
my $V = "$T/cf";
my $Secret = "turnstile-secret-" . $$;
spew("$V/secret", $Secret);
spew("$V/siteverify.php", <<'EOF');
<?php
file_put_contents(__DIR__ . '/checks.log', json_encode($_POST) . "\n", FILE_APPEND);
$ok = ($_POST['secret'] ?? '') === file_get_contents(__DIR__ . '/secret')
    && strncmp($_POST['response'] ?? '', 'good-', 5) == 0;
header('Content-Type: application/json');
echo json_encode(['success' => $ok, 'error-codes' => $ok ? [] : ['invalid-input-response']]);
EOF
spew("$V/garbage.php", "<?php header('Content-Type: text/html'); echo 'no JSON here';\n");
my $VPort = free_port();
serve($VPort, $V, "$T/cf.log");
sub checks { my $l = slurp("$V/checks.log") // ''; return map { decode_json($_) } split /\n/, $l }

# The CA proxy tree: the endpoint and inc/ from the source, names with a cfg.
# Where the endpoint checks a token comes from a file, so that a check can
# point it elsewhere.
my $B = "$T/ca";
make_path("$B/secure_html", "$B/cfg", "$B/auth", "$B/etc");
symlink("$Src/inc", "$B/inc") || die "inc: $!";
symlink("$Src/secure_html/snif-auth.php", "$B/secure_html/snif-auth.php") || die "snif-auth.php: $!";
my @Names = map { "snif-ts$_.example.test" } 1 .. 12;
spew("$B/cfg/$_.cfg", "test=1\n") for @Names;
spew("$T/verify-url", "http://127.0.0.1:$VPort/siteverify.php");
spew("$T/prepend.php", "<?php \$TurnstileVerifyUrl = trim(file_get_contents('$T/verify-url'));\n");
my $Port = free_port();
serve($Port, "$B/secure_html", "$T/server.log", '-d', "auto_prepend_file=$T/prepend.php");
my $Http = HTTP::Tiny->new(max_redirect => 0, timeout => 30);

# A request to the endpoint for a name: with headers it is a POST, with a
# hash of form fields a form POST.
sub req {
    my ($cn, $query, $hdrs) = @_;
    my $url = "http://127.0.0.1:$Port/snif-auth.php/$cn" . (defined $query ? "?$query" : '');
    return $Http->request(defined $hdrs ? 'POST' : 'GET', $url, { headers => $hdrs || {} });
}
sub form {
    my ($cn, $fields) = @_;
    return $Http->post_form("http://127.0.0.1:$Port/snif-auth.php/$cn", $fields);
}
sub auth_file { slurp("$B/auth/$_[0].auth") }
sub loc { $_[0]{headers}{location} // $_[0]{status} }
my $Day = strftime('%Y%m%d', gmtime);

# ---- neither secret ----------------------------------------------------------

my $r = req($Names[0], undef, { 'X-SNIF-Captcha' => 'good-1' });
check($r->{status} == 501, "no secret: a token approves nothing (501): $r->{status}");
$r = form($Names[0], { 'cf-turnstile-response' => 'good-1' });
check($r->{status} == 501, "nor in the form field (501): $r->{status}");
check(!checks(), "and Cloudflare is not asked");

# ---- etc/turnstile.secret alone ------------------------------------------------

spew("$B/etc/turnstile.secret", "$Secret\n");

$r = req($Names[0]);
check($r->{status} == 302 && loc($r) !~ /sitekey=|pow=/,
    "without turnstile.sitekey the authorization page is not told to show it: " . loc($r));
($r) = req($Names[0], 'pow');
check($r->{status} == 501, "no proof of work: no challenge (501): $r->{status}");

$r = req($Names[0], undef, { 'X-SNIF-Captcha' => 'bad-1' });
check($r->{status} == 403 && !defined auth_file($Names[0]), "a token Cloudflare refuses is refused (403): $r->{status}");
my @c = checks();
check(@c == 1 && ($c[0]{secret} // '') eq $Secret && ($c[0]{response} // '') eq 'bad-1',
    "the check sends the secret and the token");
check(@c == 1 && !exists $c[0]{remoteip}, "and not the client's address");
$r = req($Names[0], undef, { 'X-SNIF-Captcha' => '' });
check($r->{status} == 401, "no token is 401: $r->{status}");

$r = req($Names[0], undef, { 'X-SNIF-Captcha' => 'good-1' });
check($r->{status} == 202, "a token Cloudflare accepts approves the name (202): $r->{status}");
check((auth_file($Names[0]) // '') eq '1', "the approval file records \"1\", not the address: " . (auth_file($Names[0]) // 'none'));
check((slurp("$B/auth/captcha/day-$Day") // '') eq '1', "the day's counter counts it");
my $IpKey = substr(hmac_sha256_hex(inet_aton('127.0.0.1'), $Secret), 0, 32);
check((slurp("$B/auth/captcha/ip-$Day-$IpKey") // '') eq '1',
    "the address's counter is keyed by the Turnstile secret: " . join(' ', map { m{([^/]+)\z} } glob("$B/auth/captcha/ip-*")));

$r = form($Names[1], { 'cf-turnstile-response' => 'good-2' });
check($r->{status} == 202 && (auth_file($Names[1]) // '') eq '1', "a token in the cf-turnstile-response field approves too (202): $r->{status}");

my $n = () = checks();
$r = req($Names[0], undef, { 'X-SNIF-Captcha' => 'good-3' });
check($r->{status} == 202 && scalar(() = checks()) == $n && (slurp("$B/auth/captcha/day-$Day") // '') eq '2',
    "a repeat answers 202, counts nothing and asks Cloudflare nothing");

# No answer from Cloudflare, or no JSON: refused, and said in the log.
spew("$T/verify-url", "http://127.0.0.1:" . free_port() . "/siteverify.php");
$r = req($Names[2], undef, { 'X-SNIF-Captcha' => 'good-4' });
check($r->{status} == 403 && !defined auth_file($Names[2]), "Cloudflare unreachable: refused (403): $r->{status}");
spew("$T/verify-url", "http://127.0.0.1:$VPort/garbage.php");
$r = req($Names[2], undef, { 'X-SNIF-Captcha' => 'good-4' });
check($r->{status} == 403 && !defined auth_file($Names[2]), "an answer that is not JSON: refused (403): $r->{status}");
spew("$T/verify-url", "http://127.0.0.1:$VPort/siteverify.php");
my $log = slurp("$T/server.log") // '';
check($log =~ /snif-captcha: siteverify connect failed/ && $log =~ /snif-captcha: siteverify rejected: no JSON here/,
    "both are logged");

# The quotas: five a day per address (two approved above), then 429; the
# day's 200 across addresses.
for my $i (3 .. 6) {
    $r = req($Names[$i], undef, { 'X-SNIF-Captcha' => "good-q$i" });
    check($r->{status} == ($i < 6 ? 202 : 429), "approval $i from one address: $r->{status}");
}
check(!defined auth_file($Names[6]), "the refused one is not approved");
spew("$B/auth/captcha/ip-$Day-$IpKey", "0");
spew("$B/auth/captcha/day-$Day", "200");
$r = req($Names[7], undef, { 'X-SNIF-Captcha' => 'good-d' });
check($r->{status} == 429, "the day's 200 refuse the next (429): $r->{status}");
spew("$B/auth/captcha/day-$Day", "5");

# ---- with etc/turnstile.sitekey ------------------------------------------------

spew("$B/etc/turnstile.sitekey", "0x4AAA test+key\n");
$r = req($Names[8]);
check($r->{status} == 302 && loc($r) =~ /^https:\/\/snif\.host\/auth\?authUrl=.*&sitekey=0x4AAA%20test%2Bkey$/,
    "with turnstile.sitekey the page is told the site key: " . loc($r));

# ---- etc/pow.secret as well: the proof of work is used -------------------------

spew("$B/etc/pow.secret", "pow-secret\n");
$r = req($Names[8]);
check($r->{status} == 302 && loc($r) =~ /&pow=1$/ && loc($r) !~ /sitekey=/,
    "with pow.secret too, the page is told to solve a proof of work, not to show Turnstile: " . loc($r));
($r) = req($Names[8], 'pow');
check($r->{status} == 200, "and GET ?pow answers a challenge: $r->{status}");
$n = () = checks();
$r = req($Names[8], undef, { 'X-SNIF-Captcha' => 'good-5' });
check($r->{status} == 403 && !defined auth_file($Names[8]), "a Turnstile token in X-SNIF-Captcha is refused (403): $r->{status}");
$r = form($Names[8], { 'cf-turnstile-response' => 'good-6' });
check($r->{status} == 401 && !defined auth_file($Names[8]), "and in the form field it is no solution (401): $r->{status}");
check(scalar(() = checks()) == $n, "and Cloudflare is not asked");

# ---- per domain: example.test back on Turnstile, the relay on proof of work ------

spew("$B/etc/example.test.pow.secret", "");
spew("$B/etc/example.test.turnstile.sitekey", "0xDOMAIN\n");
$r = req($Names[9]);
check($r->{status} == 302 && loc($r) =~ /&sitekey=0xDOMAIN$/ && loc($r) !~ /pow=/,
    "an empty example.test.pow.secret puts the domain on Turnstile, with its own site key: " . loc($r));
$r = req($Names[9], undef, { 'X-SNIF-Captcha' => 'good-7' });
check($r->{status} == 202 && (auth_file($Names[9]) // '') eq '1', "and a token approves its name (202): $r->{status}");
spew("$B/etc/example.test.turnstile.secret", "domain-secret\n");
$n = () = checks();
$r = req($Names[10], undef, { 'X-SNIF-Captcha' => 'good-8' });
@c = checks();
check($r->{status} == 403 && @c == $n + 1 && ($c[-1]{secret} // '') eq 'domain-secret',
    "the domain's own turnstile.secret is the one sent (the stand-in knows only the relay's: 403): $r->{status}");

$log = slurp("$T/server.log") // '';
my @bad = grep { /PHP (Fatal|Parse)/ || (/PHP (Warning|Notice|Deprecated)/ && /snif-auth-captcha\.php|snif-auth\.php on line/ && !/snif-auth-ves/) } split /\n/, $log;
check(!@bad, "the server logged no PHP error, nor a warning from this code");
print "# $_\n" for @bad;

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
