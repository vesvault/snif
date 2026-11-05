#!/usr/bin/perl
#
# Approval by proof of work (inc/snif-auth-captcha.php), through the real
# endpoint, secure_html/snif-auth.php, served by the PHP CLI's web server on
# a scratch CA proxy tree:
#   - off without etc/pow.secret: no challenge (501), no approval (501), and
#     the authorization page is not told to use it;
#   - with it: a challenge for the name (GET ?pow), solved here, approves the
#     name (202) and records "1"; a repeat answers 202 and counts nothing;
#   - a solution approves only the name it was issued for, and not after
#     its expiry; a changed number, salt or signature is refused (403);
#   - the per-address and daily quotas (429), counted under a keyed hash of
#     the address; an IPv6 address counts by its /64.
#
#   perl ca-proxy/test/pow.t [path/to/ca-proxy]
#
# Needs php (cli). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex hmac_sha256_hex);
use Digest::MD5 qw(md5_hex);
use HTTP::Tiny;
use IO::Socket::INET;
use JSON::PP;
use MIME::Base64;
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
die "pow.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{POW_KEEP});
print "# tree $T\n" if $ENV{POW_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}

# The tree: the endpoint and inc/ from the source, names with a cfg.
my $B = "$T/ca";
make_path("$B/secure_html", "$B/cfg", "$B/auth", "$B/etc");
symlink("$Src/inc", "$B/inc") || die "inc: $!";
symlink("$Src/secure_html/snif-auth.php", "$B/secure_html/snif-auth.php") || die "snif-auth.php: $!";
my @Names = map { "snif-pow$_.example.test" } 1 .. 8;
spew("$B/cfg/$_.cfg", "test=1\n") for @Names;

# A free port, and the server on it.
my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) || die "port: $!";
my $Port = $s->sockport;
close $s;
my $Pid = fork();
die "fork: $!" unless defined $Pid;
if (!$Pid) {
    open(STDOUT, '>', "$T/server.log");
    open(STDERR, '>&', \*STDOUT);
    exec('php', '-d', 'display_errors=stderr', '-S', "127.0.0.1:$Port", '-t', "$B/secure_html");
    exit 127;
}
END { kill('TERM', $Pid) if $Pid; }
my $Http = HTTP::Tiny->new(max_redirect => 0, timeout => 20);
for (1 .. 50) {
    last if IO::Socket::INET->new(PeerAddr => "127.0.0.1:$Port");
    select(undef, undef, undef, 0.1);
}

# A request to the endpoint for a name: its status, headers and body.
sub req {
    my ($cn, $query, $hdrs) = @_;
    my $url = "http://127.0.0.1:$Port/snif-auth.php/$cn" . (defined $query ? "?$query" : '');
    my $r = $Http->request(defined $hdrs ? 'POST' : 'GET', $url, { headers => $hdrs || {} });
    return $r;
}

# Solves a challenge the way snif-pow.js does: the n whose SHA-256(salt.n)
# is the challenge.
sub solve {
    my ($c) = @_;
    for my $n (0 .. $c->{maxnumber}) {
	return $n if sha256_hex($c->{salt} . $n) eq $c->{challenge};
    }
    return undef;
}
sub payload {
    my ($c, $n, %over) = @_;
    my %p = (algorithm => 'SHA-256', challenge => $c->{challenge}, salt => $c->{salt},
	     number => $n + 0, signature => $c->{signature}, %over);
    return encode_base64(JSON::PP->new->canonical->encode(\%p), '');
}
sub challenge {
    my ($cn) = @_;
    my $r = req($cn, 'pow');
    return ($r, $r->{status} == 200 ? eval { decode_json($r->{content}) } : undef);
}
sub auth_file { slurp("$B/auth/$_[0].auth") }
my $Day = strftime('%Y%m%d', gmtime);

# ---- off without etc/pow.secret ---------------------------------------------

my ($r, $c) = challenge($Names[0]);
check($r->{status} == 501, "no pow.secret: no challenge (501): $r->{status}");
$r = req($Names[0], undef, { 'X-SNIF-Captcha' => 'x' });
check($r->{status} == 501, "and no approval by proof of work (501): $r->{status}");
$r = req($Names[0]);
check($r->{status} == 302 && ($r->{headers}{location} // '') !~ /pow=/,
    "the authorization page is not told to use it: " . ($r->{headers}{location} // $r->{status}));

# ---- on ------------------------------------------------------------------------

my $Secret = "test-secret-" . $$;
spew("$B/etc/pow.secret", "$Secret\n");
spew("$B/etc/pow.maxnumber", "3000\n");

$r = req($Names[0]);
check($r->{status} == 302 && ($r->{headers}{location} // '') =~ /^https:\/\/snif\.host\/auth\?authUrl=.*&pow=1$/,
    "with it, the authorization page is told to: " . ($r->{headers}{location} // $r->{status}));

($r, $c) = challenge($Names[0]);
check($r->{status} == 200 && $c && ($r->{headers}{'content-type'} // '') =~ m{application/json},
    "GET ?pow answers a challenge as JSON: $r->{status}");
check($c && $c->{algorithm} eq 'SHA-256' && $c->{challenge} =~ /^[0-9a-f]{64}\z/
    && $c->{salt} =~ /^[0-9a-f]{24}\.(\d+)\z/ && $1 > time() && $1 <= time() + 600
    && $c->{maxnumber} == 3000, "with an expiry in its salt and the configured work: " . ($r->{content} // ''));
check($c && $c->{signature} eq hmac_sha256_hex("$Names[0]\n$c->{challenge}", $Secret),
    "signed over the name and the challenge");
my $N = $c ? solve($c) : undef;
check(defined $N, "and solvable in [0, maxnumber]: " . ($N // 'none'));

# A solution for one name does not approve another.
$r = req($Names[1], undef, { 'X-SNIF-Captcha' => payload($c, $N) });
check($r->{status} == 403 && !defined auth_file($Names[1]), "another name's solution is refused (403): $r->{status}");
# Changed parts are refused.
my $salt2 = $c->{salt};
substr($salt2, 0, 1) = substr($salt2, 0, 1) eq '0' ? '1' : '0';
for my $t (['number', $N + 1], ['salt', $salt2], ['signature', '0' x 64], ['challenge', sha256_hex('x')]) {
    my ($part, $v) = @$t;
    my $p = $part eq 'number' ? payload($c, $v) : payload($c, $N, $part => $v);
    $r = req($Names[0], undef, { 'X-SNIF-Captcha' => $p });
    check($r->{status} == 403, "a changed $part is refused (403): $r->{status}");
}
for my $bad ('', 'not base64 !', encode_base64('{"number":"1"}', '')) {
    $r = req($Names[0], undef, { 'X-SNIF-Captcha' => $bad });
    check($r->{status} == ($bad eq '' ? 401 : 403), "a payload of '$bad' is refused ($r->{status})");
}
check(!defined auth_file($Names[0]), "and none of them approved the name");

# The right one approves it, records "1", and counts it once.
$r = req($Names[0], undef, { 'X-SNIF-Captcha' => payload($c, $N) });
check($r->{status} == 202, "the solution approves the name (202): $r->{status}");
check((auth_file($Names[0]) // '') eq '1', "the approval file records \"1\", not the address: " . (auth_file($Names[0]) // 'none'));
my @ip = glob("$B/auth/captcha/ip-$Day-*");
check((slurp("$B/auth/captcha/day-$Day") // '') eq '1' && @ip == 1, "the day's and the address's counters count it");
my ($ipname) = map { m{/ip-\d+-(.*)\z} } @ip;
check(($ipname // '') =~ /^[0-9a-f]{32}\z/ && $ipname ne md5_hex('127.0.0.1'),
    "the address's counter is not named by an unkeyed hash of it: " . ($ipname // 'none'));

# A repeat: approved already, nothing counted again.
$r = req($Names[0], undef, { 'X-SNIF-Captcha' => payload($c, $N) });
check($r->{status} == 202 && (slurp("$B/auth/captcha/day-$Day") // '') eq '1', "a repeat answers 202 and counts nothing");
($r) = challenge($Names[0]);
check($r->{status} == 202, "and a challenge for an approved name answers 202: $r->{status}");
($r) = challenge('snif-none.example.test');
check($r->{status} == 404, "a challenge for an unknown name answers 404: $r->{status}");

# Expiry: a challenge signed as the server signs, with a past expiry.
my $old = sprintf('%024x', 7) . '.' . (time() - 1);
my $oc = { salt => $old, challenge => sha256_hex($old . 5) };
$oc->{signature} = hmac_sha256_hex("$Names[1]\n$oc->{challenge}", $Secret);
$r = req($Names[1], undef, { 'X-SNIF-Captcha' => payload($oc, 5) });
check($r->{status} == 403, "an expired challenge is refused (403): $r->{status}");
# The same with a future expiry is accepted: the signing above is the server's.
my $new = sprintf('%024x', 8) . '.' . (time() + 60);
my $nc = { salt => $new, challenge => sha256_hex($new . 5) };
$nc->{signature} = hmac_sha256_hex("$Names[1]\n$nc->{challenge}", $Secret);
$r = req($Names[1], undef, { 'X-SNIF-Captcha' => payload($nc, 5) });
check($r->{status} == 202, "and the same, not expired, approves (so the expiry is what refused it): $r->{status}");

# ---- quotas --------------------------------------------------------------------

# Five a day per address: two approved above, three more, then 429.
for my $i (2 .. 5) {
    my ($cr, $cc) = challenge($Names[$i]);
    $r = req($Names[$i], undef, { 'X-SNIF-Captcha' => payload($cc, solve($cc)) });
    check($r->{status} == ($i < 5 ? 202 : 429), "approval " . ($i + 1) . " from one address: $r->{status}");
}
check(!defined auth_file($Names[5]), "the refused one is not approved");
# The day's quota, counted across addresses.
spew("$B/auth/captcha/day-$Day", "200");
spew("$B/auth/captcha/ip-$Day-$ipname", "0");
{
    my ($cr, $cc) = challenge($Names[6]);
    $r = req($Names[6], undef, { 'X-SNIF-Captcha' => payload($cc, solve($cc)) });
    check($r->{status} == 429, "the day's 200 refuse the next (429): $r->{status}");
}

# The address key, by the PHP itself: an IPv6 address by its /64, an
# IPv4-mapped one as the IPv4.
my $Key = "$T/key.php";
spew($Key, <<'EOF');
<?php
$_SERVER['DOCUMENT_ROOT'] = $argv[1] . '/secure_html';
require $argv[1] . '/inc/snif-cluster.php';
require $argv[1] . '/inc/snif-auth-captcha.php';
foreach (array_slice($argv, 2) as $ip) {
    $k = snif_captcha_ip_keys($ip, snif_captcha_counter_key('snif-x.example.test'));
    echo $k['ip'], ' ', $k['net'] ?? '-', "\n";
}
EOF
my @k = map { [split ' '] } split /\n/, `php '$Key' '$B' 2001:db8:1:2::1 2001:db8:1:2:ffff::9 2001:db8:1:3::1 ::ffff:192.0.2.1 192.0.2.1 192.0.2.2 2001:db8:2::1`;
check(@k == 7 && $k[0][0] eq $k[1][0], "two addresses in one /64 count together");
check(@k == 7 && $k[0][0] ne $k[2][0], "another /64 counts apart");
check(@k == 7 && $k[0][1] eq $k[2][1] && $k[0][1] =~ /^[0-9a-f]{32}\z/, "and in one /48, together");
check(@k == 7 && $k[6][1] ne $k[0][1], "another /48 counts apart");
check(@k == 7 && $k[3][0] eq $k[4][0] && $k[4][0] ne $k[5][0] && $k[4][1] eq '-',
    "an IPv4-mapped address counts as the IPv4, IPv4 addresses apart, and IPv4 has no /48");
spew("$B/etc/pow.secret", "another-secret\n");
my @k2 = map { [split ' '] } split /\n/, `php '$Key' '$B' 192.0.2.1`;
check(@k2 == 1 && $k2[0][0] ne $k[4][0], "the key is the secret's: another secret names it differently");

# (inc/snif-auth-ves.php warns of the absent X-VES-Authorization on every
# redirect; that is not this code's.)
my $log = slurp("$T/server.log") // '';
my @bad = grep { /PHP (Fatal|Parse)/ || (/PHP (Warning|Notice|Deprecated)/ && /snif-auth-captcha\.php|snif-auth\.php on line/ && !/snif-auth-ves/) } split /\n/, $log;
check(!@bad, "the server logged no PHP error, nor a warning from this code");
print "# $_\n" for @bad;

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
