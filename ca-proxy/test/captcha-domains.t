#!/usr/bin/perl
#
# The CAPTCHA's settings per domain, and its limits (inc/snif-auth-captcha.php),
# through the real endpoint, secure_html/snif-auth.php, served by the PHP
# CLI's web server on a scratch CA proxy tree with names under three domains:
#   - etc/<base>.pow.secret and etc/<base>.pow.maxnumber stand for their
#     domain over etc/pow.secret and etc/pow.maxnumber; an empty
#     etc/<base>.pow.secret turns the proof of work off there;
#   - the per-address counter is the relay's, whatever key a domain signs
#     its challenges with;
#   - etc/captcha-limit and etc/<base>.captcha-limit set the limits per
#     address, per domain and per day (day= only in the relay's file);
#   - an IPv6 /48 counts its /64s together (net=), and IPv4 has no /48: by
#     the PHP itself, since every request here comes from 127.0.0.1.
#
#   perl ca-proxy/test/captcha-domains.t [path/to/ca-proxy]
#
# Needs php (cli). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path remove_tree);
use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex hmac_sha256_hex);
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
die "captcha-domains.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{CAPTCHA_KEEP});
print "# tree $T\n" if $ENV{CAPTCHA_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}

my $B = "$T/ca";
make_path("$B/secure_html", "$B/cfg", "$B/auth", "$B/etc");
symlink("$Src/inc", "$B/inc") || die "inc: $!";
symlink("$Src/secure_html/snif-auth.php", "$B/secure_html/snif-auth.php") || die "snif-auth.php: $!";

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

# A new name under domain $d, with its cfg.
my $Seq = 0;
sub name { my $n = "snif-" . ++$Seq . ".$_[0]"; spew("$B/cfg/$n.cfg", "test=1\n"); $n }
sub req {
    my ($cn, $query, $hdrs) = @_;
    my $url = "http://127.0.0.1:$Port/snif-auth.php/$cn" . (defined $query ? "?$query" : '');
    return $Http->request(defined $hdrs ? 'POST' : 'GET', $url, { headers => $hdrs || {} });
}
sub challenge {
    my ($cn) = @_;
    my $r = req($cn, 'pow');
    return ($r, $r->{status} == 200 ? eval { decode_json($r->{content}) } : undef);
}
sub solve {
    my ($c) = @_;
    for my $n (0 .. $c->{maxnumber}) {
	return $n if sha256_hex($c->{salt} . $n) eq $c->{challenge};
    }
    return undef;
}
sub payload {
    my ($c, $n) = @_;
    return encode_base64(encode_json({ algorithm => 'SHA-256', challenge => $c->{challenge},
	salt => $c->{salt}, number => $n + 0, signature => $c->{signature} }), '');
}
# Approves a new name under $d by solving its challenge: the status.
sub approve {
    my ($d) = @_;
    my $cn = name($d);
    my ($r, $c) = challenge($cn);
    return "challenge $r->{status}" if !$c;
    return req($cn, undef, { 'X-SNIF-Captcha' => payload($c, solve($c)) })->{status};
}
sub loc { $_[0]{headers}{location} // $_[0]{status} }
sub clear_counters { remove_tree("$B/auth/captcha") }
my $Day = strftime('%Y%m%d', gmtime);

# ---- per-domain settings -------------------------------------------------------

my $Secret = "relay-secret-$$";
spew("$B/etc/pow.secret", "$Secret\n");
spew("$B/etc/pow.maxnumber", "3000\n");
spew("$B/etc/b.test.pow.secret", "");
spew("$B/etc/c.test.pow.secret", "c-secret\n");
spew("$B/etc/c.test.pow.maxnumber", "1000\n");
spew("$B/etc/d.test.pow.maxnumber", "not a number\n");

my $na = name('a.test');
my $r = req($na);
check($r->{status} == 302 && loc($r) =~ /&pow=1$/, "a.test, by the relay's settings: the page is told to solve: " . loc($r));
my ($cr, $c) = challenge($na);
check($c && $c->{maxnumber} == 3000 && $c->{signature} eq hmac_sha256_hex("$na\n$c->{challenge}", $Secret),
    "its challenge has the relay's work and key");

my $nb = name('b.test');
$r = req($nb);
check($r->{status} == 302 && loc($r) !~ /pow=/, "b.test, whose pow.secret is empty: the page is not told to: " . loc($r));
($cr) = challenge($nb);
check($cr->{status} == 501, "and there is no challenge (501): $cr->{status}");
$r = req($nb, undef, { 'X-SNIF-Captcha' => 'x' });
check($r->{status} == 501, "nor approval by one (501): $r->{status}");

my $cc = name('c.test');
($cr, $c) = challenge($cc);
check($c && $c->{maxnumber} == 1000 && $c->{signature} eq hmac_sha256_hex("$cc\n$c->{challenge}", 'c-secret'),
    "c.test: its challenge has its own work and key");
$r = req($cc, undef, { 'X-SNIF-Captcha' => payload($c, solve($c)) });
check($r->{status} == 202, "and its solution approves the name (202): $r->{status}");

($cr, $c) = challenge(name('d.test'));
check($c && $c->{maxnumber} == 3000, "d.test, whose pow.maxnumber is no number: the relay's work: " . ($c ? $c->{maxnumber} : $cr->{status}));

check(approve('a.test') eq '202', "a.test: a solution approves a name");
my @ip = glob("$B/auth/captcha/ip-$Day-*");
check(@ip == 1 && (slurp($ip[0]) // '') eq '2', "the address's counter is the relay's: c.test's and a.test's approvals count in one: "
    . join(' ', map { (m{([^/]+)\z})[0] . '=' . (slurp($_) // '') } @ip));
check((slurp("$B/auth/captcha/dom-$Day-a.test") // '') eq '1' && (slurp("$B/auth/captcha/dom-$Day-c.test") // '') eq '1'
    && (slurp("$B/auth/captcha/day-$Day") // '') eq '2', "each domain counts its own, and the day both");

# ---- limits --------------------------------------------------------------------

# Per domain: the relay's domain=2, c.test's own domain=1.
clear_counters();
spew("$B/etc/captcha-limit", "domain=2\n");
spew("$B/etc/c.test.captcha-limit", "domain=1\n");
my @st = map { approve('a.test') } 1 .. 3;
check("@st" eq "202 202 429", "a.test, at the relay's domain=2: @st");
@st = map { approve('c.test') } 1 .. 2;
check("@st" eq "202 429", "c.test, at its own domain=1, while a.test is full: @st");

# day= counts in the relay's file only.
clear_counters();
spew("$B/etc/captcha-limit", "");
spew("$B/etc/c.test.captcha-limit", "day=0\n");
check(approve('c.test') eq '202', "day=0 in c.test's file is not the relay's: approved");
spew("$B/etc/captcha-limit", "day=1\n");
check(approve('a.test') eq '429', "day=1 in the relay's file: the next is refused (429)");

# Per address: one counter for the relay, a limit per domain.
clear_counters();
spew("$B/etc/captcha-limit", "address=1\n");
spew("$B/etc/c.test.captcha-limit", "");
@st = (approve('a.test'), approve('c.test'));
check("@st" eq "202 429", "address=1: an approval under a.test leaves none for c.test: @st");
spew("$B/etc/c.test.captcha-limit", "# more for c.test\naddress=3 domain=10\n");
@st = (approve('a.test'), approve('c.test'), approve('c.test'), approve('c.test'));
check("@st" eq "429 202 202 429", "c.test's own address=3 lets it count on to 3: @st");
@ip = glob("$B/auth/captcha/ip-$Day-*");
check(@ip == 1 && (slurp($ip[0]) // '') eq '3', "on the one counter: " . join(' ', map { slurp($_) // '' } @ip));

# ---- the /48, by the PHP --------------------------------------------------------

clear_counters();
spew("$B/etc/captcha-limit", "net=2\n");
spew("$B/etc/c.test.captcha-limit", "");
my $Drv = "$T/quota.php";
spew($Drv, <<'EOF');
<?php
$_SERVER['DOCUMENT_ROOT'] = $argv[1] . '/secure_html';
require $argv[1] . '/inc/snif-cluster.php';
require $argv[1] . '/inc/snif-auth-captcha.php';
foreach (array_slice($argv, 2) as $ip) echo snif_captcha_quota($ip, 'snif-q.a.test') ? 'counted' : 'refused', "\n";
EOF
my @q = split /\n/, `php -d display_errors=stderr '$Drv' '$B' 2001:db8:1:1::1 2001:db8:1:2::1 2001:db8:1:3::1 2001:db8:2:1::1 2001:db8:1:1::2 192.0.2.1 192.0.2.2 192.0.2.3 2>&1`;
check("@q[0..3]" eq "counted counted refused counted",
    "net=2: two /64s of one /48 counted, a third refused, another /48 counted: @q[0..3]");
check(($q[4] // '') eq 'refused', "and the first /64 again, its /48 full: " . ($q[4] // ''));
check("@q[5..7]" eq "counted counted counted", "IPv4 addresses have no /48 to fill: @q[5..7]");
my @net = glob("$B/auth/captcha/net-$Day-*");
check(@net == 2 && !grep({ !/net-$Day-[0-9a-f]{32}\z/ } @net), "two /48 counters, named by a keyed hash: " . scalar(@net));
check(scalar(() = glob("$B/auth/captcha/ip-$Day-*")) == 6, "and the /64s and IPv4 addresses one each");

my $log = slurp("$T/server.log") // '';
my @bad = grep { /PHP (Fatal|Parse)/ || (/PHP (Warning|Notice|Deprecated)/ && /snif-auth-captcha\.php|snif-auth\.php on line/ && !/snif-auth-ves/) } split /\n/, $log;
check(!@bad, "the server logged no PHP error, nor a warning from this code");
print "# $_\n" for @bad;

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
