#!/usr/bin/perl
#
# What the CA proxy's two endpoints check in a request before it reaches a
# path, a file or a line to snif-syncd, through the real endpoints served by
# the PHP CLI's web server on a scratch CA proxy tree. That server passes a
# Host header as it comes, as a front web server would not:
#   - allocating a name (secure_html/snif-auth.php, no name): the Host must
#     be a hostname before etc/<host>.domains is read, so "../x" is 400 and
#     reads nothing outside etc/;
#   - its query and form fields, kept in cfg/<name>.cfg: a line break or a
#     NUL in one, or one that is not a string, is 400, more than 4096 bytes
#     in all is 413, and neither writes a cfg; within the limit, each is
#     one k=v line;
#   - the name in public_html/snif-cert.php: one that ends in a newline is
#     400, not a name (given through a router, since no request line can
#     carry one).
#
#   perl ca-proxy/test/input-checks.t [path/to/ca-proxy]
#
# Needs php (cli). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use IO::Socket::INET;
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
die "input-checks.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{INPUT_KEEP});
print "# tree $T\n" if $ENV{INPUT_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}

# The tree: both endpoints and inc/ from the source. The origin
# origin.test allocates in example.test; a .domains file outside etc/ names
# another zone, for the Host that tries to reach it.
my $B = "$T/ca";
make_path(map { "$B/$_" } qw(secure_html public_html cfg auth csr crt etc var));
symlink("$Src/inc", "$B/inc") || die "inc: $!";
symlink("$Src/secure_html/snif-auth.php", "$B/secure_html/snif-auth.php") || die "snif-auth.php: $!";
symlink("$Src/public_html/snif-cert.php", "$B/public_html/snif-cert.php") || die "snif-cert.php: $!";
spew("$B/etc/origin.test.domains", "example.test\n");
spew("$B/outside.domains", "outside.test\n");
# For snif-cert.php: the request's URI from X-Test-Uri (base64), which a
# request line could not carry.
spew("$B/public_html/router.php", <<'EOF');
<?php
if (isset($_SERVER['HTTP_X_TEST_URI'])) $_SERVER['REQUEST_URI'] = base64_decode($_SERVER['HTTP_X_TEST_URI']);
require __DIR__ . '/snif-cert.php';
EOF

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) || die "port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}
my @Pids;
END { kill('TERM', @Pids) if @Pids; }
sub serve {
    my ($port, $log, @args) = @_;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
	open(STDOUT, '>', $log);
	open(STDERR, '>&', \*STDOUT);
	exec('php', '-d', 'display_errors=stderr', '-S', "127.0.0.1:$port", @args);
	exit 127;
    }
    push @Pids, $pid;
    for (1 .. 50) {
	my $c = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
	if ($c) { close $c; return; }
	select(undef, undef, undef, 0.1);
    }
    die "input-checks.t: the server on $port did not start: " . (slurp($log) // '') . "\n";
}
my $Sec = free_port();
serve($Sec, "$T/secure.log", '-t', "$B/secure_html");
my $Pub = free_port();
serve($Pub, "$T/public.log", '-t', "$B/public_html", "$B/public_html/router.php");

# A raw request, so that the Host is ours: the status, the headers (lower
# case names) and the body.
sub raw {
    my ($port, $method, $path, $host, $hdrs, $body) = @_;
    my $c = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port", Timeout => 20) || die "connect: $!";
    my $req = "$method $path HTTP/1.0\r\nHost: $host\r\n";
    $req .= "$_: $hdrs->{$_}\r\n" for sort keys %{$hdrs || {}};
    $req .= 'Content-Length: ' . length($body) . "\r\n" if defined $body;
    print $c "$req\r\n", $body // '';
    local $/;
    my $rsp = <$c> // '';
    close $c;
    my ($head, $content) = split(/\r\n\r\n/, $rsp, 2);
    my ($status) = ($head // '') =~ m{^HTTP/\S+ (\d+)};
    my %h;
    for (split /\r\n/, $head // '') { $h{lc $1} = $2 if /^([^:]+):\s*(.*)$/ }
    return ($status // 0, \%h, $content // '');
}
sub cfgs { opendir(my $d, "$B/cfg") || return (); my @f = grep { /\.cfg$/ } readdir $d; closedir $d; @f }

# ---- the Host of an allocation -------------------------------------------------

my ($st, $h, $body) = raw($Sec, 'GET', '/snif-auth.php?a=1', 'origin.test:4443');
my ($cn) = ($h->{'x-snif-cn'} // '') =~ /^(?:\*\.)?(snif-[0-9a-f]{12}-[0-9a-f]{8}\.example\.test)$/;
check($st == 200 && $cn, "a hostname: a name is allocated in its zone: $st " . ($h->{'x-snif-cn'} // ''));
check($cn && (slurp("$B/cfg/$cn.cfg") // '') eq "a=1\n", 'its fields kept, one k=v line each');

my $before = scalar(cfgs());
($st, $h) = raw($Sec, 'GET', '/snif-auth.php', '../outside');
check($st == 400 && !defined $h->{'x-snif-cn'}, "a Host that leaves etc/: 400, no name: $st " . ($h->{'x-snif-cn'} // ''));
($st) = raw($Sec, 'GET', '/snif-auth.php', 'origin.test/x');
check($st == 400, "a Host with a \"/\": 400: $st");
($st) = raw($Sec, 'GET', '/snif-auth.php', '-origin.test');
check($st == 400, "a Host that is not a hostname: 400: $st");
check(scalar(cfgs()) == $before, 'and none of them writes a cfg');

# ---- the fields kept in its cfg ------------------------------------------------

for my $c (['/snif-auth.php?a=1%0Ab=2', 'a line feed in a value'],
	   ['/snif-auth.php?a=1%0D', 'a carriage return in a value'],
	   ['/snif-auth.php?a%0Ab=1', 'a line feed in a name'],
	   ['/snif-auth.php?a=1%00', 'a NUL in a value'],
	   ['/snif-auth.php?a[]=1', 'a field that is not a string']) {
    my ($path, $what) = @$c;
    ($st, $h) = raw($Sec, 'GET', $path, 'origin.test');
    check($st == 400 && !defined $h->{'x-snif-cn'}, "$what: 400, no name: $st");
}
($st) = raw($Sec, 'POST', '/snif-auth.php', 'origin.test',
	    { 'Content-Type' => 'application/x-www-form-urlencoded' }, 'p=1%0Aq=2');
check($st == 400, "a line feed in a form field: 400: $st");
($st, $h) = raw($Sec, 'GET', '/snif-auth.php?a=' . ('x' x 5000), 'origin.test');
check($st == 413 && !defined $h->{'x-snif-cn'}, "more than 4096 bytes of fields: 413, no name: $st");
($st) = raw($Sec, 'POST', '/snif-auth.php?a=' . ('x' x 3000), 'origin.test',
	    { 'Content-Type' => 'application/x-www-form-urlencoded' }, 'b=' . ('y' x 2000));
check($st == 413, "the query and the form counted together: 413: $st");
check(scalar(cfgs()) == $before, 'and none of them writes a cfg');
($st, $h) = raw($Sec, 'GET', '/snif-auth.php?a=' . ('x' x 4000), 'origin.test');
($cn) = ($h->{'x-snif-cn'} // '') =~ /(snif-[0-9a-f]{12}-[0-9a-f]{8}\.example\.test)$/;
check($st == 200 && $cn && length(slurp("$B/cfg/$cn.cfg") // '') == 4003, "within the limit: allocated, kept whole: $st");

# ---- the name in snif-cert.php ---------------------------------------------------

spew("$B/cfg/dev.example.test.cfg", "test=1\n");
($st) = raw($Pub, 'GET', '/snif-cert/dev.example.test.crt', 'dev.example.test');
check($st == 401, "a name with a cfg and no approval: 401: $st");
($st) = raw($Pub, 'GET', '/x', 'dev.example.test', { 'X-Test-Uri' => encode_base64("/snif-cert/dev.example.test\n.crt", '') });
check($st == 400, "the same name ending in a newline: 400, not a name: $st");
($st) = raw($Pub, 'GET', '/x', "dev.example.test", { 'X-Test-Uri' => encode_base64("/snif-cert/dev..example.test.crt", '') });
check($st == 400, "a name with an empty label: 400: $st");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
