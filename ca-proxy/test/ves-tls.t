#!/usr/bin/perl
#
# The approval by VES asks VESapi who created the vault item it names
# (inc/snif-auth-ves.php, ves_api_req() and snif_auth_ves()). That answer
# decides the approval, so the connection must check VESapi's certificate:
# its chain and its name (before 1.17, verify_peer_name was off, and a
# certificate for any name passed). Run by the PHP CLI against a TLS
# stand-in on 127.0.0.1, under a test CA, so no request leaves the host:
#   - a certificate for api.ves.host from the CA: the request goes out with
#     the Host and the bearer token, and its answer is used;
#   - one for another name from the same CA, a self-signed one for
#     api.ves.host, and no server at all: no request is sent, ves_api_req()
#     is NULL with status 0, nothing fatal;
#   - snif_auth_ves(): approved, and counted, only through the first; the
#     others answer 403 (it exits) and count nothing.
#
#   perl ca-proxy/test/ves-tls.t [path/to/ca-proxy]
#
# Needs php (cli) and openssl. Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
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
die "ves-tls.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;
die "ves-tls.t: needs openssl\n" if system('openssl version > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{VES_TLS_KEEP});
print "# tree $T\n" if $ENV{VES_TLS_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}
sub sh { my $c = shift; system("$c > '$T/sh.log' 2>&1") == 0 or die "ves-tls.t: $c\n" . (slurp("$T/sh.log") // '') }

# ---- certificates ------------------------------------------------------------

my $EC = '-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes';
sh("openssl req -x509 $EC -keyout '$T/ca.key' -out '$T/ca.crt' -days 2 -subj /CN=snif-ves-tls-test-ca");
# A certificate for $name from the test CA.
sub leaf {
    my ($name) = @_;
    spew("$T/$name.ext", "subjectAltName=DNS:$name\n");
    sh("openssl req $EC -keyout '$T/$name.key' -out '$T/$name.csr' -subj /CN=$name");
    sh("openssl x509 -req -in '$T/$name.csr' -CA '$T/ca.crt' -CAkey '$T/ca.key' -CAcreateserial"
       . " -days 2 -extfile '$T/$name.ext' -out '$T/$name.crt'");
}
leaf('api.ves.host');
leaf('other.example');
sh("openssl req -x509 $EC -keyout '$T/self.key' -out '$T/self.crt' -days 2 -subj /CN=api.ves.host"
   . " -addext subjectAltName=DNS:api.ves.host");

# ---- the stand-in ------------------------------------------------------------

# Answers each request with the creator's email, and writes down each
# request it received. A handshake the client gives up is not a request, nor
# is a connection it closes unused: PHP checks the certificate's name once
# the handshake is done, and then closes without sending.
spew("$T/stand.php", <<'EOF');
<?php
$ctx = stream_context_create(['ssl' => ['local_cert' => $argv[2], 'local_pk' => $argv[3]]]);
$s = stream_socket_server("tls://127.0.0.1:$argv[1]", $en, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if (!$s) { fwrite(STDERR, "stand: $es\n"); exit(1); }
for (;;) {
    $c = @stream_socket_accept($s, -1);
    if (!$c) continue;
    $req = '';
    while (($l = fgets($c)) !== false) { $req .= $l; if ($l === "\r\n") break; }
    if ($req === '') { fclose($c); continue; }
    file_put_contents($argv[4], "== request\n$req", FILE_APPEND);
    fwrite($c, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"
	. '{"result":{"file":{"creator":{"email":"tls-test@example.test"}}}}');
    fclose($c);
}
EOF

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) || die "port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}
my @Pids;
END { kill('TERM', @Pids) if @Pids; }
# A stand-in serving $cert; its port.
sub stand {
    my ($cert, $log) = @_;
    my $port = free_port();
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
	open(STDOUT, '>', "$log.out");
	open(STDERR, '>&', \*STDOUT);
	exec('php', '-d', 'display_errors=stderr', "$T/stand.php", $port, "$T/$cert.crt", "$T/$cert.key", $log);
	exit 127;
    }
    push @Pids, $pid;
    for (1 .. 100) {
	my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port, Timeout => 1);
	if ($c) { close $c; return $port; }
	sleep 0.05;
    }
    die "ves-tls.t: the stand-in for $cert did not start: " . (slurp("$log.out") // '') . "\n";
}

# ---- the client --------------------------------------------------------------

# 'req' calls ves_api_req(); 'auth' calls snif_auth_ves() with an
# X-VES-Authorization header, and says "exited" if it exits (its 403 and 429).
spew("$T/drv.php", <<'EOF');
<?php
$_SERVER['DOCUMENT_ROOT'] = $argv[1] . '/secure_html';
require $argv[2] . '/inc/snif-cluster.php';
require $argv[2] . '/inc/snif-auth-ves.php';
$VESapiAddr = $argv[3];
$VESapiCAFile = $argv[4];
if ($argv[5] === 'req') {
    $rs = ves_api_req('GET', 'vaultItems/77?fields=file(creator(email))', ['Authorization: Bearer tok-77']);
    echo $rs ? 'ok ' . $rs->file->creator->email : 'null ' . $GLOBALS['api_req_status'], "\n";
} else {
    $_SERVER['HTTP_X_VES_AUTHORIZATION'] = 'vaultItem.77.tok-77';
    $done = false;
    register_shutdown_function(function () use (&$done) { if (!$done) echo "exited\n"; });
    $e = snif_auth_ves();
    $done = true;
    echo "approved $e\n";
}
EOF

my $B = "$T/tree";
make_path("$B/secure_html", "$B/auth/ves", "$B/etc");
# The exit status, stdout and stderr of the client.
sub client {
    my ($addr, $mode) = @_;
    my $out = `php -d display_errors=stderr -d log_errors=1 -d error_log='$T/php-err' '$T/drv.php' '$B' '$Src' '$addr' '$T/ca.crt' '$mode' 2> '$T/err'`;
    my $rc = $? >> 8;
    my $err = slurp("$T/err") // '';
    s/\s+\z// for $out, $err;
    return ($rc, $out, $err);
}
sub fatal { $_[0] =~ /Fatal|Uncaught|TypeError/ }
my $Counter = "$B/auth/ves/tls-test\@example.test";

# ---- api.ves.host, from the CA: accepted -------------------------------------

my $log = "$T/good.log";
my $port = stand('api.ves.host', $log);
my ($rc, $out, $err) = client("127.0.0.1:$port", 'req');
check($rc == 0 && $out eq 'ok tls-test@example.test', "a certificate for api.ves.host from a trusted CA: the answer is used: '$out'");
my $got = slurp($log) // '';
check($got =~ m{^GET /v1/vaultItems/77\?fields=file\(creator\(email\)\) HTTP/1\.0\r$}m, 'the request reached it');
check($got =~ /^Host: api\.ves\.host\r$/m && $got =~ /^Authorization: Bearer tok-77\r$/m, 'with the Host and the bearer token');
($rc, $out, $err) = client("127.0.0.1:$port", 'auth');
check($out eq 'approved tls-test@example.test', "snif_auth_ves() approves through it: '$out'");
check((slurp($Counter) // '') =~ /^\d+\n\z/, 'and counts the approval');
unlink $Counter;

# ---- refused -----------------------------------------------------------------

for my $c (['other.example', 'a certificate for another name, from the same CA'],
	   ['self', 'a self-signed certificate for api.ves.host']) {
    my ($cert, $what) = @$c;
    my $l = "$T/$cert.log";
    my $p = stand($cert, $l);
    ($rc, $out, $err) = client("127.0.0.1:$p", 'req');
    check($out eq 'null 0' && !fatal($err), "$what: refused, NULL with status 0: '$out'");
    check((slurp($l) // '') !~ /== request|tok-77/, "$what: no request sent, the token not with it");
    ($rc, $out, $err) = client("127.0.0.1:$p", 'auth');
    check($out eq 'exited' && !fatal($err), "$what: snif_auth_ves() answers 403: '$out'");
    check(!-e $Counter, "$what: nothing counted");
}

my $closed = free_port();
($rc, $out, $err) = client("127.0.0.1:$closed", 'req');
check($out eq 'null 0' && !fatal($err), "no server: NULL with status 0, nothing fatal: '$out'");
check((slurp("$T/php-err") // '') =~ /snif-auth-ves: no VESapi connection/, 'and the reason is logged');

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
