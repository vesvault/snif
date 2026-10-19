#!/usr/bin/perl
#
# A two-node CA proxy cluster end to end, on one host (doc/cluster.md): for
# each node a CA proxy tree with the PHP served by "php -S", snif-certd issuing
# from a throwaway local CA (no network), and snif-syncd. Enrols a device
# across the two nodes, then checks that neither node accepts a CSR alone when
# a snif-syncd is down, and that a tree without etc/cluster.node behaves as a
# single relay always has.
#
#   perl ca-proxy/test/cluster.t
#
# Needs php (cli), curl and openssl. Uses ports 31101-31104 and 31201-31202 on
# 127.0.0.1. Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Copy qw(copy);
use FindBin;
use Time::HiRes qw(time sleep);
$| = 1;

my $Src = "$FindBin::Bin/..";
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

my $T = tempdir(CLEANUP => !$ENV{CLUSTER_KEEP});
print "# tree $T\n" if $ENV{CLUSTER_KEEP};
my $Main = $$;
my %Pid;
END { kill 'TERM', map { @$_ } values %Pid if %Pid && $$ == $Main }

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew { my ($p, $d) = @_; open(my $f, '>', $p) || die "$p: $!"; print $f $d; close $f }
sub wait_for { my ($f, $s) = @_; my $u = time + $s; while (time < $u) { return 1 if $f->(); sleep 0.2 } return $f->() }
sub spawn {
    my ($node, $log, %env) = @_;
    my $pid = fork;
    if (!$pid) {
	%ENV = (%ENV, %env);
	open(STDOUT, '>>', $log); open(STDERR, '>>', $log);
	exec(@{$env{_CMD}});
	exit 127;
    }
    push @{$Pid{$node}}, $pid;
    return $pid;
}

# The throwaway local CA, the same on both nodes (etc/ secrets are per node).
system("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=test-ca "
    . "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign "
    . "-keyout $T/ca.key -out $T/ca.pem 2>/dev/null") == 0 || die "openssl: CA";

my %Port = (a => [31101, 31102], b => [31103, 31104], s => [31201, 31202]);

sub tree {
    my ($n, $cluster, @peers) = @_;
    my $d = "$T/$n";
    make_path(map { "$d/$_" } qw(cfg csr auth crt apns log var arc etc sync-queue));
    system("cp -R $Src/public_html $Src/secure_html $Src/inc $d/");
    spew("$d/etc/init.test.domains", "lca.test\n");
    copy("$T/ca.pem", "$d/etc/lca.test.pub-ca");
    copy("$T/ca.key", "$d/etc/lca.test.priv-ca");
    spew("$d/etc/cluster.node", "$n\n") if $cluster;
    system("mkfifo $d/var/snif-certd.ctl");
    # php -S has no .htaccess: route /snif-cert/<cn>.csr|.crt like public_html/snif-cert/.htaccess
    spew("$d/public_html/router.php", "<?php\nif (preg_match('#^/snif-cert/#', \$_SERVER['REQUEST_URI'])) { require __DIR__ . '/snif-cert.php'; return true; }\nreturn false;\n");
    return $d;
}
sub start_php {
    my ($n, $d, $pub, $sec) = @_;
    spawn($n, "$d/php.log", _CMD => ['php', '-S', "127.0.0.1:$pub", '-t', "$d/public_html", "$d/public_html/router.php"]);
    spawn($n, "$d/php.log", _CMD => ['php', '-S', "127.0.0.1:$sec", '-t', "$d/secure_html"]);
}
sub start_certd { my ($n, $d) = @_; spawn($n, "$d/certd.out", SNIF_CA_PROXY => $d, _CMD => [$^X, "$Src/bin/snif-certd"]) }
sub start_syncd {
    my ($n, $d, @peers) = @_;
    my $pid = spawn("syncd-$n", "$d/syncd.log", SNIF_CA_PROXY => $d, SNIF_CLUSTER_NODE => $n,
	SNIF_CLUSTER_PEERS => join(' ', map { "$_=$T/$_" } @peers),
	SNIF_CLUSTER_PEER_CMD => "SNIF_CA_PROXY=%a exec $^X $Src/bin/snif-syncd --serve %n",
	SNIF_SYNCD_SET => 'Deadline=2 PingEvery=1 PingMiss=2 BackoffMax=1 ScanEvery=2', SNIF_SYNCD_STDERR => 1,
	_CMD => [$^X, "$Src/bin/snif-syncd"]);
    wait_for(sub { -S "$d/var/snif-syncd.sock" }, 5);
}
sub stop_syncd { my ($n) = @_; kill 'TERM', @{delete $Pid{"syncd-$n"} || []}; sleep 0.5 }
sub up { my ($n, $p) = @_; wait_for(sub { `SNIF_CA_PROXY=$T/$n $^X $Src/bin/snif-syncd status 2>/dev/null` =~ /^peer $p up /m }, 15) }

# curl: (status, body, headers)
sub http {
    my ($method, $url, $host, $file) = @_;
    my $cmd = "curl -s -m 20 -o $T/body -D $T/hdrs -w '%{http_code}' -X $method -H 'Host: $host'"
	. ($file ? " --data-binary \@$file" : '') . " '$url'";
    my $code = `$cmd`;
    return ($code, slurp("$T/body") // '', slurp("$T/hdrs") // '');
}
sub csr_for {
    my ($cn, $tag) = @_;
    system("openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=*.$cn' -keyout $T/$tag.key -out $T/$tag.csr 2>/dev/null");
    return "$T/$tag.csr";
}

my $A = tree('a', 1); my $B = tree('b', 1);
start_syncd('a', $A, 'b'); start_syncd('b', $B, 'a');
start_php('a', $A, @{$Port{a}}); start_php('b', $B, @{$Port{b}});
start_certd('a', $A); start_certd('b', $B);
sleep 1;
check(up('a', 'b') && up('b', 'a'), "both snif-syncd sessions are up");

# 1. Allocate on a.
my ($code, $body) = http('GET', "http://127.0.0.1:$Port{a}[1]/snif-auth.php", 'init.test');
(my $cn = $body) =~ s/^\*\.|\s+$//g;
check($code eq '200' && $cn =~ /^snif-[0-9a-f]{12}-[0-9a-f]{8}\.lca\.test$/, "a allocates a name ($code $cn)");
check(wait_for(sub { -e "$B/cfg/$cn.cfg" }, 10), "its cfg reaches b");

# 2. The CSR, PUT on b.
my $csr = csr_for($cn, 'dev');
($code, undef, my $hdrs) = http('PUT', "http://127.0.0.1:$Port{b}[0]/snif-cert/$cn.csr", $cn, $csr);
check($code eq '201' && (slurp("$A/csr/$cn.csr") // '') eq slurp($csr) && (slurp("$B/csr/$cn.csr") // '') eq slurp($csr),
    "a CSR PUT on b: 201, stored on both ($code)");
($code) = http('PUT', "http://127.0.0.1:$Port{a}[0]/snif-cert/$cn.csr", $cn, $csr);
check($code eq '201', "the same CSR again, on a: 201 ($code)");
my $csr2 = csr_for($cn, 'other');
($code) = http('PUT', "http://127.0.0.1:$Port{a}[0]/snif-cert/$cn.csr", $cn, $csr2);
check($code eq '403', "a different CSR for the name: 403 ($code)");

# 3. A name allocated on b but not yet on a: a fetches its cfg before answering.
($code, $body) = http('GET', "http://127.0.0.1:$Port{b}[1]/snif-auth.php", 'init.test');
(my $cn2 = $body) =~ s/^\*\.|\s+$//g;
unlink "$A/cfg/$cn2.cfg";	# as if it had not arrived yet
my $csr3 = csr_for($cn2, 'dev2');
($code) = http('PUT', "http://127.0.0.1:$Port{a}[0]/snif-cert/$cn2.csr", $cn2, $csr3);
check($code eq '201' && -e "$A/cfg/$cn2.cfg", "a CSR on a for a name allocated on b: a fetches the cfg, 201 ($code)");

# 4. Approval: found on a by b through FETCH.
spew("$A/auth/$cn.auth", "user\@example.com");
($code) = http('GET', "http://127.0.0.1:$Port{b}[1]/snif-auth.php/$cn", 'init.test');
check($code eq '202' && -e "$B/auth/$cn.auth", "approved on a: b's authorization page fetches it, 202 ($code)");

# 5. The first certificate, requested on b: ENSURE, lease, issue, sync to a.
my $crt;
wait_for(sub { ($code, $crt) = http('GET', "http://127.0.0.1:$Port{b}[0]/snif-cert/$cn.crt", $cn); $code eq '200' }, 20);
check($code eq '200' && $crt =~ /BEGIN CERTIFICATE/, "b issues the certificate ($code)");
check(wait_for(sub { (slurp("$A/crt/$cn.crt") // '') eq $crt }, 10), "and it reaches a");
($code, my $crta) = http('GET', "http://127.0.0.1:$Port{a}[0]/snif-cert/$cn.crt", $cn);
check($code eq '200' && $crta eq $crt, "a serves the same certificate");
my $subj = `openssl x509 -noout -subject -in $A/crt/$cn.crt 2>/dev/null`;
check(scalar($subj =~ /\*\.\Q$cn\E/), "for *.$cn");

# 6. Neither node accepts a CSR alone.
($code, $body) = http('GET', "http://127.0.0.1:$Port{b}[1]/snif-auth.php", 'init.test');
(my $cn3 = $body) =~ s/^\*\.|\s+$//g;
wait_for(sub { -e "$A/cfg/$cn3.cfg" }, 10);
stop_syncd('a');
my $csr4 = csr_for($cn3, 'dev3');
($code) = http('PUT', "http://127.0.0.1:$Port{b}[0]/snif-cert/$cn3.csr", $cn3, $csr4);
check($code eq '503' && !-e "$B/csr/$cn3.csr", "a's snif-syncd down: a CSR on b gets 503, stored nowhere ($code)");
($code) = http('PUT', "http://127.0.0.1:$Port{a}[0]/snif-cert/$cn3.csr", $cn3, $csr4);
check($code eq '503' && !-e "$A/csr/$cn3.csr", "and on a itself, with its own snif-syncd down: 503 ($code)");
start_syncd('a', $A, 'b');
check(up('a', 'b') && up('b', 'a'), "a's snif-syncd back");
($code) = http('PUT', "http://127.0.0.1:$Port{b}[0]/snif-cert/$cn3.csr", $cn3, $csr4);
check($code eq '201', "then the CSR is accepted ($code)");

# 7. A single relay: no etc/cluster.node, no snif-syncd.
my $S = tree('s', 0);
start_php('s', $S, @{$Port{s}});
sleep 1;
($code, $body) = http('GET', "http://127.0.0.1:$Port{s}[1]/snif-auth.php", 'init.test');
(my $cn5 = $body) =~ s/^\*\.|\s+$//g;
my $csr5 = csr_for($cn5, 'dev5');
($code) = http('PUT', "http://127.0.0.1:$Port{s}[0]/snif-cert/$cn5.csr", $cn5, $csr5);
my ($code2) = http('PUT', "http://127.0.0.1:$Port{s}[0]/snif-cert/$cn5.csr", $cn5, $csr5);
check($code eq '201' && $code2 eq '403' && !-d "$S/sync-queue/b", "a single relay: 201, then 403 for a repeat, as before ($code, $code2)");

if ($fail) {
    foreach my $f (map { ("$T/$_/syncd.log", "$T/$_/log/log_snif-certd", "$T/$_/php.log") } qw(a b)) {
	next if !-e $f;
	print "\n---- $f\n";
	my @l = split(/\n/, slurp($f));
	print map { "$_\n" } @l[($#l > 15 ? $#l - 15 : 0) .. $#l];
    }
}
print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
