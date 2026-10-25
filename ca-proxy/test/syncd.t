#!/usr/bin/perl
#
# snif-syncd across three nodes on one host (doc/cluster.md sections 3 to 7).
# Each node has its own CA proxy tree and daemon; a node's session to a peer
# runs "snif-syncd --serve" against the peer's socket instead of ssh.
#
#   perl ca-proxy/test/syncd.t [path/to/snif-syncd]
#
# Needs openssl (for the certificate class). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use FindBin;
use IO::Socket::UNIX;
use Socket;
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(time sleep);

my $syncd = shift || "$FindBin::Bin/../bin/snif-syncd";
$| = 1;
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

my $T = tempdir(CLEANUP => !$ENV{SYNCD_KEEP});
print "# tree $T
" if $ENV{SYNCD_KEEP};
my %Pid;
my $Set = 'Deadline=2 PingEvery=1 PingMiss=2 CSRLease=6 Margin=1 CSRWait=3 RetryDelay=0.3 BackoffMax=1 ScanEvery=2';

sub tree { "$T/$_[0]" }
sub env_for {
    my ($n, @peers) = @_;
    return (SNIF_CA_PROXY => tree($n), SNIF_CLUSTER_NODE => $n,
	SNIF_CLUSTER_PEERS => join(' ', map { "$_=" . tree($_) } @peers),
	SNIF_CLUSTER_PEER_CMD => "SNIF_CA_PROXY=%a exec $^X $syncd --serve %n",
	SNIF_SYNCD_SET => $Set, SNIF_SYNCD_STDERR => 1);
}
sub start {
    my ($n, @peers) = @_;
    make_path(map { tree($n) . "/$_" } qw(cfg csr auth crt apns log var arc));
    my $pid = fork;
    if (!$pid) {
	%ENV = (%ENV, env_for($n, @peers));
	open(STDERR, '>>', tree($n) . "/syncd.log");
	exec($^X, $syncd);
	exit 127;
    }
    $Pid{$n} = $pid;
    wait_for(sub { -S tree($n) . "/var/snif-syncd.sock" }, 5);
}
sub stop {
    my ($n) = @_;
    kill 'TERM', $Pid{$n} if $Pid{$n};
    waitpid($Pid{$n}, 0) if $Pid{$n};
    delete $Pid{$n};
    unlink tree($n) . "/var/snif-syncd.sock";
}
my $Main = $$;
END { kill 'TERM', values %Pid if %Pid && $$ == $Main }

sub wait_for {
    my ($f, $secs) = @_;
    my $until = time + $secs;
    while (time < $until) { return 1 if $f->(); sleep 0.1 }
    return $f->();
}

# ask <node> <request> [body]: the first reply line; for STATUS, all to END.
sub ask {
    my ($n, $req, $body) = @_;
    my $c = IO::Socket::UNIX->new(Peer => tree($n) . "/var/snif-syncd.sock", Type => SOCK_STREAM) || return "NOSOCK";
    print $c "$req\n", ($body // '');
    $c->flush;
    my $out = '';
    while (defined(my $l = <$c>)) {
	$out .= $l;
	last if $req ne 'STATUS' || $l eq "END\n";
    }
    close $c;
    chomp $out if $req ne 'STATUS';
    return $out;
}
# poke <node>: SYNC, which has no reply.
sub poke {
    my $c = IO::Socket::UNIX->new(Peer => tree($_[0]) . "/var/snif-syncd.sock", Type => SOCK_STREAM) || return;
    print $c "SYNC\n";
    close $c;
}
# A raw peer session into node $n, claiming to be $as.
sub peer_conn {
    my ($n, $as) = @_;
    my $c = IO::Socket::UNIX->new(Peer => tree($n) . "/var/snif-syncd.sock", Type => SOCK_STREAM);
    print $c "PEER $as\n";
    $c->flush;
    return $c;
}
sub peer_ask {
    my ($c, $req, $body) = @_;
    print $c "$req\n", ($body // '');
    $c->flush;
    my $l = <$c>;
    chomp $l if defined $l;
    return $l // 'EOF';
}
sub csr_req { my ($cn, $data) = @_; return ("CSR $cn " . length($data) . " " . sha256_hex($data), $data) }
sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew { my ($p, $d) = @_; (my $dir = $p) =~ s{/[^/]+$}{}; make_path($dir); open(my $f, '>', $p) || die "$p: $!"; print $f $d; close $f }
sub up_all { my ($n, @peers) = @_; wait_for(sub { my $s = ask($n, 'STATUS'); !grep { $s !~ /^peer $_ up /m } @peers }, 15) }
sub enqueue {
    my ($n, $peers, @rel) = @_;
    local %ENV = (%ENV, env_for($n, @$peers));
    system($^X, $syncd, 'enqueue', @rel);
}

start('a', 'b', 'c'); start('b', 'a', 'c'); start('c', 'a', 'b');
check(up_all('a', 'b', 'c') && up_all('b', 'a', 'c') && up_all('c', 'a', 'b'), "three nodes: every session is up");

# ---- CSRs ------------------------------------------------------------------
my $csr1 = "-----BEGIN CERTIFICATE REQUEST-----\none\n-----END CERTIFICATE REQUEST-----\n";
my $csr2 = "-----BEGIN CERTIFICATE REQUEST-----\ntwo\n-----END CERTIFICATE REQUEST-----\n";
my $r = ask('a', csr_req('snif-1.x.test', $csr1));
check($r eq 'STORED' && !grep({ (slurp(tree($_) . "/csr/snif-1.x.test.csr") // '') ne $csr1 } qw(a b c)),
    "a CSR accepted on a is on a, b and c when a answers ($r)");
$r = ask('a', csr_req('snif-1.x.test', $csr1));
check($r eq 'SAME', "the same CSR again: SAME ($r)");
$r = ask('c', csr_req('snif-1.x.test', $csr2));
check($r eq 'DIFFERENT', "a different CSR for the name on c: DIFFERENT ($r)");

# Different CSRs for one name on all three nodes at once.
{
    my (%kid, @kids);
    foreach my $n (qw(a b c)) {
	pipe(my $rd, my $wr);
	my $pid = fork;
	push @kids, $pid;
	if (!$pid) { close $rd; print $wr ask($n, csr_req('snif-2.x.test', "CSR from $n\n" x 4)); exit 0 }
	close $wr;
	$kid{$n} = $rd;
    }
    my %ans = map { my $fh = $kid{$_}; ($_ => scalar(<$fh>) // '') } qw(a b c);
    waitpid($_, 0) foreach @kids;
    my @stored = grep { $ans{$_} eq 'STORED' } qw(a b c);
    my @have = map { slurp(tree($_) . "/csr/snif-2.x.test.csr") // '' } qw(a b c);
    my %distinct = map { $_ => 1 } grep { length } @have;
    check(@stored <= 1 && keys(%distinct) <= 1,
	"different CSRs for one name on three nodes at once: at most one accepted, no split (" . join(', ', map { "$_=$ans{$_}" } qw(a b c)) . ")");
}

# ---- the queue and the classes -----------------------------------------------
spew(tree('a') . "/cfg/snif-3.x.test.cfg", "k=v\n");
utime(1_700_000_000, 1_700_000_000, tree('a') . "/cfg/snif-3.x.test.cfg");
enqueue('a', ['b', 'c'], 'cfg/snif-3.x.test.cfg');
check(wait_for(sub { !grep({ (slurp(tree($_) . "/cfg/snif-3.x.test.cfg") // '') ne "k=v\n" } qw(b c)) }, 10),
    "an enqueued cfg reaches b and c");
check(!grep({ (stat(tree($_) . "/cfg/snif-3.x.test.cfg"))[9] != 1_700_000_000 } qw(b c)), "with its modification time");
check(wait_for(sub { !-l tree('a') . "/sync-queue/b/cfg/snif-3.x.test.cfg" && !-l tree('a') . "/sync-queue/c/cfg/snif-3.x.test.cfg" }, 5),
    "and the queue entries are gone");

spew(tree('b') . "/cfg/snif-3.x.test.cfg", "other\n");
spew(tree('a') . "/cfg/snif-3.x.test.cfg", "k=v\n");
enqueue('a', ['b', 'c'], 'cfg/snif-3.x.test.cfg');
sleep 1.5;
check((slurp(tree('b') . "/cfg/snif-3.x.test.cfg") // '') eq "other\n", "a once-file that differs is kept, not overwritten");
check(scalar(ask('b', 'STATUS') =~ m{^conflict cfg/snif-3\.x\.test\.cfg from a$}m), "and reported as a conflict");

# Certificates: the later notAfter wins on every node, and clears the .err.
{
    my $mk = sub {
	my ($days, $out) = @_;
	system("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days $days -subj /CN=t -keyout $T/k.pem -out $out 2>/dev/null");
	return slurp($out);
    };
    my $short = $mk->(10, "$T/short.pem");
    my $long = $mk->(80, "$T/long.pem");
    spew(tree('a') . "/crt/snif-4.x.test.crt", $long);
    spew(tree('b') . "/crt/snif-4.x.test.crt", $short);
    spew(tree('b') . "/crt/snif-4.x.test.err", "old error\n");
    enqueue('b', ['a', 'c'], 'crt/snif-4.x.test.crt');
    enqueue('a', ['b', 'c'], 'crt/snif-4.x.test.crt');
    check(wait_for(sub { !grep({ (slurp(tree($_) . "/crt/snif-4.x.test.crt") // '') ne $long } qw(a b c)) }, 10),
	"the certificate with the later notAfter ends up on every node");
    check(!-e tree('b') . "/crt/snif-4.x.test.err", "and installing it removed the .err");
}

# Counters, and what a peer may PUT.
{
    spew(tree('a') . "/auth/ves/a/user\@example.com", "**");
    enqueue('a', ['b', 'c'], 'auth/ves/a/user@example.com');
    check(wait_for(sub { (slurp(tree('c') . "/auth/ves/a/user\@example.com") // '') eq "**" }, 10), "a counter file reaches the other nodes");
    my $pc = peer_conn('a', 'b');
    my $d = "*";
    my $put = sub { "PUT $_[0] " . length($d) . " " . int(time) . " " . sha256_hex($d) };
    check(peer_ask($pc, $put->('auth/ves/c/x@example.com'), $d) eq 'REJECT node', "a counter file of c, sent by b: REJECT node");
    check(peer_ask($pc, $put->('csr/snif-9.x.test.csr'), $d) eq 'REJECT csr', "a csr/ path by PUT: REJECT csr");
    check(peer_ask($pc, $put->('etc/account.key'), $d) eq 'REJECT path', "an etc/ path: REJECT path");
    check(peer_ask($pc, $put->('cfg/../etc/x.cfg'), $d) eq 'REJECT path', "a path with ..: REJECT path");
    close $pc;
    my $nc = peer_conn('a', 'zz');
    check(peer_ask($nc, "LEASE crt:snif-1.x.test 60") eq 'REJECT member', "a node a does not list: LEASE gets REJECT member");
    check(scalar(peer_ask($nc, "GET cfg/snif-3.x.test.cfg") =~ /^DATA 4 /), "and GET is answered");
    close $nc;
}

# ---- leases and FETCH ----------------------------------------------------------
{
    my $l1 = IO::Socket::UNIX->new(Peer => tree('a') . "/var/snif-syncd.sock", Type => SOCK_STREAM);
    print $l1 "LEASE snif-5.x.test\n"; $l1->flush;
    my $g = <$l1>; chomp $g;
    check($g eq 'GRANTED', "a certificate lease on a: GRANTED ($g)");
    $r = ask('b', 'LEASE snif-5.x.test');
    check($r eq 'HELD', "the same lease on b while a holds it: HELD ($r)");
    close $l1;	# the lease ends with the connection that took it
    check(wait_for(sub { ask('b', 'LEASE snif-5.x.test') eq 'GRANTED' }, 5), "after a's connection closes, b gets it");
}
spew(tree('b') . "/cfg/snif-6.x.test.cfg", "only on b\n");
$r = ask('a', 'FETCH cfg/snif-6.x.test.cfg');
check($r eq 'FOUND' && (slurp(tree('a') . "/cfg/snif-6.x.test.cfg") // '') eq "only on b\n", "FETCH a cfg only b has: FOUND, installed on a ($r)");
$r = ask('a', 'FETCH cfg/snif-nosuch.x.test.cfg');
check($r eq 'NONE', "FETCH a cfg nobody has: NONE ($r)");

# ---- reconciliation ------------------------------------------------------------
spew(tree('b') . "/cfg/snif-7.x.test.cfg", "seven\n");
spew(tree('b') . "/csr/snif-7.x.test.csr", $csr1);
spew(tree('a') . "/auth/snif-7.x.test.auth", "user\@example.com");
$r = ask('a', 'RECONCILE');
check(scalar($r =~ /^OK /), "RECONCILE on a: $r");
check((slurp(tree('a') . "/cfg/snif-7.x.test.cfg") // '') eq "seven\n" && (slurp(tree('a') . "/csr/snif-7.x.test.csr") // '') eq $csr1,
    "a pulled b's cfg and CSR");
check(wait_for(sub { !grep({ (slurp(tree($_) . "/auth/snif-7.x.test.auth") // '') ne "user\@example.com" } qw(b c)) }, 10),
    "and pushed its auth file to b and c");
check((slurp(tree('c') . "/csr/snif-7.x.test.csr") // '') eq $csr1, "the CSR a lacked went to c too, under the lease");

# ---- lease rules seen by a peer ---------------------------------------------------
{
    my $pb = peer_conn('a', 'b');
    check(peer_ask($pb, (csr_req('snif-11.x.test', $csr1))[0], $csr1) eq 'REJECT lease', "a CSR from b with no lease: REJECT lease");
    check(peer_ask($pb, "LEASE csr:snif-11.x.test 1") eq 'GRANTED', "b takes a 1 s CSR lease on a");
    sleep 1.5;
    check(peer_ask($pb, (csr_req('snif-11.x.test', $csr1))[0], $csr1) eq 'REJECT lease', "b's CSR arriving after the lease ended: REJECT lease");
    check(!-e tree('a') . "/csr/snif-11.x.test.csr", "and nothing is stored");
    check(peer_ask($pb, "LEASE csr:snif-12.x.test 60") eq 'GRANTED', "b takes a lease on a");
    my $pc = peer_conn('a', 'c');
    check(peer_ask($pc, "LEASE csr:snif-12.x.test 60") eq 'HELD', "c asks a for the lease a granted to b: HELD");
    check(peer_ask($pc, (csr_req('snif-12.x.test', $csr2))[0], $csr2) eq 'REJECT lease', "and c's CSR under it: REJECT lease");
    close $pc;
    check(peer_ask($pb, "RELEASE csr:snif-12.x.test") eq 'OK', "b releases it");
    close $pb;
}

# Simultaneous certificate leases on three nodes: never two holders, and no
# grant is left behind.
{
    my (%kid, @kids);
    foreach my $n (qw(a b c)) {
	pipe(my $rd, my $wr);
	my $pid = fork;
	push @kids, $pid;
	if (!$pid) {
	    close $rd;
	    my $c = IO::Socket::UNIX->new(Peer => tree($n) . "/var/snif-syncd.sock", Type => SOCK_STREAM);
	    print $c "LEASE snif-13.x.test\n"; $c->flush;
	    my $l = <$c> // ''; chomp $l;
	    print $wr $l; close $wr;
	    sleep 1;	# hold it a moment, then the connection closes and releases it
	    exit 0;
	}
	close $wr;
	$kid{$n} = $rd;
    }
    my %ans = map { my $fh = $kid{$_}; ($_ => scalar(<$fh>) // '') } qw(a b c);
    waitpid($_, 0) foreach @kids;
    my $holders = grep { $ans{$_} eq 'GRANTED' } qw(a b c);
    check($holders <= 1 && !grep({ $ans{$_} !~ /^(GRANTED|HELD)$/ } qw(a b c)),
	"three certificate leases at once: at most one GRANTED (" . join(', ', map { "$_=$ans{$_}" } qw(a b c)) . ")");
    check(wait_for(sub { !grep({ ask($_, 'STATUS') !~ /^held 0 granted 0$/m } qw(a b c)) }, 5),
	"afterwards no node holds or has granted it");
    check(ask('b', 'LEASE snif-13.x.test') eq 'GRANTED', "and it can be taken again");
}

# ENSURE: a CSR only a holds reaches b and c.
spew(tree('a') . "/csr/snif-14.x.test.csr", $csr2);
$r = ask('a', 'ENSURE snif-14.x.test');
check($r eq 'STORED' && !grep({ (slurp(tree($_) . "/csr/snif-14.x.test.csr") // '') ne $csr2 } qw(b c)), "ENSURE sends a's CSR to b and c ($r)");

# The queue: a dangling entry is dropped; a claimed entry survives a restart.
{
    make_path(tree('a') . "/sync-queue/b/cfg");
    symlink(tree('a') . "/cfg/snif-gone.x.test.cfg", tree('a') . "/sync-queue/b/cfg/snif-gone.x.test.cfg");
    poke('a');
    check(wait_for(sub { !-l tree('a') . "/sync-queue/b/cfg/snif-gone.x.test.cfg" }, 5), "a dangling queue entry is dropped");
    check(scalar(slurp(tree('a') . "/syncd.log") =~ /snif-gone\.x\.test\.cfg is gone, dropped/), "and logged");
    stop('a');
    spew(tree('a') . "/cfg/snif-15.x.test.cfg", "fifteen\n");
    make_path(tree('a') . "/sync-queue/b/.inflight/cfg");
    symlink(tree('a') . "/cfg/snif-15.x.test.cfg", tree('a') . "/sync-queue/b/.inflight/cfg/snif-15.x.test.cfg");
    start('a', 'b', 'c');
    check(wait_for(sub { (slurp(tree('b') . "/cfg/snif-15.x.test.cfg") // '') eq "fifteen\n" }, 10), "an entry claimed before a restart is sent after it");
    check(up_all('a', 'b', 'c'), "a is back up");
}

# A grant does not survive a restart of the node that gave it.
{
    my $pb = peer_conn('c', 'b');
    check(peer_ask($pb, "LEASE csr:snif-16.x.test 60") eq 'GRANTED', "b takes a lease on c");
    close $pb;
    stop('c'); start('c', 'a', 'b');
    $pb = peer_conn('c', 'b');
    check(peer_ask($pb, (csr_req('snif-16.x.test', $csr1))[0], $csr1) eq 'REJECT lease', "after c restarts, b's CSR under that lease: REJECT lease");
    close $pb;
    up_all('a', 'b', 'c'); up_all('c', 'a', 'b');
}

# newest: the later modification time wins.
{
    spew(tree('a') . "/apns/_abc.x.test.apns", "old-token");
    utime(1_700_000_000, 1_700_000_000, tree('a') . "/apns/_abc.x.test.apns");
    spew(tree('b') . "/apns/_abc.x.test.apns", "new-token");
    enqueue('a', ['b', 'c'], 'apns/_abc.x.test.apns');
    enqueue('b', ['a', 'c'], 'apns/_abc.x.test.apns');
    check(wait_for(sub { !grep({ (slurp(tree($_) . "/apns/_abc.x.test.apns") // '') ne "new-token" } qw(a b c)) }, 10),
	"a wake token: the newer one ends up on every node");
}

# ---- a node down, eviction, a node rejoining -------------------------------------
stop('c');
check(wait_for(sub { ask('a', 'STATUS') =~ /^peer c down /m }, 6), "c stopped: a marks it down");
my $t0 = time;
$r = ask('a', csr_req('snif-8.x.test', $csr1));
check($r eq 'UNREACHABLE' && time - $t0 < 1.5 && !-e tree('a') . "/csr/snif-8.x.test.csr" && !-e tree('b') . "/csr/snif-8.x.test.csr",
    "a CSR with c down: UNREACHABLE at once, stored nowhere ($r)");
$r = ask('a', 'LEASE snif-8.x.test');
check($r eq 'ALONE', "a certificate lease with c down: ALONE ($r)");
$r = ask('a', 'ENSURE snif-1.x.test');
check($r eq 'UNREACHABLE', "ENSURE with c down: UNREACHABLE ($r)");
$r = ask('a', 'FETCH cfg/snif-nosuch.x.test.cfg');
check($r eq 'UNREACHABLE', "FETCH a cfg b lacks, with c down: UNREACHABLE ($r)");

stop('a'); start('a', 'b'); stop('b'); start('b', 'a');
check(up_all('a', 'b') && up_all('b', 'a'), "c evicted on a and b");
$r = ask('a', csr_req('snif-8.x.test', $csr1));
check($r eq 'STORED' && (slurp(tree('b') . "/csr/snif-8.x.test.csr") // '') eq $csr1, "a and b accept without c ($r)");
start('c', 'a', 'b');
sleep 2;
$r = ask('c', csr_req('snif-10.x.test', $csr1));
check($r eq 'UNREACHABLE' && !-e tree('c') . "/csr/snif-10.x.test.csr", "the evicted c, back up, accepts nothing ($r)");

# Seeding a new node d, listed by nobody yet.
start('d', 'a', 'b');
check(up_all('d', 'a', 'b'), "d's sessions to a and b are up");
$r = ask('d', 'SEED a');
check(scalar($r =~ /^OK /) && !grep({ !-e tree('d') . "/$_" } qw(csr/snif-1.x.test.csr csr/snif-8.x.test.csr cfg/snif-3.x.test.cfg crt/snif-4.x.test.crt)),
    "SEED a copies a's state to d ($r)");

# A crt/ that is a link, as in a tree from the initial release (crt ->
# public_html/snif-cert): LIST and reconciliation still see what it holds.
{
    my $e = tree('e');
    make_path("$e/public_html/snif-cert");
    symlink("$e/public_html/snif-cert", "$e/crt");
    spew("$e/public_html/snif-cert/snif-11.x.test.crt", slurp("$T/long.pem"));
    local $ENV{SNIF_CA_PROXY} = $e;
    open(my $p, '-|', $^X, '-e', 'do $ARGV[0] or die $@ || $!; print map { "$_->[0]\n" } main::list_local("crt")', $syncd) || die "$^X: $!";
    my $out = do { local $/; <$p> } // '';
    close $p;
    check($out eq "crt/snif-11.x.test.crt\n", "LIST crt follows a crt/ that is a link (" . join(' ', split(/\n/, $out)) . ")");
}

if ($fail) {
    foreach my $n (sort grep { -e tree($_) . "/syncd.log" } qw(a b c d)) {
	print "\n---- $n: last lines of syncd.log\n";
	my @l = split(/\n/, slurp(tree($n) . "/syncd.log") // '');
	print map { "$_\n" } @l[($#l > 25 ? $#l - 25 : 0) .. $#l];
    }
}
print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
