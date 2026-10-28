#!/usr/bin/perl
#
# snif-syncd with a judge (doc/cluster.md section 5.1): two nodes on one host
# and a throwaway named as the judge. A CSR needs two votes of three: the
# node's own, its peer's and the judge's. Checks that both nodes up never ask
# the judge; that with the peer down the judge's record decides and the CSR is
# queued for the peer; that two nodes cut off from each other accept exactly
# one of two CSRs for a name; that a node back after missing a CSR refuses
# another one; that an answer whose signature does not verify counts for
# nothing; and that without SNIF_CLUSTER_JUDGE nothing changes.
#
#   perl ca-proxy/test/judge.t [path/to/snif-syncd]
#
# Needs Net::DNS, named (copied, because its AppArmor profile admits only
# /etc/bind), tsig-keygen and dig. Uses ports 31301-31302 on 127.0.0.1.
# Exits non-zero if any check fails; skips, exit 0, without the tools.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Copy qw(copy);
use FindBin;
use IO::Socket::UNIX;
use IO::Socket::INET;
use Socket;
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(time sleep);
use POSIX ();

my $syncd = shift || "$FindBin::Bin/../bin/snif-syncd";
$| = 1;
my ($Named) = grep { -x } ('/usr/sbin/named', '/usr/bin/named');
my ($Keygen) = grep { -x } ('/usr/sbin/tsig-keygen', '/usr/bin/tsig-keygen');
my $Dig = `command -v dig 2>/dev/null` =~ s/\s+$//r;
if (!eval { require Net::DNS; 1 } || !$Named || !$Keygen || !$Dig) {
    print "# skipped: needs Net::DNS, named, tsig-keygen and dig\n";
    exit 0;
}

my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
    return $ok;
}

my $T = tempdir(CLEANUP => !$ENV{JUDGE_KEEP});
print "# tree $T\n" if $ENV{JUDGE_KEEP};
my $Main = $$;
my %Pid;
END { kill 'TERM', values %Pid if %Pid && $$ == $Main }
my $Set = 'Deadline=2 PingEvery=1 PingMiss=2 CSRLease=8 Margin=1 CSRWait=3 RetryDelay=0.3 BackoffMax=1 ScanEvery=2';
# A zone name of the deployed shape: its own zone, under an internal one,
# with a leading underscore.
my ($Zone, $Port, $Fake) = ('_snif-judge.lo.test', 31301, 31302);

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew { my ($p, $d) = @_; (my $dir = $p) =~ s{/[^/]+$}{}; make_path($dir); open(my $f, '>', $p) || die "$p: $!"; print $f $d; close $f }
sub wait_for { my ($f, $s) = @_; my $u = time + $s; while (time < $u) { return 1 if $f->(); sleep 0.1 } return $f->() }
sub tree { "$T/$_[0]" }

# ---- the judge: a throwaway named ------------------------------------------
make_path("$T/ns");
copy($Named, "$T/ns/named") && chmod(0755, "$T/ns/named") || die "copy named: $!";
system("$Keygen -a hmac-sha256 snif-judge > $T/ns/judge.key") == 0 || die "tsig-keygen";
system("$Keygen -a hmac-sha256 snif-judge > $T/ns/wrong.key") == 0 || die "tsig-keygen";	# same name, other secret
# The nameserver's name is outside the zone, as dns2's is: check-names fails a
# primary zone that has an A record under a label with an underscore.
spew("$T/ns/$Zone.db", "\$TTL 0\n\@ IN SOA ns.example. hostmaster.example. 1 3600 600 86400 0\n\@ IN NS ns.example.\n");
spew("$T/ns/named.conf", <<EOF);
include "$T/ns/judge.key";
options {
    directory "$T/ns";
    listen-on port $Port { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    pid-file "$T/ns/named.pid";
};
controls { };
zone "$Zone" {
    type primary;
    file "$T/ns/$Zone.db";
    update-policy { grant snif-judge subdomain $Zone. TXT; };
};
EOF
sub start_named {
    my $pid = fork;
    if (!$pid) {
	open(STDOUT, '>>', "$T/ns/named.log"); open(STDERR, '>&', \*STDOUT);
	{ exec('/bin/sh', '-c', "ulimit -v 700000; exec $T/ns/named -c $T/ns/named.conf -n 1 -g") };
	POSIX::_exit(127);
    }
    $Pid{named} = $pid;
    return wait_for(sub { `$Dig +short +norec +time=1 +tries=1 -p $Port \@127.0.0.1 $Zone SOA 2>/dev/null` =~ /\S/ }, 10);
}
sub stop_named { kill 'TERM', $Pid{named}; waitpid(delete $Pid{named}, 0) }
# The judge's record for a name: the sha256 it holds, or ''.
sub judged { my ($cn) = @_; return `$Dig +short +norec -p $Port \@127.0.0.1 $cn.$Zone TXT 2>/dev/null` =~ s/["\s]//gr }

# A responder that answers every request NOERROR, unsigned: a forged vote.
sub start_fake {
    my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $Fake, Listen => 5, ReuseAddr => 1) || die "fake: $!";
    my $pid = fork;
    if (!$pid) {
	while (my $c = $l->accept) {
	    while (read($c, my $len, 2) == 2) {
		read($c, my $q, unpack('n', $len)) || last;
		my $i = 12;				# the zone section: one name, type, class
		$i += 1 + ord(substr($q, $i, 1)) while ord(substr($q, $i, 1));
		my $r = substr($q, 0, 2) . pack('n', 0xA800) . pack('n4', 1, 0, 0, 0) . substr($q, 12, $i + 5 - 12);
		print $c pack('n', length $r), $r;
	    }
	    close $c;
	}
	POSIX::_exit(0);
    }
    close $l;
    $Pid{fake} = $pid;
}

# ---- the nodes ---------------------------------------------------------------
# A session from n to p runs through a wrapper: $T/cut-n-p cuts it (and every
# reconnect), $T/sess-n-p.pid is its process, to cut one that is up.
sub env_for {
    my ($n, $judge, @peers) = @_;
    return (SNIF_CA_PROXY => tree($n), SNIF_CLUSTER_NODE => $n,
	SNIF_CLUSTER_PEERS => join(' ', map { "$_=" . tree($_) } @peers),
	SNIF_CLUSTER_PEER_CMD => "test -e $T/cut-%n-%p && exit 1; echo \$\$ > $T/sess-%n-%p.pid; SNIF_CA_PROXY=%a exec $^X $syncd --serve %n",
	SNIF_CLUSTER_JUDGE => $judge // '', SNIF_SYNCD_SET => $Set, SNIF_SYNCD_STDERR => 1);
}
sub start {
    my ($n, $judge, @peers) = @_;
    make_path(map { tree($n) . "/$_" } qw(cfg csr auth crt apns log var arc etc));
    unlink tree($n) . "/var/snif-syncd.sock";
    my $pid = fork;
    if (!$pid) {
	%ENV = (%ENV, env_for($n, $judge, @peers));
	open(STDERR, '>>', tree($n) . "/syncd.log");
	exec($^X, $syncd);
	exit 127;
    }
    $Pid{$n} = $pid;
    return wait_for(sub { -S tree($n) . "/var/snif-syncd.sock" }, 5);
}
sub stop {
    my ($n) = @_;
    kill 'TERM', $Pid{$n} if $Pid{$n};
    waitpid($Pid{$n}, 0) if $Pid{$n};
    delete $Pid{$n};
    unlink tree($n) . "/var/snif-syncd.sock";
}
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
sub csr_req { my ($cn, $data) = @_; return ("CSR $cn " . length($data) . " " . sha256_hex($data), $data) }
sub csr { "-----BEGIN CERTIFICATE REQUEST-----\n$_[0]\n-----END CERTIFICATE REQUEST-----\n" }
sub has { my ($n, $cn) = @_; return slurp(tree($n) . "/csr/$cn.csr") // '' }
sub state_is { my ($n, $p, $st) = @_; wait_for(sub { ask($n, 'STATUS') =~ /^peer $p $st /m }, 15) }
sub queued { my ($n, $p) = @_; return ask($n, 'STATUS') =~ /^peer $p \S+ queue=(\d+)/m ? $1 : -1 }
sub cut { my ($n, $p) = @_; spew("$T/cut-$n-$p", ''); my $pid = slurp("$T/sess-$n-$p.pid"); kill 'TERM', $pid =~ /(\d+)/ if $pid }
sub heal { my ($n, $p) = @_; unlink "$T/cut-$n-$p" }

my $J = "$Zone\@127.0.0.1#$Port";
foreach my $n (qw(a b)) { make_path(tree($n) . "/etc"); copy("$T/ns/judge.key", tree($n) . "/etc/$Zone.tsig") }
check(start_named(), "the judge (named) starts");
start('a', $J, 'b'); start('b', $J, 'a');
check(state_is('a', 'b', 'up') && state_is('b', 'a', 'up'), "two nodes with a judge: both sessions up");
my $st = ask('a', 'STATUS');
check(scalar($st =~ /^judge \Q$Zone\E\@127\.0\.0\.1#$Port majority=2 last=none$/m), "status names the judge and the majority");

# 1. Both nodes up: the peers are a majority, the judge is not asked.
my $r = ask('a', csr_req('snif-1.x.test', csr('one')));
check($r eq 'STORED' && has('b', 'snif-1.x.test') eq csr('one'), "both up: a CSR on a is STORED on both ($r)");
check(judged('snif-1.x.test') eq '', "and the judge was not asked (no record)");

# 2. The peer down: this node and the judge are two votes of three.
stop('b');
check(state_is('a', 'b', 'down'), "b's snif-syncd stopped: a sees b down");
$r = ask('a', csr_req('snif-2.x.test', csr('two')));
check($r eq 'STORED' && has('a', 'snif-2.x.test') eq csr('two'), "b down: a CSR on a is STORED with the judge ($r)");
check(judged('snif-2.x.test') eq sha256_hex(csr('two')), "the judge holds its sha256");
check(queued('a', 'b') == 1, "and it is queued for b (queue=" . queued('a', 'b') . ")");
$r = ask('a', csr_req('snif-2.x.test', csr('two')));
check($r eq 'SAME', "the same CSR again: SAME ($r)");
$r = ask('a', csr_req('snif-2.x.test', csr('two-other')));
check($r eq 'DIFFERENT', "another CSR for the name: DIFFERENT ($r)");
check(ask('a', 'STATUS') =~ /^judge \S+ majority=2 last=\d+s (SET|SAME)$/m, "status shows the judge's last answer");

# 3. b back: the owed CSR reaches it.
start('b', $J, 'a');
check(state_is('a', 'b', 'up') && state_is('b', 'a', 'up'), "b back");
check(wait_for(sub { has('b', 'snif-2.x.test') eq csr('two') }, 15), "the CSR accepted without b reaches b");
check(wait_for(sub { queued('a', 'b') == 0 }, 10), "and a's queue for b is empty");

# 4. Cut off from each other, two CSRs for one name at once: one is accepted.
cut('a', 'b'); cut('b', 'a');
check(state_is('a', 'b', 'down') && state_is('b', 'a', 'down'), "a and b cut off from each other");
foreach my $round (1 .. 3) {
    my $cn = "snif-race$round.x.test";
    my %got;
    my @kids;
    foreach my $n (qw(a b)) {
	pipe(my $rd, my $wr);
	my $pid = fork;
	if (!$pid) { close $rd; print $wr ask($n, csr_req($cn, csr("$n-$round"))); close $wr; POSIX::_exit(0) }
	close $wr;
	push @kids, [$n, $rd, $pid];
    }
    foreach my $k (@kids) { my ($n, $rd, $pid) = @$k; local $/; $got{$n} = <$rd> // ''; waitpid($pid, 0) }
    my @won = grep { $got{$_} eq 'STORED' } qw(a b);
    my @lost = grep { $got{$_} eq 'DIFFERENT' } qw(a b);
    my $w = $won[0] // '';
    check(@won == 1 && @lost == 1 && judged($cn) eq sha256_hex(csr("$w-$round")) && has($lost[0] // 'a', $cn) eq '',
	"cut off, round $round: exactly one STORED, the other DIFFERENT, the judge holds the winner's ($got{a}, $got{b})");
    $got{w} = $w;
    push @main::Races, [$cn, $w, $lost[0]];
}

# 5. Healed: each winner's CSR reaches the other node, with no conflict.
heal('a', 'b'); heal('b', 'a');
check(state_is('a', 'b', 'up') && state_is('b', 'a', 'up'), "the link back");
foreach my $rc (@main::Races) {
    my ($cn, $w, $l) = @$rc;
    next if !$w || !$l;
    check(wait_for(sub { has($l, $cn) eq csr("$w-" . ($cn =~ /race(\d)/)[0]) }, 15), "$cn: the CSR $w accepted reaches $l");
}
check(ask('a', 'STATUS') !~ /^conflict/m && ask('b', 'STATUS') !~ /^conflict/m, "no conflicts on either node");

# 6. A node back after missing a CSR, still cut off from its peer: the judge
# refuses it another CSR, and accepts the same one.
stop('b');
check(state_is('a', 'b', 'down'), "b stopped again");
$r = ask('a', csr_req('snif-6.x.test', csr('six')));
check($r eq 'STORED', "a CSR on a without b ($r)");
cut('a', 'b'); cut('b', 'a');
start('b', $J, 'a');
check(state_is('b', 'a', 'down'), "b back but cut off from a");
$r = ask('b', csr_req('snif-6.x.test', csr('six-other')));
check($r eq 'DIFFERENT' && has('b', 'snif-6.x.test') eq '', "on b, another CSR for the name: DIFFERENT, stored nowhere ($r)");
$r = ask('b', csr_req('snif-6.x.test', csr('six')));
check($r eq 'STORED' && has('b', 'snif-6.x.test') eq csr('six'), "on b, the same CSR: STORED (the judge's SAME is the second vote) ($r)");
heal('a', 'b'); heal('b', 'a');
check(state_is('a', 'b', 'up') && state_is('b', 'a', 'up'), "the link back");
check(wait_for(sub { queued('a', 'b') == 0 }, 15) && ask('a', 'STATUS') !~ /^conflict/m, "a's owed copy arrives as SAME: queue empty, no conflict");

# 7. ENSURE (before a first certificate) with the peer down: the judge's vote.
stop('b');
check(state_is('a', 'b', 'down'), "b stopped");
spew(tree('a') . "/csr/snif-7.x.test.csr", csr('seven'));
$r = ask('a', 'ENSURE snif-7.x.test');
check($r eq 'STORED' && judged('snif-7.x.test') eq sha256_hex(csr('seven')), "ENSURE with b down: STORED, the judge holds it ($r)");
check(queued('a', 'b') == 1, "and it is queued for b");

# 8. The judge down too: no majority.
stop_named();
$r = ask('a', csr_req('snif-8.x.test', csr('eight')));
check($r eq 'UNREACHABLE' && has('a', 'snif-8.x.test') eq '', "the judge and b down: UNREACHABLE, stored nowhere ($r)");
check(ask('a', 'STATUS') =~ /^judge \S+ majority=2 last=\d+s ERROR|^judge \S+ majority=2 last=\d+s no answer/m, "status shows the judge's failure");

# 9. The judge down, both nodes up: the peers alone are a majority.
start('b', $J, 'a');
check(state_is('a', 'b', 'up') && state_is('b', 'a', 'up'), "b back");
$r = ask('a', csr_req('snif-9.x.test', csr('nine')));
check($r eq 'STORED' && has('b', 'snif-9.x.test') eq csr('nine'), "the judge down, both up: STORED on both ($r)");
check(wait_for(sub { has('b', 'snif-7.x.test') eq csr('seven') }, 15), "ENSURE's owed CSR reaches b");

# 10. A forged vote: an unsigned NOERROR counts for nothing.
check(start_named(), "the judge back");
start_fake();
stop('a');
start('a', "$Zone\@127.0.0.1#$Fake", 'b');
stop('b');
check(state_is('a', 'b', 'down'), "a judges by a responder that answers NOERROR unsigned; b down");
$r = ask('a', csr_req('snif-10.x.test', csr('ten')));
check($r eq 'UNREACHABLE' && has('a', 'snif-10.x.test') eq '', "the unsigned answer is no vote: UNREACHABLE ($r)");
check(scalar(slurp(tree('a') . "/syncd.log") =~ /judge snif-10\.x\.test: ERROR no answer \(not signed\)/), "and the log says the answer was not signed");

# 11. A wrong key: the judge refuses, no vote.
stop('a');
copy("$T/ns/wrong.key", tree('a') . "/etc/$Zone.tsig");
start('a', $J, 'b');
$r = ask('a', csr_req('snif-11.x.test', csr('eleven')));
check($r eq 'UNREACHABLE' && judged('snif-11.x.test') eq '', "a wrong key: UNREACHABLE, nothing at the judge ($r)");
copy("$T/ns/judge.key", tree('a') . "/etc/$Zone.tsig");

# 12. Without SNIF_CLUSTER_JUDGE: as before, the peer down means no CSR.
stop('a');
start('a', undef, 'b');
check(ask('a', 'STATUS') !~ /^judge/m, "no SNIF_CLUSTER_JUDGE: no judge in status");
$r = ask('a', csr_req('snif-12.x.test', csr('twelve')));
check($r eq 'UNREACHABLE' && judged('snif-12.x.test') eq '' && has('a', 'snif-12.x.test') eq '', "and b down: UNREACHABLE, the judge never asked ($r)");

# 13. A setting that is not <zone>@<server>, or no key: the daemon refuses to start.
stop('a');
foreach my $case (['nonsense', 'is not'], ["other.test\@127.0.0.1#$Port", 'cannot read']) {
    my ($v, $msg) = @$case;
    local %ENV = (%ENV, env_for('a', $v, 'b'));
    my $out = `$^X $syncd 2>&1`;
    check($? != 0 && $out =~ /SNIF_CLUSTER_JUDGE.*\Q$msg\E/, "SNIF_CLUSTER_JUDGE=$v: refuses to start ($msg)");
}

if ($fail) {
    foreach my $f (map { tree($_) . "/syncd.log" } qw(a b)) {
	next if !-e $f;
	print "\n---- $f\n";
	my @l = split(/\n/, slurp($f));
	print map { "$_\n" } @l[($#l > 25 ? $#l - 25 : 0) .. $#l];
    }
}
print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
