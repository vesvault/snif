#!/usr/bin/perl
#
# The CA proxy daemons' copy of their log lines to syslog (SNIF_SYSLOG), sent
# to a socket of the test's own (SNIF_SYSLOG_PATH), never this host's syslog:
# snif-syncd run as a daemon (its start, a peer down and up, the status line
# and its timer, a fatal error, SNIF_SYSLOG=0, a syslog it cannot reach),
# snif-certd's and snif-apnsd's lines, loaded as in their own tests, and the
# fatal-error hook of snif-certd and snif-syncd, loaded.
#
#   perl ca-proxy/test/syslog.t [path/to/ca-proxy/bin]
#
# Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use FindBin;
use IO::Socket::UNIX;
use IO::Select;
use Socket;
use POSIX ();
use Time::HiRes qw(time sleep);

# Loads a daemon's source into package $LoadPkg. Defined before every
# file-scoped "my" below: a string eval sees the lexicals in scope where it is
# compiled, and a daemon global of the same name ($Syslog) would land in one.
sub load {
    my ($LoadPkg, $LoadFile) = @_;
    open(my $LoadFh, '<', $LoadFile) or die "$LoadFile: $!";
    my $LoadSrc = do { local $/; <$LoadFh> };
    close $LoadFh;
    no strict; no warnings;
    eval "package $LoadPkg;\n$LoadSrc";
    die "loading $LoadFile: $@" if $@;
}

my $Bin = shift || "$FindBin::Bin/../bin";
$| = 1;
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

my $T = tempdir(CLEANUP => !$ENV{SYSLOG_KEEP});
print "# tree $T\n" if $ENV{SYSLOG_KEEP};

# ---- the test's syslog ------------------------------------------------------

my $SockPath = "$T/syslog.sock";
my $Syslog = IO::Socket::UNIX->new(Type => SOCK_DGRAM, Local => $SockPath) || die "$SockPath: $!\n";
my $Sel = IO::Select->new($Syslog);
my %Pri = (err => 27, warning => 28, notice => 29, info => 30);	# facility daemon
my @Got;	# {pri, ident, pid, msg}, as they arrived

sub take {
    my ($wait) = @_;
    return 0 if !$Sel->can_read($wait);
    defined($Syslog->recv(my $buf, 65536)) || return 0;
    $buf =~ s/[\0\r\n]+\z//;
    if ($buf =~ /^<(\d+)>.*?\b(snif-[a-z]+)\[(\d+)\]: (.*)\z/s) {
	push @Got, { pri => $1, ident => $2, pid => $3, msg => $4 };
    } else {
	push @Got, { pri => -1, ident => '', pid => 0, msg => $buf };
    }
    return 1;
}

# The messages matching $f, waiting up to $secs for at least $n of them.
sub got {
    my ($secs, $n, $f) = @_;
    my $until = time + $secs;
    while (1) {
	my @m = grep { $f->($_) } @Got;
	return @m if @m >= $n;
	my $left = $until - time;
	return @m if $left <= 0;
	take($left > 0.2 ? 0.2 : $left);
    }
}
sub drain { 1 while take(0) }
sub by { my ($pid, $pri, $re) = @_; return sub { $_[0]{pid} == $pid && (!$pri || $_[0]{pri} == $Pri{$pri}) && $_[0]{msg} =~ $re } }

sub slurp { open(my $h, '<', $_[0]) || return ''; local $/; my $s = <$h>; close $h; $s }

sub wait_for {
    my ($f, $secs) = @_;
    my $until = time + $secs;
    while (time < $until) { return 1 if $f->(); sleep 0.1 }
    return $f->();
}

# ---- snif-syncd as a daemon --------------------------------------------------

my %Pid;
my $Main = $$;
END { kill 'TERM', values %Pid if %Pid && $$ == $Main }

sub tree { "$T/$_[0]" }
my $Set = 'Deadline=2 PingEvery=1 PingMiss=2 BackoffMax=1 ScanEvery=2 StatusDown=1 StatusEvery=60';
my $Serve = "SNIF_CA_PROXY=%a exec $^X $Bin/snif-syncd --serve %n";

# start <node> <peers> [env...]: no var/ in the tree with NOVAR => 1.
sub start {
    my ($n, $peers, %env) = @_;
    my $novar = delete $env{NOVAR};
    make_path(map { tree($n) . "/$_" } grep { !$novar || $_ ne 'var' } qw(cfg csr auth crt apns log var arc));
    my $pid = fork;
    if (!$pid) {
	%ENV = (%ENV, SNIF_CA_PROXY => tree($n), SNIF_CLUSTER_NODE => $n, SNIF_CLUSTER_PEERS => $peers,
	    SNIF_CLUSTER_PEER_CMD => $Serve, SNIF_CLUSTER_JUDGE => '', SNIF_SYNCD_SET => $Set,
	    SNIF_SYSLOG => '', SNIF_SYSLOG_PATH => $SockPath, %env);
	delete $ENV{SNIF_SYNCD_STDERR};
	open(STDERR, '>>', tree($n) . "/stderr");
	exec($^X, "$Bin/snif-syncd");
	exit 127;
    }
    $Pid{$n} = $pid;
    wait_for(sub { -S tree($n) . "/var/snif-syncd.sock" }, 5) if !$novar;
    return $pid;
}
sub stop {
    my ($n) = @_;
    return if !$Pid{$n};
    kill 'TERM', $Pid{$n};
    waitpid($Pid{$n}, 0);
    delete $Pid{$n};
}
sub logfile { slurp(tree($_[0]) . "/log/log_snif-syncd") }

# 1. A node whose one peer never answers.
{
    my $pid = start('a', 'x=nowhere', SNIF_CLUSTER_PEER_CMD => 'exit 1');
    my ($s) = got(5, 1, by($pid, 'notice', qr/^starting snif-syncd, node a, peers x$/));
    check($s && $s->{ident} eq 'snif-syncd', "the start line, at notice, as snif-syncd[pid]");
    check(scalar(got(5, 1, by($pid, 'warning', qr/^peer x: down \(/))), "a peer down, at warning");
    my @st = got(6, 2, by($pid, 'warning', qr/^status: peer x (down|hello) queue=0 oldest=0s; conflicts 0$/));
    check(@st >= 2, "a status line at warning while the peer is not up, every StatusDown (" . scalar(@st) . ")");
    my $l = logfile('a');
    check($l =~ /\]: starting snif-syncd, node a, peers x\n/ && $l =~ /\]: peer x: down \(/ && $l =~ /\]: status: peer x /,
	"the same lines in log/log_snif-syncd");
    check(!grep({ $_->{pri} == -1 } @Got), "every message has a priority and an identity");
    stop('a');
}

# 2. Two nodes: up, then the peer stops.
{
    drain(); @Got = ();
    my $pb = start('b', 'c=' . tree('c'));
    my $pc = start('c', 'b=' . tree('b'));
    check(scalar(got(10, 1, by($pc, 'notice', qr/^peer b: up$/))), "a peer up, at notice");
    check(scalar(got(5, 1, by($pc, 'info', qr/^status: peer b up queue=0 oldest=0s; conflicts 0$/))),
	"the status line at info while every peer is up");
    my $up = time;
    drain(); @Got = ();
    stop('b');
    check(scalar(got(5, 1, by($pc, 'warning', qr/^peer b: down \(/))), "the peer down");
    my @st = got(5, 1, by($pc, 'warning', qr/^status: peer b (down|hello) /));
    check(@st && time - $up < 10, sprintf("a peer going down brings the status line forward from StatusEvery (60 s) to StatusDown (%.1f s)", time - $up));
    stop('c');
}

# 3. SNIF_SYSLOG=0: the file only.
{
    drain(); @Got = ();
    my $pid = start('d', 'x=nowhere', SNIF_CLUSTER_PEER_CMD => 'exit 1', SNIF_SYSLOG => 0);
    wait_for(sub { logfile('d') =~ /status: / }, 5);
    take(0.5);
    check(logfile('d') =~ /status: peer x/ && !grep({ $_->{pid} == $pid } @Got), "SNIF_SYSLOG=0: in the file, nothing to syslog");
    stop('d');
}

# 4. No socket at SNIF_SYSLOG_PATH: the file only, and never the system's
# syslog, which Sys::Syslog would take instead.
{
    my $pid = start('e', 'x=nowhere', SNIF_CLUSTER_PEER_CMD => 'exit 1', SNIF_SYSLOG_PATH => "$T/none.sock");
    wait_for(sub { logfile('e') =~ /status: / }, 5);
    my $l = logfile('e');
    check($l =~ m{\]: SNIF_SYSLOG: cannot use syslog \(no socket at \Q$T\E/none\.sock\)} && $l =~ /\]: status: peer x/ && kill(0, $pid),
	"no socket at SNIF_SYSLOG_PATH: the daemon says so, runs, and logs to its file");
    check(slurp(tree('e') . "/stderr") eq '', "with nothing on stderr");
    stop('e');
}

# 5. A syslog that goes away while the daemon runs loses only the copy.
{
    my $gone = "$T/gone.sock";
    my $rx = IO::Socket::UNIX->new(Type => SOCK_DGRAM, Local => $gone) || die "$gone: $!\n";
    my $pid = start('g', 'x=nowhere', SNIF_CLUSTER_PEER_CMD => 'exit 1', SNIF_SYSLOG_PATH => $gone);
    my $first = '';
    $rx->recv($first, 65536) if IO::Select->new($rx)->can_read(5);
    check($first =~ /snif-syncd\[$pid\]: starting snif-syncd, node g/, "a second syslog socket gets the start line");
    close $rx;
    unlink $gone;
    my $n = () = logfile('g') =~ /\]: status: /g;
    wait_for(sub { (() = logfile('g') =~ /\]: status: /g) >= $n + 2 }, 5);
    my $m = () = logfile('g') =~ /\]: status: /g;
    check($m >= $n + 2 && kill(0, $pid), "with it gone, the daemon runs and its status lines go on in the file ($n, then $m)");
    check(slurp(tree('g') . "/stderr") eq '', "with nothing on stderr");
    stop('g');
}

# 6. A fatal error after the start goes to syslog too.
{
    drain(); @Got = ();
    my $pid = start('f', 'x=nowhere', SNIF_CLUSTER_PEER_CMD => 'exit 1', NOVAR => 1);
    waitpid($pid, 0);
    delete $Pid{f};
    my $sock = quotemeta(tree('f') . "/var/snif-syncd.sock");
    check(scalar(got(3, 1, by($pid, 'err', qr{^fatal: snif-syncd: $sock: }))), "a fatal error, at err");
    check(logfile('f') =~ m{snif-syncd: .*/var/snif-syncd\.sock: }, "and in the file");
}

# ---- snif-certd and snif-apnsd, loaded ---------------------------------------

package Net::APNS::Simple;
$INC{'Net/APNS/Simple.pm'} = 1;
sub new { bless {}, shift }
sub prepare { }
sub notify { 1 }

package main;

my $ct = "$T/certd";
mkdir $ct; mkdir "$ct/$_" foreach qw(etc csr crt log var);
{
    local $ENV{SNIF_CA_PROXY} = $ct;
    local $ENV{SNIF_SYSLOG} = '';
    load('CertD', "$Bin/snif-certd");
}
{
    no warnings 'once';
    drain(); @Got = ();
    check(CertD::syslog_wanted($CertD::SyslogSetting), "snif-certd: syslog is on by default");
    check(!CertD::syslog_wanted($_), "SNIF_SYSLOG=$_ turns it off") foreach qw(0 no off false);
    my $why = CertD::syslog_open('snif-certd', $SockPath);
    check($why eq '', "snif-certd opens syslog" . ($why ? ": $why" : ''));
    $CertD::Syslog = 1;
    my $dom = 'snif-1.example.test';
    $CertD::ErrDomain = $dom;
    open(*CertD::LOG, '>>', "$ct/log/$dom.log") || die;
    CertD::dlog('LOG', "issue $dom (mode=local) ...");
    CertD::flog('LOG', 0, 'load_csr', 'stub failure');
    CertD::flog('LOG', 1, 'register');
    close *CertD::LOG;
    my $mine = sub { my ($pri, $msg) = @_; sub { $_[0]{ident} eq 'snif-certd' && $_[0]{pid} == $$ && $_[0]{pri} == $Pri{$pri} && $_[0]{msg} eq $msg } };
    check(scalar(got(3, 1, $mine->('err', "$dom: load_csr: ERROR stub failure"))), "an issue's failed step: the domain in front, at err");
    check(scalar(got(3, 1, $mine->('info', "$dom: register: OK"))), "a step that passed, at info");
    check(scalar(got(3, 1, $mine->('info', "issue $dom (mode=local) ..."))), "a line that names the domain gets it once");
    my $f = slurp("$ct/log/$dom.log");
    check($f =~ /\]: load_csr: ERROR stub failure\n/ && $f !~ /\Q$dom\E: load_csr/, "log/<domain>.log keeps its lines as they were");
    {
	local *STDERR;
	open(STDERR, '>>', "$ct/log/log_snif-certd");
	CertD::dlog('STDERR', "$dom: not issued now: no lease", 'warning');
	$CertD::Syslog = 0;
	CertD::dlog('STDERR', "not copied");
    }
    check(scalar(got(3, 1, $mine->('warning', "$dom: not issued now: no lease"))), "a daemon line, at its priority");
    take(0.3);
    check(!grep({ $_->{msg} eq 'not copied' } @Got) && slurp("$ct/log/log_snif-certd") =~ /\]: not copied\n/, "syslog not open: the file only");
}

my $at = "$T/apnsd";
mkdir $at; mkdir "$at/$_" foreach qw(etc apns log var);
{
    local $ENV{SNIF_CA_PROXY} = $at;
    local $ENV{SNIF_APNS_BUNDLE} = 'com.example.test';
    local $ENV{SNIF_SYSLOG} = '';
    load('ApnsD', "$Bin/snif-apnsd");
}
{
    no warnings 'once';
    drain(); @Got = ();
    my $why = ApnsD::syslog_open('snif-apnsd', $SockPath);
    check($why eq '', "snif-apnsd opens syslog" . ($why ? ": $why" : ''));
    $ApnsD::Syslog = 1;
    my $file = "$at/log/log_snif-apnsd";
    my $mine = sub { my ($pri, $re) = @_; sub { $_[0]{ident} eq 'snif-apnsd' && $_[0]{pid} == $$ && $_[0]{pri} == $Pri{$pri} && $_[0]{msg} =~ $re } };
    {
	local *STDERR;
	open(STDERR, '>>', $file);
	STDERR->autoflush(1);
	ApnsD::apns_rspfn([':status' => 410, 'apns-id' => 'id-1'], qq({"reason":\n"Unregistered"}), 'tok-secret');
	$ApnsD::SyslogOnly = 1;
	ApnsD::apns_rspfn([':status' => 400], '{"reason":"BadDeviceToken"}', 'tok-secret');
	ApnsD::dlog('STDERR', "cannot queue x", 'err');
	$ApnsD::SyslogOnly = 0;
    }
    check(scalar(got(3, 1, $mine->('warning', qr/^apns_rspfn: status 410: \{"reason": "Unregistered"\}$/))), "a refused push: one line, at warning");
    check(scalar(got(3, 1, $mine->('warning', qr/^apns_rspfn: status 400: /))) && scalar(got(3, 1, $mine->('err', qr/^cannot queue x$/))),
	"with no log file, each line still goes to syslog");
    check(!grep({ $_->{msg} =~ /tok-secret/ } @Got), "the token is not in it");
    my $f = slurp($file);
    check($f =~ /\]: apns_rspfn: status 410: .*\napns-id: id-1\n/s, "the file gets the line and the headers");
    check($f !~ /status 400|cannot queue/, "and nothing written while there is no log file (syslog only)");
}

# ---- the fatal-error hook of snif-certd and snif-syncd -----------------------
# A fatal error goes to syslog at err. An error caught while a module compiles
# does not: $^S is undef then, not true. snif-certd loads Crypt::LE and Net::DNS
# after its hook is in place, and JSON::MaybeXS, under Crypt::LE, probes for an
# optional module that way.

{
    local %ENV = (%ENV, map { $_ => '' } qw(SNIF_CA_PROXY SNIF_CLUSTER_NODE SNIF_CLUSTER_PEERS SNIF_CLUSTER_LEASE
	SNIF_CLUSTER_PEER_CMD SNIF_CLUSTER_JUDGE SNIF_CLUSTER_RECONCILE_DAYS SNIF_SYSLOG));
    load('SyncD', "$Bin/snif-syncd");
}
my $Lib = "$T/lib";
mkdir $Lib;
unshift @INC, $Lib;
foreach my $d (['CertD', 'snif-certd'], ['SyncD', 'snif-syncd']) {
    my ($pkg, $ident) = @$d;
    no strict 'refs';
    no warnings 'once';
    drain(); @Got = ();
    my $why = &{"${pkg}::syslog_open"}($ident, $SockPath);
    ${"${pkg}::Syslog"} = 1;
    my $hook = \&{"${pkg}::fatal_to_syslog"};
    # A module that probes for two modules that are not there while it compiles.
    my $probe = "SnifProbe$pkg";
    open(my $h, '>', "$Lib/$probe.pm") || die "$Lib/$probe.pm: $!";
    print $h "package $probe;\n",
	"use constant HAVE => defined eval { require No::Such::SnifProbeA };\n",
	"BEGIN { eval 'use No::Such::SnifProbeB; 1' }\n",
	"1;\n";
    close $h;
    my $loaded = do { local $SIG{__DIE__} = $hook; eval { require "$probe.pm"; 1 } };
    my $pid = fork;
    if (!$pid) {
	# Dies outside any eval, as a daemon does, and leaves without the test's END blocks.
	$SIG{__DIE__} = sub { $hook->(@_); POSIX::_exit(0) };
	die "$ident test fatal\n";
    }
    waitpid($pid, 0);
    check($why eq '' && scalar(got(3, 1, sub { $_[0]{ident} eq $ident && by($pid, 'err', qr/^fatal: \Q$ident\E test fatal$/)->($_[0]) })),
	"$ident: a fatal error, at err");
    take(0.3);
    my @false = grep { $_->{pid} == $$ && $_->{msg} =~ /^fatal: / } @Got;
    check($loaded && !@false, "$ident: an error caught while a module compiles is not fatal"
	. (@false ? " (sent: $false[0]{msg})" : ''));
    ${"${pkg}::Syslog"} = 0;
}

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
