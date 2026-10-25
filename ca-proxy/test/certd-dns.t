#!/usr/bin/perl
#
# snif-certd DNS-01 challenge handling, against stub Crypt::LE and Net::DNS
# modules (neither needs to be installed). The stub nameservers model a primary
# that takes TSIG updates and a secondary that follows it after a set number of
# queries; the stub ACME server checks, at verification time, that every
# challenge value is served by every nameserver.
#
#   perl ca-proxy/test/certd-dns.t [path/to/snif-certd]
#
# Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;

my $certd = shift || "$FindBin::Bin/../bin/snif-certd";
my ($pass, $fail) = (0, 0);

sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

# ---- stub DNS ------------------------------------------------------------
#
# %Stub::Served{$ns}{$name} = { value => 1 } is what nameserver $ns answers.
# Each nameserver handles an update as %Stub::UpdateMode says: 'accept' (the
# primary's default), 'refuse' (the secondary's default, as a secondary does),
# or 'down' (no answer, to queries either). The secondary copies the primary
# once it has been queried $Stub::Lag times since the last update (never, if
# undef). _acme-challenge.<host> is an alias for snif-pool.<base>, as the
# wildcard *.<base> makes it on the public relay, unless %Stub::Alias says
# otherwise; a name's zone is its parent unless %Stub::ZoneOf says otherwise.

package Stub;
our (%Served, @Primary, @Secondary, $Lag, $SinceUpdate, $RefuseValue, $NSLookupFails, @Log, @AllLog);
our (%UpdateMode, %Alias, %ZoneOf, $NoAlias, $RefuseDel, @UpdLog);
sub reset {
    %Served = (); @Primary = ('ns.example.test'); @Secondary = ('ns2.example.test');
    $Lag = 0; $SinceUpdate = 0; $RefuseValue = undef; $NSLookupFails = 0; @Log = ();
    %UpdateMode = (); %Alias = (); %ZoneOf = (); $NoAlias = 0; $RefuseDel = 0; @UpdLog = ();
}
sub mode { my ($ns) = @_; return $UpdateMode{$ns} // ($ns eq $Primary[0] ? 'accept' : 'refuse') }
sub wildcard_alias { my ($n) = @_; (my $b = $n) =~ s/^_acme-challenge\.[^.]+\.//; return "snif-pool.$b" }
sub alias { my ($n) = @_; return exists $Alias{$n} ? $Alias{$n} : ($n =~ /^_acme-challenge\./ ? wildcard_alias($n) : undef) }
sub final_target {	# what a resolver ends up at from $n
    my ($n) = @_;
    for (1 .. 8) { my $t = alias($n); last if !defined $t; $n = $t }
    return $n;
}
sub zone_of { my ($n) = @_; return $ZoneOf{$n} if exists $ZoneOf{$n}; (my $z = $n) =~ s/^[^.]+\.//; return $z }
sub values_on {
    my ($ns, $name) = @_;
    return sort keys %{$Served{$ns}{$name} || {}};
}
sub tick {
    return if !defined $Lag || $SinceUpdate++ < $Lag;
    foreach my $s (@Secondary) {
	$Served{$s} = { map { $_ => { %{$Served{$Primary[0]}{$_}} } } keys %{$Served{$Primary[0]} || {}} };
    }
}

package Net::DNS;
$INC{'Net/DNS.pm'} = 1;
sub rr_add { my ($n, $ttl, $t, $v) = split ' ', shift; return { op => 'add', name => $n, value => $v } }
sub rr_del { my ($n, $t, $v) = split ' ', shift; return { op => 'del', name => $n, value => $v } }

package Net::DNS::Update;
sub new { my ($c, $zone) = @_; return bless { zone => $zone, rr => [] }, $c }
sub push { my ($s, $sec, $rr) = @_; push @{$s->{rr}}, $rr }
# The real one reads the key file with while (<>), leaving $_ undefined.
sub sign_tsig { $_[0]{tsig} = $_[1]; $_ = undef }

package Net::DNS::Resolver;
sub new { my ($c, %a) = @_; return bless { ns => $a{nameservers} }, $c }
sub nameservers { $_[0]{ns} = [$_[1]] }
sub send {
    my ($s, $q, $type) = @_;
    if (ref $q) {	# an update
	my $ns = $s->{ns}[0];
	my $mode = Stub::mode($ns);
	push @Stub::UpdLog, "$ns $mode " . join(',', map { "$_->{op} $_->{name}" . (defined $_->{value} ? " $_->{value}" : "") } @{$q->{rr}}) . " zone=$q->{zone}";
	return undef if $mode eq 'down';
	return bless { rcode => 'REFUSED' }, 'Stub::Packet' if $mode eq 'refuse';
	foreach my $rr (@{$q->{rr}}) {
	    return bless { rcode => 'REFUSED' }, 'Stub::Packet' if defined $Stub::RefuseValue && ($rr->{value} // '') eq $Stub::RefuseValue;
	    return bless { rcode => 'REFUSED' }, 'Stub::Packet' if $Stub::RefuseDel && $rr->{op} eq 'del';
	}
	foreach my $rr (@{$q->{rr}}) {
	    push @Stub::Log, "$rr->{op} $rr->{name}" . (defined $rr->{value} ? " $rr->{value}" : "");
	    push @Stub::AllLog, $Stub::Log[-1];
	    my $set = $Stub::Served{$ns}{$rr->{name}} ||= {};
	    if ($rr->{op} eq 'add') { $set->{$rr->{value}} = 1 }
	    elsif (defined $rr->{value}) { delete $set->{$rr->{value}} }
	    else { %$set = () }
	}
	$Stub::SinceUpdate = 0 if $ns eq $Stub::Primary[0];
	return bless { rcode => 'NOERROR' }, 'Stub::Packet';
    }
    if (($type // '') eq 'CNAME') {	# recursive, one hop
	my $t = $Stub::NoAlias ? undef : Stub::alias($q);
	return bless { answer => [ defined $t ? (bless { type => 'CNAME', cname => $t }, 'Stub::RR') : () ] }, 'Stub::Packet';
    }
    if (($type // '') eq 'SOA') {	# recursive
	my $soa = bless { type => 'SOA', owner => Stub::zone_of($q) }, 'Stub::RR';
	return bless +{ ($soa->{owner} eq $q ? 'answer' : 'authority') => [$soa] }, 'Stub::Packet';
    }
    Stub::tick();
    my $ns = $s->{ns}[0];
    return undef if Stub::mode($ns) eq 'down';
    return bless { answer => [ map { bless { type => 'TXT', txt => $_ }, 'Stub::RR' } Stub::values_on($ns, $q) ] }, 'Stub::Packet';
}
sub query {
    my ($s, $zone, $type) = @_;
    return undef if $Stub::NSLookupFails;
    return bless { answer => [ map { bless { type => 'NS', ns => $_ }, 'Stub::RR' } @Stub::Primary, @Stub::Secondary ] }, 'Stub::Packet';
}

package Stub::Packet;
sub header { $_[0] }
sub rcode { $_[0]{rcode} }
sub answer { @{$_[0]{answer} || []} }
sub authority { @{$_[0]{authority} || []} }

package Stub::RR;
sub type { $_[0]{type} }
sub txtdata { $_[0]{txt} }
sub nsdname { $_[0]{ns} }
sub cname { $_[0]{cname} }
sub owner { $_[0]{owner} }

# ---- stub Crypt::LE ------------------------------------------------------

package Crypt::LE;
$INC{'Crypt/LE.pm'} = 1;
$INC{'Crypt/OpenSSL/RSA.pm'} = 1;	# load_le() requires it for its padding shim
our (@Names, $VerifyFails, $Verified, @SeenAtVerify, $CSRNames);
sub OK { 0 }
sub new { bless {}, shift }
sub error_details { $_[0]{err} || 'stub error' }
sub load_account_key { 0 }
sub load_csr { $CSRNames = $_[2]; 0 }
sub register { 0 }
sub accept_tos { 0 }
sub request_challenge { 0 }
sub accept_challenge {
    my ($s, $cb, $p, $type) = @_;
    my $failed = 0;
    foreach my $d (@Names) {
	(my $host = $d) =~ s/^\*\.//;
	# The record value differs per name, as a real key authorization does.
	(my $rec = "rec-$d") =~ s/\*/w/g;
	$failed++ if !$cb->({ domain => $d, host => $host, record => $rec }, $p);
    }
    $s->{err} = "challenge callback failed" if $failed;
    return $failed ? 1 : 0;
}
sub verify_challenge {
    my ($s) = @_;
    $Verified = 1;
    Stub::tick();	# Let's Encrypt querying is a query too
    # What Let's Encrypt would find, whichever nameserver it asked.
    @SeenAtVerify = ();
    my $missing = 0;
    foreach my $d (@Names) {
	(my $host = $d) =~ s/^\*\.//;
	(my $rec = "rec-$d") =~ s/\*/w/g;
	my $target = Stub::final_target("_acme-challenge.$host") . ".";
	foreach my $ns (@Stub::Primary, @Stub::Secondary) {
	    next if Stub::mode($ns) eq 'down';	# resolvers move on to another server
	    my $ok = grep { $_ eq $rec } Stub::values_on($ns, $target);
	    push @SeenAtVerify, "$ns $rec " . ($ok ? 1 : 0);
	    $missing++ if !$ok;
	}
    }
    $s->{err} = "stub: $missing value(s) not served at verification" if $missing;
    return ($missing || $VerifyFails) ? 1 : 0;
}
sub request_certificate { 0 }
sub request_issuer_certificate { 0 }
sub certificate { "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----" }
sub issuer { "-----BEGIN CERTIFICATE-----\nstub-issuer\n-----END CERTIFICATE-----" }

# ---- load snif-certd without running its loop ----------------------------

package main;

my $tree = tempdir(CLEANUP => 1);
mkdir "$tree/$_" foreach qw(etc csr crt log var);
$ENV{SNIF_CA_PROXY} = $tree;

open(my $fh, '<', $certd) or die "$certd: $!";
my $src = do { local $/; <$fh> };
close $fh;
# A snif-certd from before the loader guard: stop it before the daemon loop.
$src =~ s/^close STDERR;$/return 1;\nclose STDERR;/m if $src !~ /^return 1 if caller;$/m;
{
    package main;
    no strict; no warnings;
    eval $src;
    die "loading $certd: $@" if $@;
}
$main::DNSPoll = 0 if defined $main::DNSPoll;
$main::DNSWait = 0 if defined $main::DNSWait;

my $n = 0;
sub attempt {
    my (@names) = @_;
    Stub::reset();
    @Crypt::LE::Names = @names;
    $Crypt::LE::VerifyFails = 0;
    $Crypt::LE::Verified = 0;
    my $dom = "snif-" . ++$n . ".example.test";
    open(my $t, '>', "$tree/etc/example.test.tsig"); close $t;
    open(my $c, '>', "$tree/csr/$dom.csr"); print $c "stub csr\n"; close $c;
    return $dom;
}
sub run {
    my ($dom) = @_;
    unlink "$tree/log/$dom.log", "$tree/crt/$dom.crt", "$tree/crt/$dom.err";
    local *STDERR;
    open(STDERR, '>>', "$tree/log/stderr");
    main::getcert($dom);
}
sub issued { -s "$tree/crt/$_[0].crt" }
sub err { my $f = "$tree/crt/$_[0].err"; return -e $f ? do { open(my $e, '<', $f); local $/; <$e> } : '' }
sub leftover { return map { my $ns = $_; map { "$ns $_" } map { my $n = $_; map { "$n=$_" } Stub::values_on($ns, $n) } keys %{$Stub::Served{$ns} || {}} } (@_ ? @_ : @Stub::Primary) }
sub updlog { join('; ', @Stub::UpdLog) }

# 1. Apex and wildcard: two values on one name, both served when verified.
{
    my $d = attempt('*.x.example.test', 'x.example.test');
    $Stub::Served{'ns.example.test'}{'snif-pool.example.test.'}{'other-attempt'} = 1;
    run($d);
    check(issued($d), "apex+wildcard: issued");
    check(!grep(/ 0$/, @Crypt::LE::SeenAtVerify), "apex+wildcard: both values on both nameservers at verification (" . join('; ', @Crypt::LE::SeenAtVerify) . ")");
    my @left = leftover();
    check(scalar(@left == 1 && $left[0] =~ /=other-attempt$/), "apex+wildcard: own values removed, another attempt's value kept (" . join('; ', @left) . ")");
}

# 2. The secondary lags: verification waits until it serves the values.
{
    my $d = attempt('*.x.example.test', 'x.example.test');
    $Stub::Lag = 3;
    $main::DNSWait = 30;
    run($d);
    check(issued($d), "secondary lag: issued");
    check(!grep(/ 0$/, @Crypt::LE::SeenAtVerify), "secondary lag: verified only once ns2 served both values");
    $main::DNSWait = 0;
}

# 3. The secondary never catches up: no verification, error recorded, cleaned.
{
    my $d = attempt('*.x.example.test', 'x.example.test');
    $Stub::Lag = undef;
    run($d);
    check(!issued($d), "secondary stuck: not issued");
    check(!$Crypt::LE::Verified, "secondary stuck: Let's Encrypt was not asked to verify");
    check(scalar(err($d) =~ /^wait_challenges: not served .*ns2\.example\.test/), "secondary stuck: .err names the nameserver (" . (err($d) =~ s/\s+$//r) . ")");
    check(!leftover(), "secondary stuck: records removed");
}

# 4. The second update is refused: the first value added is still removed.
{
    my $d = attempt('*.x.example.test', 'x.example.test');
    $Stub::RefuseValue = 'rec-x.example.test';
    run($d);
    check(!issued($d), "update refused: not issued");
    check(!leftover(), "update refused: the value that was added is removed (" . join('; ', @Stub::Log) . ")");
}

# 5. Verification fails: records removed, error recorded.
{
    my $d = attempt('*.x.example.test');
    $Crypt::LE::VerifyFails = 1;
    run($d);
    check(scalar(!issued($d) && err($d) =~ /^verify_challenge/), "verify fails: not issued, .err from verify_challenge");
    check(!leftover(), "verify fails: records removed");
}

# 6. The NS set cannot be looked up: issuance is not blocked on it.
{
    my $d = attempt('*.x.example.test');
    $Stub::NSLookupFails = 1;
    run($d);
    check(issued($d), "no NS lookup: issued without waiting");
}

# 8. The alias of _acme-challenge.<host> leads to another zone: the value goes
# to the alias target, in that zone, and is removed from it.
{
    my $d = attempt('*.x.example.test');
    $Stub::Alias{'_acme-challenge.x.example.test'} = 'snif-pool.pool.test';
    $Stub::ZoneOf{'snif-pool.pool.test'} = 'snif-pool.pool.test';
    run($d);
    check(issued($d), "alias: issued");
    check(scalar(grep { /^ns\.example\.test accept add snif-pool\.pool\.test\. \S+ zone=snif-pool\.pool\.test$/ } @Stub::UpdLog),
	"alias: the value went to the alias target, in its own zone (" . updlog() . ")");
    check(!leftover(), "alias: removed");
}

# 9. A chain of two aliases is followed to its end.
{
    my $d = attempt('*.x.example.test');
    $Stub::Alias{'_acme-challenge.x.example.test'} = 'hop.other.test';
    $Stub::Alias{'hop.other.test'} = 'snif-pool.pool.test';
    $Stub::ZoneOf{'snif-pool.pool.test'} = 'snif-pool.pool.test';
    run($d);
    check(scalar(issued($d) && grep { / add snif-pool\.pool\.test\. .*zone=snif-pool\.pool\.test$/ } @Stub::UpdLog),
	"alias chain: followed to the last name (" . updlog() . ")");
}

# 10. The alias cannot be followed: snif-pool.<base> in zone <base>, as before.
{
    my $d = attempt('*.x.example.test');
    $Stub::NoAlias = 1;
    run($d);
    check(scalar(issued($d) && grep { / add snif-pool\.example\.test\. .*zone=example\.test$/ } @Stub::UpdLog),
	"no alias: falls back to snif-pool.<base> (" . updlog() . ")");
}

# 11. Two independent masters: the value goes to both and is removed from both.
{
    my $d = attempt('*.x.example.test', 'x.example.test');
    $Stub::UpdateMode{'ns2.example.test'} = 'accept';
    $Stub::Lag = undef;
    run($d);
    check(issued($d), "two masters: issued");
    check(!grep(/ 0$/, @Crypt::LE::SeenAtVerify), "two masters: both serve both values at verification");
    my @left = leftover(@Stub::Primary, @Stub::Secondary);
    check(!@left, "two masters: removed from both (" . join('; ', @left) . ")");
}

# 12. A nameserver is down: the attempt neither waits on it nor fails, and no
# removal is sent to it.
{
    my $d = attempt('*.x.example.test');
    $Stub::UpdateMode{'ns2.example.test'} = 'down';
    $Stub::Lag = undef;
    $main::DNSWait = 30;
    my $t0 = time;
    run($d);
    $main::DNSWait = 0;
    check(issued($d), "one server down: issued");
    check(time - $t0 < 5, "one server down: not waited on");
    check(!grep(/^ns2\.example\.test \S+ del /, @Stub::UpdLog), "one server down: no removal sent to it");
    check(!leftover(), "one server down: removed from the server that took it");
}

# 13. Every nameserver is down: not issued.
{
    my $d = attempt('*.x.example.test');
    $Stub::UpdateMode{$_} = 'down' foreach (@Stub::Primary, @Stub::Secondary);
    run($d);
    check(scalar(!issued($d) && err($d) =~ /^accept_challenge/), "all servers down: not issued, .err from accept_challenge");
}

# 14. A removal that fails is kept and done after a later attempt.
{
    my $d = attempt('*.x.example.test');
    $Stub::RefuseDel = 1;
    run($d);
    check(scalar(issued($d) && leftover() && -s $main::PendingFile), "failed removal: kept in $main::PendingFile");
    $Stub::RefuseDel = 0;
    { local *STDERR; open(STDERR, '>>', "$tree/log/stderr"); main::cleanup_challenges(); }
    check(scalar(!leftover() && !-e $main::PendingFile), "failed removal: done on the next cleanup");
}

# 15. A removal that keeps failing is given up after $PendingDays.
{
    attempt('*.x.example.test');
    $Stub::Served{'ns.example.test'}{'snif-pool.example.test.'}{'stale'} = 1;
    open(my $p, '>', $main::PendingFile);
    print $p join("\t", 1, 'example.test', 'ns.example.test', "$tree/etc/example.test.tsig", 'snif-pool.example.test.', 'stale'), "\n";
    close $p;
    $Stub::RefuseDel = 1;
    { local *STDERR; open(STDERR, '>>', "$tree/log/stderr"); main::cleanup_challenges(); }
    check(!-e $main::PendingFile, 'stale removal: given up after $PendingDays days');
}

# 16. An init origin (etc/<origin>.domains) gets a certificate for its own
#     name, not the wildcard, by DNS-01 through its own challenge name.
my $origin = 'snif.example.test';
sub origin_attempt {
    attempt($origin);
    open(my $f, '>', "$tree/etc/$origin.domains"); print $f "example.test\n"; close $f;
    open(my $c, '>', "$tree/csr/$origin.csr"); print $c "stub csr\n"; close $c;
    $Crypt::LE::CSRNames = undef;
}
{
    origin_attempt();
    run($origin);
    check(issued($origin), "origin: issued");
    check(($Crypt::LE::CSRNames // '') eq $origin, "origin: the CSR is checked for the name itself (" . ($Crypt::LE::CSRNames // 'none') . ")");
    check($main::mode eq 'dns' && @Crypt::LE::SeenAtVerify && !grep(/ 0$/, @Crypt::LE::SeenAtVerify),
	"origin: DNS-01, the value served at its challenge alias ($main::mode; " . join('; ', @Crypt::LE::SeenAtVerify) . ")");
    my $d = attempt('*.x.example.test');
    run($d);
    check(($Crypt::LE::CSRNames // '') eq "*.$d", "device zone beside an origin: still the wildcard");
}

# 17. An origin under a local-CA base domain still issues from Let's Encrypt;
#     the base's device zones still issue locally.
{
    origin_attempt();
    open(my $p, '>', "$tree/etc/example.test.pub-ca"); close $p;
    run($origin);
    check(issued($origin) && $main::mode eq 'dns', "origin under a local CA: Let's Encrypt ($main::mode)");
    my $d = attempt('*.x.example.test');
    run($d);
    check($main::mode eq 'local', "device zone under that local CA: local ($main::mode)");
    unlink "$tree/etc/example.test.pub-ca", "$tree/etc/$origin.domains";
}

# 7. Updates only ever delete a specific value, never the whole RRset.
check(!grep(/^del \S+$/, @Stub::AllLog), "no RRset-wide delete in any update (" . scalar(@Stub::AllLog) . " updates)");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
