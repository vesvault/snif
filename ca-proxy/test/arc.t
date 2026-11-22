#!/usr/bin/perl
#
# snif-arc: archiving and the retention periods (README, "snif-arc"), on a
# scratch CA proxy tree, with SNIF_ARC_NOW standing in for the clock.
#
#   perl ca-proxy/test/arc.t [path/to/snif-arc]
#
# Needs openssl and GNU date, find and touch. Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use FindBin;

my $arc = shift || "$FindBin::Bin/../bin/snif-arc";
$| = 1;
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

my $T = tempdir(CLEANUP => !$ENV{ARC_KEEP});
print "# tree $T\n" if $ENV{ARC_KEEP};
my $D = 86400;
my $Real = time;
# The clock snif-arc sees: 400 days from now, so that a certificate issued
# today for 1 day expired 399 days before it, and one for 200 days, 200.
my $Now = $Real + 400 * $D;

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d, $age) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
    utime($Now - $age, $Now - $age, $p) if defined $age;
}
sub mtime { (stat $_[0])[9] }
sub day { my @t = gmtime($_[0]); sprintf('%04d%02d%02d', $t[5] + 1900, $t[4] + 1, $t[3]) }
sub cert {
    my ($days) = @_;
    my $k = "$T/key.pem";
    my $pem = `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout '$k' -subj /CN=snif-test -days $days 2>/dev/null`;
    die "openssl req failed\n" if $pem !~ /BEGIN CERTIFICATE/;
    return $pem;
}
my $Short = cert(1);	# expired 399 days before $Now
my $Long = cert(200);	# expired 200 days before $Now
my $Cur = cert(460);	# 60 days left at $Now
my $Left20 = cert(420);	# 20 days left
my $Left10 = cert(410);	# 10 days left
my $Left8 = cert(408);	# 8 days left
my $Left3 = cert(403);	# 3 days left

sub run {
    my ($base, %set) = @_;
    local %ENV = (%ENV, SNIF_CA_PROXY => $base, SNIF_ARC_NOW => $Now, %set);
    delete @ENV{grep { /^SNIF_ARC_.*_DAYS$/ && !exists $set{$_} } keys %ENV};
    my $out = `'$arc' 2>&1`;
    return ($? >> 8, $out);
}

# ---- one tree with every period set ---------------------------------------------
my $B = "$T/ca";
make_path(map { "$B/$_" } qw(cfg csr auth crt log arc etc var));
my $E = day($Now - 300 * $D);	# an archive day 300 days back
my $A = day($Now - 200 * $D);	# 200 days back
my $M = day($Now - 100 * $D);	# 100 days back
my $R = day($Now - 10 * $D);	# 10 days back

# Devices (SNIF_ARC_DEVICE_DAYS=365).
spew("$B/cfg/dev-gone.x.test.cfg", "", 500 * $D);
spew("$B/auth/dev-gone.x.test.auth", 'user@example.com', 500 * $D);
spew("$B/csr/dev-gone.x.test.csr", "csr", 500 * $D);
spew("$B/log/dev-gone.x.test.log", "log", 450 * $D);
spew("$B/arc/$A/dev-gone.x.test.crt", $Short, 450 * $D);
spew("$B/auth/dev-down.x.test.auth", 'user@example.com', 500 * $D);
spew("$B/arc/$A/dev-down.x.test.crt", $Long, 450 * $D);
spew("$B/auth/dev-live.x.test.auth", '1', 500 * $D);
spew("$B/crt/dev-live.x.test.crt", $Cur, 10 * $D);
spew("$B/auth/dev-noissue-old.x.test.auth", '1', 400 * $D);
spew("$B/cfg/dev-noissue-old.x.test.cfg", "", 400 * $D);
spew("$B/auth/dev-noissue-new.x.test.auth", '1', 100 * $D);
# Archiving, by the certificate's expiry: one with less than 14 days left
# moves, however young its file (a 64-day certificate, 54 days on); one with
# more stays, however old (a 100-day one, 80 days on); a file under 14 days
# old is not read; a root bundle stays.
spew("$B/auth/dev-arch.x.test.auth", '1', 300 * $D);
spew("$B/crt/dev-arch.x.test.crt", $Left10, 54 * $D);
spew("$B/auth/dev-keep.x.test.auth", '1', 300 * $D);
spew("$B/crt/dev-keep.x.test.crt", $Left20, 80 * $D);
spew("$B/auth/dev-young.x.test.auth", '1', 300 * $D);
spew("$B/crt/dev-young.x.test.crt", $Long, 5 * $D);
spew("$B/crt/mesh.x.test.crt", $Long, 200 * $D);
spew("$B/etc/mesh.x.test.pub-ca", "ca");
# Not renewed: an archived certificate with less than 5 days left and none
# newer in crt/ is reported; one renewed, or with more left, is not.
spew("$B/auth/due-soon.x.test.auth", '1', 300 * $D);
spew("$B/arc/$R/due-soon.x.test.crt", $Left3, 61 * $D);
spew("$B/auth/due-renewed.x.test.auth", '1', 300 * $D);
spew("$B/arc/$R/due-renewed.x.test.crt", $Left3, 61 * $D);
spew("$B/crt/due-renewed.x.test.crt", $Cur, 4 * $D);
spew("$B/auth/due-later.x.test.auth", '1', 300 * $D);
spew("$B/arc/$R/due-later.x.test.crt", $Left8, 56 * $D);
# Names never approved (SNIF_ARC_UNAPPROVED_DAYS=30).
spew("$B/cfg/un-old.x.test.cfg", "purpose=test\n", 31 * $D);
spew("$B/csr/un-old.x.test.csr", "csr", 31 * $D);
spew("$B/cfg/un-new.x.test.cfg", "", 10 * $D);
spew("$B/cfg/un-issued.x.test.cfg", "", 40 * $D);
spew("$B/crt/un-issued.x.test.crt", $Long, 5 * $D);
spew("$B/cfg/un-arc.x.test.cfg", "", 40 * $D);
spew("$B/arc/$R/un-arc.x.test.crt", $Long, 85 * $D);
# Older archived copies (SNIF_ARC_OLD_DAYS=90).
spew("$B/auth/multi.x.test.auth", '1', 20 * $D);
spew("$B/arc/$A/multi.x.test.crt", $Long, 280 * $D);
spew("$B/arc/$M/multi.x.test.crt", $Long, 180 * $D);
spew("$B/arc/$R/multi.x.test.crt", $Long, 85 * $D);
spew("$B/auth/single.x.test.auth", '1', 20 * $D);
spew("$B/arc/$M/single.x.test.crt", $Long, 180 * $D);
spew("$B/auth/emptied.x.test.auth", '1', 20 * $D);
spew("$B/arc/$E/emptied.x.test.crt", $Long, 380 * $D);
spew("$B/arc/$R/emptied.x.test.crt", $Long, 85 * $D);
# Approvals and counters (SNIF_ARC_AUTH_DAYS=30).
spew("$B/auth/ok-old.x.test.auth", 'old@example.com', 40 * $D);
chmod(0640, "$B/auth/ok-old.x.test.auth");
spew("$B/auth/ok-new.x.test.auth", 'new@example.com', 10 * $D);
spew("$B/auth/ok-one.x.test.auth", '1', 40 * $D);
spew("$B/auth/.ok-old.x.test.auth.syncd99+", 'temp@example.com', 40 * $D);
my ($t60, $t40, $t5, $t2) = map { $Now - $_ * $D } (60, 40, 5, 2);
spew("$B/auth/ves/n1/user\@example.com", "*** $t60\n$t40\n$t5\n**", 2 * $D);
spew("$B/auth/ves/n1/gone\@example.com", "$t60\n$t40\n", 40 * $D);
spew("$B/auth/ves/n1/same\@example.com", "$t5\n", 5 * $D);
spew("$B/auth/ves/single\@example.com", "$t40\n", 40 * $D);
spew("$B/auth/captcha/n1/day-20250101", "3", 40 * $D);
spew("$B/auth/captcha/n1/ip-20250101-" . ('a' x 32), "1", 40 * $D);
spew("$B/auth/captcha/n1/day-20990101", "1", 5 * $D);
spew("$B/auth/captcha/n1/net-20250101-" . ('b' x 32), "1", 40 * $D);
spew("$B/auth/captcha/n1/dom-20250101-x.test", "2", 40 * $D);
spew("$B/auth/captcha/n1/dom-20990101-x.test", "1", 5 * $D);
spew("$B/auth/captcha/n1/notes", "kept", 40 * $D);

my $before_ok = mtime("$B/auth/ok-old.x.test.auth");
my $before_user = mtime("$B/auth/ves/n1/user\@example.com");
my $before_same = mtime("$B/auth/ves/n1/same\@example.com");
my ($rc, $out) = run($B, SNIF_ARC_DEVICE_DAYS => 365, SNIF_ARC_UNAPPROVED_DAYS => 30,
    SNIF_ARC_OLD_DAYS => 90, SNIF_ARC_AUTH_DAYS => 30);
my @out = split /\n/, $out;
my $Due = qr/^snif-arc: due-soon\.x\.test: not renewed, its certificate expires \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
check($rc == 0, "a run with every period set exits 0 ($rc)");
check(@out == 2 && $out[1] eq "snif-arc: archived 1, not renewed 1, devices removed 2, unapproved names removed 1, older archived copies removed 3, approvals cleared 2, counter files trimmed 7",
    "and reports what it did: $out");
check(@out == 2 && $out[0] =~ $Due, "a name whose certificate has 3 days left, and no newer one, is reported: $out[0]");

check(!grep({ -e "$B/$_" } qw(cfg/dev-gone.x.test.cfg auth/dev-gone.x.test.auth csr/dev-gone.x.test.csr log/dev-gone.x.test.log), "arc/$A/dev-gone.x.test.crt"),
    "a device whose newest certificate expired over a year ago: every file removed");
check(-e "$B/auth/dev-down.x.test.auth" && -e "$B/arc/$A/dev-down.x.test.crt", "one whose certificate expired 200 days ago: kept");
check((slurp("$B/auth/dev-down.x.test.auth") // '') eq '1', "and its approval, 500 days old, no longer names the account");
check(-e "$B/auth/dev-live.x.test.auth" && -e "$B/crt/dev-live.x.test.crt", "one with a current certificate: kept");
check(!-e "$B/auth/dev-noissue-old.x.test.auth" && !-e "$B/cfg/dev-noissue-old.x.test.cfg", "approved 400 days ago and never issued: removed");
check(-e "$B/auth/dev-noissue-new.x.test.auth", "approved 100 days ago and never issued: kept");
my $Today = day($Now);
check(!-e "$B/crt/dev-arch.x.test.crt" && -e "$B/arc/$Today/dev-arch.x.test.crt" && -e "$B/auth/dev-arch.x.test.auth",
    "a certificate with 10 days left, its file 54 days old, is archived, and its device kept");
check(-e "$B/crt/dev-keep.x.test.crt", "one with 20 days left, its file 80 days old, stays");
check(-e "$B/crt/dev-young.x.test.crt", "a file 5 days old is not read, and stays");
check(-e "$B/crt/mesh.x.test.crt", "a local CA's root bundle stays in crt/");

check(!-e "$B/cfg/un-old.x.test.cfg" && !-e "$B/csr/un-old.x.test.csr", "a name never approved, 31 days old: removed");
check(-e "$B/cfg/un-new.x.test.cfg", "one 10 days old: kept");
check(-e "$B/cfg/un-issued.x.test.cfg", "an unapproved name with a certificate (its approval yet to arrive): kept");
check(-e "$B/cfg/un-arc.x.test.cfg", "one with an archived certificate: kept");

check(!-e "$B/arc/$A/multi.x.test.crt" && !-e "$B/arc/$M/multi.x.test.crt" && -e "$B/arc/$R/multi.x.test.crt",
    "older archived copies archived over 90 days ago removed, the newest kept");
check(-e "$B/arc/$M/single.x.test.crt", "a name's only archived copy kept, however old");
check(!-e "$B/arc/$E/emptied.x.test.crt" && -e "$B/arc/$R/emptied.x.test.crt", "an older copy 300 days back removed");
check(!-e "$B/arc/$E" && -d "$B/arc/$A", "the archive day it leaves empty is removed, one still holding a copy stays");

check((slurp("$B/auth/ok-old.x.test.auth") // '') eq '1', "an approval 40 days old no longer names the account");
check(mtime("$B/auth/ok-old.x.test.auth") == $before_ok && ((stat "$B/auth/ok-old.x.test.auth")[2] & 07777) == 0640,
    "and keeps its modification time and mode");
check((slurp("$B/auth/ok-new.x.test.auth") // '') eq 'new@example.com', "one 10 days old still does");
check((slurp("$B/auth/.ok-old.x.test.auth.syncd99+") // '') eq 'temp@example.com', "a file being written is left alone");
check((slurp("$B/auth/ves/n1/user\@example.com") // '') eq "$t5\n** $t2\n",
    "a counter keeps its last 30 days, and a run without a time gets the file's");
check(mtime("$B/auth/ves/n1/user\@example.com") == $before_user, "and keeps its modification time");
check(!-e "$B/auth/ves/n1/gone\@example.com", "a counter with nothing recent is removed");
check(!-e "$B/auth/ves/single\@example.com", "so is one in a single relay's auth/ves/");
check(mtime("$B/auth/ves/n1/same\@example.com") == $before_same, "a recent counter is not rewritten");
check(!-e "$B/auth/captcha/n1/day-20250101" && !-e "$B/auth/captcha/n1/ip-20250101-" . ('a' x 32) && -e "$B/auth/captcha/n1/day-20990101",
    "captcha counters over 30 days old removed, a recent one kept");
check(!-e "$B/auth/captcha/n1/net-20250101-" . ('b' x 32) && !-e "$B/auth/captcha/n1/dom-20250101-x.test"
    && -e "$B/auth/captcha/n1/dom-20990101-x.test", "so are a /48's and a domain's");
check(-e "$B/auth/captcha/n1/notes", "and a file with no counter's name is left, however old");

($rc, $out) = run($B, SNIF_ARC_DEVICE_DAYS => 365, SNIF_ARC_UNAPPROVED_DAYS => 30,
    SNIF_ARC_OLD_DAYS => 90, SNIF_ARC_AUTH_DAYS => 30);
@out = split /\n/, $out;
check($rc == 0 && @out == 2 && $out[0] =~ $Due
    && $out[1] eq "snif-arc: archived 0, not renewed 1, devices removed 0, unapproved names removed 0, older archived copies removed 0, approvals cleared 0, counter files trimmed 0",
    "a second run finds nothing more, and reports the name not renewed again: $out");

# ---- the same kind of tree with no period set ----------------------------------
my $C = "$T/plain";
make_path(map { "$C/$_" } qw(cfg csr auth crt log arc etc var));
spew("$C/cfg/un-old.x.test.cfg", "", 31 * $D);
spew("$C/auth/dev-gone.x.test.auth", 'user@example.com', 500 * $D);
spew("$C/arc/$A/dev-gone.x.test.crt", $Short, 450 * $D);
spew("$C/arc/$M/dev-gone.x.test.crt", $Short, 300 * $D);
spew("$C/auth/ves/n1/gone\@example.com", "$t60\n", 40 * $D);
spew("$C/crt/dev-arch.x.test.crt", $Long, 80 * $D);
($rc, $out) = run($C);
chomp $out;
check($rc == 0 && $out eq "snif-arc: archived 1", "with no period set it only archives: $out");
check(!grep({ !-e "$C/$_" } qw(cfg/un-old.x.test.cfg auth/dev-gone.x.test.auth auth/ves/n1/gone@example.com), "arc/$A/dev-gone.x.test.crt", "arc/$M/dev-gone.x.test.crt")
    && (slurp("$C/auth/dev-gone.x.test.auth") // '') eq 'user@example.com',
    "and removes or changes nothing else");
($rc, $out) = run($C, SNIF_ARC_AUTH_DAYS => 'thirty');
check($rc == 0 && $out =~ /SNIF_ARC_AUTH_DAYS='thirty' is not a number of days, ignored/ && (slurp("$C/auth/dev-gone.x.test.auth") // '') eq 'user@example.com',
    "a period that is not a number is reported and ignored");

# ---- a file in crt/ that is not a certificate ------------------------------------
my $F = "$T/bad";
make_path(map { "$F/$_" } qw(cfg csr auth crt log arc etc var));
spew("$F/crt/garbled.x.test.crt", "not a certificate\n", 20 * $D);
spew("$F/crt/new-garbled.x.test.crt", "not a certificate\n", 5 * $D);
($rc, $out) = run($F);
@out = split /\n/, $out;
check($rc == 1 && @out == 2 && $out[0] eq "snif-arc: crt/garbled.x.test.crt: no expiry openssl can read, archived"
    && $out[1] eq "snif-arc: archived 1, FAILED 1", "a file with no expiry openssl can read is archived, reported, and the run fails: $out");
check(!-e "$F/crt/garbled.x.test.crt" && -e "$F/arc/$Today/garbled.x.test.crt" && -e "$F/crt/new-garbled.x.test.crt",
    "it is moved to arc/; one under 14 days old is not read");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
