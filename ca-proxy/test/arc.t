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
spew("$B/crt/dev-live.x.test.crt", $Long, 10 * $D);
spew("$B/auth/dev-noissue-old.x.test.auth", '1', 400 * $D);
spew("$B/cfg/dev-noissue-old.x.test.cfg", "", 400 * $D);
spew("$B/auth/dev-noissue-new.x.test.auth", '1', 100 * $D);
# Archiving: a certificate over 75 days old moves; a root bundle stays.
spew("$B/auth/dev-arch.x.test.auth", '1', 300 * $D);
spew("$B/crt/dev-arch.x.test.crt", $Long, 80 * $D);
spew("$B/crt/mesh.x.test.crt", $Long, 200 * $D);
spew("$B/etc/mesh.x.test.pub-ca", "ca");
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

my $before_ok = mtime("$B/auth/ok-old.x.test.auth");
my $before_user = mtime("$B/auth/ves/n1/user\@example.com");
my $before_same = mtime("$B/auth/ves/n1/same\@example.com");
my ($rc, $out) = run($B, SNIF_ARC_DEVICE_DAYS => 365, SNIF_ARC_UNAPPROVED_DAYS => 30,
    SNIF_ARC_OLD_DAYS => 90, SNIF_ARC_AUTH_DAYS => 30);
chomp $out;
check($rc == 0, "a run with every period set exits 0 ($rc)");
check($out eq "snif-arc: archived 1, devices removed 2, unapproved names removed 1, older archived copies removed 3, approvals cleared 2, counter files trimmed 5",
    "and reports what it did: $out");

check(!grep({ -e "$B/$_" } qw(cfg/dev-gone.x.test.cfg auth/dev-gone.x.test.auth csr/dev-gone.x.test.csr log/dev-gone.x.test.log), "arc/$A/dev-gone.x.test.crt"),
    "a device whose newest certificate expired over a year ago: every file removed");
check(-e "$B/auth/dev-down.x.test.auth" && -e "$B/arc/$A/dev-down.x.test.crt", "one whose certificate expired 200 days ago: kept");
check((slurp("$B/auth/dev-down.x.test.auth") // '') eq '1', "and its approval, 500 days old, no longer names the account");
check(-e "$B/auth/dev-live.x.test.auth" && -e "$B/crt/dev-live.x.test.crt", "one with a current certificate: kept");
check(!-e "$B/auth/dev-noissue-old.x.test.auth" && !-e "$B/cfg/dev-noissue-old.x.test.cfg", "approved 400 days ago and never issued: removed");
check(-e "$B/auth/dev-noissue-new.x.test.auth", "approved 100 days ago and never issued: kept");
my $Today = day($Now);
check(!-e "$B/crt/dev-arch.x.test.crt" && -e "$B/arc/$Today/dev-arch.x.test.crt" && -e "$B/auth/dev-arch.x.test.auth",
    "a certificate 80 days old is archived, and its device kept");
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

($rc, $out) = run($B, SNIF_ARC_DEVICE_DAYS => 365, SNIF_ARC_UNAPPROVED_DAYS => 30,
    SNIF_ARC_OLD_DAYS => 90, SNIF_ARC_AUTH_DAYS => 30);
chomp $out;
check($rc == 0 && $out eq "snif-arc: archived 0, devices removed 0, unapproved names removed 0, older archived copies removed 0, approvals cleared 0, counter files trimmed 0",
    "a second run finds nothing more: $out");

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

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
