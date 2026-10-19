#!/usr/bin/perl
#
# snifdog's state directory: the default per configuration, the one-base-per-
# directory guard, the pass lock, and the cron.d loop over every
# configuration. Needs no network: nothing here reaches a CT source.
#
#   perl snifdog/test/state.t [path/to/snifdog]
#
# Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Fcntl qw(:flock);
use FindBin;

my $snifdog = shift || "$FindBin::Bin/../bin/snifdog";
my $crond = "$FindBin::Bin/../etc/cron.d/snifdog";
my $mkdirs = "$FindBin::Bin/../mkdirs";
my ($pass, $fail) = (0, 0);

sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

sub put {
    my ($path, $text) = @_;
    (my $dir = $path) =~ s{/[^/]+$}{};
    make_path($dir);
    open my $fh, '>', $path or die "$path: $!";
    print $fh $text;
    close $fh;
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    my $s = <$fh>;
    close $fh;
    return $s;
}

# Run the real script with a configuration; returns (exit code, output).
sub run {
    my ($conf, @args) = @_;
    my $q = join ' ', map { "'$_'" } @args;
    my $out = `SNIFDOG_CONF='$conf' perl '$snifdog' $q 2>&1`;
    return ($? >> 8, $out);
}

require $snifdog;
our (%C, $StateLock);

my $tmp = tempdir(CLEANUP => 1);
my $spki = 'ab' x 32;

# ---- the default state directory -----------------------------------------

put("$tmp/d/a.example.conf", "SNIFDOG_BASE=a.example\nSNIFDOG_SYSLOG=0\n");
load_conf("$tmp/d/a.example.conf");
check($C{dir} eq '/var/lib/snif/snifdog/a.example',
    "a configuration in a directory defaults to /var/lib/snif/snifdog/<base>");

put("$tmp/d/upper.conf", "SNIFDOG_BASE=B.Example\nSNIFDOG_SYSLOG=0\n");
load_conf("$tmp/d/upper.conf");
check($C{dir} eq '/var/lib/snif/snifdog/b.example', "the default directory uses the base in lower case");

put("$tmp/d/explicit.conf", "SNIFDOG_BASE=a.example\nSNIFDOG_DIR=$tmp/x\nSNIFDOG_SYSLOG=0\n");
load_conf("$tmp/d/explicit.conf");
check($C{dir} eq "$tmp/x", "an explicit SNIFDOG_DIR wins");

if (!-e '/etc/snif/snifdog.conf') {
    load_conf('/etc/snif/snifdog.conf');
    check($C{dir} eq '/var/lib/snif/snifdog', "the legacy /etc/snif/snifdog.conf keeps /var/lib/snif/snifdog");
} else {
    print "skip - /etc/snif/snifdog.conf exists on this host, legacy default not checked\n";
}

put("$tmp/d/bad.conf", "SNIFDOG_BASE=../etc\n");
check(!eval { load_conf("$tmp/d/bad.conf"); 1 } && $@ =~ /not a domain name/,
    "a base that is not a domain name is refused");

# ---- one base per state directory ----------------------------------------

put("$tmp/a.conf", "SNIFDOG_BASE=a.example\nSNIFDOG_DIR=$tmp/s\nSNIFDOG_SYSLOG=0\n");
put("$tmp/b.conf", "SNIFDOG_BASE=b.example\nSNIFDOG_DIR=$tmp/s\nSNIFDOG_SYSLOG=0\n");

load_conf("$tmp/a.conf");
my @r = state_claim();
check($r[0], "a new state directory is claimed");
check((slurp("$tmp/s/var/base") // '') eq "a.example\n", "the claim records its base in var/base");
close $StateLock;

load_conf("$tmp/b.conf");
@r = state_claim();
check(!$r[0] && !$r[2] && $r[1] =~ /belongs to a\.example/, "another base is refused the directory");
close $StateLock if $StateLock;

my ($rc, $out) = run("$tmp/b.conf", 'pin', '*.snif-1.b.example', '--spki', $spki);
check($rc == 78, "snifdog pin for another base exits 78 (got $rc)");

# An older directory with no var/base: adopted only by the base its pins are for.
put("$tmp/oa.conf", "SNIFDOG_BASE=a.example\nSNIFDOG_DIR=$tmp/old\nSNIFDOG_SYSLOG=0\n");
put("$tmp/ob.conf", "SNIFDOG_BASE=b.example\nSNIFDOG_DIR=$tmp/old\nSNIFDOG_SYSLOG=0\n");
load_conf("$tmp/oa.conf");
pin_add('*.snif-1.a.example', $spki, source => 'test');
check(!-e "$tmp/old/var/base", "pinning alone does not claim the directory");

load_conf("$tmp/ob.conf");
@r = state_claim();
check(!$r[0] && $r[1] =~ /pin outside b\.example/, "an unclaimed directory with another base's pins is refused");
check(!-e "$tmp/old/var/base", "the refused claim records nothing");
close $StateLock if $StateLock;

load_conf("$tmp/oa.conf");
@r = state_claim();
check($r[0] && (slurp("$tmp/old/var/base") // '') eq "a.example\n",
    "an unclaimed directory is adopted by the base its pins are for");
close $StateLock;

# ---- the pass lock --------------------------------------------------------

open my $hold, '>>', "$tmp/s/var/lock" or die $!;
flock($hold, LOCK_EX) or die $!;

load_conf("$tmp/a.conf");
@r = state_claim();
check(!$r[0] && $r[2], "a held lock reads as busy");
close $StateLock if $StateLock;

($rc, $out) = run("$tmp/a.conf", 'poll');
check($rc == 0 && $out eq '', "poll on a busy directory skips quietly, exit 0, no output (got $rc)");

($rc, $out) = run("$tmp/a.conf", 'pin', '*.snif-2.a.example', '--spki', $spki);
check($rc == 75, "pin on a busy directory exits 75 (got $rc)");

close $hold;
($rc, $out) = run("$tmp/a.conf", 'pin', '*.snif-2.a.example', '--spki', $spki);
check($rc == 0 && $out =~ /pinned/, "pin works once the lock is free (got $rc)");

# ---- the cron.d loop -------------------------------------------------------

my ($line) = grep { m{^\*/15\s} } split /\n/, (slurp($crond) // '');
my ($cmd) = ($line // '') =~ /^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.*)$/;
check(defined $cmd, "the cron.d entry has a command");

put("$tmp/stub", "#!/bin/sh\necho \"\$SNIFDOG_CONF \$1\" >> '$tmp/ran'\n");
chmod 0755, "$tmp/stub";

sub cron_run {
    my ($etc) = @_;
    unlink "$tmp/ran";
    (my $c = $cmd) =~ s{/etc/snif}{$etc}g;
    $c =~ s{/usr/bin/snifdog}{$tmp/stub}g;
    system('sh', '-c', $c);
    return slurp("$tmp/ran") // '';
}

put("$tmp/e1/snifdog.conf", "SNIFDOG_BASE=snif.xyz\n");
put("$tmp/e1/snifdog.d/snif.example.conf", "SNIFDOG_BASE=snif.example\n");
put("$tmp/e1/snifdog.d/vesmail.example.conf", "SNIFDOG_BASE=vesmail.example\n");
check(cron_run("$tmp/e1") eq "$tmp/e1/snifdog.conf poll\n$tmp/e1/snifdog.d/snif.example.conf poll\n"
    . "$tmp/e1/snifdog.d/vesmail.example.conf poll\n",
    "cron runs the legacy configuration and every one in snifdog.d");

put("$tmp/e2/snifdog.d/only.example.conf", "SNIFDOG_BASE=only.example\n");
check(cron_run("$tmp/e2") eq "$tmp/e2/snifdog.d/only.example.conf poll\n",
    "cron runs snifdog.d alone when there is no legacy configuration");

make_path("$tmp/e3");
check(cron_run("$tmp/e3") eq '', "cron runs nothing when there is no configuration");

# ---- mkdirs ------------------------------------------------------------------

put("$tmp/m/etc/snifdog.conf", "SNIFDOG_BASE=snif.xyz\n");
put("$tmp/m/etc/snifdog.d/b.example.conf", "SNIFDOG_BASE=b.example\n");
put("$tmp/m/etc/snifdog.d/x.example.conf", "SNIFDOG_BASE=x.example\nSNIFDOG_DIR=$tmp/m/custom\n");
my $mk = slurp($mkdirs) // '';
$mk =~ s{/etc/snif}{$tmp/m/etc}g;
$mk =~ s{/var/lib/snif/snifdog}{$tmp/m/state}g;
put("$tmp/m/mkdirs", $mk);
system('bash', "$tmp/m/mkdirs");
check(-d "$tmp/m/state/pins" && -d "$tmp/m/state/var" && -d "$tmp/m/state/evidence",
    "mkdirs creates the legacy configuration's directories");
check(-d "$tmp/m/state/b.example/var", "mkdirs creates a snifdog.d configuration's default directory");
check(-d "$tmp/m/custom/var", "mkdirs honours an explicit SNIFDOG_DIR");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
