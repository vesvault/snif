#!/usr/bin/perl
#
# The approval counters on a scratch CA proxy tree, run by the PHP CLI under
# php-fpm's umask (0022). A root install chowns the tree to snif and
# bin/snif-arc rewrites counters as snif, so the web server's user can go on
# writing a counter only if it is group-writable:
#   - VES (inc/snif-auth-ves.php, snif_auth_ves_count()): the leaky bucket;
#     counters and a cluster node's counter directory group-writable; a
#     counter that cannot be opened refused rather than a fatal error.
#   - CAPTCHA (inc/snif-auth-captcha.php, snif_captcha_quota()): its
#     directory, a node's directory and the day's counters group-writable.
#
#   perl ca-proxy/test/auth-counters.t [path/to/ca-proxy]
#
# Needs php (cli). Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use POSIX qw(strftime);
use FindBin;

my $Src = shift || "$FindBin::Bin/..";
$| = 1;
my ($pass, $fail) = (0, 0);
sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}
die "auth-counters.t: needs php (cli)\n" if system('php -v > /dev/null 2>&1') != 0;

my $T = tempdir(CLEANUP => !$ENV{AUTH_COUNTERS_KEEP});
print "# tree $T\n" if $ENV{AUTH_COUNTERS_KEEP};

sub slurp { open(my $f, '<', $_[0]) || return undef; local $/; my $s = <$f>; close $f; $s }
sub spew {
    my ($p, $d) = @_;
    (my $dir = $p) =~ s{/[^/]+$}{};
    make_path($dir);
    open(my $f, '>', $p) || die "$p: $!";
    print $f $d;
    close $f;
}
sub mode { my @s = stat $_[0]; @s ? $s[2] & 07777 : -1 }

# Each driver counts one approval in a tree, then prints whether it was
# counted and the umask; a full VES bucket exits (429) before that.
my $Ves = "$T/ves.php";
spew($Ves, <<'EOF');
<?php
$_SERVER['DOCUMENT_ROOT'] = $argv[1] . '/secure_html';
require $argv[2] . '/inc/snif-cluster.php';
require $argv[2] . '/inc/snif-auth-ves.php';
$r = snif_auth_ves_count($argv[3]);
printf("%s %04o\n", $r ? 'counted' : 'refused', umask());
EOF
my $Captcha = "$T/captcha.php";
spew($Captcha, <<'EOF');
<?php
$_SERVER['DOCUMENT_ROOT'] = $argv[1] . '/secure_html';
require $argv[2] . '/inc/snif-cluster.php';
require $argv[2] . '/inc/snif-auth-captcha.php';
$r = snif_captcha_quota($argv[3], 'snif-ac.example.test');
printf("%s %04o\n", $r ? 'counted' : 'refused', umask());
EOF

# The exit status, stdout and stderr of a driver, run under umask 0022.
sub count {
    my ($drv, $base, $arg) = @_;
    my $old = umask(022);
    my $out = `php -d display_errors=stderr -d log_errors=0 '$drv' '$base' '$Src' '$arg' 2> '$T/err'`;
    my $rc = $? >> 8;
    umask($old);
    my $err = slurp("$T/err") // '';
    s/\s+\z// for $out, $err;
    return ($rc, $out, $err);
}

# A CA proxy tree; a cluster node's if $node is given.
sub tree {
    my ($name, $node) = @_;
    my $b = "$T/$name";
    make_path("$b/secure_html", "$b/auth/ves", "$b/etc");
    spew("$b/etc/cluster.node", "$node\n") if $node;
    return $b;
}

# ---- VES ---------------------------------------------------------------------

# A single relay counts in auth/ves/<email>.
my $S = tree('single');
my $Sa = "$S/auth/ves/a\@example.com";
my ($rc, $out, $err) = count($Ves, $S, 'a@example.com');
check($rc == 0 && $out eq "counted 0022" && $err eq '', "an approval is counted and the umask is put back: $out$err");
check(mode($Sa) == 0664, sprintf("a new counter is group-writable: %04o", mode($Sa)));
check((slurp($Sa) // '') =~ /^\d+\n\z/, "and holds the approval's time");

# A cluster node counts in auth/ves/<node>/<email>, and makes the directory.
my $C = tree('node', 'n1');
my $Ca = "$C/auth/ves/n1/a\@example.com";
($rc, $out, $err) = count($Ves, $C, 'a@example.com');
check($rc == 0 && $out eq "counted 0022" && $err eq '', "a cluster node counts it: $out$err");
check((mode("$C/auth/ves/n1") & 0777) == 0775, sprintf("in a node directory it makes group-writable: %04o", mode("$C/auth/ves/n1")));
check(mode($Ca) == 0664, sprintf("a new counter there is group-writable too: %04o", mode($Ca)));

# The bucket: a limit of 1 that never refills takes two approvals, then 429.
spew("$C/etc/ves-limit", "1 0\n");
($rc, $out, $err) = count($Ves, $C, 'a@example.com');
check($rc == 0 && $out eq "counted 0022" && $err eq '', "a second approval fits a limit of 1 that never refills: $out$err");
($rc, $out, $err) = count($Ves, $C, 'a@example.com');
check($rc == 0 && $out eq '' && $err eq '', "a third is refused (429) before anything is written: '$out$err'");
my @l = split /\n/, (slurp($Ca) // '');
check(@l == 2, "and the counter keeps two times: " . scalar(@l));
unlink "$C/etc/ves-limit";

# A counter this user cannot append to, as one a root install has chowned
# was: not counted, so snif_auth_ves() answers 403; PHP warns, nothing fatal.
my $Cb = "$C/auth/ves/n1/b\@example.com";
if ($> == 0) {
    print "# as root a read-only counter is still appended to: not checked\n";
} else {
    spew($Cb, "1700000000\n");
    chmod(0444, $Cb);
    ($rc, $out, $err) = count($Ves, $C, 'b@example.com');
    check($rc == 0 && $out eq "refused 0022", "a counter that cannot be opened is not counted: $out");
    check($err =~ /fopen\(.*Permission denied/ && $err !~ /Fatal|TypeError/, "PHP warns why, and nothing is fatal: $err");
    check((slurp($Cb) // '') eq "1700000000\n", "and the counter is left as it was");
}

# ---- CAPTCHA -----------------------------------------------------------------

# A cluster node with no auth/captcha yet: the quota makes it, and the node's.
($rc, $out, $err) = count($Captcha, $C, '192.0.2.1');
check($rc == 0 && $out eq "counted 0022" && $err eq '', "a CAPTCHA approval is counted and the umask is put back: $out$err");
check((mode("$C/auth/captcha") & 0777) == 0770, sprintf("auth/captcha, made here, is group-writable: %04o", mode("$C/auth/captcha")));
check((mode("$C/auth/captcha/n1") & 0777) == 0775, sprintf("so is the node's directory: %04o", mode("$C/auth/captcha/n1")));
my @day = glob("$C/auth/captcha/n1/day-* $C/auth/captcha/n1/dom-* $C/auth/captcha/n1/ip-*");
check(@day == 3 && !grep({ mode($_) != 0664 } @day), "and the day's three counters: " . join(' ', map { sprintf('%04o', mode($_)) } @day));
my $Day = strftime('%Y%m%d', gmtime);
check((slurp("$C/auth/captcha/n1/day-$Day") // '') eq '1', "which count it");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
