#!/usr/bin/perl
#
# snif-apnsd wake tokens, against a stub Net::APNS::Simple (it need not be
# installed): a token is replaced atomically and keeps the old file's access
# time, which host_check reads as the time of the last wake.
#
#   perl ca-proxy/test/apnsd.t [path/to/snif-apnsd]
#
# Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;

my $apnsd = shift || "$FindBin::Bin/../bin/snif-apnsd";
my ($pass, $fail) = (0, 0);

sub check {
    my ($ok, $what) = @_;
    print(($ok ? "ok" : "NOT OK"), " - $what\n");
    $ok ? $pass++ : $fail++;
}

package Net::APNS::Simple;
$INC{'Net/APNS/Simple.pm'} = 1;
our @Sent;
sub new { bless {}, shift }
sub prepare { my ($s, $token) = @_; push @Sent, $token }
sub notify { 1 }

package main;

my $tree = tempdir(CLEANUP => 1);
mkdir "$tree/$_" foreach qw(etc apns log var);
$ENV{SNIF_CA_PROXY} = $tree;

open(my $fh, '<', $apnsd) or die "$apnsd: $!";
my $src = do { local $/; <$fh> };
close $fh;
# A snif-apnsd from before the loader guard and the SNIF_CA_PROXY override:
# stop it before the daemon loop, and point it at the scratch tree.
$src =~ s/^close STDERR;$/return 1;\nclose STDERR;/m if $src !~ /^return 1 if caller;$/m;
$src =~ s/^\$BaseDir = `/\$BaseDir = \$ENV{SNIF_CA_PROXY} || `/m if $src !~ /SNIF_CA_PROXY\}/;
{
    no strict; no warnings;
    eval $src;
    die "loading $apnsd: $@" if $@;
}

my $host = 'snif-abcdefg12345.snif.xyz';
my $f = main::apns_fname($host);
sub slurp { open(my $h, '<', $_[0]) || return undef; local $/; my $s = <$h>; close $h; $s }

main::host_set_apns($host, 'token-1');
check(scalar((slurp($f) // '') eq 'token-1'), "a new token is stored");
check(!-e "$f+", "no temp file is left");

# Nothing reads the file again before host_check: under relatime, a read of a
# file whose access time is older than its modification time refreshes it.
my $old = time - 3600;
utime($old, $old, $f);
my $ino = (stat $f)[1];
main::host_set_apns($host, 'token-2');
my @st = stat $f;
check($st[1] != $ino, "a token is replaced by a rename, not a rewrite in place");
check($st[8] == $old, "keeping the old access time");
check($st[9] >= time - 5, "with a fresh modification time");

@Net::APNS::Simple::Sent = ();
main::host_check($host, 'connid-1');
check(scalar("@Net::APNS::Simple::Sent" eq 'token-2'), "host_check wakes with the replaced token");
main::host_check($host, 'connid-2');
check(scalar(@Net::APNS::Simple::Sent == 1), "and not again within \$ResendAfter");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
