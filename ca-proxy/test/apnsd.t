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
our (@Sent, %New);
sub new { my $c = shift; %New = @_; bless {}, $c }
sub prepare { my ($s, $token) = @_; push @Sent, $token }
sub notify { 1 }

package main;

my $tree = tempdir(CLEANUP => 1);
mkdir "$tree/$_" foreach qw(etc apns log var);
$ENV{SNIF_CA_PROXY} = $tree;
$ENV{SNIF_APNS_BUNDLE} = 'com.example.test';

open(my $fh, '<', $apnsd) or die "$apnsd: $!";
my $src = do { local $/; <$fh> };
close $fh;
# A snif-apnsd from before the loader guard and the SNIF_CA_PROXY override:
# stop it before the daemon loop, and point it at the scratch tree.
$src =~ s/^close STDERR;$/return 1;\nclose STDERR;/m if $src !~ /^return 1 if caller;$/m;
$src =~ s/^\$BaseDir = `/\$BaseDir = \$ENV{SNIF_CA_PROXY} || `/m if $src !~ /SNIF_CA_PROXY\}/;
sub load {
    no strict; no warnings;
    eval $src;
    die "loading $apnsd: $@" if $@;
}
load();

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
my %new = %Net::APNS::Simple::New;
check(scalar(($new{bundle_id} // '') eq 'com.example.test'), "the bundle ID comes from SNIF_APNS_BUNDLE");
check(scalar(!$new{development} && ($new{cert_file} // '') eq "$tree/etc/apns.cer"), "production by default, with etc/apns.cer");

# No bundle ID: a token is still stored, and no push goes out.
{ no warnings 'once'; $main::BundleId = ''; }
$main::Apns = undef;
@Net::APNS::Simple::Sent = ();
my $host2 = 'snif-hijklmn67890.snif.xyz';
main::host_set_apns($host2, 'token-3');
utime($old, $old, main::apns_fname($host2));
my $ok = eval { main::host_check($host2, 'connid-3'); 1 };
check(scalar($ok && !@Net::APNS::Simple::Sent && (slurp(main::apns_fname($host2)) // '') eq 'token-3'),
    "with no bundle ID, a token is stored and no push is sent" . ($ok ? '' : ": $@"));

{
    local $ENV{SNIF_APNS_DEV} = 1;
    load();
}
$main::Apns = undef;
%Net::APNS::Simple::New = ();
main::apns_send('token-4', 'msg');
%new = %Net::APNS::Simple::New;
check(scalar($new{development} && ($new{cert_file} // '') eq "$tree/etc/apns-dev.cer"), "SNIF_APNS_DEV=1: development, with etc/apns-dev.cer");

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
