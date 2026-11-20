#!/usr/bin/perl
#
# What a pass does when its CT source fails. Only an answer about
# the request itself -- an HTTP 4xx other than 408 or 429 -- can mean the
# source rejected the cursor, and only then does the pass start the base
# again from the beginning. A rate limit (429), a timeout (408), a server
# error, a failed connection or an unreadable answer ends the pass with
# the cursor kept, and nothing is fetched a second time. A source that asks
# to wait (Retry-After) delays the next pass in watch mode, up to an hour.
# The CertSpotter adapter puts the wait into its error. A failure is one
# log line. Needs no network: the pass runs against a stand-in source, and
# the adapter against a stand-in user agent.
#
#   perl snifdog/test/fetch-errors.t [path/to/snifdog]
#
# Exits non-zero if any check fails.

use strict;
use warnings;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use FindBin;
use lib "$FindBin::Bin/../lib";

my $snifdog = shift || "$FindBin::Bin/../bin/snifdog";
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

require $snifdog;
our (%C);
# snifdog's `use lib` puts an installed library ahead of this checkout's.
unshift @INC, "$FindBin::Bin/../lib";

# The log, kept here instead of printed.
my @Log;
{
    no warnings qw(redefine once);
    *main::say_log = sub { push @Log, "[$_[0]] $_[1]" };
}

# A stand-in source: each fetch takes the next answer of its script, and the
# cursor it was asked for is written down.
package FakeSrc {
    sub new { my ($class, @script) = @_; bless { script => [@script], asked => [] }, $class }
    sub fetch {
	my ($self, $cursor) = @_;
	push @{$self->{asked}}, $cursor;
	my $a = shift @{$self->{script}} or die "fake: out of answers\n";
	die $a->{die} if $a->{die};
	return @{$a->{ok}};
    }
}
my $Src;
{
    no warnings qw(redefine once);
    *main::load_source = sub { $Src };
}

my $tmp = tempdir(CLEANUP => 1);
put("$tmp/fe.conf", "SNIFDOG_BASE=fe.example\nSNIFDOG_DIR=$tmp/state\nSNIFDOG_SYSLOG=0\nSNIFDOG_BACKFILL=0\nSNIF_CA_PROXY=\n");
load_conf("$tmp/fe.conf");

# One pass from cursor 100 against @script: its exit code, what was asked.
sub pass_with {
    my (@script) = @_;
    @Log = ();
    delete $C{retry_after};
    cursor_save('100');
    $Src = FakeSrc->new(@script);
    my $rc = run_pass();
    return ($rc, join(',', map { $_ eq '' ? '(begin)' : $_ } @{$Src->{asked}}));
}
sub logged { my ($re) = @_; scalar grep { /$re/ } @Log }
sub one_line { !grep { /\n/ } @Log }

# ---- a failure that says nothing about the cursor: the pass ends -------------

for my $c (['certspotter: 429 Too Many Requests (retry after 120s)', 'a rate limit (429)'],
	   ['certspotter: 408 Request Timeout', 'a timeout (408)'],
	   ['certspotter: 503 Service Unavailable', 'a server error (503)'],
	   ["certspotter: 500 Can't connect to api.certspotter.com:443 (Connection timed out)", 'a failed connection'],
	   ['certspotter: bad JSON response', 'an unreadable answer']) {
    my ($err, $what) = @$c;
    my ($rc, $asked) = pass_with({ die => "$err\n" });
    check($rc == 1 && $asked eq '100', "$what: one fetch, at the cursor, and the pass fails: $asked");
    check(cursor_load() eq '100', "$what: the cursor is kept");
    check(!logged(qr/cursor rejected/), "$what: not read as a rejected cursor");
    check(logged(qr/^\[ERROR\] fetch: \Q$err\E$/) == 1 && one_line(), "$what: one ERROR line");
}

# ---- an answer about the request: the cursor was rejected --------------------

my ($rc, $asked) = pass_with({ die => "certspotter: 400 Bad Request\n" }, { ok => [[], '7', 0] });
check($rc == 0 && $asked eq '100,(begin)', "a 400: the pass starts again from the beginning: $asked");
check(cursor_load() eq '7', 'and saves the cursor it reaches');
check(logged(qr/^\[NOTICE\] cursor rejected \(certspotter: 400 Bad Request\); restarting from the beginning$/) == 1
      && one_line(), 'one NOTICE line, not split');

($rc, $asked) = pass_with({ die => "crt.sh: 404 Not Found\n" }, { die => "crt.sh: 404 Not Found\n" });
check($rc == 1 && $asked eq '100,(begin)', "a 404, twice: one restart, then the pass fails: $asked");
check(cursor_load() eq '100', 'the cursor is kept when the restart fails too');

($rc, $asked) = pass_with({ ok => [[], '150', 0] });
check($rc == 0 && $asked eq '100' && cursor_load() eq '150' && logged(qr/^\[INFO\] pass done:/),
      "no failure: one fetch, the cursor moves on, the pass is done: $asked");

check(!cursor_rejected('certspotter: 429 Too Many Requests') && !cursor_rejected('certspotter: 4290 x')
      && cursor_rejected('certspotter: 410 Gone') && cursor_rejected('crt.sh: 400 Bad Request'),
      'cursor_rejected(): 410 and 400 are, 429 is not');

# ---- the wait before the next pass -------------------------------------------

$C{interval} = 900;
pass_with({ die => "certspotter: 429 Too Many Requests (retry after 120s)\n" });
@Log = ();
check(next_sleep() == 900 && !@Log, 'a wait shorter than the poll interval: the interval');
$C{retry_after} = 1800;
check(next_sleep() == 1800 && logged(qr/^\[NOTICE\] the source asked to wait 1800s: next pass in 1800s$/),
      'a longer wait is kept');
$C{retry_after} = 7200;
check(next_sleep() == 3600, 'up to an hour');
check(next_sleep() == 900, 'once: the pass after it waits the interval again');

# ---- the CertSpotter adapter -------------------------------------------------

require HTTP::Response;
require HTTP::Date;
require Snif::CT::CertSpotter;
check(index($INC{'Snif/CT/CertSpotter.pm'}, "$FindBin::Bin/../lib/") == 0,
      "the adapter is this checkout's: $INC{'Snif/CT/CertSpotter.pm'}");
package FakeUA {
    sub new { my ($class, $rsp) = @_; bless { rsp => $rsp }, $class }
    sub request { $_[0]{rsp} }
}
sub cs_error {
    my ($code, $msg, %h) = @_;
    my $r = HTTP::Response->new($code, $msg);
    $r->header($_ => $h{$_}) for keys %h;
    my $cs = Snif::CT::CertSpotter->new(base => 'fe.example', ua => FakeUA->new($r));
    eval { $cs->fetch('100') };
    return $@;
}
check(cs_error(429, 'Too Many Requests', 'Retry-After' => '120') eq "certspotter: 429 Too Many Requests (retry after 120s)\n",
      'a 429 with Retry-After in seconds: the wait is in the error');
my $e = cs_error(503, 'Service Unavailable', 'Retry-After' => HTTP::Date::time2str(time + 300));
check($e =~ /^certspotter: 503 Service Unavailable \(retry after (\d+)s\)\n\z/ && $1 >= 298 && $1 <= 301,
      "an HTTP date: in seconds from now: $e");
check(cs_error(503, 'Service Unavailable') eq "certspotter: 503 Service Unavailable\n", 'none: the status line alone');
check(cs_error(429, 'Too Many Requests', 'Retry-After' => 'soon') eq "certspotter: 429 Too Many Requests\n",
      'an unreadable one is left out');

print "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
