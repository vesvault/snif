#/**************************************************************************
# *     _________
# *    /````````_\                  S N I F ~ e2e TLS trust for IoT
# *   /\     , / O\      ___
# *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
# *  | |     |  ``/`````\___/       e2e TLS CA Proxy
# *  | |     | . | <"""""""~~
# *  |  \___/ ``  \________/        https://snif.host
# *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
# *    \_________/                  Jim Zubov <jz@vesvault.com>
# *
# *
# * Apache License, Version 2.0
# * You may use, copy, modify, merge, publish, distribute and/or sell copies
# * of the Software under the terms of the Apache License, Version 2.0, a copy
# * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
# *
# * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# * CONDITIONS OF ANY KIND, either express or implied.
# *
# **************************************************************************/

# Snif::CT::CrtSh -- M1 fallback CT source adapter.
#
# crt.sh returns the full history for a name in one (large) JSON query but has
# no server cursor and no inline DER: the PEM for each entry needs a second
# `?d=<id>` fetch. So the "cursor" here is just the max-seen crt.sh `id`
# high-water mark. The listing is fetched once per instance and cached; fetch()
# then pages through it, DER-fetching at most $PAGE entries per call and reporting
# $more while the listing still holds newer ids -- so the caller can checkpoint
# its high-water mark and resume a partial history seed after an interruption
# (crt.sh is slow/flaky and a full seed is hundreds of serial fetches).
#
# See Snif::CT::CertSpotter for the shared adapter contract.

package Snif::CT::CrtSh;

use strict;
use warnings;
use LWP::UserAgent;
use JSON::PP;
use MIME::Base64;

my $LIST = 'https://crt.sh/?output=json&q=';
my $ONE  = 'https://crt.sh/?d=';
my $PAGE = 20;   # DER fetches per fetch() call: the caller's checkpoint granularity

sub new {
    my ($class, %opt) = @_;
    my $self = {
	base => $opt{base} || 'snif.xyz',
	ua   => $opt{ua} || _ua(),
    };
    return bless $self, $class;
}

sub name { 'crtsh' }

sub _ua {
    my $ua = LWP::UserAgent->new(timeout => 180);
    $ua->agent('snifdog/0.1 (https://snif.host)');
    $ua->default_header('Accept' => 'application/json');
    return $ua;
}

# crt.sh is habitually flaky: the wildcard-identity listing (`q=%.domain`) is a
# heavy DB query that frequently 502/504/times out, and it rate-limits (429) a
# burst of per-cert `?d=` fetches. Retry transient failures (5xx/429/timeout)
# with exponential backoff so a one-shot history seed can actually complete; a
# 4xx other than 429 is permanent and returned immediately.
sub _get {
    my ($self, $url, $tries) = @_;
    $tries ||= 1;
    my $rsp;
    for my $attempt (1 .. $tries) {
	$rsp = $self->{ua}->get($url);
	return $rsp if $rsp->is_success;
	last unless $rsp->code >= 500 || $rsp->code == 429;	# transient only
	last if $attempt == $tries;
	sleep($attempt < 5 ? (2 ** $attempt) : 32);		# 2,4,8,16,32...
    }
    return $rsp;
}

sub fetch {
    my ($self, $cursor) = @_;
    my $hw = (defined $cursor && $cursor =~ /^\d+$/) ? $cursor : 0;
    my $list = $self->{_list} ||= $self->_list;
    my $newhw = $hw;
    my $more = 0;
    my @recs;
    # Ascending id order so the high-water mark advances monotonically; DER-fetch
    # at most $PAGE entries per call so the caller can checkpoint a long seed.
    for my $it (@$list) {
	my $id = $it->{id};
	next if $id <= $hw;
	if (@recs >= $PAGE) { $more = 1; last }   # entries remain for the next call
	my $der = $self->_der($id);
	push @recs, {
	    id          => $id,
	    source      => 'crtsh',
	    der         => $der,
	    spki        => undef,   # computed by core from der via openssl
	    dns_names   => [ _sans($it->{name_value}) ],
	    not_before  => $it->{not_before},
	    not_after   => $it->{not_after},
	    issuer      => $it->{issuer_name},
	    serial      => $it->{serial_number},
	    cert_sha256 => undef,
	};
	$newhw = $id if $id > $newhw;
    }
    return (\@recs, $newhw, $more);
}

# Fetch the full-history listing for the name once and cache it (id-ascending,
# deduped) so pagination across fetch() calls is stable and costs one LIST query.
sub _list {
    my ($self) = @_;
    my $rsp = $self->_get($LIST . '%25.' . $self->{base}, 5);
    die "crt.sh: " . $rsp->status_line . "\n" unless $rsp->is_success;
    my $arr = eval { decode_json($rsp->decoded_content) };
    die "crt.sh: bad JSON response\n" unless ref $arr eq 'ARRAY';
    my %seen;
    return [
	grep { defined $_->{id} && !$seen{$_->{id}}++ }
	sort { ($a->{id} || 0) <=> ($b->{id} || 0) } @$arr
    ];
}

# Fetch and DER-decode the PEM for one crt.sh entry. A PEM certificate is just
# base64-wrapped DER, so no openssl is needed to recover the DER bytes.
sub _der {
    my ($self, $id) = @_;
    my $rsp = $self->_get($ONE . $id, 3);
    return undef unless $rsp->is_success;
    my $pem = $rsp->decoded_content;
    return undef unless $pem =~ /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s;
    my $b64 = $1;
    $b64 =~ s/\s+//g;
    my $der = eval { decode_base64($b64) };
    return ($der && length $der) ? $der : undef;
}

# crt.sh name_value is a newline-separated list of the CN + dNSName SANs; keep
# the DNS-ish names (dropping e-mail / IP / anything with whitespace), dedup.
sub _sans {
    my ($nv) = @_;
    return () unless defined $nv;
    my %seen;
    my @out;
    for my $n (split /\s*\n\s*/, $nv) {
	next unless $n =~ /^\*?[A-Za-z0-9._-]+$/;
	next unless $n =~ /\./;
	next if $seen{lc $n}++;
	push @out, $n;
    }
    return @out;
}

1;
