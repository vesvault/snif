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

# Snif::CT::CertSpotter -- M1 default CT source adapter.
#
# The certspotter issuances API returns the cert DER inline (expand=cert_der)
# and pages via a persistent, monotonic `after=<id>` issuance cursor. Backfill
# starts at after=0 and streams the full history in order; steady state resumes
# from the saved cursor. Ideal for a watcher: DER in one call, no second fetch,
# resumable. It also returns `pubkey_sha256` -- the SHA-256 of the DER SPKI,
# i.e. exactly the snifdog pin -- so no openssl shell-out is needed on this path.
#
# Adapter contract (shared by every Snif::CT::* source):
#   $src = Snif::CT::CertSpotter->new(base => 'snif.xyz', token => '...', ...);
#   ($records, $next_cursor, $more) = $src->fetch($cursor);
# where each record is a hashref:
#   { id, source, der, spki, dns_names[], not_before, not_after, issuer,
#     serial, cert_sha256 }
# `spki` (lowercase hex sha256 of the DER SPKI) may be undef, in which case the
# core computes it from `der` via openssl. `$more` is true while more pages
# remain; the caller loops fetch() until it is false, persisting $next_cursor.

package Snif::CT::CertSpotter;

use strict;
use warnings;
use LWP::UserAgent;
use JSON::PP;
use MIME::Base64;

my $API = 'https://api.certspotter.com/v1/issuances';

sub new {
    my ($class, %opt) = @_;
    my $self = {
	base  => $opt{base} || 'snif.xyz',
	token => $opt{token},
	ua    => $opt{ua} || _ua(),
    };
    return bless $self, $class;
}

sub name { 'certspotter' }

sub _ua {
    my $ua = LWP::UserAgent->new(timeout => 120);
    $ua->agent('snifdog/0.1 (https://snif.host)');
    $ua->default_header('Accept' => 'application/json');
    return $ua;
}

# One page after $cursor. certspotter returns issuances in ascending id order,
# so the cursor is simply the id of the last item returned; an empty page means
# we are caught up.
sub fetch {
    my ($self, $cursor) = @_;
    $cursor = 0 unless defined $cursor && $cursor ne '';
    my $url = sprintf(
	'%s?domain=%s&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert_der&after=%s',
	$API, $self->{base}, $cursor);
    my $req = HTTP::Request->new(GET => $url);
    $req->header(Authorization => 'Bearer ' . $self->{token}) if $self->{token};
    my $rsp = $self->{ua}->request($req);
    die "certspotter: " . $rsp->status_line . "\n" unless $rsp->is_success;
    my $arr = eval { decode_json($rsp->decoded_content) };
    die "certspotter: bad JSON response\n" unless ref $arr eq 'ARRAY';
    my @recs;
    for my $it (@$arr) {
	my $der = $it->{cert_der} ? decode_base64($it->{cert_der}) : undef;
	push @recs, {
	    id          => $it->{id},
	    source      => 'certspotter',
	    der         => $der,
	    spki        => _hex($it->{pubkey_sha256}),
	    dns_names   => $it->{dns_names} || [],
	    not_before  => $it->{not_before},
	    not_after   => $it->{not_after},
	    issuer      => _issuer($it->{issuer}),
	    serial      => undef,
	    cert_sha256 => _hex($it->{cert_sha256}),
	};
    }
    my $next = @recs ? $recs[-1]{id} : $cursor;
    my $more = @recs ? 1 : 0;
    return (\@recs, $next, $more);
}

sub _issuer {
    my ($iss) = @_;
    return undef unless defined $iss;
    return $iss unless ref $iss;
    return $iss->{name} if $iss->{name};
    return $iss->{friendly_name} if $iss->{friendly_name};
    return undef;
}

# certspotter hex digests come back lowercase, occasionally with a colon prefix
# ("SHA256:"); normalise to a bare lowercase hex string.
sub _hex {
    my ($h) = @_;
    return undef unless defined $h && length $h;
    $h =~ s/^[A-Za-z0-9]+://;
    $h = lc $h;
    return $h =~ /^[0-9a-f]+$/ ? $h : undef;
}

1;
