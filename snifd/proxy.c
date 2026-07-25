/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include "proxy.h"


static const char *snif_proxy_v4map(const char *host) {
    if (host && !strncmp(host, "::ffff:", 7) && strchr(host + 7, '.')) return host + 7;
    return host;
}

/* the relay reports the client address in the bracketed [addr] form */
static const char *snif_proxy_unbrack(const char *host, char *tmp, int tmplen) {
    if (host && host[0] == '[') {
	const char *e = strchr(host, ']');
	int l = e - host - 1;
	if (e && l < tmplen) {
	    memcpy(tmp, host + 1, l);
	    tmp[l] = 0;
	    return tmp;
	}
    }
    return host;
}

/**************************************************************************
 * Build a PROXY protocol v1 line (haproxy doc/proxy-protocol.txt) from
 * numeric src / dst address strings. The families must match; a v4-mapped
 * form on either side is reduced to plain v4, a v4 dst under a v6 src is
 * promoted to a v4-mapped v6 form. Falls back to "PROXY UNKNOWN" if a
 * well-formed line cannot be built, so the receiver's expectation of a
 * header is always met.
 * Returns the length written, not counting the trailing NUL.
 **************************************************************************/
int snif_proxy_hdr(char *out, int outmax, const char *shost, const char *sport, const char *dhost, const char *dport) {
    char stmp[64];
    char dtmp[64];
    shost = snif_proxy_v4map(snif_proxy_unbrack(shost, stmp, sizeof(stmp)));
    dhost = snif_proxy_v4map(snif_proxy_unbrack(dhost, dtmp, sizeof(dtmp)));
    int r = 0;
    if (shost && *shost && sport && *sport && dhost && *dhost && dport && *dport) {
	char f6 = !!strchr(shost, ':');
	const char *dpfx = "";
	if (!!strchr(dhost, ':') != f6) {
	    if (f6 && strchr(dhost, '.')) dpfx = "::ffff:";
	    else shost = NULL;
	}
	if (shost) r = snprintf(out, outmax, "PROXY TCP%c %s %s%s %s %s\r\n", (f6 ? '6' : '4'), shost, dpfx, dhost, sport, dport);
    }
    if (r <= 0 || r >= outmax) {
	r = snprintf(out, outmax, "PROXY UNKNOWN\r\n");
	if (r >= outmax) {
	    if (outmax > 0) out[0] = 0;
	    r = 0;
	}
    }
    return r;
}

static void snif_proxy_addr(int fd, char peerf, char *host, socklen_t hlen, char *port, socklen_t plen) {
    struct sockaddr_in6 sa;
    socklen_t sl = sizeof(sa);
    host[0] = port[0] = 0;
    if ((peerf ? getpeername(fd, (struct sockaddr *)&sa, &sl) : getsockname(fd, (struct sockaddr *)&sa, &sl)) < 0
	|| getnameinfo((struct sockaddr *)&sa, sl, host, hlen, port, plen, NI_NUMERICHOST | NI_NUMERICSERV)
    ) host[0] = port[0] = 0;
}

/**************************************************************************
 * PROXY line for a connector fwd connection: src = the client address as
 * reported by the relay, dst = the destination the local connection is
 * delivered to (the peer of lclfd).
 **************************************************************************/
int snif_proxy_fwdhdr(char *out, int outmax, const char *shost, const char *sport, int lclfd) {
    char dhost[64];
    char dport[16];
    snif_proxy_addr(lclfd, 1, dhost, sizeof(dhost), dport, sizeof(dport));
    return snif_proxy_hdr(out, outmax, shost, sport, dhost, dport);
}

/**************************************************************************
 * PROXY line for a relay static map connection: both addresses first-hand
 * from the accepted client socket, src = getpeername, dst = getsockname
 * (the relay address the client actually connected to).
 **************************************************************************/
int snif_proxy_clnhdr(char *out, int outmax, int clnfd) {
    char shost[64];
    char sport[16];
    char dhost[64];
    char dport[16];
    snif_proxy_addr(clnfd, 1, shost, sizeof(shost), sport, sizeof(sport));
    snif_proxy_addr(clnfd, 0, dhost, sizeof(dhost), dport, sizeof(dport));
    return snif_proxy_hdr(out, outmax, shost, sport, dhost, dport);
}
