/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <syslog.h>
#include "jTree.h"
#include "util.h"
#include "abuse.h"

jTree *snif_abuse_jtree = NULL;
unsigned short snif_abuse_sense = 256;

struct snif_abuse {
    unsigned long tstamp;
    unsigned int abused;
    unsigned short ct;
    unsigned short len;
    char addr[0];
};

static int snif_abuse_cmpfn(void *a, void *b, void *arg) {
    struct snif_abuse *aa = a;
    int len = (int)(long long) arg;
    if (aa->len > len) {
	return 1;
    }
    if (aa->len < len) {
	return -1;
    }
    return memcmp(aa->addr, b, len);
}


static struct snif_abuse *snif_abuse_seek(int fd, struct sockaddr_in6 *sa, socklen_t *sl) {
    *sl = sizeof(*sa);
    if (getpeername(fd, (struct sockaddr *)sa, sl) < 0) return NULL;
    void *ad;
    int al;
    switch (sa->sin6_family) {
	case AF_INET:
	    ad = &((struct sockaddr_in *) sa)->sin_addr;
	    al = sizeof(((struct sockaddr_in *) sa)->sin_addr);
	    break;
	case AF_INET6:
	    ad = &((struct sockaddr_in6 *) sa)->sin6_addr;
	    al = sizeof(((struct sockaddr_in6 *) sa)->sin6_addr);
	    break;
	default:
	    return 0;
    }
    unsigned char depth;
    void **ap = jTree_seek(&snif_abuse_jtree, ad, (void *)(long long)al, &snif_abuse_cmpfn, &depth);
    struct snif_abuse *ab = *ap;
    if (!ab) {
	*ap = ab = malloc(sizeof(*ab) + al);
	ab->abused = 0;
	ab->len = al;
	memcpy(ab->addr, ad, al);
	ab->tstamp = 0;
	ab->ct = 0;
    }
#ifdef SNIF_DEBUG
    printf("snif_abuse_seek fd=%d al=%d ab=%p t=%lu\n", fd, al, ab, ab->tstamp);
#endif
    return ab;
}

#define	snif_abuse_getaddr(buf, sa, sl)	(getnameinfo((struct sockaddr *)sa, sl, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) >= 0 ? buf : "")

int snif_abuse(int fd, int grace) {
    struct sockaddr_in6 sa;
    socklen_t sl;
    struct snif_abuse *ab = snif_abuse_seek(fd, &sa, &sl);
    if (!ab) return 0;
    unsigned long t = snif_time();
    if (ab->tstamp > t + grace) {
	char peer[64];
	if (!ab->abused++) snif_log("abuse peer=%s", snif_abuse_getaddr(peer, &sa, sl));
	return 1;
    }
    if (t > ab->tstamp) {
	ab->ct = 0;
	ab->tstamp = t;
	if (ab->abused > 1) {
	    char peer[64];
	    snif_log("abuse(+%u) peer=%s", ab->abused - 1, snif_abuse_getaddr(peer, &sa, sl));
	}
	ab->abused = 0;
    } else {
	ab->ct += snif_abuse_sense;
	ab->tstamp += (ab->ct >> 8);
	ab->ct &= 0xff;
    }
    return 0;
}

void snif_abuse_add(int fd, int abuse) {
    if (abuse <= 0) return;
    struct sockaddr_in6 sa;
    socklen_t sl;
    struct snif_abuse *ab = snif_abuse_seek(fd, &sa, &sl);
    if (!ab) return;
    unsigned long t = snif_time();
    if (t > ab->tstamp) ab->tstamp = t;
    int a = abuse * snif_abuse_sense + ab->ct;
    ab->tstamp += a / 256;
    ab->ct = a & 0xff;
    if (ab->tstamp > t + SNIF_ABUSE_MAX) ab->tstamp = t + SNIF_ABUSE_MAX;
}

