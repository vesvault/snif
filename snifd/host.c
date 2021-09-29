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
#include "jTree.h"
#include "sock.h"
#include "ctl.h"
#include "cln.h"
#include "util.h"
#include "host.h"


jTree *snif_host_tree = NULL;


int snif_host_jtreefn(void *data, void *term, void *arg) {
    return strcmp(((snif_host *) data)->hostname, (const char *) term);
}

snif_host *snif_host_get(const char *hostname, int len) {
    if (!hostname || len < 1 || len > SNIF_CLN_MAXHOST) return NULL;
    char lcname[SNIF_CLN_MAXHOST + 1];
    const char *s = hostname;
    const char *tail = s + len;
    char *d = lcname;
    while (s < tail) {
	char c = *s++;
	*d++ = (c >= 'A' && c <= 'Z' ? c | 0x20 : c);
    }
    *d = 0;
    unsigned char depth = 0;
    snif_host **phost = (snif_host **) jTree_seek(&snif_host_tree, (void *) lcname, NULL, &snif_host_jtreefn, &depth);
    snif_host *host = *phost;
    if (!host) {
	host = *phost = malloc(sizeof(snif_host) + d - lcname);
	strcpy(host->hostname, lcname);
	host->clients = NULL;
	host->ctls = NULL;
    }
    return host;
}

int snif_host_notifyl(snif_host *host, const char *ntfy, int l) {
    snif_sock *ctl;
    int ct = 0;
    for (ctl = host->ctls; ctl; ctl = ctl->chain) {
	if (snif_ctl_out(ctl, ntfy, l) > 0) ct++;
    }
    return ct;
}

void snif_host_chkalive(snif_host *host) {
    snif_sock *ctl;
    unsigned long t = snif_time();
    for (ctl = host->ctls; ; ctl = ctl->chain) {
	if (!ctl) return;
	unsigned long a = snif_ctl_alive(ctl);
	if (a && a <= t) {
	    snif_ctl_alive(ctl) = 0;
	    break;
	}
    }
    snif_sock *cln;
    for (cln = host->clients; cln; cln = cln->chain) if (!cln->peer) {
	char ntfy[1024];
	snif_cln_push(cln, snif_cln_notify(cln, ntfy));
    }
}
