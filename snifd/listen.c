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
#include <poll.h>
#include "sock.h"
#include "util.h"
#include "listen.h"

#ifdef SNIF_DIAGS
#include <syslog.h>
#endif

snif_sock *snif_listen_add(snif_listen *lstn, snif_sock *sock) {
    if (!sock) return NULL;
    int i = lstn->firstempty;
    if (i < lstn->pollct && lstn->socks[i]) {
	int j;
	int jlast = -1;
	for (j = i + 1; j <= lstn->pollct; j++) if (j >= lstn->pollct || !lstn->socks[j]) {
	    if (jlast >= 0) lstn->pollfds[jlast].fd = -1 - j;
	    else lstn->firstempty = j;
	    jlast = j;
	}
	i = lstn->firstempty;
    }
    if (i < lstn->pollct) {
	lstn->firstempty = -1 - lstn->pollfds[i].fd;
    } else {
	i = lstn->pollct;
	lstn->firstempty = i + 1;
    }
    if (i >= lstn->pollmax) {
	lstn->pollmax = i + 1024;
	lstn->pollfds = realloc(lstn->pollfds, lstn->pollmax * sizeof(*lstn->pollfds));
	lstn->socks = realloc(lstn->socks, lstn->pollmax * sizeof(*lstn->socks));
    }
    if (i >= lstn->pollct) lstn->pollct = i + 1;
    lstn->pollfds[i].fd = -1;
    sock->pollfn(sock, &lstn->pollfds[i]);
    sock->listenidx = i;
    return lstn->socks[i] = sock;
}

void snif_listen_remove(snif_listen *lstn, snif_sock *sock) {
    if (sock && sock->listenidx < lstn->pollct && lstn->socks[sock->listenidx] == sock) {
	lstn->socks[sock->listenidx] = NULL;
	lstn->pollfds[sock->listenidx].fd = -1 - lstn->firstempty;
	if (sock->listenidx < lstn->firstempty) lstn->firstempty = sock->listenidx;
	while (lstn->pollct > 0 && !lstn->socks[lstn->pollct - 1]) lstn->pollct--;
    }
}

int snif_listen_poll(snif_listen *lstn) {
    int tmout = lstn->chktime - snif_time();
    if (tmout < 1) tmout = 1;
    int r = poll(lstn->pollfds, lstn->pollct, tmout * 1000);
    lstn->chktime = snif_time() + SNIF_LISTEN_TMOUT;
    int i;
    for (i = 0; i < lstn->pollct; i++) {
	snif_sock *sk = lstn->socks[i];
	struct pollfd *pl = &lstn->pollfds[i];
#ifdef SNIF_DIAGS
	int e = pl->revents & pl->events;
	if (sk) {
	    if (e & POLLIN) sk->diags.in++;
	    if (e & POLLOUT) sk->diags.out++;
	    if (e & POLLHUP) sk->diags.hup++;
	    if (e & POLLNVAL) sk->diags.nval++;
	    if (e & POLLERR) sk->diags.err++;
	    if (e & POLLPRI) sk->diags.pri++;
	} else if (pl->fd >= 0) snif_log("diags poll=%lld fd=%d ev=%08x sk=(nil)\n", lstn->ctpolls, pl->fd, e);
#endif
	if (sk) sk->pollfn(sk, pl);
    }
#ifdef SNIF_DIAGS
    lstn->ctpolls++;
#endif
    return r;
}

int snif_listen_pushl(snif_listen *lstn, const char *ntfy, int len) {
    int ct = 0;
    snif_sock *sk;
    for (sk = lstn->push; sk; sk = sk->chain) {
	if (len < 0) len = strlen(ntfy);
	if (snif_sock_out(sk, ntfy, len) > 0) ct++;
    }
    return ct;
}

int snif_listen_shutdown(snif_listen *lstn) {
    int i;
    while (1) {
	if (++lstn->shutdn > 16) return -1;
	for (i = 0; i < lstn->pollct; i++) {
	    if (lstn->socks[i]) lstn->socks[i]->pollfn(lstn->socks[i], NULL);
	}
	if (!lstn->pollct) break;
	lstn->chktime = 0;
	snif_listen_poll(lstn);
    }
    free(lstn->socks);
    free(lstn->pollfds);
    return 0;
}
