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
#include <time.h>
#include <stdio.h>
#include "sock.h"
#include "host.h"
#include "listen.h"
#include "buf.h"
#include "cln.h"
#include "srv.h"


void snif_srv_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_srv_free fd=%d\n", sock->fd);
#endif
    snif_buf_free(sock->rd);
    return snif_sock_free(sock);
}

void snif_srv_error(snif_sock *sock) {
    snif_srv_free(sock);
}

void snif_srv_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_srv_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    int bytes = snif_sock_rw(sock, pollfd, NULL);
    if (bytes < 0) return;
    if (!sock->peer) {
	while (1) {
	    char cmd1[8];
	    char cmd2[16];
	    char connid[sizeof(sock->cln.connid)];
	    int c = snif_buf_readl(sock->rd,
		sizeof(cmd1), cmd1,
		sizeof(cmd2), cmd2,
		sizeof(connid), connid,
		0);
	    if (c < 0) break;
	    if (c >= 3 && !strcmp(cmd1, "SNIF") && !strcmp(cmd2, "ACCEPT")) {
		snif_sock **ppeer = snif_cln_get(connid);
#ifdef SNIF_DEBUG
		printf("snif_srv_pollfn fd=%d connid=%s peer=%p\n", sock->fd, connid, *ppeer);
#endif
		if (ppeer && *ppeer && !(*ppeer)->peer) {
		    sock->peer = *ppeer;
		    sock->peer->peer = sock;
		    sock->wr = sock->peer->rd;
		    sock->peer->wr = sock->rd;
		    sock->wr->low = sock->rd->low = SNIF_SRV_BUFLOW;
		    snif_sock_rw(sock, pollfd, NULL);
		    if (sock->peer->cln.rbytes < 0 && sock->listen->push) {
			char buf[sizeof(connid) + 16];
			sprintf(buf, "SNIF CLEAR %s\r\n", connid);
			snif_listen_push(sock->listen, buf);
		    }
		} else return snif_srv_error(sock);
		break;
	    }
	}
	if (!sock->peer && !sock->rd->max) snif_sock_done(sock);
    } else if (bytes > 0) snif_sock_tmout(sock, sock->listen->tmout.idle);
}


snif_sock *snif_srv(snif_sock *sock) {
    int fd = snif_sock_accept(sock, SNIF_SRV_ABUSE);
#ifdef SNIF_DEBUG
    printf("snif_srv fd=%d\n", fd);
#endif
    if (fd < 0) return NULL;
    snif_sock *skconn = malloc(offsetof(snif_sock, srv) + sizeof(skconn->srv));
    skconn->fd = fd;
    skconn->pollfn = &snif_srv_pollfn;
    skconn->listen = sock->listen;
    snif_sock_initconn(skconn);
    skconn->rd = snif_buf_new(SNIF_SRV_BUFSIZE);
    snif_sock_tmout(skconn, skconn->listen->tmout.conn);
    return skconn;
}

