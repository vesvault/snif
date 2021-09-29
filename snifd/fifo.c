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
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include "sock.h"
#include "host.h"
#include "listen.h"
#include "buf.h"
#include "cln.h"
#include "abuse.h"
#include "fifo.h"


void snif_fifo_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_fifo_free fd=%d\n", sock->fd);
#endif
    snif_buf_free(sock->rd);
    snif_buf_free(sock->wr);
    return snif_sock_free(sock);
}

int snif_fifo_open(const char *fname, int write) {
    int fd = open(fname, (write ? O_WRONLY | O_NONBLOCK | O_APPEND : O_RDONLY | O_NONBLOCK));
    snif_sock_setnb(fd);
    return fd;
}

void snif_fifo_restart(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_fifo_restart fd=%d\n", sock->fd);
#endif
    struct pollfd *pollfd = &sock->listen->pollfds[sock->listenidx];
    snif_sock_shutdown(sock);
    sock->fd = snif_fifo_open(sock->fifo.fname, sock->fifo.write);
    if (sock->fd >= 0) {
	snif_sock_initpoll(sock, pollfd);
    } else {
	pollfd->fd = -1;
	snif_sock_tmout(sock, sock->listen->tmout.retry);
    }
}

void snif_fifo_error(snif_sock *sock) {
    snif_fifo_free(sock);
}

void snif_fifo_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd || sock->fd < 0) switch (sock->listen->shutdn) {
	case 0:
	    return snif_fifo_restart(sock);
	case 1:
	case 2:
	    return;
	default:
	    return snif_fifo_free(sock);
    }
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_rw(sock, pollfd, NULL) < 0) return;
    if (sock->rd) while (1) {
	char cmd1[8];
	char cmd2[16];
	char connid[SNIF_CLN_MAXHOST + 1];
	char arg[SNIF_CLN_MAXHOST + 1];
	int len;
	int c = snif_buf_scanl(sock->rd, &len,
	    sizeof(cmd1), cmd1,
	    sizeof(cmd2), cmd2,
	    sizeof(connid), connid,
	    sizeof(arg), arg,
	    0);
	if (c < 0) break;
	if (c >= 3 && !strcmp(cmd1, "SNIF")) {
	    snif_sock *wch;
	    for (wch = sock->listen->watch; wch; wch = wch->chain) {
		snif_sock_out(wch, sock->rd->buf, len);
	    }
	    if (!strcmp(cmd2, "CLOSE")) {
		snif_sock **ppeer = snif_cln_get(connid);
		if (ppeer && *ppeer) snif_sock_done(*ppeer);
	    } else if (!strcmp(cmd2, "ABUSE")) {
		snif_sock **ppeer = snif_cln_get(connid);
		if (ppeer && *ppeer) {
		    int abuse = 30;
		    if (c > 3) sscanf(arg, "%d", &abuse);
		    snif_abuse_add((*ppeer)->fd, abuse);
		}
	    } else if (!strcmp(cmd2, "MSG")) {
		snif_host *host = snif_host_get(connid, strlen(connid));
		if (host) snif_host_notifyl(host, sock->rd->buf, len);
	    } else if (c >= 4 && !strcmp(cmd2, "CONNECT")) {
		char *p = strchr(arg, ':');
		snif_host *host = p ? snif_host_get(arg, p - arg) : NULL;
		if (host) snif_host_notifyl(host, sock->rd->buf, len);
	    }
	}
	snif_buf_shift(sock->rd, len);
    }
}

snif_sock *snif_fifo(const char *fname, int write, snif_listen *lstn) {
    int fd = snif_fifo_open(fname, write);
    if (fd < 0) switch (errno) {
	case ENXIO:
	    break;
	default:
	    return NULL;
    }
    snif_sock *skconn = malloc(offsetof(snif_sock, fifo) + sizeof(skconn->fifo));
    skconn->fd = fd;
    skconn->pollfn = &snif_fifo_pollfn;
    skconn->listen = lstn;
    skconn->fifo.fname = fname;
    skconn->fifo.write = write;
    skconn->chain = NULL;
    snif_sock_initconn(skconn);
    *(write ? &skconn->wr : &skconn->rd) = snif_buf_new(SNIF_FIFO_BUFSIZE);
    return skconn;
}

