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
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include "buf.h"
#include "listen.h"
#include "util.h"
#include "abuse.h"
#include "sock.h"


snif_sock *snif_sock_initconn(snif_sock *sock) {
    sock->peer = NULL;
    sock->rd = sock->wr = NULL;
    sock->chktime = 0;
    snif_listen_add(sock->listen, sock);
    return sock;
}

void snif_sock_initpoll(snif_sock *sock, struct pollfd *pollfd) {
    pollfd->fd = sock->fd;
    pollfd->events = POLLIN | POLLERR | POLLHUP | (sock->wr && sock->wr->len ? POLLOUT : 0);
    pollfd->revents = 0;
}

void snif_sock_tmout(snif_sock *sock, int tmout) {
    sock->chktime = snif_time() + tmout;
    if (sock->listen->chktime > sock->chktime) sock->listen->chktime = sock->chktime;
}

int snif_sock_chktmout(snif_sock *sock) {
    if (sock->chktime <= snif_time()) return snif_sock_done(sock);
    if (sock->listen->chktime > sock->chktime) sock->listen->chktime = sock->chktime;
    return 0;
}

int snif_sock_accept(snif_sock *sock, int abuse) {
    int fd = accept(sock->fd, NULL, NULL);
    if (snif_abuse(fd, abuse)) {
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return -1;
    }
    snif_sock_setnb(fd);
    return fd;
}

int snif_sock_connect(const char *host, const char *port) {
    struct addrinfo hint = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_ADDRCONFIG,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *ai = NULL;
    int r = getaddrinfo(host, port, &hint, &ai);
    if (r) return -1;
    struct addrinfo *a;
    int fd = -1;
    for (a = ai; a; a = a->ai_next) {
	fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0) continue;
	if (connect(fd, a->ai_addr, a->ai_addrlen) >= 0) {
	    snif_sock_setnb(fd);
	    break;
	}
	close(fd);
	fd = -1;
    }
    freeaddrinfo(ai);
    return fd;
}

int snif_sock_setnb(int fd) {
    if (fd >= 0) {
	int flgs = fcntl(fd, F_GETFL, 0);
	if (flgs != -1) {
	    flgs |= O_NONBLOCK;
	    return fcntl(fd, F_SETFL, flgs);
	}
    }
    return -1;
}

snif_sock *snif_sock_addchain(snif_sock *sock, snif_sock **chain) {
    for (; *chain; chain = &(*chain)->chain);
    return *chain = sock;
}

void snif_sock_removechain(snif_sock *sock, snif_sock **chain) {
    for (; *chain; chain = &(*chain)->chain) if (*chain == sock) {
	*chain = sock->chain;
	break;
    }
}

int snif_sock_done(snif_sock *sock) {
    if (sock->peer) sock->peer->pollfn(sock->peer, NULL);
    sock->pollfn(sock, NULL);
    return -1;
}

void snif_sock_update(snif_sock *sock, struct pollfd *pollfd) {
    pollfd->events = (pollfd->events & ~(POLLIN | POLLOUT))
	| (sock->rd && sock->rd->len < (sock->rd->low && sock->rd->max ? sock->rd->low : sock->rd->max) ? POLLIN : 0)
	| (sock->wr && (sock->wr->len || !sock->wr->max) ? POLLOUT : 0);
}

int snif_sock_rw(snif_sock *sock, struct pollfd *pollfd, void *ssl) {
    int rs = 0;
    if (pollfd->revents & POLLOUT) {
	int r = (ssl ? snif_buf_send_ssl(sock->wr, ssl) : snif_buf_send(sock->wr, sock->fd));
#ifdef SNIF_DEBUG
	printf("snif_sock_rw fd=%d send=%d eof=%d\n", sock->fd, r, snif_buf_eof(sock->wr));
#endif
	if (r < 0) return snif_sock_done(sock);
	rs += r;
    }
    if (pollfd->revents & POLLIN) {
	int r = (ssl ? snif_buf_recv_ssl(sock->rd, ssl) : snif_buf_recv(sock->rd, sock->fd));
#ifdef SNIF_DEBUG
	printf("snif_sock_rw fd=%d recv=%d eof=%d\n", sock->fd, r, snif_buf_eof(sock->rd));
#endif
	if (r < 0) return snif_sock_done(sock);
	else while (r > 0 && sock->rd->len == sock->rd->max && sock->rd->low && sock->rd->max < SNIF_SOCK_MAXBUF) {
	    snif_buf *buf = sock->rd;
	    buf->max *= 2;
	    buf = realloc(buf, sizeof(*buf) + buf->max);
	    if (sock->peer && sock->peer->wr == sock->rd) sock->peer->wr = buf;
	    sock->rd = buf;
	    int r2 = (ssl ? snif_buf_recv_ssl(buf, ssl) : snif_buf_recv(buf, sock->fd));
#ifdef SNIF_DEBUG
	    printf("snif_sock_rw+ fd=%d recv=%d eof=%d\n", sock->fd, r2, snif_buf_eof(buf));
#endif
	    if (r2 < 0) return snif_sock_done(sock);
	    r += r2;
	}
	rs = r;
    } else if (pollfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
	return snif_sock_done(sock);
    }
    if (snif_buf_eof(sock->wr)) {
	if (sock->wr) shutdown(sock->fd, SHUT_RDWR);
	if (snif_buf_eof(sock->rd)) return snif_sock_done(sock);
    }
    snif_sock_update_peer(sock);
    snif_sock_update(sock, pollfd);
    return rs;
}

int snif_sock_out(snif_sock *sock, const char *src, int len) {
    int r = snif_buf_append(sock->wr, src, len);
    if (r >= 0) snif_sock_update(sock, &sock->listen->pollfds[sock->listenidx]);
    return r;
}

void snif_sock_shutdown(snif_sock *sock) {
    if (sock->fd >= 0) {
	shutdown(sock->fd, SHUT_RDWR);
	close(sock->fd);
	sock->fd = -1;
    }
}

void snif_sock_free(snif_sock *sock) {
    if (sock) {
	snif_sock_shutdown(sock);
	snif_listen_remove(sock->listen, sock);
    }
    free(sock);
}
