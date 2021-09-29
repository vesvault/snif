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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include "sock.h"
#include "listen.h"
#include "buf.h"
#include "watch.h"
#include "../lib/conn.h"
#include "../lib/cert.h"
#include "util.h"
#include "fwd.h"


void snif_fwd_free(snif_sock *sock) {
    snif_buf_free(sock->rd);
    snif_buf_free(sock->wr);
    if (sock->fwd.ssl) SSL_free(sock->fwd.ssl);
    return snif_sock_free(sock);
}

void snif_fwd_error(snif_sock *sock) {
    if (sock->peer) snif_sock_free(sock->peer);
    return snif_fwd_free(sock);
}

void snif_fwd_test(snif_sock *sock) {
    char hostname[128];
    char lhost[64];
    if (gethostname(hostname, sizeof(hostname)) < 0) hostname[0] = 0;
    struct sockaddr_in6 sa;
    socklen_t sl = sizeof(sa);
    if (getsockname(sock->fd, (struct sockaddr *)&sa, &sl) < 0
	|| getnameinfo((struct sockaddr *)&sa, sl, lhost, sizeof(lhost), NULL, 0, NI_NUMERICHOST) < 0
    ) lhost[0] = 0;
    sprintf(sock->wr->buf, "HTTP/1.0 200 Ok\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"SNIF e2e TLS Connector is running\r\n"
	"CN = %s\r\n"
	"host = %s\r\n"
	"addr = %s\r\n"
	"pid = %d\r\n",
	sock->fwd.cert->cn,
	hostname,
	lhost,
	getpid()
    );
    sock->wr->len = strlen(sock->wr->buf);
    sock->wr->max = 0;
}

void snif_fwd_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_fwd_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    if (!sock->rd) {
	if (sock->wr->len) {
	    if (snif_sock_rw(sock, pollfd, NULL) < 0 || sock->wr->len) return;
	}
	if (sock->fwd.port->flags & SNIF_WF_TERMTLS) {
	    if (!sock->fwd.ssl) {
		sock->fwd.ssl = snif_cert_ssl(sock->fwd.cert);
		if (!sock->fwd.ssl) return snif_fwd_error(sock);
		SSL_set_fd(sock->fwd.ssl, sock->fd);
	    }
	    int r = SSL_accept(sock->fwd.ssl);
	    if (r <= 0) switch (SSL_get_error(sock->fwd.ssl, r)) {
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SSL:
		case SSL_ERROR_SYSCALL:
		    return snif_fwd_error(sock);
		case SSL_ERROR_WANT_READ:
		    pollfd->events |= POLLIN;
		    return;
		case SSL_ERROR_WANT_WRITE:
		    pollfd->events |= POLLOUT;
		    return;
		default:
		    return;
	    }
	}
	sock->rd = snif_buf_new(SNIF_FWD_BUFSIZE);
	if (sock->peer) sock->peer->wr = sock->rd;
	else snif_fwd_test(sock);
	snif_sock_update(sock, pollfd);
    }
    if (snif_sock_rw(sock, pollfd, sock->fwd.ssl) > 0) {
	if (!sock->peer && !sock->wr->len) {
	    snif_sock_done(sock);
	    return;
	}
	snif_sock_tmout(sock, sock->listen->tmout.idle);
    }
}

void snif_fwd_lcl_free(snif_sock *sock) {
    if (sock->listen->push) {
	char buf[64];
	sprintf(buf, "SNIF FORWARD %d\r\n", sock->fd);
	snif_listen_push(sock->listen, buf);
    }
    return snif_sock_free(sock);
}

void snif_fwd_lcl_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_fwd_lcl_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    if (snif_sock_rw(sock, pollfd, NULL) > 0) snif_sock_tmout(sock, sock->listen->tmout.idle);
}

snif_sock *snif_fwd_lcl(snif_watch_port *wp, snif_listen *lstn) {
    int fd = snif_sock_connect(wp->lhost, wp->lport);
#ifdef SNIF_DEBUG
    printf("snif_fwd_lcl fd=%d lhost=%s lport=%s\n", fd, wp->lhost, wp->lport);
#endif
    if (fd < 0) return NULL;
    snif_sock *skconn = malloc(offsetof(snif_sock, ref));
    skconn->fd = fd;
    skconn->pollfn = &snif_fwd_lcl_pollfn;
    skconn->listen = lstn;
    snif_sock_initconn(skconn);
    return skconn;
}

snif_sock *snif_fwd(snif_conn *conn, snif_watch_port *wp, snif_cert *cert, snif_listen *lstn) {
    snif_sock *sklcl;
    if (wp->lport && wp->lport[0]) {
	sklcl = snif_fwd_lcl(wp, lstn);
	if (!sklcl) return NULL;
    } else if (wp->flags & SNIF_WF_TERMTLS) sklcl = NULL;
    else return NULL;
    int fd = snif_sock_connect(conn->fwd.host, conn->fwd.port);
#ifdef SNIF_DEBUG
    printf("snif_fwd fd=%d connid=%s fwd.host=%s fwd.port=%s\n", fd, conn->connid, conn->fwd.host, conn->fwd.port);
#endif
    if (fd < 0) {
	if (sklcl) snif_sock_done(sklcl);
	return NULL;
    }
    snif_sock *skfwd = malloc(offsetof(snif_sock, fwd) + sizeof(skfwd->fwd));
    skfwd->fd = fd;
    skfwd->pollfn = &snif_fwd_pollfn;
    skfwd->listen = lstn;
    snif_sock_initconn(skfwd);
    skfwd->fwd.ssl = NULL;
    skfwd->fwd.cert = cert;
    skfwd->fwd.port = wp;
    skfwd->peer = sklcl;
    if (sklcl) sklcl->peer = skfwd;
    skfwd->wr = snif_buf_new(SNIF_FWD_BUFSIZE);
    if (sklcl) {
	sklcl->rd = skfwd->wr;
	snif_sock_tmout(sklcl, lstn->tmout.conn);
	char rhost[64];
	char rport[16];
	struct sockaddr_in6 sa;
	socklen_t sl = sizeof(sa);
	if (getsockname(sklcl->fd, (struct sockaddr *)&sa, &sl) < 0
	    || getnameinfo((struct sockaddr *)&sa, sl, rhost, sizeof(rhost), rport, sizeof(rport), NI_NUMERICHOST | NI_NUMERICSERV) < 0
	) rhost[0] = rport[0] = 0;
	snif_log("connid=%s cln=%s:%s fwd=[%s]:%s", conn->connid, conn->cln.host, conn->cln.port, rhost, rport);
	if (sklcl->listen->push) {
	    char ntfy[1024];
	    sprintf(ntfy, "SNIF FORWARD %d %s %s:%s [%s]:%s %s:%s\r\n",
		sklcl->fd,
		conn->connid,
		conn->srv.host,
		conn->srv.port,
		rhost,
		rport,
		conn->cln.host,
		conn->cln.port
	    );
	    snif_listen_push(sklcl->listen, ntfy);
	}
    }
    snif_sock_tmout(skfwd, lstn->tmout.conn);
    return skfwd;
}

