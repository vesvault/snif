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
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include "util.h"
#include "sock.h"
#include "listen.h"
#include "buf.h"
#include "fwd.h"
#include "../lib/cert.h"
#include "../lib/conn.h"
#include "watch.h"


void snif_watch_logopen(snif_sock *sock) {
    snif_log("watch=%d open cn=%s errno=%d", sock->fd, sock->watch.cert->cn, errno);
    if (sock->fd >= 0 && sock->listen->push) {
	char buf[320];
	sprintf(buf, "SNIF CTL %d %s\r\n", sock->fd, snif_cert_hostname(sock->watch.cert));
	snif_listen_push(sock->listen, buf);
    }
}

void snif_watch_logclose(snif_sock *sock) {
    if (sock->fd >= 0) {
	snif_log("watch=%d close", sock->fd);
	if (sock->listen->push) {
	    char buf[64];
	    sprintf(buf, "SNIF CTL %d\r\n", sock->fd);
	    snif_listen_push(sock->listen, buf);
	}
    }
}

void snif_watch_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_watch_free fd=%d\n", sock->fd);
#endif
    snif_buf_free(sock->rd);
    snif_buf_free(sock->wr);
    snif_watch_logclose(sock);
    if (sock->watch.ssl) SSL_free(sock->watch.ssl);
    return snif_sock_free(sock);
}

void snif_watch_restart(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_watch_restart fd=%d\n", sock->fd);
#endif
    struct pollfd *pollfd = &sock->listen->pollfds[sock->listenidx];
    snif_buf_free(sock->rd);
    snif_buf_free(sock->wr);
    snif_watch_logclose(sock);
    snif_sock_shutdown(sock);
    sock->rd = sock->wr = NULL;
    if (sock->watch.ssl) SSL_free(sock->watch.ssl);
    sock->watch.ssl = NULL;
    snif_cert_reset(sock->watch.cert);
    sock->fd = snif_sock_connect(sock->watch.rhost, sock->watch.rport);
    if (sock->fd >= 0) {
	snif_sock_initpoll(sock, pollfd);
	snif_sock_tmout(sock, sock->listen->tmout.conn);
    } else {
	pollfd->fd = -1;
	snif_sock_tmout(sock, sock->listen->tmout.retry);
    }
    snif_watch_logopen(sock);
}

void snif_watch_error(snif_sock *sock) {
    snif_watch_free(sock);
}

void snif_watch_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd || sock->fd < 0) switch (sock->listen->shutdn) {
	case 0:
	    return snif_watch_restart(sock);
	case 1:
	    return;
	default:
	    return snif_watch_free(sock);
    }
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if ((!sock->rd || !sock->watch.alive) && snif_sock_chktmout(sock) < 0) return;
    if (sock->rd) {
	int bytes = snif_sock_rw(sock, pollfd, sock->watch.ssl);
	if (bytes >= 0) {
           if (bytes > 0) {
               sock->watch.alive = sock->listen->tmout.alive;
               snif_sock_tmout(sock, sock->listen->tmout.watch);
           } else {
               char buf[64];
               char *p = buf;
               snif_conn_idle(&p, sizeof(buf))
                   && snif_sock_out(sock, buf, p - buf) > 0
                   && (snif_sock_tmout(sock, sock->watch.alive), 0);
               sock->watch.alive = 0;
           }
	    while (1) {
		char *p = sock->rd->buf;
		snif_conn *conn = snif_conn_receive((const char **)&p, sock->rd->len);
		snif_buf_shift(sock->rd, p - sock->rd->buf);
		if (!conn) break;
		struct snif_watch_port *wp;
		for (wp = sock->watch.ports; wp->port && strcmp(wp->port, conn->srv.port); wp++);
		if (wp->port) {
		    char buf[128];
		    snif_sock *fwd = snif_fwd(conn, wp, sock->watch.cert, sock->listen);
		    if (fwd) {
			p = buf;
			snif_conn_accept(&p, sizeof(buf), conn);
			snif_sock_out(sock, buf, p - buf);
			p = buf;
			snif_conn_forward(&p, sizeof(buf), conn);
			snif_sock_out(fwd, buf, p - buf);
		    } else {
			p = buf;
			snif_conn_reject(&p, sizeof(buf), conn);
			snif_sock_out(sock, buf, p - buf);
		    }
		}
		snif_conn_free(conn);
	    }
	}
	return;
    }
    if (!sock->watch.ssl) {
	sock->watch.ssl = snif_cert_ssl(sock->watch.cert);
	if (!sock->watch.ssl) return snif_watch_error(sock);
	SSL_set_fd(sock->watch.ssl, sock->fd);
    }
    int r = SSL_accept(sock->watch.ssl);
    if (r > 0) {
	sock->rd = snif_buf_new(SNIF_WATCH_BUFSIZE);
	sock->wr = snif_buf_new(SNIF_WATCH_BUFSIZE);
       snif_sock_tmout(sock, sock->listen->tmout.watch);
       sock->watch.alive = sock->listen->tmout.alive;
	char buf[288];
	char *p = buf;
	if (snif_conn_start(&p, sizeof(buf), sock->watch.rhost) > 0) {
	    snif_sock_out(sock, buf, p - buf);
	}
    } else switch (SSL_get_error(sock->watch.ssl, r)) {
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SSL:
	case SSL_ERROR_SYSCALL:
	    return snif_watch_error(sock);
	default:
	    break;
    }
}

snif_sock *snif_watch(const char *rhost, const char *rport, struct snif_cert *cert, struct snif_watch_port *ports, snif_listen *lstn) {
    int fd = snif_sock_connect(rhost, rport);
#ifdef SNIF_DEBUG
    printf("snif_watch fd=%d rhost=%s rport=%s\n", fd, rhost, rport);
#endif
    if (fd < 0) return NULL;
    snif_sock *skconn = malloc(offsetof(snif_sock, watch) + sizeof(skconn->watch));
    skconn->chain = NULL;
    skconn->watch.rhost = rhost;
    skconn->watch.rport = rport;
    skconn->watch.ports = ports;
    skconn->watch.cert = cert;
    skconn->watch.ssl = NULL;
    skconn->watch.alive = 0;
    skconn->fd = fd;
    skconn->pollfn = &snif_watch_pollfn;
    skconn->listen = lstn;
    snif_sock_initconn(skconn);
    snif_sock_tmout(skconn, skconn->listen->tmout.conn);
    snif_watch_logopen(skconn);
    return skconn;
}

