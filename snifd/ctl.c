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
#include <syslog.h>
#include "jTree.h"
#include "util.h"
#include "../lib/cert.h"
#include "sock.h"
#include "host.h"
#include "listen.h"
#include "buf.h"
#include "cln.h"
#include "abuse.h"
#include "ctl.h"


void snif_ctl_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_ctl_free fd=%d\n", sock->fd);
#endif
    if (sock->ctl.host) {
	snif_log("ctl=%d close", sock->fd);
	if (sock->listen->push) {
	    char buf[64];
	    sprintf(buf, "SNIF CTL %d\r\n", sock->fd);
	    snif_listen_push(sock->listen, buf);
	}
    }
    snif_buf_free(sock->rd);
    snif_buf_free(sock->wr);
    if (sock->ctl.host) {
	snif_sock_removechain(sock, &sock->cln.host->ctls);
	snif_host_chkalive(sock->cln.host);
    }
    if (sock->ctl.ssl) {
	SSL_shutdown(sock->ctl.ssl);
	SSL_free(sock->ctl.ssl);
    }
    return snif_sock_free(sock);
}

void snif_ctl_error(snif_sock *sock) {
    snif_ctl_free(sock);
}

void snif_ctl_sethost(snif_sock *sock, const char *hostname, int len) {
    snif_host *h = sock->ctl.host = snif_host_get(hostname, len);
    if (h) {
	sock->chain = NULL;
	snif_sock_addchain(sock, &h->ctls);
	snif_sock *cln;
	char ntfy[1024];
	for (cln = h->clients; cln; cln = cln->chain) if (!cln->peer) {
	    snif_cln_notify(cln, ntfy);
	    if (snif_ctl_out(sock, ntfy, strlen(ntfy)) <= 0) break;
	}
	if (sock->listen->push) {
	    char rhost[64];
	    char rport[16];
	    struct sockaddr_in6 sa;
	    socklen_t sl = sizeof(sa);
	    if (getpeername(sock->fd, (struct sockaddr *)&sa, &sl) >= 0
		&& getnameinfo((struct sockaddr *)&sa, sl, rhost, sizeof(rhost), rport, sizeof(rport), NI_NUMERICHOST | NI_NUMERICSERV) >= 0
	    ) {
		sprintf(ntfy, "SNIF CTL %d %.*s [%s]:%s\r\n", sock->fd, len, hostname, rhost, rport);
		snif_listen_push(sock->listen, ntfy);
	    }
	}
    }
}

int snif_ctl_out(snif_sock *sock, const char *buf, int len) {
    int r = snif_sock_out(sock, buf, len);
    if (r <= 0) return r;
    if (!sock->ctl.alive) return 0;
    unsigned long t = snif_time() + sock->listen->tmout.alive;
    if (t < sock->ctl.alive) sock->ctl.alive = t;
    return r;
}

void snif_ctl_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_ctl_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    if (sock->ctl.host) {
	snif_host_chkalive(sock->ctl.host);
	if (sock->ctl.alive && sock->ctl.alive < sock->listen->chktime) sock->listen->chktime = sock->ctl.alive;
	int bytes = snif_sock_rw(sock, pollfd, sock->ctl.ssl);
	if (bytes < 0) return;
	if (bytes > 0) snif_sock_tmout(sock, sock->listen->tmout.idle);
	while (1) {
	    char cmd1[8];
	    char cmd2[16];
	    char connid[SNIF_CLN_MAXHOST + 1];
	    char arg[16];
	    int len;
	    int c = snif_buf_scanl(sock->rd, &len,
		sizeof(cmd1), cmd1,
		sizeof(cmd2), cmd2,
		sizeof(connid), connid,
		sizeof(arg), arg,
		0);
	    if (c < 0) break;
	    sock->ctl.alive = SNIF_CTL_MAXTIME;
	    if (c >= 3 && !strcmp(cmd1, "SNIF")) {
		int fpush = 0;
		if (!strcmp(cmd2, "CLOSE")) {
		    snif_sock **ppeer = snif_cln_get(connid);
		    if (ppeer) {
			if (*ppeer) snif_sock_done(*ppeer);
		    } else fpush = 1;
		} else if (!strcmp(cmd2, "ABUSE")) {
		    snif_sock **ppeer = snif_cln_get(connid);
		    if (ppeer) {
			int abuse = 30;
			if (c > 3) sscanf(arg, "%d", &abuse);
			if (*ppeer) snif_abuse_add((*ppeer)->fd, abuse);
		    } else fpush = 1;
		} else if (!strcmp(cmd2, "MSG")) {
		    if (c >= 4 && !strcmp(connid, sock->ctl.host->hostname)) fpush = 1;
		}
		if (fpush) {
		    unsigned long t = snif_time();
		    if (sock->ctl.pushtime < t + SNIF_CTL_PUSHGRACE) {
			if (sock->ctl.pushtime < t) sock->ctl.pushtime = t;
			sock->ctl.pushtime++;
			snif_listen_pushl(sock->listen, sock->rd->buf, len);
		    }
		}
	    } else if (c >= 1 && !strcmp(cmd1, "NOOP")) {
		snif_sock_out(sock, "NOOP\r\n", 6);
	    }
	    snif_buf_shift(sock->rd, len);
	}
	return;
    }
    if (!sock->ctl.ssl) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	const SSL_METHOD *method = TLS_client_method();
#else
	const SSL_METHOD *method = SSLv23_client_method();
#endif
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) return snif_ctl_error(sock);
	SSL_CTX_set_default_verify_paths(ctx);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify_depth(ctx, 8);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	sock->ctl.ssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	SSL_set_fd(sock->ctl.ssl, sock->fd);
    }
    if (SSL_is_init_finished(sock->ctl.ssl)) {
	if (snif_sock_rw(sock, pollfd, sock->ctl.ssl) < 0) return;
	while (1) {
	    char cmd1[8];
	    char cmd2[16];
	    char host[SNIF_CLN_MAXHOST + 1];
	    int c = snif_buf_readl(sock->rd,
		sizeof(cmd1), cmd1,
		sizeof(cmd2), cmd2,
		sizeof(host), host,
		0);
	    if (c < 0) break;
	    if (c >= 3 && !strcmp(cmd1, "SNIF") && !strcmp(cmd2, "LISTEN")) {
		X509 *crt = SSL_get_peer_certificate(sock->ctl.ssl);
		int cl;
		const char *cn = snif_cert_getcn(crt, &cl);
		int hl = strlen(host);
		const char *p = strchr(host, '.');
		if ((hl == cl - 2 && cn[1] == '.')
		    || (hl >= cl && !strncmp(cn + 1, p, cl - 1) && host[0] != '*')
		) {
		    snif_ctl_sethost(sock, host, hl);
		    snif_sock_tmout(sock, sock->listen->tmout.idle);
		}
		X509_free(crt);
	    }
	    if (sock->ctl.host) break;
	}
	return;
    }
    int r = SSL_connect(sock->ctl.ssl);
    if (r > 0) {
	long vrfy = SSL_get_verify_result(sock->ctl.ssl);
	X509 *crt = SSL_get_peer_certificate(sock->ctl.ssl);
	int cl;
	const char *cn = crt ? snif_cert_getcn(crt, &cl) : NULL;
	char rhost[64];
	char rport[16];
	struct sockaddr_in6 sa;
	socklen_t sl = sizeof(sa);
	if (getpeername(sock->fd, (struct sockaddr *)&sa, &sl) < 0
	    || getnameinfo((struct sockaddr *)&sa, sl, rhost, sizeof(rhost), rport, sizeof(rport), NI_NUMERICHOST | NI_NUMERICSERV) < 0
	) rhost[0] = rport[0] = 0;
	snif_log("ctl=%d open cn=%.*s vrfy=%ld remote=[%s]:%s", sock->fd, (cn ? cl : 0), (cn ? cn : ""), vrfy, rhost, rport);
	if (vrfy != X509_V_OK || !crt) cn = NULL;
	if (cn) {
	    sock->wr = snif_buf_new(SNIF_CTL_WBUFSIZE);
	    sock->rd = snif_buf_new(SNIF_CTL_RBUFSIZE);
	    if (cn[0] != '*') {
		snif_ctl_sethost(sock, cn, cl);
		snif_sock_tmout(sock, sock->listen->tmout.idle);
	    }
	}
	if (crt) X509_free(crt);
	if (!cn) return snif_ctl_error(sock);
    } else switch (SSL_get_error(sock->ctl.ssl, r)) {
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SSL:
	case SSL_ERROR_SYSCALL:
	    return snif_ctl_error(sock);
	default:
	    break;
    }
}

snif_sock *snif_ctl(snif_sock *sock) {
    int fd = snif_sock_accept(sock, SNIF_CTL_ABUSE);
#ifdef SNIF_DEBUG
    printf("snif_ctl fd=%d\n", fd);
#endif
    if (fd < 0) return NULL;
    snif_sock *skconn = malloc(offsetof(snif_sock, ctl) + sizeof(skconn->ctl));
    skconn->fd = fd;
    skconn->pollfn = &snif_ctl_pollfn;
    skconn->listen = sock->listen;
    skconn->ctl.ssl = NULL;
    skconn->ctl.host = NULL;
    skconn->ctl.alive = SNIF_CTL_MAXTIME;
    skconn->ctl.pushtime = 0;
    snif_sock_initconn(skconn);
    snif_sock_tmout(skconn, sock->listen->tmout.conn);
    return skconn;
}
