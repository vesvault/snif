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
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <time.h>
#include "jTree.h"
#include "sock.h"
#include "host.h"
#include "listen.h"
#include "buf.h"
#include "cln.h"


jTree *snif_cln_tree = NULL;

int snif_cln_jtreefn(void *data, void *term, void *arg) {
    return strcmp(((snif_sock *) data)->cln.connid, (const char *) term);
}

snif_sock **snif_cln_seek(const char *connid, int create) {
    unsigned char depth = 0;
    return (snif_sock **) jTree_seek(&snif_cln_tree, (void *) connid, NULL, &snif_cln_jtreefn, (create ? &depth : NULL));
}

int snif_cln_snifn(SSL *ssl, int *al, void *arg) {
    snif_sock *sock = arg;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    int l;
    if (!sni || (l = strlen(sni)) > SNIF_CLN_MAXHOST) return SSL_TLSEXT_ERR_ALERT_FATAL;
    sock->cln.host = snif_host_get(sni, l);
    sock->chain = NULL;
    snif_sock_addchain(sock, &sock->cln.host->clients);
    SSL_set_bio(ssl, NULL, NULL);
    return SSL_TLSEXT_ERR_NOACK;
}

void snif_cln_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_cln_free fd=%d\n", sock->fd);
#endif
    if (sock->cln.rbytes < 0 && sock->listen->push) {
	char buf[128];
	sprintf(buf, "SNIF CLOSE %s\r\n", sock->cln.connid);
	snif_listen_push(sock->listen, buf);
    }
    jTree_delete(&snif_cln_tree, jTree_seek(&snif_cln_tree, (void *) sock->cln.connid, NULL, &snif_cln_jtreefn, NULL));
    snif_buf_free(sock->rd);
    if (sock->cln.host) snif_sock_removechain(sock, &sock->cln.host->clients);
    if (sock->cln.ctx) SSL_CTX_free(sock->cln.ctx);
    return snif_sock_free(sock);
}

void snif_cln_error(snif_sock *sock) {
    snif_cln_free(sock);
}

char *snif_cln_notify(snif_sock *sock, char *buf) {
    if (!buf) buf = malloc(1024);
    char rhost[64];
    char rport[16];
    struct sockaddr_in6 sa;
    socklen_t sl = sizeof(sa);
    if (getpeername(sock->fd, (struct sockaddr *)&sa, &sl) < 0
	|| getnameinfo((struct sockaddr *)&sa, sl, rhost, sizeof(rhost), rport, sizeof(rport), NI_NUMERICHOST | NI_NUMERICSERV) < 0
    ) rhost[0] = rport[0] = 0;
    sprintf(buf, "SNIF CONNECT %s %s:%s %s:%s [%s]:%s\r\n",
	sock->cln.connid,
	sock->cln.host->hostname,
	sock->cln.parent->port.port,
	sock->listen->srv->port.host,
	sock->listen->srv->port.port,
	rhost,
	rport
    );
    return buf;
}

int snif_cln_push(snif_sock *sock, const char *ntfy) {
    sock->cln.rbytes = -1;
    return snif_listen_push(sock->listen, ntfy);
}

void snif_cln_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_cln_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    int bytes = snif_sock_rw(sock, pollfd, NULL);
    if (bytes < 0) return;
    if (sock->peer) {
	if (bytes > 0) snif_sock_tmout(sock, sock->listen->tmout.idle);
	return;
    }
    if (sock->cln.host) {
	if (!sock->rd->max) snif_sock_done(sock);
	return;
    }
    if (sock->cln.rbytes >= sock->rd->len) return;
    sock->cln.rbytes = sock->rd->len;
    if (!sock->cln.ctx) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	const SSL_METHOD *method = TLS_server_method();
#else
	const SSL_METHOD *method = TLSv1_2_server_method();
#endif
	sock->cln.ctx = SSL_CTX_new(method);
	if (!sock->cln.ctx) return snif_cln_error(sock);
	if (SSL_CTX_set_tlsext_servername_callback(sock->cln.ctx, &snif_cln_snifn) <= 0
	    || SSL_CTX_set_tlsext_servername_arg(sock->cln.ctx, sock) <= 0
	) {
	    return snif_cln_error(sock);
	}
    }
    BIO *bbuf = BIO_new_mem_buf(sock->rd->buf, sock->rd->len);
    BIO *bfd = BIO_new_fd(sock->fd, BIO_NOCLOSE);
    SSL *ssl = SSL_new(sock->cln.ctx);
    SSL_set_bio(ssl, bbuf, bfd);
    int r = SSL_accept(ssl);
    int e = SSL_get_error(ssl, r);
    SSL_free(ssl);
    if (sock->cln.host) {
	SSL_CTX_free(sock->cln.ctx);
	sock->cln.ctx = NULL;
	unsigned char connid[16];
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	unsigned int mdlen = sizeof(connid);
	if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) <= 0
	    || EVP_DigestUpdate(mdctx, sock->rd->buf, sock->rd->len) <= 0
	    || EVP_DigestFinal_ex(mdctx, connid, &mdlen) <= 0) {
	    RAND_bytes(connid, sizeof(connid));
	}
	EVP_MD_CTX_destroy(mdctx);
	sprintf(sock->cln.connid, "%016llx%04hx", *((long long *) connid), *((unsigned short *)(connid + 8)));
	snif_sock **pconn = snif_cln_seek(sock->cln.connid, 1);
	if (*pconn) {
	    snif_sock_done(sock);
	    return;
	}
	*pconn = sock;
#ifdef SNIF_DEBUG
	printf("snif_cln_pollfn fd=%d connid=%s pconn=%p\n", sock->fd, sock->cln.connid, pconn);
#endif
	char ntfy[1024];
	snif_cln_notify(sock, ntfy);
	if (snif_host_notify(sock->cln.host, ntfy) <= 0) snif_cln_push(sock, ntfy);
    } else switch (e) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SSL:
	    return snif_cln_error(sock);
	default:
	    break;
    }
}


snif_sock *snif_cln(snif_sock *sock) {
    int fd = snif_sock_accept(sock, SNIF_CLN_ABUSE);
#ifdef SNIF_DEBUG
    printf("snif_cln fd=%d\n", fd);
#endif
    if (fd < 0) return NULL;
    snif_sock *skconn = malloc(offsetof(snif_sock, cln) + sizeof(skconn->cln));
    skconn->fd = fd;
    skconn->pollfn = &snif_cln_pollfn;
    skconn->listen = sock->listen;
    skconn->cln.parent = sock;
    skconn->cln.ctx = NULL;
    skconn->cln.rbytes = 0;
    skconn->cln.host = NULL;
    snif_sock_initconn(skconn);
    skconn->rd = snif_buf_new(SNIF_CLN_BUFSIZE);
    snif_sock_tmout(skconn, skconn->listen->tmout.cln);
    return skconn;
}

