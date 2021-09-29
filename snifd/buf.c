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
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <unistd.h>
#include "buf.h"

snif_buf *snif_buf_new(int max) {
    snif_buf *buf = malloc(sizeof(snif_buf) + max);
    buf->max = max;
    buf->len = 0;
    buf->low = 0;
    return buf;
}

void snif_buf_shift(snif_buf *buf, int l) {
    if (buf->len > l) {
	memmove(buf->buf, buf->buf + l, buf->len - l);
	buf->len -= l;
    } else {
	buf->len = 0;
    }
}

int snif_buf_recv(snif_buf *buf, int fd) {
    if (!buf || buf->len >= buf->max) return 0;
    int r = read(fd, buf->buf + buf->len, buf->max - buf->len);
    if (r > 0) {
	buf->len += r;
	return r;
    }
    if (!r) {
	return buf->max = 0;
    }
    switch (errno) {
#if EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case EAGAIN:
	    return 0;
	default:
	    return SNIF_BUF_ERR;
    }
}

int snif_buf_send(snif_buf *buf, int fd) {
    if (!buf) return 0;
    int r = buf->len ? write(fd, buf->buf, buf->len) : 0;
    if (r >= 0) {
	snif_buf_shift(buf, r);
	if (!buf->max && !buf->len) {
	    shutdown(fd, SHUT_WR);
	}
	return r;
    }
    switch (errno) {
#if EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case EAGAIN:
	    return 0;
	default:
	    return SNIF_BUF_ERR;
    }
}

int snif_buf_recv_ssl(snif_buf *buf, void *ssl) {
    if (!buf || buf->len >= buf->max) return 0;
    int r = SSL_read(ssl, buf->buf + buf->len, buf->max - buf->len);
    if (r > 0) {
	buf->len += r;
	return r;
    }
    switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_ZERO_RETURN:
	    return buf->max = 0;
	case SSL_ERROR_SSL:
	case SSL_ERROR_SYSCALL:
	    return SNIF_BUF_ERR;
	default:
	    return 0;
    }
}

int snif_buf_send_ssl(snif_buf *buf, void *ssl) {
    if (!buf) return 0;
    int r = buf->len ? SSL_write(ssl, buf->buf, buf->len) : 1;
    if (r > 0) {
	snif_buf_shift(buf, r);
	if (!buf->max && !buf->len) {
	    SSL_shutdown(ssl);
	}
	return r;
    }
    switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_SSL:
	case SSL_ERROR_SYSCALL:
	    return SNIF_BUF_ERR;
	default:
	    return 0;
    }
}

int snif_buf_append(snif_buf *buf, const char *src, int len) {
    if (!buf || len + buf->len > buf->max) return -1;
    memcpy(buf->buf + buf->len, src, len);
    buf->len += len;
    return len;
}

int snif_buf_scanl(snif_buf *buf, int *cmdlen, ...) {
    if (!buf->len) return -1;
    const char *s = buf->buf;
    const char *nl = memchr(s, '\n', buf->len);
    if (!nl) return -1;
    const char *eol = nl;
    if (eol > s && eol[-1] == '\r') eol--;
    va_list va;
    va_start(va, cmdlen);
    int ct = 0;
    char *d = NULL;
    int len;
    while (s < eol) {
	if (!d) {
	    len = va_arg(va, int);
	    if (len <= 0) break;
	    d = va_arg(va, char *);
	    ct++;
	}
	char c = *s++;
	switch (c) {
	    case ' ': case '\t': case 0:
		*d = 0;
		d = NULL;
		break;
	    default:
		if (len > 1) {
		    *d++ = c;
		    len--;
		}
		break;
	}
    }
    if (d) *d = 0;
    va_end(va);
    if (cmdlen) *cmdlen = nl - buf->buf + 1;
    else snif_buf_shift(buf, nl - buf->buf + 1);
    return ct;
}
