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
#include <unistd.h>
#include "sock.h"
#include "listen.h"
#include "port.h"



void snif_port_free(snif_sock *sock) {
    return snif_sock_free(sock);
}

void snif_port_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_port_free(sock);
    if (pollfd->fd < 0) {
	snif_sock_setpoll(sock, pollfd, POLLIN | POLLPRI | POLLHUP | POLLERR);
	return;
    }
    if (pollfd->revents & POLLIN) {
	sock->port.connfn(sock);
    }
}

snif_sock *snif_port(const char *host, const char *port, snif_listen *lstn, snif_sock * (* connfn)(snif_sock *)) {
    struct addrinfo hint = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *ai = NULL;
    int r = getaddrinfo(host, port, &hint, &ai);
    if (r) return NULL;
    struct addrinfo *a;
    snif_sock *sk = NULL;
    for (a = ai; a; a = a->ai_next) {
	int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0) return NULL;
	int flg = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &flg, sizeof(flg));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *) &flg, sizeof(flg));
#endif
	if (bind(fd, a->ai_addr, a->ai_addrlen) < 0) {
	    close(fd);
	    return NULL;
	}
	if (listen(fd, 16) < 0) {
	    close(fd);
	    return NULL;
	}
	sk = malloc(offsetof(snif_sock, port) + sizeof(sk->port));
	sk->listen = lstn;
	sk->pollfn = &snif_port_pollfn;
	sk->port.host = host;
	sk->port.port = port;
	sk->port.connfn = connfn;
	sk->fd = fd;
	snif_listen_add(lstn, sk);
    }
    freeaddrinfo(ai);
    return sk;
}
