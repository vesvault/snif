/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include "sock.h"
#include "listen.h"
#include "buf.h"
#include "srv.h"
#include "map.h"


snif_map *snif_map_list = NULL;

snif_map *snif_map_add(char *host, const char *port, const char *dsthost, const char *dstport) {
    snif_map *map = malloc(sizeof(*map));
    char *s;
    for (s = host; *s; s++) if (*s >= 'A' && *s <= 'Z') *s |= 0x20;
    map->host = host;
    map->port = port;
    map->dsthost = dsthost;
    map->dstport = dstport;
    map->chain = snif_map_list;
    return snif_map_list = map;
}

/* host matched but no port entry: sentinel with a NULL dsthost,
 * snif_map_conn() fails on it so the client is dropped right away */
static snif_map snif_map_drop = {NULL, NULL, NULL, NULL, NULL};

snif_map *snif_map_find(const char *host, const char *port) {
    snif_map *map;
    snif_map *rs = NULL;
    for (map = snif_map_list; map; map = map->chain) {
	if (strcmp(map->host, host)) continue;
	if (!strcmp(map->port, port)) return map;
	rs = &snif_map_drop;
    }
    return rs;
}

void snif_map_free(snif_sock *sock) {
#ifdef SNIF_DEBUG
    printf("snif_map_free fd=%d\n", sock->fd);
#endif
    snif_buf_free(sock->rd);
    return snif_sock_free(sock);
}

void snif_map_pollfn(snif_sock *sock, struct pollfd *pollfd) {
    if (!pollfd) return snif_map_free(sock);
    if (pollfd->fd < 0) return snif_sock_initpoll(sock, pollfd);
    if (snif_sock_chktmout(sock) < 0) return;
    if (snif_sock_rw(sock, pollfd, NULL) > 0) snif_sock_tmout(sock, sock->listen->tmout.idle);
}

snif_sock *snif_map_conn(snif_map *map, snif_sock *cln) {
    int fd = map->dsthost ? snif_sock_connect(map->dsthost, map->dstport) : -1;
#ifdef SNIF_DEBUG
    printf("snif_map_conn fd=%d %s:%s\n", fd, map->dsthost, map->dstport);
#endif
    if (fd < 0) return NULL;
    snif_sock *sock = malloc(offsetof(snif_sock, srv) + sizeof(sock->srv));
    sock->fd = fd;
    sock->pollfn = &snif_map_pollfn;
    sock->listen = cln->listen;
    snif_sock_initconn(sock);
    sock->rd = snif_buf_new(SNIF_MAP_BUFSIZE);
    sock->peer = cln;
    cln->peer = sock;
    sock->wr = cln->rd;
    cln->wr = sock->rd;
    sock->wr->low = sock->rd->low = SNIF_SRV_BUFLOW;
    snif_sock_tmout(sock, sock->listen->tmout.idle);
    snif_sock_tmout(cln, cln->listen->tmout.idle);
    return sock;
}
