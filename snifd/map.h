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


#define	SNIF_MAP_BUFSIZE	5120

typedef struct snif_map {
    struct snif_map *chain;
    const char *host;
    const char *port;
    const char *dsthost;
    const char *dstport;
    int flags;
} snif_map;

#define	SNIF_MAP_F_PROXY	0x02

snif_map *snif_map_add(char *host, const char *port, const char *dsthost, const char *dstport, int flags);
snif_map *snif_map_find(const char *host, const char *port);
struct snif_sock *snif_map_conn(snif_map *map, struct snif_sock *cln);
