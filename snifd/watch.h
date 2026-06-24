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


#define	SNIF_WATCH_BUFSIZE	4096

typedef struct snif_watch_port {
    const char *port;
    const char *lhost;
    const char *lport;
    int flags;
} snif_watch_port;

#define	SNIF_WF_TERMTLS		0x01

struct snif_cert;
struct snif_listen;

struct snif_sock *snif_watch(const char *rhost, const char *rport, struct snif_cert *cert, struct snif_watch_port *ports, struct snif_listen *lstn);
