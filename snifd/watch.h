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
