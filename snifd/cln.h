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


#define	SNIF_CLN_MAXHOST	255
#define	SNIF_CLN_BUFSIZE	5120
#define	SNIF_CLN_ABUSE		60

struct snif_sock *snif_cln(struct snif_sock *sock);
struct snif_sock **snif_cln_seek(const char *connid, int create);
#define	snif_cln_get(connid)	snif_cln_seek(connid, 0)
char *snif_cln_notify(struct snif_sock *sock, char *buf);
int snif_cln_push(struct snif_sock *sock, const char *ntfy);
