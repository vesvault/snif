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


struct snif_sock;

typedef struct snif_listen {
    struct pollfd *pollfds;
    struct snif_sock **socks;
    int pollct;
    int pollmax;
    int firstempty;
    unsigned long chktime;
    struct {
	int cln;
	int conn;
	int idle;
	int retry;
	int alive;
	int watch;
    } tmout;
    struct snif_sock *ctl;
    struct snif_sock *srv;
    struct snif_sock *push;
    struct snif_sock *input;
    struct snif_sock *watch;
    char shutdn;
#ifdef SNIF_DIAGS
    long long ctpolls;
#endif
} snif_listen;

#define	SNIF_LISTEN_TMOUT	900

struct snif_sock *snif_listen_add(struct snif_listen *lstn, struct snif_sock *sock);
void snif_listen_remove(struct snif_listen *lstn, struct snif_sock *sock);
int snif_listen_poll(struct snif_listen *lstn);
int snif_listen_pushl(struct snif_listen *lstn, const char *ntfy, int len);
#define	snif_listen_push(lstn, ntfy)	snif_listen_pushl(lstn, ntfy, -1)
int snif_listen_shutdown(struct snif_listen *lstn);
