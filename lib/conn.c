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
#include <stdio.h>
#include "conn.h"


int snif_conn_start(char **ctlbuf, int ctllen, const char *hostname) {
    if (strlen(hostname) > ctllen - 16) return 0;
    sprintf(*ctlbuf, "SNIF LISTEN %s\r\n", hostname);
    int l = strlen(*ctlbuf);
    *ctlbuf += l;
    return l;
}

static int snif_conn_addr_parse(struct snif_conn_addr *addr, char **dp, char *dtail) {
    char *d = *dp;
    if (d >= dtail) return 0;
    *d++ = 0;
    if (d >= dtail) return 0;
    char *sp = memchr(d, ' ', dtail - d);
    if (!sp) sp = dtail;
    char *p = sp - 1;
    while (p > d) {
	if (*p == ':') {
	    *p = 0;
	    addr->host = d;
	    addr->port = p + 1;
	    *dp = sp;
	    return 1;
	}
	p--;
    }
    return 0;
}

struct snif_conn *snif_conn_receive_cb(const char **ctlbuf, int ctllen, void *arg, void (* callbk)(void *arg, const char *buf, int len)) {
    const char *s = *ctlbuf;
    const char *tail = s + ctllen;
    snif_conn *conn = NULL;
    while (!conn) {
	const char *lf = memchr(s, '\n', tail - s);
	if (!lf) break;
	if (lf - s >= 24 && !strncmp(s, "SNIF CONNECT ", 13)) {
	    s += 13;
	    int l = lf - s;
	    conn = malloc(sizeof(*conn) + l);
	    memcpy(conn->connid, s, l);
	    char *d = memchr(conn->connid, ' ', l);
	    char *dtail = conn->connid + l;
	    if (l > 0 && dtail[-1] == '\r') dtail--;
	    if (d
		&& snif_conn_addr_parse(&conn->srv, &d, dtail)
		&& snif_conn_addr_parse(&conn->fwd, &d, dtail)
		&& snif_conn_addr_parse(&conn->cln, &d, dtail)
		) *d = 0;
	    else {
		free(conn);
		conn = NULL;
	    }
	} else if (callbk) {
	    callbk(arg, s, lf - s - (lf > s && lf[-1] == '\r' ? 1 : 0));
	}
	*ctlbuf = s = lf + 1;
    }
    return conn;
}

int snif_conn_forward(char **fwdbuf, int fwdlen, struct snif_conn *conn) {
    if (strlen(conn->connid) > fwdlen - 16) return 0;
    sprintf(*fwdbuf, "SNIF ACCEPT %s\r\n", conn->connid);
    int l = strlen(*fwdbuf);
    *fwdbuf += l;
    return l;
}

int snif_conn_accept(char **ctlbuf, int ctllen, struct snif_conn *conn) {
    if (ctllen < 5) return 0;
    strcpy(*ctlbuf, "OK\r\n");
    *ctlbuf += 4;
    return 4;
}

int snif_conn_reject(char **ctlbuf, int ctllen, struct snif_conn *conn) {
    if (strlen(conn->connid) > ctllen - 16) return 0;
    sprintf(*ctlbuf, "SNIF CLOSE %s\r\n", conn->connid);
    int l = strlen(*ctlbuf);
    *ctlbuf += l;
    return l;
}

int snif_conn_abuse(char **ctlbuf, int ctllen, struct snif_conn *conn, int abuse) {
    if (strlen(conn->connid) > ctllen - 24) return 0;
    sprintf(*ctlbuf, "SNIF ABUSE %s %d\r\n", conn->connid, abuse);
    int l = strlen(*ctlbuf);
    *ctlbuf += l;
    return l;
}

int snif_conn_msg(char **ctlbuf, int ctllen, const char *hostname, const char *msg) {
    if (!hostname || !msg || strlen(hostname) + strlen(msg) > ctllen - 16) return 0;
    sprintf(*ctlbuf, "SNIF MSG %s %s\r\n", hostname, msg);
    int l = strlen(*ctlbuf);
    *ctlbuf += l;
    return l;
}

int snif_conn_idle(char **ctlbuf, int ctllen) {
    if (ctllen < 7) return 0;
    strcpy(*ctlbuf, "NOOP\r\n");
    *ctlbuf += 6;
    return 6;
}
