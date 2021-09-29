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


typedef struct snif_conn {
    struct snif_conn_addr {
	const char *host;
	const char *port;
    } srv;
    struct snif_conn_addr fwd;
    struct snif_conn_addr cln;
    char connid[1];
} snif_conn;


int snif_conn_start(char **ctlbuf, int ctllen, const char *hostname);
struct snif_conn *snif_conn_receive_cb(const char **ctlbuf, int ctllen, void *arg, void (* callbk)(void *arg, const char *buf, int len));
#define	snif_conn_receive(ctlbuf, ctllen)	snif_conn_receive_cb(ctlbuf, ctllen, NULL, NULL)
int snif_conn_forward(char **fwdbuf, int fwdlen, struct snif_conn *conn);
int snif_conn_accept(char **ctlbuf, int ctllen, struct snif_conn *conn);
int snif_conn_reject(char **ctlbuf, int ctllen, struct snif_conn *conn);
int snif_conn_abuse(char **ctlbuf, int ctllen, struct snif_conn *conn, int abuse);
int snif_conn_msg(char **ctlbuf, int ctllen, const char *hostname, const char *msg);
int snif_conn_idle(char **ctlbuf, int ctllen);
#define	snif_conn_free(conn)	free(conn)
