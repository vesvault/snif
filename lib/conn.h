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


/**************************************************************************
 * An incoming SNIF connection notification.
 *   .srv - the server host:port the client intends to connect to,
 *          host will match the hostname communicated in snif_conn_start()
 *   .fwd - the forward port to connect to, see snif_conn_forward()
 *   .cln - the client's remote host:port
 *   .connid - SNIF connection ID
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


/**************************************************************************
 * Generate the first message to be sent into a newly established snif ctl
 * connection. Normally the control connection is opened to TCP
 * snif_cert_hostname(cert), port "snif" (7123)
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_start(char **ctlbuf, int ctllen, const char *hostname);

/**************************************************************************
 * Listen for connection notifications on the ctl connection. This call
 * blocks and returns the received connection notification as
 * struct snif_conn. The returned struct snif_conn is to be deallocated
 * by snif_conn_free() when done.
 * An optional callbk with arg is called when receiving any message other
 * than a connection notification.
 **************************************************************************/
struct snif_conn *snif_conn_receive_cb(const char **ctlbuf, int ctllen, void *arg, void (* callbk)(void *arg, const char *buf, int len));

/**************************************************************************
 * A shorthand for snif_conn_receive_cb() without the optional callback.
 **************************************************************************/
#define	snif_conn_receive(ctlbuf, ctllen)	snif_conn_receive_cb(ctlbuf, ctllen, NULL, NULL)

/**************************************************************************
 * Generate a message for the newly established snif-srv fwd connection to
 * TCP snif_conn.fwd.host:snif_conn.fwd.port when accepting snif_conn.
 * Immediately upon sending this message, the fwd connection is to be
 * treated as a client TLS connection.
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_forward(char **fwdbuf, int fwdlen, struct snif_conn *conn);

/**************************************************************************
 * Generate a message for the ctl connection when accepting snif_conn
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_accept(char **ctlbuf, int ctllen, struct snif_conn *conn);

/**************************************************************************
 * Generate a message for the ctl connection when rejecting snif_conn
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_reject(char **ctlbuf, int ctllen, struct snif_conn *conn);

/**************************************************************************
 * Generate an abuse score notification for the ctl connection with the
 * respect to a received snif_conn
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_abuse(char **ctlbuf, int ctllen, struct snif_conn *conn, int abuse);

/**************************************************************************
 * Prepare a custom app-level message over the ctl connection, to be
 * handled by a specific SNIF peripheral process
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_msg(char **ctlbuf, int ctllen, const char *hostname, const char *msg);

/**************************************************************************
 * Generate an idle keepalive message for the ctl connection,
 * call periodically with 1-15 minute interval to promptly detect
 * disconnects
 *   ctlbuf - the buffer pointer
 *   ctllen - max space available in *ctlbuf
 *   hostname - from snif_cert_hostname()
 * On success - returns the length written to the buffer,
 *              *ctlbuf points to the next position. The buffer content is
 *              to be sent to the ctl connection by external logic
 * On error - returns 0
 **************************************************************************/
int snif_conn_idle(char **ctlbuf, int ctllen);

/**************************************************************************
 * Deallocate struct snif_conn returned by snif_conn_receive*
 **************************************************************************/
#define	snif_conn_free(conn)	free(conn)
