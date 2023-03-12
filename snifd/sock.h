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


#ifndef SNIF_SOCK_MAXBUF
#define	SNIF_SOCK_MAXBUF	131072
#endif

struct pollfd;

typedef struct snif_sock {
    int fd;
    int listenidx;
    struct snif_listen *listen;
    void (* pollfn)(struct snif_sock *sock, struct pollfd *pollfd);
#ifdef SNIF_DIAGS
    struct {
	long long start;
	long long in;
	long long out;
	long long err;
	long long hup;
	long long nval;
	long long pri;
    } diags;
#endif
    union {
	struct {
	    const char *host;
	    const char *port;
	    struct snif_sock * (* connfn)(struct snif_sock *sock);
	} port;
	struct {
	    struct snif_sock *peer;
	    struct snif_sock *chain;
	    struct snif_buf *rd;
	    struct snif_buf *wr;
	    unsigned long chktime;
	    union {
		struct {
		    struct snif_host *host;
		    void *ctx;
		    struct snif_sock *parent;
		    int rbytes;
		    char connid[24];
		} cln;
		struct {
		    struct snif_host *host;
		    void *ssl;
		    unsigned long alive;
		    unsigned long pushtime;
		} ctl;
		struct {} srv;
		struct {
		    const char *fname;
		    char write;
		} fifo;
		struct {
		    struct snif_cert *cert;
		    void *ssl;
		    unsigned long alive;
		    struct snif_watch_port *ports;
		    const char *rhost;
		    const char *rport;
		} watch;
		struct {
		    struct snif_cert *cert;
		    void *ssl;
		    struct snif_watch_port *port;
		} fwd;
		void *ref;
	    };
	};
    };
} snif_sock;

struct snif_sock *snif_sock_initconn(struct snif_sock *sock);
void snif_sock_setpoll(struct snif_sock *sock, struct pollfd *pollfd, int ev);
void snif_sock_initpoll(struct snif_sock *sock, struct pollfd *pollfd);
int snif_sock_accept(struct snif_sock *sock, int abuse);
int snif_sock_connect(const char *host, const char *port);
int snif_sock_setnb(int fd);
struct snif_sock *snif_sock_addchain(struct snif_sock *sock, struct snif_sock **chain);
void snif_sock_removechain(struct snif_sock *sock, struct snif_sock **chain);
int snif_sock_rw(struct snif_sock *sock, struct pollfd *pollfd, void *ssl);
int snif_sock_out(struct snif_sock *sock, const char *src, int len);
void snif_sock_update(struct snif_sock *sock, struct pollfd *pollfd);
#define snif_sock_update_peer(sock)	(sock->peer && (snif_sock_update(sock->peer, &sock->listen->pollfds[sock->peer->listenidx]), 0))
void snif_sock_tmout(struct snif_sock *sock, int tmout);
int snif_sock_chktmout(struct snif_sock *sock);
int snif_sock_done(struct snif_sock *sock);
void snif_sock_shutdown(struct snif_sock *sock);
void snif_sock_free(struct snif_sock *sock);
