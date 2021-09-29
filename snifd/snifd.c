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
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "sock.h"
#include "port.h"
#include "cln.h"
#include "srv.h"
#include "ctl.h"
#include "listen.h"
#include "util.h"
#include "../lib/cert.h"
#include "watch.h"
#include "fifo.h"
#include "abuse.h"
#include "help.h"

char snifd_shutdn = 0;

int snifd_parse(int l, char **parse, const char *arg) {
    if (!arg) return 0;
    char *cp = strdup(arg);
    char *s = cp;
    int i;
    int ct = 0;
    char **pp = parse;
    for (i = 0; i < l; i++) {
	char *e = s ? strchr(s, ':') : NULL;
	if (e) *e++ = 0;
	*pp++ = s;
	if (s) ct++;
	s = e;
    }
    return ct;
}

#define	snifd_CHKD()	\
    if (watchf) { \
	er = E_CONFL; \
	break; \
    }

#define	snifd_CHKR()	\
    if (!watchf) { \
	if (lstn.pollct) { \
	    er = E_CONFL; \
	    break; \
	} \
	watchf = 1; \
    }

#define	snifd_CHKV(sk)	\
    if (sk) { \
	er = E_DUP; \
	break; \
    }

#define	snifd_CHKA(n)	\
    if (n >= argc) { \
	er = E_END; \
	break; \
    }

#define	SNIF_DEFAULT_PORT	"7123"
#define	SNIF_DEFAULT_SRV_PORT	"7120"

enum {E_OK, E_ARG, E_VAL, E_END, E_CONFL, E_DUP, E_LSTN, E_CONN, E_IO, E_TLS, E_AUTH, E_SHDN};


void snifd_shutdn_fn(int sig) {
    snifd_shutdn = 1;
}

int snifd_shutdn_sig(int sig) {
    struct sigaction sa;
    sigaction(sig, NULL, &sa);
    sa.sa_handler = &snifd_shutdn_fn;
    return sigaction(sig, &sa, NULL);
}

int main(int argc, char **argv, char **env) {
    snif_listen lstn = {
	.pollfds = NULL,
	.socks = NULL,
	.pollct = 0,
	.pollmax = 0,
	.firstempty = 0,
	.ctl = NULL,
	.srv = NULL,
	.push = NULL,
	.input = NULL,
	.watch = NULL,
	.tmout = {
	    .cln = 60,
	    .conn = 30,
	    .idle = 1800,
	    .retry = 15,
	    .alive = 10
	},
	.shutdn = 0
    };
    struct snif_cert cert = {
	.certfile = NULL,
	.pkeyfile = NULL,
	.passphrase = NULL,
	.initurl = NULL,
	.biofn = NULL,
	.ctxfn = NULL,
	.rootstore = NULL,
	.authurl = NULL,
	.cn = NULL,
	.hostname = NULL,
	.ou = NULL,
	.ctx = NULL,
	.ssl = NULL,
	.pkey = NULL
    };
    struct snif_watch_port *wports = NULL;
    char watchf = 0;
    char er = E_OK;
    char waitf = 0;
    unsigned widx = 0;
    snifd_shutdn_sig(SIGINT);
    snifd_shutdn_sig(SIGTERM);
    snif_init();
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) < 0) strcpy(hostname, "localhost");
    char *parse[3];
    int i;
    const char *host, *port;
    for (i = 1; i < argc; i++) {
	const char *a = argv[i];
	if (a[0] == '-') {
	    char cmd = a[1];
	    switch (cmd) {
		case 'l':
		    snifd_CHKD()
		    snifd_CHKV(lstn.ctl)
		    snifd_CHKA(++i)
		    snifd_parse(2, parse, argv[i]);
		    host = parse[1] ? parse[0] : NULL;
		    port = parse[parse[1] ? 1 : 0];
		    lstn.ctl = snif_port(host, port, &lstn, &snif_ctl);
		    if (!lstn.ctl) er = E_LSTN;
		    break;
		case 's':
		    snifd_CHKD()
		    snifd_CHKV(lstn.srv)
		    snifd_CHKA(++i)
		    snifd_parse(2, parse, argv[i]);
		    host = parse[1] ? parse[0] : hostname;
		    port = parse[parse[1] ? 1 : 0];
		    lstn.srv = snif_port(host, port, &lstn, &snif_srv);
		    if (!lstn.srv) er = E_LSTN;
		    break;
		case 'p':
		    snifd_CHKA(++i)
		    if (!snif_sock_addchain(snif_fifo((port = argv[i]), 1, &lstn), &lstn.push)) er = E_IO;
		    break;
		case 'i':
		    snifd_CHKA(++i)
		    if (!snif_sock_addchain(snif_fifo((port = argv[i]), 0, &lstn), &lstn.input)) er = E_IO;
		    break;
		case 'r':
		    snifd_CHKR()
		    snifd_CHKA(++i)
		    snifd_parse(2, parse, argv[i]);
		    host = parse[0];
		    port = parse[1] ? parse[1] : SNIF_DEFAULT_PORT;
		    if (!snif_watch(host, port, &cert, wports, &lstn)) er = E_CONN;
		    watchf = 2;
		    break;
		case 'c':
		    snifd_CHKR()
		    snifd_CHKV(cert.certfile)
		    snifd_CHKA(++i)
		    cert.certfile = argv[i];
		    break;
		case 'k':
		    snifd_CHKR()
		    snifd_CHKV(cert.pkeyfile)
		    snifd_CHKA(++i)
		    cert.pkeyfile = argv[i];
		    break;
		case 'a':
		    snifd_CHKR()
		    snifd_CHKV(cert.initurl)
		    snifd_CHKA(++i)
		    cert.initurl = argv[i];
		    break;
		case 'd':
		    waitf = 1;
		    break;
		case 't':
		    snifd_CHKA(++i)
		    if (sscanf(argv[i], "%hu", &snif_abuse_sense) != 1) er = E_VAL;
		    break;
		default:
		    er = E_ARG;
		    break;
	    }
	} else if (watchf) {
	    if (!wports) {
		wports = malloc((argc - i + 1) * sizeof(*wports));
	    }
	    snifd_parse(3, parse, a);
	    wports[widx].flags = 0;
	    char **pport = parse + (parse[2] ? 2 : (parse[1] ? 1 : 0));
	    if (*pport) {
		if (**pport == '^') {
		    wports[widx].flags |= SNIF_WF_TERMTLS;
		    (*pport)++;
		}
	    }
	    wports[widx].port = parse[0];
	    wports[widx].lhost = host = parse[2] ? parse[1] : hostname;
	    wports[widx++].lport = port = *pport;
	} else {
	    snifd_parse(2, parse, a);
	    host = (parse[1] ? parse[0] : NULL);
	    port = parse[parse[1] ? 1 : 0];
	    if (!snif_port(host, port, &lstn, &snif_cln)) er = E_LSTN;
	    widx++;
	}
	if (er != E_OK) break;
    }
    if (wports) wports[widx].port = NULL;
    if (er == E_OK && !watchf) {
	if (!widx) er = E_ARG;
	else if (!lstn.ctl) {
	    host = NULL;
	    port = SNIF_DEFAULT_PORT;
	    lstn.ctl = snif_port(host, port, &lstn, &snif_ctl);
	    if (!lstn.ctl) er = E_LSTN;
	}
	if (er == E_OK && !lstn.srv) {
	    host = hostname;
	    port = SNIF_DEFAULT_SRV_PORT;
	    lstn.srv = snif_port(host, port, &lstn, &snif_srv);
	    if (!lstn.srv) er = E_LSTN;
	}
    } else if (er == E_OK && watchf) {
	snif_cert_init(&cert);
	char authf = 0;
	while (!snifd_shutdn) {
	    er = E_OK;
	    if (snif_cert_ctx(&cert)) {
		if (watchf < 2) {
		    host = snif_cert_hostname(&cert);
		    if (widx) {
			char *h = strdup(host);
			if (!(lstn.watch = snif_watch(h, (port = SNIF_DEFAULT_PORT), &cert, wports, &lstn))) {
			    er = E_CONN;
			    free(h);
			}
		    } else {
			printf("%s\n", host);
			snifd_shutdn = 1;
		    }
		}
	    } else if (cert.authurl) {
		er = E_AUTH;
		if (!authf && lstn.push) {
		    authf = 1;
		    char ntfy[320];
		    sprintf(ntfy, "SNIF AUTHURL %.256s\r\n", cert.authurl);
		    if (snif_listen_push(&lstn, ntfy) >= 0) snif_listen_poll(&lstn);
		}
	    } else er = E_TLS;
	    if (er == E_OK || !waitf) break;
	    sleep(15);
	}
    }
    switch (er) {
	case E_LSTN:
	    fprintf(stderr, "Error binding on %s:%s (%d %s)\n", (host ? host : "*"), port, errno, strerror(errno));
	    break;
	case E_CONN:
	    fprintf(stderr, "Error connecting to %s:%s (%d %s)\n", host, port, errno, strerror(errno));
	    break;
	case E_IO:
	    fprintf(stderr, "I/O error on %s (%d %s)\n", port, errno, strerror(errno));
	    break;
	case E_AUTH:
	    printf("Authorization required (use -d to silently retry):\n%s\n", cert.authurl);
	    break;
	case E_TLS: {
	    fprintf(stderr, "TLS error (use -d to silently retry)\n");
	    if (cert.tlserr.line) fprintf(stderr, "  %d (ctx %d %d): %s\n", cert.tlserr.line, cert.tlserr.ctxcode, cert.tlserr.ctxdepth, ERR_error_string(cert.tlserr.code, NULL));
	    long e;
	    while ((e = ERR_get_error())) {
		fprintf(stderr, "  %s\n", ERR_error_string(e, NULL));
	    }
	    break;
	}
	case E_END:
	    fprintf(stderr, "Unexpected end of arguments, see -h\n");
	    break;
	case E_CONFL:
	    fprintf(stderr, "Conflicting arguments, see -h\n");
	    break;
	case E_DUP:
	    fprintf(stderr, "Duplicate argument, see -h\n");
	    break;
	case E_OK:
	    break;
	default:
	    snif_out_ansi(1, snif_banner);
	    snif_out_ansi(1, snif_help);
	    break;
    }
    if (er == E_OK) while (!snifd_shutdn) {
	snif_listen_poll(&lstn);
    }
    if (snif_listen_shutdown(&lstn) < 0) {
	fprintf(stderr, "Shutdown failed\n");
	if (er == E_OK) er = E_SHDN;
    }
    return er;
}
