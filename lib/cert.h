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


typedef struct snif_cert {
    const char *certfile;
    const char *pkeyfile;
    const char *passphrase;
    const char *initurl;
    const char *ou;
    void *(* biofn)(const char *fname, int wr);
    void (* ctxfn)(void *sslctx);
    void *rootstore;
    char *authurl;
    char *cn;
    char *hostname;
    void *pkey;
    void *ctx;
    void *ssl;
    long long int download_at;
    int error;
    struct {
	unsigned long code;
	short int line;
	short int ctxcode;
	short int ctxdepth;
    } tlserr;
} snif_cert;

#define	SNIF_CERT_RSA_BITS	4096
#define	SNIF_CERT_SUBJ_O	"SNIF-relay-local-cert"
#define	SNIF_CERT_MAXSIZE	32768

#define	SNIF_CE_API	-1
#define	SNIF_CE_IO	-2
#define	SNIF_CE_LIB	-3
#define	SNIF_CE_CERT	-4

#ifndef	SNIF_CERT_UAAPP
#define	SNIF_CERT_UAAPP	snif-cert
#endif
#ifndef	SNIF_CERT_RECHECK
#define	SNIF_CERT_RECHECK	900
#endif
#ifndef	SNIF_CERT_RETRY
#define	SNIF_CERT_RETRY		10
#endif
#ifndef	SNIF_CERT_EXPIRE
#define	SNIF_CERT_EXPIRE	86400
#endif
#ifndef	SNIF_CERT_REFRESH
#define	SNIF_CERT_REFRESH	(7 * 86400)
#endif

#define snif_cert_timegm(tm)	((((((long long)(tm)->tm_year - ((tm)->tm_mon >= 2 ? 68 : 69)) * 1461 / 4\
	+ ((long long)((tm)->tm_mon >= 2 ? (tm)->tm_mon - 2 : (tm)->tm_mon + 10) * 3059 + 51) / 100\
	+ (tm)->tm_mday - 672 - ((tm)->tm_year - ((tm)->tm_mon >= 2 ? 0 : 1)) / 100 * 3 / 4)\
	* 24 + (tm)->tm_hour) * 60 + (tm)->tm_min) * 60 + (tm)->tm_sec)

struct snif_cert *snif_cert_init(struct snif_cert *cert);
const char *snif_cert_hostname(struct snif_cert *cert);
const char *snif_cert_alloccn(struct snif_cert *cert);
void *snif_cert_pkey(struct snif_cert *cert);
void *snif_cert_ctx(struct snif_cert *cert);
void *snif_cert_ssl(struct snif_cert *cert);
void snif_cert_idle(struct snif_cert *cert);
void snif_cert_reset(struct snif_cert *cert);

const char *snif_cert_getcn(void *x509, int *plen);
