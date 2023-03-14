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
 * All fields before .flags ore to be set directly.
 *   .certfile - file path for new or existing PEM cert
 *   .pkeyfile - file path for new or existing PEM private key. Must be
 *               writable if the file doesn't exist.
 *   .passphare - the passphrase for .pkeyfile, may be NULL
 *   .initurl  - SNIF CA proxy initurl, e.g. "https://snif.snif.xyz:4443"
 *   .apiurl   - SNIF CA proxy API URL, only if required by the proxy,
 *               NULL for default http API links
 *   .ou       - CSR OU= value, normally NULL
 *   .biofn    - A function to return BIO * for cert and pkey files,
 *               NULL for default
 *   .ctxfn    - SSL_CTX initialization callback for curl,
                 NULL for default
 **************************************************************************/
typedef struct snif_cert {
    const char *certfile;
    const char *pkeyfile;
    const char *passphrase;
    const char *initurl;
    const char *apiurl;
    const char *ou;
    void *(* biofn)(const char *fname, int wr);
    void (* ctxfn)(void *sslctx);
    void *rootstore;
    int flags;
    void *alloc_rootstore;
    char *authurl;
    char *cn;
    char *hostname;
    void *pkey;
    void *ctx;
    void *dl_ctx;
    void *ssl;
    long long int download_at;
    int error;
    struct {
	unsigned long code;
	short int line;
	short int ctxcode;
	short int ctxdepth;
    } tlserr;
    struct snif_cert_buf *unsaved;
} snif_cert;

#define	SNIF_F_LEGACY		0x0001

/**************************************************************************
 * RSA private key bits
 **************************************************************************/
#ifndef	SNIF_CERT_RSA_BITS
#define	SNIF_CERT_RSA_BITS	4096
#endif

/**************************************************************************
 * CSR subject O= value
 **************************************************************************/
#ifndef	SNIF_CERT_SUBJ_O
#define	SNIF_CERT_SUBJ_O	"SNIF-relay-local-cert"
#endif

/**************************************************************************
 * Maximum size of the PEM encoded TLS cert
 **************************************************************************/
#ifndef	SNIF_CERT_MAXSIZE
#define	SNIF_CERT_MAXSIZE	32768
#endif

/**************************************************************************
 * snif_cert_* error codes
 **************************************************************************/
#define	SNIF_CE_OK	0
#define	SNIF_CE_API	-1
#define	SNIF_CE_IO	-2
#define	SNIF_CE_LIB	-3
#define	SNIF_CE_CERT	-4

/**************************************************************************
 * App name for user-agent in the CA proxy requests
 **************************************************************************/
#ifndef	SNIF_CERT_UAAPP
#define	SNIF_CERT_UAAPP	snif-cert
#endif

/**************************************************************************
 * API retry timeout for renewal of a still valid cert
 **************************************************************************/
#ifndef	SNIF_CERT_RECHECK
#define	SNIF_CERT_RECHECK	900
#endif

/**************************************************************************
 * API retry timeout for the first issuance or renewal of an expired cert
 **************************************************************************/
#ifndef	SNIF_CERT_RETRY
#define	SNIF_CERT_RETRY		10
#endif

/**************************************************************************
 * Forced renewal before the expiration time
 **************************************************************************/
#ifndef	SNIF_CERT_EXPIRE
#define	SNIF_CERT_EXPIRE	86400
#endif

/**************************************************************************
 * First renewal attempt before the expiration time
 **************************************************************************/
#ifndef	SNIF_CERT_REFRESH
#define	SNIF_CERT_REFRESH	(7 * 86400)
#endif

/**************************************************************************
 * Internal.
 **************************************************************************/
const char *snif_cert_getcn(void *x509, int *plen);
#define snif_cert_timegm(tm)	((((((long long)(tm)->tm_year - ((tm)->tm_mon >= 2 ? 68 : 69)) * 1461 / 4\
	+ ((long long)((tm)->tm_mon >= 2 ? (tm)->tm_mon - 2 : (tm)->tm_mon + 10) * 3059 + 51) / 100\
	+ (tm)->tm_mday - 672 - ((tm)->tm_year - ((tm)->tm_mon >= 2 ? 0 : 1)) / 100 * 3 / 4)\
	* 24 + (tm)->tm_hour) * 60 + (tm)->tm_min) * 60 + (tm)->tm_sec)

/**************************************************************************
 * Legacy init, user snif_cert_init_ex() instead
 **************************************************************************/
#define	snif_cert_init(cert)	snif_cert_init_ex(cert, SNIF_F_LEGACY)

/**************************************************************************
 * Initialize a static or newly allocated struct snif_cert.
 * If cert == NULL - a new struct snif_cert is allocated and initialized
 * If cert != NULL - all fields starting with .flags in the struct snif_cert
 * are initialized.
 * flags: SNIF_F_*
 *   SNIF_F_LEGACY: use an obsolete platform-dependent way of generating a
 *                  SNIF hostname for a wildcard cert. Use to keep the
 *                  hostname compatible with old versions of SNIF.
 **************************************************************************/
struct snif_cert *snif_cert_init_ex(struct snif_cert *cert, int flags);

/**************************************************************************
 * Get the SNIF hostname for the current certificate.
 **************************************************************************/
const char *snif_cert_hostname(struct snif_cert *cert);

/**************************************************************************
 * Set the SNIF hostname. MUST match the current wildcard certificate,
 * otherwise SNUF relay will refuse the service.
 **************************************************************************/
const char *snif_cert_sethostname(snif_cert *cert, const char *host);

/**************************************************************************
 * Get a cert CN, allocate a new one if no cert exists yet.
 **************************************************************************/
const char *snif_cert_alloccn(struct snif_cert *cert);

/**************************************************************************
 * Get an EVP_PKEY * for the private key.
 * Do not deallocate.
 **************************************************************************/
void *snif_cert_pkey(struct snif_cert *cert);

/**************************************************************************
 * Get a validated SSL_CTX * for the current cert, go through the cert
 * issuance or renewal if none exists yet.
 * If NULL is returned - check snif_cert_authurl(cert)
 * Do not deallocate.
 **************************************************************************/
void *snif_cert_ctx(struct snif_cert *cert);

/**************************************************************************
 * Get an interactive authoruzation url if user authorization is required
 * be the CA proxy. Communicate this url to the user if not NULL, and
 * try snif_cert_ctx(cert) after the user authorization is complete.
 * Do not deallocate.
 **************************************************************************/
#define snif_cert_authurl(cert)	((cert)->authurl)

/**************************************************************************
 * Get an instantiated SSL * for the current cert.
 * Deallocate with SSL_free().
 **************************************************************************/
void *snif_cert_ssl(struct snif_cert *cert);

/**************************************************************************
 * Idle cycle, call periodically to maintain the cert and renew if
 * necessary, the renewed cert if saved to cert->certfile.
 **************************************************************************/
#define	snif_cert_idle(cert)	((void)snif_cert_ctx(cert))

/**************************************************************************
 * Get a SNIF_CE_* code for the last call
 **************************************************************************/
#define	snif_cert_error(cert)	((cert)->error)

/**************************************************************************
 * Deallocate all dynamic fields in snif_cert, call when done with the SNIF
 * session.
 **************************************************************************/
void snif_cert_reset(struct snif_cert *cert);

