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

#ifdef _WIN32
#define	WIN32_LEAN_AND_MEAN
#define	timezone	_timezone
#endif

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <errno.h>
#include "cert.h"


int snif_cert_passfn(char *buf, int size, int rwflag, void *u) {
    snif_cert *cert = u;
    if (!cert->passphrase) return -1;
    int l = strlen(cert->passphrase);
    if (l > size) return -1;
    memcpy(buf, cert->passphrase, l);
    return l;
}

struct snif_cert_buf {
    int len;
    char buf[SNIF_CERT_MAXSIZE];
};

size_t snif_cert_curldlfn(void *ptr, size_t size, size_t nmemb, void *stream) {
    int len = size * nmemb;
    struct snif_cert_buf *cbuf = stream;
    if (cbuf->len < 0 || len > sizeof(cbuf->buf) - cbuf->len) {
	cbuf->len = -1;
	return 0;
    }
    memcpy(cbuf->buf + cbuf->len, ptr, len);
    cbuf->len += len;
    return len;
}

size_t snif_cert_curlhdrfn(void *ptr, size_t size, size_t nmemb, void *stream) {
    int len = size * nmemb;
    snif_cert *cert = stream;
    char hkey[32];
    const char *s = ptr;
    const char *tail = s + len;
    const char *v = memchr(s, ':', len);
    if (v && v - s < sizeof(hkey)) {
	char *d = hkey;
	while (s < v) {
	    char c = *s++;
	    *d++ = c >= 'A' && c <= 'Z' ? c | 0x20 : c;
	}
	*d = 0;
	char **pval;
	if (!strcmp(hkey, "x-snif-cn")) pval = &cert->cn;
	else if (!strcmp(hkey, "x-snif-authurl")) pval = &cert->authurl;
	else pval = NULL;
	if (pval && !*pval) {
	    while (v + 1 < tail) if (*++v != ' ') break;
	    *pval = d = malloc(tail - v + 1);
	    while (v < tail) {
		char c = *v++;
		switch (c) {
		    case ' ': case '\r': case '\n': case '\t': case ';':
			c = 0;
		    default:
			break;
		}
		if (!c) break;
		*d++ = c;
	    }
	    *d = 0;
	}
    }
    return len;
}

size_t snif_cert_curlignorefn(void *ptr, size_t size, size_t nmemb, void *stream) {
    return size * nmemb;
}

struct snif_cert_upbuf {
    int len;
    char *buf;
};

size_t snif_cert_curlsendfn(void *ptr, size_t size, size_t nmemb, void *stream) {
    struct snif_cert_upbuf *up = stream;
    int len = size * nmemb;
    if (len > up->len) len = up->len;
    memcpy(ptr, up->buf, len);
    up->buf += len;
    up->len -= len;
    return len;
}

CURLcode snif_cert_curlctxfn(CURL *curl, void *sslctx, void *parm) {
    snif_cert *cert = parm;
#if	(OPENSSL_VERSION_NUMBER >= 0x10002000L)
    if (cert->rootstore) SSL_CTX_set1_verify_cert_store(sslctx, cert->rootstore);
#else
    if (cert->rootstore) SSL_CTX_set_cert_store(sslctx, cert->rootstore);
#endif
    if (cert->ctxfn) cert->ctxfn(sslctx);
    return CURLE_OK;
}

void *snif_cert_curlfn(snif_cert *cert) {
    struct CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, &snif_cert_curlctxfn);
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, cert);
#ifdef SNIF_CAINFO
    curl_easy_setopt(curl, CURLOPT_CAINFO, SNIF_CAINFO);
#endif
#ifdef SNIF_DEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    return curl;
}

char *snif_cert_curlua(snif_cert *cert, char *buf) {
#define	SNIF_CERT_UAAPPSTR2(_app)	#_app
#define	SNIF_CERT_UAAPPSTR(_app)	SNIF_CERT_UAAPPSTR2(_app)
    sprintf(buf, "User-Agent: %s SNIF (https://snif.host) (%s)", SNIF_CERT_UAAPPSTR(SNIF_CERT_UAAPP), curl_version());
    return buf;
}

time_t snif_cert_asn1time(const ASN1_TIME *t) {
    if (!t) return 0;
    int l = ASN1_STRING_length(t);
    if (l < 13) return 0;
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const char *s = (const char *)ASN1_STRING_get0_data(t);
#else
    const char *s = (const char *)ASN1_STRING_data((ASN1_TIME *) t);
#endif
    struct tm tm;
    int wd = (l >= 15);
    sscanf(s, (wd ? "%4d%2d%2d%2d%2d%2d" : "%2d%2d%2d%2d%2d%2d"), &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    tm.tm_mon--;
    if (wd) tm.tm_year -= 1900;
    else if (tm.tm_year < 80) tm.tm_year += 100;
    return mktime(&tm) - timezone;
}

const char *snif_cert_basecn(snif_cert *cert) {
    const char *bn = cert->cn;
    if (bn[0] == '*' && bn[1] == '.') bn += 2;
    return bn;
}

const char *snif_cert_hostname(snif_cert *cert) {
    if (!cert->hostname && cert->cn) {
	if (cert->cn[0] == '*') {
	    EVP_PKEY *pkey = snif_cert_pkey(cert);
	    if (!pkey) return NULL;
	    unsigned char hash[16];
	    char *h = malloc(strlen(cert->cn) + 16);
	    cert->hostname = h;
	    *h++ = 'r';
	    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	    unsigned int mdlen = sizeof(hash);
	    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) > 0) {
		int l = i2d_PrivateKey(pkey, NULL);
		if (l > 0) {
		    unsigned char *buf = malloc(l);
		    unsigned char *d = buf;
		    if (i2d_PrivateKey(pkey, &d) > 0) {
			EVP_DigestUpdate(mdctx, buf, l);
		    }
		    free(buf);
		}
		if (EVP_DigestFinal_ex(mdctx, hash, &mdlen) > 0) {
		    sprintf(h, "%08lx%04hx", *((unsigned long *)hash), *((unsigned short *)(hash + 4)));
		    h += 12;
		}
	    }
	    EVP_MD_CTX_destroy(mdctx);
	    strcpy(h, cert->cn + 1);
	} else cert->hostname = cert->cn;
    }
    return cert->hostname;
}

int snif_cert_setsubj(snif_cert *cert, X509_NAME *subj) {
    return (X509_NAME_add_entry_by_NID(subj, NID_countryName, MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0) > 0
	&& X509_NAME_add_entry_by_NID(subj, NID_organizationName, MBSTRING_ASC, (unsigned char *)SNIF_CERT_SUBJ_O, -1, -1, 0) > 0
	&& (!cert->ou || X509_NAME_add_entry_by_NID(subj, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)cert->ou, -1, -1, 0) > 0)
	&& X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC, (unsigned char *)cert->cn, -1, -1, 0) > 0
    ) ? 1 : 0;
}

#define	snif_cert_bio(cert, file, wr)	((cert)->biofn ? (cert)->biofn(file, wr) : BIO_new_file(file, (wr ? "w" : "r")))
#define	snif_cert_TLSERR(cert)		((cert)->tlserr.line = __LINE__, (cert)->tlserr.code = ERR_get_error())

int snif_cert_verify_chain(snif_cert *cert, BIO *in) {
    X509 *crt = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (!crt) return (snif_cert_TLSERR(cert), 0);
    X509_STORE_CTX *sctx = X509_STORE_CTX_new();
    STACK_OF(X509) *ca = sk_X509_new_null();
    X509 *ccrt;
    while (1) {
	ccrt = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (!ccrt) {
	    ERR_clear_error();
	    break;
	}
	sk_X509_push(ca, ccrt);
    }
    int vrfy = X509_STORE_CTX_init(sctx, cert->rootstore, crt, ca) > 0 ? X509_verify_cert(sctx) : 0;
    cert->tlserr.ctxcode = X509_STORE_CTX_get_error(sctx);
    cert->tlserr.ctxdepth = X509_STORE_CTX_get_error_depth(sctx);
    X509_STORE_CTX_cleanup(sctx);
    X509_STORE_CTX_free(sctx);
    while ((ccrt = sk_X509_pop(ca))) X509_free(ccrt);
    sk_X509_free(ca);
    if (vrfy > 0) vrfy = X509_check_private_key(crt, snif_cert_pkey(cert));
    else snif_cert_TLSERR(cert);
    if (vrfy > 0) {
	int cl;
	const char *cn = snif_cert_getcn(crt, &cl);
	vrfy = cn && cert->cn && !strncmp(cn, cert->cn, cl) && !cert->cn[cl] ? 1 : (snif_cert_TLSERR(cert), 0);
    }
    if (vrfy > 0) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	time_t exp = snif_cert_asn1time(X509_get0_notAfter(crt));
#else
	time_t exp = snif_cert_asn1time(X509_get_notAfter(crt));
#endif
	if (exp - SNIF_CERT_REFRESH <= time(NULL)) vrfy = (snif_cert_TLSERR(cert), 0);
    }
    X509_free(crt);
    return vrfy;
}

const char *snif_cert_alloccn(snif_cert *cert) {
    if (cert->cn) return cert->cn;
    if (cert->pkey) EVP_PKEY_free(cert->pkey);
    cert->pkey = NULL;
    struct CURL *curl = snif_cert_curlfn(cert);
    char buf[1024];
    curl_easy_setopt(curl, CURLOPT_URL, cert->initurl);
    struct curl_slist *hdrs = curl_slist_append(NULL, snif_cert_curlua(cert, buf));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &snif_cert_curlhdrfn);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, cert);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &snif_cert_curlignorefn);
    int curlerr = curl_easy_perform(curl);
    long code;
    if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (curlerr == CURLE_OK && (code / 100 == 2)) return cert->cn;
    cert->error = SNIF_CE_API;
    free(cert->cn);
    return cert->cn = NULL;
}

int snif_cert_sendreq(snif_cert *cert, X509_REQ *req) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509_REQ(bio, req) <= 0) {
	BIO_free(bio);
	return 0;
    }
    struct snif_cert_upbuf up;
    up.len = BIO_get_mem_data(bio, &up.buf);
    struct CURL *curl = snif_cert_curlfn(cert);
    char buf[1024];
    const char *bn = snif_cert_basecn(cert);
    sprintf(buf, "http://%s/snif-cert/%s.csr", bn, bn);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    struct curl_slist *hdrs = curl_slist_append(NULL, snif_cert_curlua(cert, buf));
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/pkcs10");
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, &snif_cert_curlsendfn);
    curl_easy_setopt(curl, CURLOPT_READDATA, &up);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, up.len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &snif_cert_curlhdrfn);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, cert);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &snif_cert_curlignorefn);
    int curlerr = curl_easy_perform(curl);
    long code;
    if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    BIO_free(bio);
    if (curlerr == CURLE_OK) switch (code) {
	case 201: return 1;
	default: break;
    }
    cert->error = SNIF_CE_API;
    return 0;
}


snif_cert *snif_cert_init(snif_cert *cert) {
    if (!cert) {
	cert = malloc(sizeof(snif_cert));
	cert->certfile = cert->pkeyfile = cert->passphrase = cert->initurl = NULL;
	cert->rootstore = NULL;
	cert->biofn = NULL;
	cert->ctxfn = NULL;
    }
    cert->ctx = NULL;
    cert->ssl = NULL;
    cert->pkey = NULL;
    cert->cn = cert->hostname = cert->authurl = NULL;
    cert->download_at = 0;
    cert->error = 0;
    if (!cert->rootstore) {
	cert->rootstore = X509_STORE_new();
	X509_STORE_set_default_paths(cert->rootstore);
    }
    return cert;
}

int snif_cert_download(snif_cert *cert) {
    char buf[1024];
    struct CURL *curl = snif_cert_curlfn(cert);
    const char *bn = snif_cert_basecn(cert);
    sprintf(buf, "http://%s/snif-cert/%s.crt", bn, bn);
    curl_easy_setopt(curl, CURLOPT_URL, buf);
    struct curl_slist *hdrs = curl_slist_append(NULL, "Accept: application/x-x509-ca-cert, application/pkix-cert");
    hdrs = curl_slist_append(hdrs, snif_cert_curlua(cert, buf));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &snif_cert_curlhdrfn);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, cert);
    struct snif_cert_buf *cbuf = malloc(sizeof(struct snif_cert_buf));
    cbuf->len = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &snif_cert_curldlfn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, cbuf);
    int curlerr = curl_easy_perform(curl);
    long code;
    if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    int rs;
    if (curlerr == CURLE_OK) {
	if (code != 401) {
	    free(cert->authurl);
	    cert->authurl = NULL;
	}
	if (code == 200 && cbuf->len > 0) {
	    BIO *bio = BIO_new_mem_buf(cbuf->buf, cbuf->len);
	    rs = snif_cert_verify_chain(cert, bio);
	    BIO_free(bio);
	    int retry = 5;
	    while (rs > 0) {
		bio = snif_cert_bio(cert, cert->certfile, 1);
		if (bio) {
		    const char *s = cbuf->buf;
		    const char *tail = s + cbuf->len;
		    int w = 0;
		    while (s < tail) {
			w = BIO_write(bio, s, tail - s);
			if (w < 0) break;
			s += w;
		    }
		    BIO_free(bio);
		    if (w >= 0) break;
		    if (retry-- <= 0) {
			rs = 0;
			cert->error = SNIF_CE_IO;
		    }
		} else {
		    rs = 0;
		    cert->error = SNIF_CE_IO;
		}
	    }
	} else {
	    switch (code) {
		case 503:
		case 401:
		    cert->error = 0;
		    break;
		default:
		    cert->error = SNIF_CE_API;
		    break;
	    }
	    rs = 0;
	}
    } else {
	rs = 0;
	cert->error = SNIF_CE_API;
    }
    free(cbuf);
    if (rs <= 0) cert->download_at = time(NULL) + (cert->ctx ? SNIF_CERT_RECHECK : SNIF_CERT_RETRY);
    return rs;
}

void *snif_cert_pkey(snif_cert *cert) {
    if (!cert->pkey && !cert->cn) {
	BIO *bio = snif_cert_bio(cert, cert->pkeyfile, 0);
	if (bio) {
	    cert->pkey = PEM_read_bio_PrivateKey(bio, NULL, &snif_cert_passfn, cert);
	    BIO_free(bio);
	    if (!cert->pkey) {
		cert->error = SNIF_CE_CERT;
		return (snif_cert_TLSERR(cert), NULL);
	    }
	} else if (errno != ENOENT) {
	    cert->error = SNIF_CE_IO;
	    return (snif_cert_TLSERR(cert), NULL);
	}
    }
    if (!cert->pkey && cert->initurl) {
	BIGNUM *e = BN_new();
	BN_set_word(e, 0x10001);
	RSA *rsa = RSA_new();
	const char *cn = snif_cert_alloccn(cert);
	if (cn && RSA_generate_key_ex(rsa, SNIF_CERT_RSA_BITS, e, NULL) > 0) {
	    EVP_PKEY *pkey = EVP_PKEY_new();
	    EVP_PKEY_assign_RSA((EVP_PKEY *) pkey, rsa);
	    X509_REQ *req = X509_REQ_new();
	    X509 *pcrt = X509_new();
	    if (X509_REQ_set_pubkey(req, pkey) > 0
		&& X509_set_pubkey(pcrt, pkey) > 0
		&& snif_cert_setsubj(cert, X509_REQ_get_subject_name(req))
		&& snif_cert_setsubj(cert, X509_get_subject_name(pcrt))
		&& snif_cert_setsubj(cert, X509_get_issuer_name(pcrt))
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
		&& X509_gmtime_adj(X509_getm_notBefore(pcrt), 0)
		&& X509_gmtime_adj(X509_getm_notAfter(pcrt), 60L)
#else
		&& X509_gmtime_adj(X509_get_notBefore(pcrt), 0)
		&& X509_gmtime_adj(X509_get_notAfter(pcrt), 60L)
#endif
		&& ASN1_INTEGER_set(X509_get_serialNumber(pcrt), 1) > 0
		&& X509_REQ_set_version(req, 0) > 0
		&& X509_REQ_sign(req, pkey, EVP_sha256()) > 0
		&& X509_sign(pcrt, pkey, EVP_sha256()) > 0
		&& snif_cert_sendreq(cert, req)
	    ) {
		BIO *bio = snif_cert_bio(cert, cert->certfile, 1);
		if (bio) {
		    int r = PEM_write_bio_X509(bio, pcrt);
		    BIO_free(bio);
		    if (r > 0) {
			bio = snif_cert_bio(cert, cert->pkeyfile, 1);
			if (bio) {
			    r = PEM_write_bio_PKCS8PrivateKey(bio, pkey, (cert->passphrase ? EVP_aes_256_cbc() : NULL), NULL, 0, &snif_cert_passfn, cert);
			    BIO_free(bio);
			    if (r > 0) {
				cert->pkey = pkey;
				pkey = NULL;
			    }
			}
		    }
		}
		if (pkey) cert->error = SNIF_CE_IO;
	    } else cert->error = (snif_cert_TLSERR(cert), SNIF_CE_LIB);
	    if (pkey) EVP_PKEY_free(pkey);
	    X509_REQ_free(req);
	    X509_free(pcrt);
	} else {
	    RSA_free(rsa);
	    cert->error = (snif_cert_TLSERR(cert), SNIF_CE_LIB);
	}
	BN_free(e);
    }
    return cert->pkey;
}

void *snif_cert_ctx(snif_cert *cert) {
    if (cert->ctx && time(NULL) >= cert->download_at && snif_cert_download(cert) > 0) {
	SSL_CTX_free(cert->ctx);
	cert->ctx = NULL;
    }
    if (!cert->ctx) {
	cert->error = 0;
	const char *au = cert->authurl;
	EVP_PKEY *pkey = snif_cert_pkey(cert);
	if (!pkey || (!au && cert->authurl)) return NULL;
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	const SSL_METHOD *method = TLS_server_method();
#else
	const SSL_METHOD *method = TLSv1_2_server_method();
#endif
	SSL_CTX *ctx = SSL_CTX_new(method);
	SSL *ssl;
	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0
	    || SSL_CTX_use_certificate_chain_file(ctx, cert->certfile) <= 0
	    || SSL_CTX_check_private_key(ctx) <= 0
	    || !(ssl = SSL_new(ctx))
	) {
	    SSL_CTX_free(ctx);
	    cert->error = SNIF_CE_CERT;
	    return NULL;
	}
	X509 *crt = SSL_get_certificate(ssl);
	if (crt && !cert->cn) {
	    int cl;
	    const char *cn = snif_cert_getcn(crt, &cl);
	    if (cn) {
		memcpy((cert->cn = malloc(cl + 1)), cn, cl);
		cert->cn[cl] = 0;
	    } else {
		crt = NULL;
		cert->error = SNIF_CE_CERT;
	    }
	}
	if (!crt) {
	    SSL_CTX_free(ctx);
	    SSL_free(ssl);
	    cert->error = SNIF_CE_CERT;
	    return NULL;
	}
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	time_t exp = snif_cert_asn1time(X509_get0_notAfter(crt));
#else
	time_t exp = snif_cert_asn1time(X509_get_notAfter(crt));
#endif
	time_t t = time(NULL);
	cert->download_at = exp - SNIF_CERT_REFRESH;
	int dl = t >= cert->download_at ? snif_cert_download(cert) : 0;
	int expd = exp < t + SNIF_CERT_EXPIRE;
	if (expd) {
	    SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    return dl > 0 ? snif_cert_ctx(cert) : NULL;
	}
	cert->ctx = ctx;
	if (cert->ssl) SSL_free(cert->ssl);
	cert->ssl = ssl;
    }
    return cert->ctx;
}

void *snif_cert_ssl(snif_cert *cert) {
    if (!snif_cert_ctx(cert)) return NULL;
    SSL *ssl = cert->ssl;
    cert->ssl = NULL;
    if (!ssl) ssl = SSL_new(cert->ctx);
    return ssl;
}

void snif_cert_idle(snif_cert *cert) {
    if (cert->cn && time(NULL) >= cert->download_at && snif_cert_download(cert) > 0) {
	if (cert->ctx) SSL_CTX_free(cert->ctx);
	cert->ctx = NULL;
	snif_cert_ctx(cert);
    }
}

void snif_cert_reset(snif_cert *cert) {
    if (cert->pkey) EVP_PKEY_free(cert->pkey);
    cert->pkey = NULL;
    if (cert->ctx) SSL_CTX_free(cert->ctx);
    cert->ctx = NULL;
    if (cert->ssl) SSL_free(cert->ssl);
    cert->ssl = NULL;
    if (cert->hostname != cert->cn) free(cert->hostname);
    free(cert->cn);
    cert->cn = cert->hostname = NULL;
    free(cert->authurl);
    cert->authurl = NULL;
}

const char *snif_cert_getcn(void *x509, int *plen) {
    X509_NAME *subj = X509_get_subject_name(x509);
    if (!subj) return NULL;
    int i;
    for (i = 0; i < X509_NAME_entry_count(subj); i++) {
	X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
	if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(e)) == NID_commonName) {
	    ASN1_STRING *as = X509_NAME_ENTRY_get_data(e);
	    if (plen) *plen = ASN1_STRING_length(as);
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	    return (const char *) ASN1_STRING_get0_data(as);
#else
	    return (const char *) ASN1_STRING_data(as);
#endif
	}
    }
    return NULL;
}
