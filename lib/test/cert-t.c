/*
 * libsnif certificate checks, run by lib/test/cert.sh, which makes the
 * certificates and serves the download directory:
 *
 *   cert-t <dir> <port>
 *
 * <dir> holds ca.pem (the trusted test root), dev.key (the connector key),
 * good.crt (*.snif-t.test from ca.pem), other.crt (the same name and key
 * from another root) and ph.crt (a self-signed placeholder, as libsnif
 * writes while the first certificate is issued). 127.0.0.1:<port> serves
 * good.crt as /snif-t.test.crt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "../cert.h"

#define	DEAD_API	"http://127.0.0.1:9/"

static int pass = 0, fail = 0;
static const char *dir;
static char crtpath[1024], keypath[1024], apiurl[256];

static void check(int ok, const char *what) {
    printf("%s - %s\n", ok ? "ok" : "NOT OK", what);
    if (ok) pass++;
    else fail++;
}

static char *slurp(const char *name, long *plen) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(65536);
    long len = buf ? fread(buf, 1, 65536, f) : 0;
    fclose(f);
    *plen = len;
    return buf;
}

static int same(const char *a, const char *b) {
    long la, lb;
    char *x = slurp(a, &la);
    char *y = slurp(b, &lb);
    int r = x && y && la == lb && !memcmp(x, y, la);
    free(x);
    free(y);
    return r;
}

/* The saved chain each case starts from: a copy, since a download replaces it */
static void save(const char *name) {
    long len;
    char *buf = slurp(name, &len);
    FILE *f = fopen(crtpath, "wb");
    if (buf && f) fwrite(buf, 1, len, f);
    if (f) fclose(f);
    free(buf);
}

static X509_STORE *test_store(void) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/ca.pem", dir);
    FILE *f = fopen(path, "r");
    X509 *ca = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    X509_STORE *st = X509_STORE_new();
    if (ca) X509_STORE_add_cert(st, ca);
    X509_free(ca);
    return st;
}

static int add_test_root(snif_cert *cert) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/ca.pem", dir);
    FILE *f = fopen(path, "r");
    X509 *ca = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    int r = ca && cert->rootstore && X509_STORE_add_cert(cert->rootstore, ca) > 0;
    X509_free(ca);
    return r;
}

static void setup(snif_cert *cert, const char *saved, X509_STORE *store, const char *api) {
    memset(cert, 0, sizeof(*cert));
    save(saved);
    cert->certfile = crtpath;
    cert->pkeyfile = keypath;
    cert->apiurl = api;
    cert->rootstore = store;
    snif_cert_init_ex(cert, SNIF_F_KEYSPEC);
}

int main(int argc, char **argv) {
    if (argc < 3) {
	fprintf(stderr, "usage: cert-t <dir> <port>\n");
	return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    dir = argv[1];
    snprintf(crtpath, sizeof(crtpath), "%s/cur.crt", dir);
    snprintf(keypath, sizeof(keypath), "%s/dev.key", dir);
    snprintf(apiurl, sizeof(apiurl), "http://127.0.0.1:%s/", argv[2]);
    X509_STORE *store = test_store();
    snif_cert cert;

    /* A saved chain is verified against the roots at load */
    setup(&cert, "good.crt", store, DEAD_API);
    check(snif_cert_ctx(&cert) != NULL, "a saved chain from a trusted root is used");
    check(cert.cn && !strcmp(cert.cn, "*.snif-t.test"), "its name is read from it");
    snif_cert_reset(&cert);

    setup(&cert, "other.crt", store, DEAD_API);
    check(snif_cert_ctx(&cert) == NULL, "a saved chain from another root is refused");
    check(snif_cert_error(&cert) == SNIF_CE_CERT, "  with SNIF_CE_CERT");
    check(cert.cn && !strcmp(cert.cn, "*.snif-t.test"), "  and its name is kept, for the renewal");
    check(cert.download_at <= time(NULL) + SNIF_CERT_RETRY, "  and a renewal is due within SNIF_CERT_RETRY");
    snif_cert_reset(&cert);

    setup(&cert, "good.crt", NULL, DEAD_API);
    check(snif_cert_ctx(&cert) == NULL, "a saved chain is refused when its root is not in the default paths");
    snif_cert_reset(&cert);

    setup(&cert, "good.crt", store, DEAD_API);
    cert.cn = strdup("*.other.test");
    check(snif_cert_ctx(&cert) == NULL, "a saved chain for another name is refused");
    snif_cert_reset(&cert);

    /* The placeholder at start-up: refused, but it names the host to renew */
    setup(&cert, "ph.crt", store, apiurl);
    check(snif_cert_ctx(&cert) != NULL, "a saved placeholder leads to a download, which is used");
    check(same("cur.crt", "good.crt"), "  and saved");
    snif_cert_reset(&cert);

    setup(&cert, "ph.crt", store, DEAD_API);
    check(snif_cert_ctx(&cert) == NULL, "a saved placeholder with no CA proxy gives no context");
    check(cert.cn && !strcmp(cert.cn, "*.snif-t.test"), "  but its name is kept");
    snif_cert_reset(&cert);

    /* snif_cert_reset() then snif_cert_init_ex() on the same struct */
    setup(&cert, "good.crt", NULL, DEAD_API);
    X509_STORE *made = cert.rootstore;
    check(made && cert.alloc_rootstore == made, "init with no root store makes one");
    add_test_root(&cert);
    check(snif_cert_ctx(&cert) != NULL, "  and verifies against it");
    snif_cert_reset(&cert);
    check(!cert.rootstore && !cert.alloc_rootstore, "reset frees that store and clears .rootstore");
    snif_cert_init_ex(&cert, SNIF_F_KEYSPEC);
    check(cert.rootstore && cert.alloc_rootstore == cert.rootstore, "init again makes a new store");
    check(add_test_root(&cert) && snif_cert_ctx(&cert) != NULL, "  and verifies against it");
    snif_cert_reset(&cert);

    /* snif_cert_reset() and use again without init, as snifd's watch restart does */
    setup(&cert, "good.crt", NULL, DEAD_API);
    add_test_root(&cert);
    check(snif_cert_ctx(&cert) != NULL, "a chain verified against the store made at init");
    snif_cert_reset(&cert);
    check(snif_cert_ctx(&cert) == NULL, "after reset, used again: verified against a new default store");
    check(cert.rootstore && cert.alloc_rootstore == cert.rootstore, "  which is made on use");
    snif_cert_reset(&cert);

    /* A caller's root store is the caller's */
    setup(&cert, "good.crt", store, DEAD_API);
    check(snif_cert_ctx(&cert) != NULL, "a chain verified against the caller's store");
    snif_cert_reset(&cert);
    check(cert.rootstore == store && !cert.alloc_rootstore, "reset leaves the caller's store set");
    snif_cert_init_ex(&cert, SNIF_F_KEYSPEC);
    check(cert.rootstore == store && snif_cert_ctx(&cert) != NULL, "init again keeps it, and verifies against it");
    snif_cert_reset(&cert);

    X509_STORE_free(store);
    printf("%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
