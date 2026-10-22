#!/bin/bash
#
# libsnif certificate checks: a chain loaded from the certificate file is
# verified against the roots, and snif_cert_reset() leaves no freed root
# store behind, whether the struct is initialized again or used as it is.
# Builds lib/test/cert-t.c with lib/cert.c, makes throwaway CAs, and serves
# a chain for the download over HTTP.
#
#   lib/test/cert.sh
#
# CFLAGS defaults to AddressSanitizer, which turns a use of freed memory
# into a failure; set CFLAGS=-g to build without it.
#
# Uses port 28180 on 127.0.0.1. Needs cc, openssl, python3, and the libssl
# and libcurl headers. Exits non-zero if any check fails.

LIB=$(realpath "$(dirname "$0")/..")
CC=${CC:-cc}
CFLAGS=${CFLAGS--g -fsanitize=address -fno-omit-frame-pointer -Wno-deprecated-declarations}
PORT=28180

T=$(mktemp -d /var/tmp/snif-cert.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

$CC $CFLAGS -o "$T/cert-t" "$LIB/test/cert-t.c" "$LIB/cert.c" -lssl -lcrypto -lcurl || exit 1
cd "$T" || exit 1

# Two roots; one connector key with a certificate from each, for the same
# wildcard name; a self-signed placeholder like the one libsnif writes.
for c in ca other-ca; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 31 \
	-subj /CN=$c.snif-t.test -keyout $c.key -out $c.pem 2>/dev/null || exit 1
done
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out dev.key 2>/dev/null || exit 1
openssl req -new -key dev.key -subj '/CN=*.snif-t.test' -out dev.csr 2>/dev/null || exit 1
openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -out good.crt 2>/dev/null || exit 1
openssl x509 -req -in dev.csr -CA other-ca.pem -CAkey other-ca.key -CAcreateserial -days 30 -out other.crt 2>/dev/null || exit 1
openssl req -x509 -key dev.key -subj '/CN=*.snif-t.test' -days 1 -out ph.crt 2>/dev/null || exit 1

mkdir www && cp good.crt www/snif-t.test.crt
python3 -m http.server $PORT --bind 127.0.0.1 --directory www >/dev/null 2>&1 &
for i in $(seq 50); do
    (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
    sleep 0.1
done

# The default paths are the system's, not a test root.
unset SSL_CERT_FILE SSL_CERT_DIR
ASAN_OPTIONS=detect_leaks=0 ./cert-t "$T" $PORT
