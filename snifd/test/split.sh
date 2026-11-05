#!/bin/bash
#
# A ClientHello that reaches the relay in pieces (snifd/cln.c): the relay
# waits for the rest, reads the name and connects the client, as it does
# for a hello in one read. A hello with a post-quantum key share
# (X25519MLKEM768, sent by default since OpenSSL 3.5) is about 1.5 KB, so
# it always crosses the network as two TCP segments. One relay; a connector
# for dev.test with a certificate from a throwaway CA; an openssl s_server
# behind the connector; the client is python3's ssl over a plain socket, so
# that the test chooses where the hello is cut.
#
#   snifd/test/split.sh [path/to/snifd]
#
# Uses ports 23120, 23123, 23443 and 23444 on 127.0.0.1. Needs openssl and
# python3. Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-split.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; sleep 0.3; rm -rf "$T"; }
trap cleanup EXIT
cd "$T" || exit 1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=test-ca -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=dev.test \
    -keyout dev.key -out dev.csr 2>/dev/null
openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -out dev.crt 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=backend -keyout be.key -out be.pem 2>/dev/null

# cl.py <port> <mode>: a client for dev.test that sends its hello in the
# pieces <mode> names, 0.5 s apart, then finishes the handshake, trusting
# only the backend's certificate. Prints "<result> <ms> <hello bytes>":
# ok, alert:<reason>, eof, reset or timeout; for junk, closed or open.
cat >cl.py <<'EOF'
import socket, ssl, sys, time
port, mode = int(sys.argv[1]), sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations('be.pem')
ctx.check_hostname = False
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(inc, out, server_hostname='dev.test')
try:
    tls.do_handshake()
except ssl.SSLWantReadError:
    pass
h = out.read()
rec = lambda b: h[:3] + len(b).to_bytes(2, 'big') + b
parts = {
    'whole': [h],
    'split': [h[:200], h[200:]],
    'header': [h[:3], h[3:]],
    'three': [h[:100], h[100:700], h[700:]],
    'records': [rec(h[5:len(h) // 2]), rec(h[len(h) // 2:])],
    'leave': [h[:200]],
    'junk': [b'GET / HTTP/1.0\r\n\r\n'],
}[mode]
s = socket.create_connection(('127.0.0.1', port), timeout=(3 if mode == 'junk' else 10))
t = time.time()
ms = lambda: int((time.time() - t) * 1000)
try:
    for i, p in enumerate(parts):
        if i:
            time.sleep(0.5)
        s.sendall(p)
except OSError:
    pass	# the relay hung up: what it sent first is read below
if mode == 'leave':
    s.close()
    print('left', ms(), len(h))
    sys.exit()
if mode == 'junk':
    try:
        while s.recv(4096):
            pass
        print('closed', ms(), 0)
    except socket.timeout:
        print('open', ms(), 0)
    sys.exit()
try:
    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            d = out.read()
            if d:
                s.sendall(d)
            d = s.recv(16384)
            if not d:
                print('eof', ms(), len(h))
                sys.exit()
            inc.write(d)
    s.sendall(out.read())
    print('ok', ms(), len(h))
except ssl.SSLError as e:
    print('alert:' + str(e.reason), ms(), len(h))
except socket.timeout:
    print('timeout', ms(), len(h))
except OSError:
    print('reset', ms(), len(h))
EOF

openssl s_server -quiet -accept 127.0.0.1:23444 -cert be.pem -key be.key -www >/dev/null 2>&1 &
SSL_CERT_FILE=$T/ca.pem "$SNIFD" -l 127.0.0.1:23123 -s 127.0.0.1:23120 127.0.0.1:23443 >relay.log 2>&1 &
sleep 1
SSL_CERT_FILE=$T/ca.pem "$SNIFD" -c dev.crt -k dev.key -r 127.0.0.1:23123 23443:127.0.0.1:23444 >conn.log 2>&1 &
sleep 1.5

client() { python3 cl.py 23443 "$1"; }

set -- $(client whole)
check $([ "$1" = ok ] && echo 1) "a hello in one piece reaches the device [$*]"
set -- $(client split)
check $([ "$1" = ok ] && echo 1) "a hello cut after 200 bytes reaches the device [$*]"
set -- $(client header)
check $([ "$1" = ok ] && echo 1) "a hello cut inside the record header reaches the device [$*]"
set -- $(client three)
check $([ "$1" = ok ] && echo 1) "a hello in three pieces reaches the device [$*]"
set -- $(client records)
check $([ "$1" = ok ] && echo 1) "a hello in two TLS records, sent apart, reaches the device [$*]"

client leave >/dev/null
set -- $(client whole)
check $([ "$1" = ok ] && echo 1) "after a client leaves mid-hello, the next one still gets through [$*]"

set -- $(client junk)
check $([ "$1" = closed ] && [ "$2" -lt 1000 ] && echo 1) "bytes that are not TLS are still turned away at once [$*]"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
