#!/bin/bash
#
# A connector's reconnects to its relay (snifd/watch.c). A stub relay
# (python3) takes the connector's first four connections, each its own way:
# it refuses the certificate in the TLS handshake; ends the connection after
# the LISTEN; answers the LISTEN, then ends the connection; ends the next one
# after the LISTEN. Then a snifd relay that accepts the certificate takes the
# port, and a client reaches the device's backend through it. The connector's
# certificate is from a throwaway CA.
#
#   snifd/test/reconnect.sh [path/to/snifd]
#
# Takes about 70 s: the waits are snifd's retry timeout (15 s) and its double.
# The cap, SNIF_WATCH_MAXRETRY, is not reached.
#
# Uses ports 24120, 24123, 24443 and 24444 on 127.0.0.1. Needs openssl and
# python3. Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-reconnect.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; sleep 0.3; rm -rf "$T"; }
trap cleanup EXIT
cd "$T" || exit 1

# A connector certificate that outlives SNIF_CERT_REFRESH, so the connector
# never tries to download a renewal; a backend certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=test-ca -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=dev.test \
    -keyout dev.key -out dev.csr 2>/dev/null
openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -out dev.crt 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=backend -keyout be.key -out be.pem 2>/dev/null

# stub.py <port> <log> <how>...: a relay that takes one connection for each
# <how>, then exits. A relay is the TLS client on the connection the
# connector opens.
#   refuse - verifies the connector's certificate against no CA: the
#            handshake fails, and the connector gets an alert
#   drop   - reads the LISTEN line, then closes
#   answer - reads the LISTEN line, sends a NOOP, closes 1 s later
# Writes "<time> <how> <the LISTEN line, or the error>" to <log> for each.
cat >stub.py <<'EOF'
import socket, ssl, sys, time
port, log = int(sys.argv[1]), sys.argv[2]
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(('127.0.0.1', port))
ls.listen(8)
f = open(log, 'w', buffering=1)
open(log + '.ready', 'w').close()
for how in sys.argv[3:]:
    c, _ = ls.accept()
    t = time.time()
    c.settimeout(10)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if how != 'refuse':
        ctx.verify_mode = ssl.CERT_NONE
    try:
        s = ctx.wrap_socket(c)
        buf = b''
        while b'\n' not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        what = buf.split(b'\n')[0].decode().rstrip('\r')
        if how == 'answer':
            s.sendall(b'NOOP\r\n')
            time.sleep(1)
        s.close()
    except (ssl.SSLError, OSError) as e:
        what = type(e).__name__
        c.close()
    f.write('%.3f %s %s\n' % (t, how, what))
ls.close()
EOF

# lines <n> <timeout s>: waits until the stub has logged n connections
lines() {
    local i
    for i in $(seq $(($2 * 5))); do [ "$(wc -l <stub.log 2>/dev/null)" -ge $1 ] 2>/dev/null && return; sleep 0.2; done
}
at() { sed -n "$1p" stub.log | cut -d' ' -f1; }		# at <n>: the time of connection n
logged() { sed -n "$1p" stub.log | cut -d' ' -f2-; }	# logged <n>: how, and what the stub saw
since() { [ -n "$1" ] && [ -n "$2" ] && awk "BEGIN { printf \"%.1f\", $2 - $1 }" || echo none; }	# since <t1> <t2>: t2 - t1, in s
within() { [ "$1" != none ] && awk "BEGIN { exit !($1 >= $2 && $1 <= $3) }" && echo 1; }	# within <x> <lo> <hi>

openssl s_server -quiet -accept 127.0.0.1:24444 -cert be.pem -key be.key -www >/dev/null 2>&1 &
python3 stub.py 24123 stub.log refuse drop answer drop &
STUB=$!
for i in $(seq 25); do [ -e stub.log.ready ] && break; sleep 0.2; done

# libsnif verifies the connector's saved certificate against the default paths.
SSL_CERT_FILE=$T/ca.pem "$SNIFD" -c dev.crt -k dev.key -r 127.0.0.1:24123 24443:127.0.0.1:24444 >conn.log 2>&1 &

lines 2 25
check $([ "$(logged 1)" = "refuse SSLCertVerificationError" ] && echo 1) "the stub refuses the first handshake ($(logged 1))"
d=$(since "$(at 1)" "$(at 2)")
check $(within "$d" 13 18) "after a failed handshake, the connector reconnects after the retry timeout, 15 s (${d} s)"

lines 3 40
d=$(since "$(at 2)" "$(at 3)")
check $([[ "$(logged 2)" = "drop SNIF LISTEN "* ]] && within "$d" 28 33) \
    "a connection ended after the LISTEN: the next wait doubles, 30 s (${d} s)"

lines 4 10
d=$(since "$(at 3)" "$(at 4)")
check $([[ "$(logged 3)" = "answer SNIF LISTEN "* ]] && within "$d" 0.5 3) \
    "a connection the relay answered on: the connector reconnects as soon as it ends, 1 s on (${d} s)"
check $([[ "$(logged 4)" = "drop SNIF LISTEN "* ]] && echo 1) "and sends its LISTEN again ($(logged 4))"

# The stub exits after the fourth connection; snifd sets SO_REUSEPORT, so it
# must be gone before the relay binds the port.
kill $STUB 2>/dev/null; wait $STUB 2>/dev/null
SSL_CERT_FILE=$T/ca.pem "$SNIFD" -l 127.0.0.1:24123 -s 127.0.0.1:24120 127.0.0.1:24443 >relay.log 2>&1 &
sleep 0.5
hs=no
echo | timeout 30 openssl s_client -connect 127.0.0.1:24443 -servername dev.test 2>&1 | grep -q "BEGIN CERTIFICATE" && hs=yes
d=$(since "$(at 4)" "$(date +%s.%N)")
check $([ $hs = yes ] && echo 1) "a relay that accepts the certificate gets the device: a client waiting there reaches the backend"
check $(within "$d" 13 19) "the connection after the answered one was ended unanswered: the wait is back at 15 s (${d} s)"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
