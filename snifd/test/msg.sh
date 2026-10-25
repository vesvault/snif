#!/bin/bash
#
# A connector's SNIF MSG for its own name (snifd/ctl.c): the relay hands it to
# its output FIFOs and to every other control connection for that name on
# this node, never back to the sender. Three control connections, two for
# dev.test and one for other.test, from a stub connector (python3), with
# certificates from a throwaway CA; one output FIFO, read by cat, and one
# input FIFO, as a peer's tunnel would write it.
#
#   snifd/test/msg.sh [path/to/snifd]
#
# Uses ports 25120, 25123 and 25443 on 127.0.0.1. Needs openssl, python3 and
# mkfifo. Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-msg.XXXXXX)
cleanup() { exec 7>&-; kill $(jobs -p) 2>/dev/null; sleep 0.3; rm -rf "$T"; }
trap cleanup EXIT
cd "$T" || exit 1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=test-ca -keyout ca.key -out ca.pem 2>/dev/null
for h in dev other; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=$h.test \
	-keyout $h.key -out $h.csr 2>/dev/null
    openssl x509 -req -in $h.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -out $h.crt 2>/dev/null
done

# conn.py <crt> <key> <out> <send>: a connector's control connection. It is
# the TLS server on the connection it opens; a certificate for a single name
# registers that name at the handshake. Writes "#ready" and then each line
# from the relay to <out>, and sends the content of <send> whenever that file
# appears, removing it.
cat >conn.py <<'EOF'
import os, select, socket, ssl, sys
crt, key, out, send = sys.argv[1:5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
s = ctx.wrap_socket(socket.create_connection(('127.0.0.1', 25123)), server_side=True)
f = open(out, 'w', buffering=1)
f.write('#ready\n')
buf = b''
while True:
    if os.path.exists(send):
        with open(send, 'rb') as g:
            s.sendall(g.read())
        os.unlink(send)
    if s.pending() or select.select([s], [], [], 0.1)[0]:
        d = s.recv(4096)
        if not d:
            break
        buf += d
        while b'\n' in buf:
            l, buf = buf.split(b'\n', 1)
            f.write(l.decode().rstrip('\r') + '\n')
EOF

mkfifo out in
cat out >pushed &
exec 7<>in	# the peer's side of the input FIFO, held open
SSL_CERT_FILE=$T/ca.pem "$SNIFD" -l 127.0.0.1:25123 -s 127.0.0.1:25120 -p out -i in 127.0.0.1:25443 >snifd.log 2>&1 &
sleep 1
python3 conn.py dev.crt dev.key a.out a.send &
python3 conn.py dev.crt dev.key b.out b.send &
python3 conn.py other.crt other.key c.out c.send &

# has <file> <line>: 1 if the file has the line, within 3 s; the FIFO's
# lines end in CR LF
has() {
    local i
    for i in $(seq 15); do tr -d '\r' 2>/dev/null <"$1" | grep -qxF "$2" && { echo 1; return; }; sleep 0.2; done
}
hasnt() { grep -qF "$2" "$1" 2>/dev/null || echo 1; }
say() { printf '%s\r\n' "$2" >$1.send+ && mv $1.send+ $1.send; }

check $([ "$(has a.out '#ready')$(has b.out '#ready')$(has c.out '#ready')" = 111 ] && echo 1) \
    "three connectors are up, two of them for dev.test"
sleep 0.5

say a "SNIF MSG dev.test hello-1"
check $(has b.out "SNIF MSG dev.test hello-1") "a MSG from one dev.test connector reaches the other"
check $(has pushed "SNIF MSG dev.test hello-1") "and the output FIFO, as before"

say a "SNIF MSG other.test spoof-1"
echo "SNIF MSG dev.test from-peer" >&7
check $(has a.out "SNIF MSG dev.test from-peer") "a MSG from the input FIFO reaches the first dev.test connector"
check $(has b.out "SNIF MSG dev.test from-peer") "and the second"
sleep 1
check $(hasnt a.out hello-1) "the sender does not get its own MSG back"
check $(hasnt c.out hello-1) "a connector for another name does not get it"
check $(hasnt c.out from-peer) "nor the one from the input FIFO"
check $([ "$(hasnt b.out spoof-1)$(hasnt c.out spoof-1)$(hasnt pushed spoof-1)" = 111 ] && echo 1) \
    "a MSG naming another host goes nowhere"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
