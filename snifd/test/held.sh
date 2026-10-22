#!/bin/bash
#
# Held CONNECTs across two relays (doc/cluster.md section 2.1). Two snifd
# relays on 127.0.0.1, A and B, with their peer FIFOs joined by cat; a
# connector for dev.test with a certificate from a throwaway CA; an
# openssl s_server behind the connector.
#
#   snifd/test/held.sh [path/to/snifd] [debug]
#
# "debug" means snifd was built with CFLAGS="-DSNIF_DEBUG -DSNIF_HOST_MAXHELD=2".
# It adds the checks that read relay A's debug output: CLOSE, CLEAR, the cap
# and expiry. SNIF_TEST_NO_EXPIRY=1 skips the expiry check, which takes 80 s.
#
# Uses ports 28120-28123, 28443-28444, 29120-29123 and 29443 on 127.0.0.1.
# Needs openssl, stdbuf and mkfifo. Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
DEBUG=$2
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-held.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; sleep 0.3; rm -rf "$T"; }
trap cleanup EXIT
cd "$T" || exit 1

# A connector certificate for dev.test that outlives SNIF_CERT_REFRESH, so the
# connector never tries to download a renewal; a backend certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=test-ca -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=dev.test \
    -keyout dev.key -out dev.csr 2>/dev/null
openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -out dev.crt 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=backend -keyout be.key -out be.pem 2>/dev/null

# The tunnels: opening the input side read-write never blocks, and a reader
# blocked in open() lets snifd's non-blocking open of its output FIFO succeed.
mkfifo a-out-b a-in-b b-out-a b-in-a
tunnel_ab() { cat a-out-b 1<>b-in-a & TAB=$!; }
tunnel_ba() { cat b-out-a 1<>a-in-b & TBA=$!; }
tunnel_ab; tunnel_ba

# The relays verify the connector's certificate against the default paths.
export SSL_CERT_FILE=$T/ca.pem
stdbuf -oL "$SNIFD" -l 127.0.0.1:28123 -s 127.0.0.1:28120 -p a-out-b -i a-in-b 127.0.0.1:28443 >a.log 2>&1 &
stdbuf -oL "$SNIFD" -l 127.0.0.1:29123 -s 127.0.0.1:29120 -p b-out-a -i b-in-a 127.0.0.1:29443 >b.log 2>&1 &
unset SSL_CERT_FILE
openssl s_server -quiet -accept 127.0.0.1:28444 -cert be.pem -key be.key -www >/dev/null 2>&1 &
sleep 1

conn_start() {	# conn_start <relay control port>
    # libsnif verifies the connector's saved certificate against the default paths too.
    SSL_CERT_FILE=$T/ca.pem "$SNIFD" -c dev.crt -k dev.key -r 127.0.0.1:$1 28443:127.0.0.1:28444 29443:127.0.0.1:28444 >conn.log 2>&1 &
    CONN=$!
}
conn_stop() { [ -n "$CONN" ] && kill $CONN 2>/dev/null; wait $CONN 2>/dev/null; CONN=; sleep 0.5; }

# client <relay port> <timeout s>: prints "<ms> <yes|no>", yes if the handshake
# reached the backend
client() {
    local s=$(date +%s%N) hs=no
    echo | timeout "$2" openssl s_client -connect 127.0.0.1:$1 -servername dev.test 2>&1 | grep -q "BEGIN CERTIFICATE" && hs=yes
    echo "$(( ($(date +%s%N) - s) / 1000000 )) $hs"
}
quit_client() { echo | timeout "$2" openssl s_client -connect 127.0.0.1:$1 -servername dev.test >/dev/null 2>&1; }
alines() { grep -c "$1" a.log; }
lastid() { grep "$1" a.log | tail -${2:-1} | head -1 | sed 's/.*connid=\([^ ]*\).*/\1/'; }

conn_start 28123; sleep 1.5
set -- $(client 29443 10)
check $([ "$2" = yes ] && echo 1) "a client on B reaches a device on A"
set -- $(client 28443 10)
check $([ "$2" = yes ] && echo 1) "a client on A reaches a device on A"
conn_stop

client 29443 15 >c2 &
P=$!; sleep 2; conn_start 28123; wait $P
set -- $(cat c2)
check $([ "$2" = yes ] && [ "$1" -lt 5000 ] && echo 1) "a client on B reaches a device that connects to A 2 s later (${1} ms)"
conn_stop

if [ "$DEBUG" = debug ]; then
    h0=$(alines "snif_host_hold "); f0=$(alines "snif_host_heldfree ")
    quit_client 29443 1; sleep 1
    check $([ $(( $(alines "snif_host_hold ") - h0 )) = 1 ] && [ $(( $(alines "snif_host_heldfree ") - f0 )) = 1 ] && echo 1) \
	"A holds a waiting client's CONNECT and drops it on B's CLOSE"
    s0=$(grep -c "snif_srv" b.log)
    conn_start 28123; sleep 1.5
    check $([ $(( $(grep -c "snif_srv" b.log) - s0 )) = 0 ] && echo 1) "a connector starting on A later gets no line for the gone client"
    conn_stop

    h0=$(alines "snif_host_hold "); f0=$(alines "snif_host_heldfree ")
    client 29443 15 >c4 &
    P=$!; sleep 1; conn_start 29123; wait $P; sleep 0.5
    set -- $(cat c4)
    check $([ "$2" = yes ] && [ $(( $(alines "snif_host_hold ") - h0 )) = 1 ] && [ $(( $(alines "snif_host_heldfree ") - f0 )) = 1 ] && echo 1) \
	"a client served on B by a connector that connected there: A drops its line on B's CLEAR"
    conn_stop

    h0=$(alines "snif_host_hold "); f0=$(alines "snif_host_heldfree ")
    PS=; for i in 1 2 3; do quit_client 29443 4 & PS="$PS $!"; sleep 0.4; done
    sleep 0.5
    first=$(lastid "snif_host_hold " 3)
    check $([ $(( $(alines "snif_host_hold ") - h0 )) = 3 ] && [ $(( $(alines "snif_host_heldfree ") - f0 )) = 1 ] \
	&& grep "snif_host_heldfree " a.log | tail -1 | grep -q "connid=$first" && echo 1) \
	"past the cap (2), the oldest held line is dropped"
    wait $PS

    if [ -z "$SNIF_TEST_NO_EXPIRY" ]; then
	f0=$(alines "snif_host_heldfree ")
	quit_client 29443 2 &
	sleep 1; kill $TBA; wait $TBA 2>/dev/null
	old=$(lastid "snif_host_hold ")
	sleep 2
	check $([ $(( $(alines "snif_host_heldfree ") - f0 )) = 0 ] && echo 1) "with the tunnel from B cut, the CLOSE is lost and the line stays"
	sleep 60; tunnel_ba; sleep 16	# B reopens its output FIFO every 15 s
	quit_client 29443 2; sleep 1
	check $(grep "snif_host_heldfree " a.log | grep -q "connid=$old" && echo 1) "the line expires after the client timeout"
    fi
fi

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
