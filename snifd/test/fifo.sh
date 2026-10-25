#!/bin/bash
#
# Output FIFOs that nobody reads (snifd/listen.c, snifd/fifo.c), as a relay
# cluster node's tunnel FIFOs before its tunnels start, or snifd-out-apnsd.ctl
# on a node that runs no snif-apnsd. The relay must start, keep what it pushes,
# and deliver it once a reader opens the FIFO, at start and after a reader
# goes away. Up to 1.08, snifd crashed at start: a FIFO with no reader
# restarted before it knew its poll slot. glibc's malloc perturb fills each
# new allocation, so the bug shows every time instead of only when the heap
# happens to hold zeros.
#
#   snifd/test/fifo.sh [path/to/snifd]
#
# Uses ports 26120, 26123 and 26443 on 127.0.0.1. Needs openssl and mkfifo.
# Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-fifo.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; sleep 0.3; rm -rf "$T"; }
trap cleanup EXIT
cd "$T" || exit 1

# client <sni>: a ClientHello for a name no connector holds here, which the
# relay pushes as SNIF CONNECT to every output FIFO
client() { echo | timeout 2 openssl s_client -connect 127.0.0.1:26443 -servername "$1" >/dev/null 2>&1; }
# pushed <file> <sni>: 1 if the file has a CONNECT for the name, within 3 s
pushed() {
    local i
    for i in $(seq 15); do grep -q "^SNIF CONNECT [0-9a-f]* $2:26443 " "$1" 2>/dev/null && { echo 1; return; }; sleep 0.2; done
}
alive() { kill -0 $S 2>/dev/null && echo 1; }

mkfifo out1 out2 in
MALLOC_PERTURB_=165 GLIBC_TUNABLES=glibc.malloc.perturb=165 \
    "$SNIFD" -l 127.0.0.1:26123 -s 127.0.0.1:26120 -p out1 -p out2 -i in 127.0.0.1:26443 >snifd.log 2>&1 &
S=$!
sleep 1
if [ -z "$(alive)" ]; then wait $S; st=$?; fi
check $(alive) "the relay starts with two output FIFOs that nobody reads${st:+ (exit $st)}"
[ -n "$st" ] && { echo "$PASS passed, $FAIL failed"; exit 1; }

client one.test
check $(alive) "and stays up while it pushes to them"

cat out1 >got1 &
R=$!
client two.test
check $(pushed got1 one.test) "a reader that opens the FIFO later gets what was pushed before"
check $(pushed got1 two.test) "and what is pushed after"

kill $R; wait $R 2>/dev/null
sleep 0.5
client three.test
cat out1 >got2 &
client four.test
check $(pushed got2 three.test) "after the reader goes away, a new one gets what was pushed meanwhile"
check $(pushed got2 four.test) "and what is pushed after"
check $(alive) "the relay is still up, with out2 never read"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
