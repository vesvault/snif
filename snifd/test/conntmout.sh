#!/bin/bash
#
# Connect timeout per address (snifd/sock.c, doc/cluster.md section 9),
# through the relay static map: one mapped name points at 192.0.2.1, which
# must silently drop packets from here, and one at a local openssl s_server.
#
#   snifd/test/conntmout.sh [path/to/snifd]
#
# Skips, exiting 0, if 192.0.2.1 answers or refuses instead of dropping.
# Uses ports 27120, 27123, 27443 and 27444 on 127.0.0.1.
# Exits non-zero if any check fails.

SNIFD=$(realpath "${1:-$(dirname "$0")/../snifd}")
PASS=0; FAIL=0
check() {	# check [1] <what>: a failed condition expands to nothing, leaving one argument
    if [ $# = 2 ] && [ "$1" = 1 ]; then echo "ok - $2"; PASS=$((PASS + 1)); else echo "NOT OK - ${@: -1}"; FAIL=$((FAIL + 1)); fi
}

T=$(mktemp -d /var/tmp/snif-conntmout.XXXXXX)
cleanup() { kill $(jobs -p) 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

timeout 8 bash -c '</dev/tcp/192.0.2.1/443' 2>/dev/null
if [ $? != 124 ]; then echo "SKIP - 192.0.2.1:443 is not silently dropped from here"; exit 0; fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=ok.example -keyout "$T/k.pem" -out "$T/c.pem" 2>/dev/null
openssl s_server -quiet -accept 127.0.0.1:27444 -cert "$T/c.pem" -key "$T/k.pem" -www >/dev/null 2>&1 &
"$SNIFD" -l 127.0.0.1:27123 -s 127.0.0.1:27120 \
    -m dead.example:27443:192.0.2.1:443 -m ok.example:27443:127.0.0.1:27444 \
    127.0.0.1:27443 >"$T/snifd.log" 2>&1 &
sleep 1

# client <sni> <timeout s>: prints "<ms> <yes|no>"
client() {
    local s=$(date +%s%N) hs=no
    echo | timeout "$2" openssl s_client -connect 127.0.0.1:27443 -servername "$1" 2>&1 | grep -q "BEGIN CERTIFICATE" && hs=yes
    echo "$(( ($(date +%s%N) - s) / 1000000 )) $hs"
}

set -- $(client ok.example 10)
check $([ "$2" = yes ] && echo 1) "a mapped name with a live destination connects (${1} ms)"

client dead.example 40 >"$T/dead" &
P=$!; sleep 1
set -- $(client ok.example 40)
ok_ms=$1; ok_hs=$2
wait $P
set -- $(cat "$T/dead")
check $([ "$2" = no ] && [ "$1" -ge 4500 ] && [ "$1" -lt 7000 ] && echo 1) "a blackholed destination is given up after the 5 s timeout (${1} ms)"
check $([ "$ok_hs" = yes ] && [ "$ok_ms" -lt 7000 ] && echo 1) "a client arriving meanwhile is served once it ends (${ok_ms} ms)"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
