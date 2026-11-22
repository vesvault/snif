#!/bin/bash
#
# Psalm's taint analysis of the CA proxy's PHP (psalm.xml, README beside
# this file).
#
#   ca-proxy/test/psalm/run.sh [psalm options]
#     e.g. --report=psalm.sarif, or --set-baseline=psalm-baseline.xml.
#     Exits as Psalm does: 0 with no finding outside the baseline, 2 with
#     one, 1 if it could not run.
#   ca-proxy/test/psalm/run.sh --sarif FILE
#     The same, writing the findings outside the baseline to FILE as SARIF,
#     for GitHub's code scanning. Psalm's own report lists the baselined
#     ones too, as notes; they are left out.
#   ca-proxy/test/psalm/run.sh --canary
#     Runs canary/canary.php, one flaw per kind of input the plugin gives
#     Psalm, and exits 0 only if Psalm finds each of them.
#
# Paths in what Psalm reports are relative to the repository's root.
#
# Psalm's phar is fetched, pinned by version and sha256, into $PSALM_CACHE
# (default ~/.cache/snif-psalm). Without mbstring, which Psalm needs to
# report where a finding is, byte-wise stand-ins are loaded (mb-shim.php).

set -eu
D=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$D/../../.." && pwd)
V=6.20.8
SUM=fc62edda7a746503c7f34f514185a3786c871703daa93c910344b75dcc648770
C=${PSALM_CACHE:-$HOME/.cache/snif-psalm}
P="$C/psalm-$V.phar"

if ! { [ -f "$P" ] && echo "$SUM  $P" | sha256sum -c --quiet - > /dev/null 2>&1; }; then
    mkdir -p "$C"
    curl -sSfL -o "$P.tmp" "https://github.com/vimeo/psalm/releases/download/$V/psalm.phar"
    if ! echo "$SUM  $P.tmp" | sha256sum -c --quiet - > /dev/null 2>&1; then
	echo "run.sh: psalm.phar $V does not match its sha256" >&2
	rm -f "$P.tmp"
	exit 1
    fi
    mv "$P.tmp" "$P"
fi

psalm() {   # psalm <config> <root> [options]
    local cfg=$1 root=$2
    shift 2
    local pre=()
    php -r 'exit(extension_loaded("mbstring") ? 0 : 1);' || pre=(-d "auto_prepend_file=$D/mb-shim.php")
    php -d memory_limit=512M ${pre[@]+"${pre[@]}"} "$P" -c "$cfg" --root="$root" --no-cache \
	--threads=1 --no-progress --taint-analysis "$@"
}

if [ "${1:-}" = --sarif ]; then
    dst=${2:?run.sh --sarif FILE}
    all=$(mktemp --suffix=.sarif)
    trap 'rm -f "$all"' EXIT
    psalm "$D/psalm.xml" "$R" --report="$all" > /dev/null && rc=0 || rc=$?
    [ "$rc" -le 2 ] && [ -s "$all" ] || { echo "run.sh --sarif: psalm exited $rc" >&2; exit 1; }
    # Psalm names files from psalm.xml's directory: from the root instead.
    php -r '$j = json_decode(file_get_contents($argv[1]), true);
	$rel = function ($u) use ($argv) {
	    $p = realpath($argv[3] . "/" . $u);
	    return $p !== false && strpos($p, $argv[4] . "/") === 0 ? substr($p, strlen($argv[4]) + 1) : $u;
	};
	foreach ($j["runs"] as &$run) {
	    $run["results"] = array_values(array_filter($run["results"],
		function ($r) { return ($r["level"] ?? "") !== "note"; }));
	    array_walk_recursive($run["results"], function (&$v, $k) use ($rel) { if ($k === "uri") $v = $rel($v); });
	}
	unset($run);
	file_put_contents($argv[2], json_encode($j, JSON_UNESCAPED_SLASHES));
	echo "run.sh --sarif: ", count($j["runs"][0]["results"]), " finding(s) outside the baseline\n";' "$all" "$dst" "$D" "$R"
    exit $rc
fi
if [ "${1:-}" != --canary ]; then
    psalm "$D/psalm.xml" "$R" "$@"
    exit $?
fi

want=$(sed -n 's|^// EXPECT \([0-9][0-9]*\)$|\1|p' "$D/canary/canary.php")
out=$(mktemp)
trap 'rm -f "$out"' EXIT
psalm "$D/canary/psalm.xml" "$D/canary" --output-format=json > "$out" && rc=0 || rc=$?
[ "$rc" -eq 2 ] || { echo "run.sh --canary: psalm exited $rc, not 2 (findings)" >&2; cat "$out" >&2; exit 1; }
got=$(php -r '$j = json_decode(file_get_contents($argv[1]), true);
    $l = [];
    foreach ($j ?: [] as $i) if (strpos($i["type"], "Tainted") === 0) $l[$i["line_from"]] = 1;
    echo count($l);' "$out")
echo "run.sh --canary: Psalm found $got of the canary's $want flawed lines"
[ "$got" -eq "$want" ]
