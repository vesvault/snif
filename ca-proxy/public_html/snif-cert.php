<?php
/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 **************************************************************************/

$BasePath = $_SERVER['DOCUMENT_ROOT'] . "/..";

$CfgPath = "$BasePath/cfg";
$CSRPath = "$BasePath/csr";
$AuthPath = "$BasePath/auth";
$CrtPath = "$BasePath/crt";
$CSRMinSize = 128;
$CSRMaxSize = 16384;

require_once "$BasePath/inc/snif-cluster.php";

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') exit;

# The certificate CN is taken from the request path (/snif-cert/<cn>.csr|.crt)
# so this endpoint can be served both from the per-host catch-all domain and
# from the HTTPS initialization origin (e.g. snif.snif.xyz:4443), where the Host
# header is the init host rather than the CN. Falls back to the Host header.
if (preg_match('#/snif-cert/([^/?]+)\.(?:csr|crt)(?:[?\#].*)?$#', $_SERVER['REQUEST_URI'], $rm)) {
    $Domain = strtolower($rm[1]);
} else {
    $Domain = strtolower($_SERVER['HTTP_HOST']);
}
if (!preg_match('/^\w([\.\-]?\w)*$/', $Domain)) {
    header('HTTP/1.0 400 Bad Request');
    exit;
}

# The base AuthUrl advertised to the connector (X-SNIF-AuthUrl) is per-<base
# domain> configuration, matching etc/<base>.keyalgo / etc/<base>.tsig: read
# etc/<base>.authurl, then a server-wide etc/authurl, then fall back to the
# public SNIF initialization origin. A trailing slash is enforced (the CN is
# appended to it).
$AuthBase = preg_replace('/^[^.]*\./', '', $Domain);
$authfile = file_exists("$BasePath/etc/$AuthBase.authurl") ? "$BasePath/etc/$AuthBase.authurl"
    : (file_exists("$BasePath/etc/authurl") ? "$BasePath/etc/authurl" : null);
$AuthUrl = $authfile ? trim(file_get_contents($authfile)) : "";
if ($AuthUrl === "") $AuthUrl = "https://snif.snif.xyz:4443/";
$AuthUrl = rtrim($AuthUrl, "/") . "/";

if ($_SERVER['REQUEST_URI'] == "/snif-cert/$Domain.csr") {
    $csr_file = "$CSRPath/$Domain.csr";
    # In a cluster snif-syncd decides: an identical CSR again is accepted, a
    # different one is refused (doc/cluster.md section 5).
    if (!snif_cluster_node() && file_exists($csr_file)) {
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    if ($_SERVER['REQUEST_METHOD'] != 'PUT' || !snif_cluster_have("cfg/$Domain.cfg")) {
	header('HTTP/1.0 404 Not Found');
	exit;
    }
    $csr = file_get_contents('php://input');
    if (strlen($csr) < $CSRMinSize || strlen($csr) > $CSRMaxSize) {
	header('HTTP/1.0 400 Bad Request');
	exit;
    }
    if (snif_cluster_node()) {
	$r = snif_cluster_req("CSR $Domain " . strlen($csr) . " " . hash('sha256', $csr), $csr);
	if ($r === 'DIFFERENT') {
	    header('HTTP/1.0 403 Forbidden');
	    exit;
	}
	if ($r !== 'STORED' && $r !== 'SAME') {
	    header('HTTP/1.0 503 Service Unavailable');
	    exit;
	}
    } elseif (!file_put_contents($csr_file, $csr)) {
	header('HTTP/1.0 502 Bad Gateway');
	exit;
    }
    header('HTTP/1.0 201 Created');
    header("X-SNIF-AuthUrl: $AuthUrl$Domain");
    exit;
} elseif ($_SERVER['REQUEST_URI'] == "/snif-cert/$Domain.crt") {
    if ($_SERVER['REQUEST_METHOD'] != 'GET') {
	header('HTTP/1.0 405 Method Not Allowed');
	exit;
    }
    $crt_file = "$CrtPath/$Domain.crt";
    if (file_exists($crt_file)) {
	header('Content-Type: application/x-x509-ca-cert');
	echo file_get_contents($crt_file);
	exit;
    }
    if (!snif_cluster_have("cfg/$Domain.cfg")) {
	header('HTTP/1.0 404 Not Found');
	exit;
    }
    if (!file_exists("$AuthPath/$Domain.auth")) {
	header('HTTP/1.0 401 Unauthorized');
	header("X-SNIF-AuthUrl: $AuthUrl$Domain");
	exit;
    }
    set_time_limit(2);
    $w = 0;
    # "n" opens the pipe non-blocking: with no snif-certd reading it, the open
    # fails at once (ENXIO) and the client gets 502. A blocking open held the
    # request until the web server gave up on it; set_time_limit() does not
    # count time spent blocked in open().
    $fd = @fopen("$BasePath/var/snif-certd.ctl", "wn");
    if ($fd) {
	stream_set_blocking($fd, false);
	$buf = "SNIF CERT $Domain\r\n";
	$w = fwrite($fd, $buf, strlen($buf));
	if (!fclose($fd)) $w = 0;
    }
    # A prior issuance attempt recorded a terminal error: deliver it to the client
    # (distinct status + message) rather than an endless 503 "still working". The
    # certd nudge above still lets a later attempt clear the error and succeed.
    $err_file = "$CrtPath/$Domain.err";
    if (file_exists($err_file)) {
	$msg = trim(@file_get_contents($err_file));
	if ($msg === '' || $msg === false) $msg = 'Certificate issuance failed';
	header('HTTP/1.0 422 Unprocessable Entity');
	header('Content-Type: text/plain');
	echo $msg, "\n";
	exit;
    }
    if ($w) {
	header('HTTP/1.0 503 Service Unavailable');
    } else {
	header('HTTP/1.0 502 Bad Gateway');
    }
    exit;
}


header('HTTP/1.0 404 Not Found');
