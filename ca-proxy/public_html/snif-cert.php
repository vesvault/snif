<?php
/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 **************************************************************************/

$AuthUrl = "https://snif.snif.xyz:4443/";
$BasePath = $_SERVER['DOCUMENT_ROOT'] . "/..";

$CfgPath = "$BasePath/cfg";
$CSRPath = "$BasePath/csr";
$AuthPath = "$BasePath/auth";
$CrtPath = "$BasePath/crt";
$CSRMinSize = 128;
$CSRMaxSize = 16384;

$Domain = strtolower($_SERVER['HTTP_HOST']);
if (!preg_match('/^\w([\.\-]?\w)*$/', $Domain)) {
    header('HTTP/1.0 400 Bad Request');
    exit;
}

if ($_SERVER['REQUEST_URI'] == "/snif-cert/$Domain.csr") {
    $csr_file = "$CSRPath/$Domain.csr";
    if (file_exists($csr_file)) {
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    if ($_SERVER['REQUEST_METHOD'] != 'PUT' || !file_exists("$CfgPath/$Domain.cfg")) {
	header('HTTP/1.0 404 Not Found');
	exit;
    }
    $csr = file_get_contents('php://input');
    if (strlen($csr) < $CSRMinSize || strlen($csr) > $CSRMaxSize) {
	header('HTTP/1.0 400 Bad Request');
	exit;
    }
    if (!file_put_contents($csr_file, $csr)) {
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
    if (!file_exists("$CfgPath/$Domain.cfg")) {
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
    $fd = fopen("$BasePath/var/snif-certd.ctl", "w");
    stream_set_blocking($fd, false);
    if ($fd) {
	$buf = "SNIF CERT $Domain\r\n";
	$w = fwrite($fd, $buf, strlen($buf));
	if (!fclose($fd)) $w = 0;
    }
    if ($w) {
	header('HTTP/1.0 503 Service Unavailable');
    } else {
	header('HTTP/1.0 502 Bad Gateway');
    }
    exit;
}


header('HTTP/1.0 404 Not Found');
