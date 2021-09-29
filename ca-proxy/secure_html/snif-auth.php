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

$AuthPageUrl = "https://snif.host/auth?authUrl=";

$BaseDir = $_SERVER['DOCUMENT_ROOT'] . '/..';
$EtcDir = "$BaseDir/etc";
$CfgDir = "$BaseDir/cfg";
$CsrDir = "$BaseDir/csr";
$AuthDir = "$BaseDir/auth";

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') exit;

$Host = strtolower(preg_replace('/\:.*/', '', $_SERVER['HTTP_HOST']));
$cn = strtolower(preg_replace('/^\/*/', '', $_SERVER['PATH_INFO']));

if ($cn == '') {
    preg_match_all('/(\S+)/s', file_get_contents("$EtcDir/$Host.domains"), $dp);
    if (!$dp[1]) {
	header("HTTP/1.0 502 Bad Gateway");
	exit;
    }
    $d = preg_replace('/^\./', '', $dp[1][array_rand($dp[1], 1)]);
    $hash = md5(openssl_random_pseudo_bytes(16));
    $cn = 'snif-' . substr($hash, 12, 12) . '-' . substr($hash, 24, 8) . '.' . $d;
    $cfg = [];
    foreach ($_GET AS $k => $v) array_push($cfg, "$k=$v\n");
    foreach ($_POST AS $k => $v) array_push($cfg, "$k=$v\n");
    if (file_put_contents("$CfgDir/$cn.cfg", join("", $cfg)) === false) {
	header("HTTP/1.0 502 Bad Gateway");
	exit;
    }
    $wc = file_exists("$EtcDir/$d.tsig") ? "*." : "";
    header("X-SNIF-CN: $wc$cn");
    header("Content-Type: text/plain");
    echo $wc;
    echo $cn;
    echo "\n";
    exit;
}

if (!file_exists("$CfgDir/$cn.cfg")) {
    header("HTTP/1.0 404 Not Found");
    exit;
}

if (file_exists("$AuthDir/$cn.auth")) {
    header("HTTP/1.0 202 Accepted");
    exit;
}

require "$BaseDir/inc/snif-auth-ves.php";

$auth = snif_auth_ves();

if (!isset($auth)) {
    header("Location: $AuthPageUrl" . "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit;
}

if (!$auth) {
    header("HTTP/1.0 401 Unauthorized");
    exit;
}

if (!file_put_contents("$AuthDir/$cn.auth", $auth)) {
    header("HTTP/1.0 502 Bad Gateway");
    exit;
}

header("HTTP/1.0 202 Accepted");

set_time_limit(2);
$fd = fopen("$BaseDir/var/snif-certd.ctl", "w");
stream_set_blocking($fd, false);
if ($fd) {
    $buf = "SNIF CERT $cn\r\n";
    fwrite($fd, $buf, strlen($buf));
    fclose($fd);
}
