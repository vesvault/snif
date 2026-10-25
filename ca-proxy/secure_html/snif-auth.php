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

$BaseDir = $_SERVER['DOCUMENT_ROOT'] . '/..';
$EtcDir = "$BaseDir/etc";
$CfgDir = "$BaseDir/cfg";
$CsrDir = "$BaseDir/csr";
$AuthDir = "$BaseDir/auth";

require_once "$BaseDir/inc/snif-cluster.php";

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
    snif_cluster_enqueue("cfg/$cn.cfg");
    # A wildcard for the device zone wherever bin/snif-certd can issue one: a
    # local CA (etc/<d>.pub-ca / etc/<d>.priv-ca) or DNS-01 (etc/<d>.tsig).
    # Otherwise a single-host cert, verified over HTTP-01.
    $wc = (file_exists("$EtcDir/$d.pub-ca") || file_exists("$EtcDir/$d.priv-ca") || file_exists("$EtcDir/$d.tsig")) ? "*." : "";
    header("X-SNIF-CN: $wc$cn");
    # Optional server-side key algorithm policy: a per-base-domain etc/<d>.keyalgo
    # or the server-wide etc/keyalgo (one line, e.g. "EC:P-256"). Returned here,
    # alongside X-SNIF-CN, so the connector reads it before it generates its key.
    # The certificate private key is never seen by the proxy - this only steers
    # the connector's local key generation and is not persisted per hostname.
    $keyalgo = @file_get_contents(file_exists("$EtcDir/$d.keyalgo") ? "$EtcDir/$d.keyalgo" : "$EtcDir/keyalgo");
    if ($keyalgo !== false && preg_match('/^[A-Za-z0-9][A-Za-z0-9:._\-]*/', trim($keyalgo), $km)) {
	header("X-SNIF-KeyAlgo: $km[0]");
    }
    header("Content-Type: text/plain");
    echo $wc;
    echo $cn;
    echo "\n";
    exit;
}

if (!snif_cluster_have("cfg/$cn.cfg")) {
    header("HTTP/1.0 404 Not Found");
    exit;
}

# In a cluster the name may have been approved on another node already.
if (file_exists("$AuthDir/$cn.auth") || (snif_cluster_node() && snif_cluster_req("FETCH auth/$cn.auth") === 'FOUND')) {
    header("HTTP/1.0 202 Accepted");
    exit;
}

if (isset($_POST['cf-turnstile-response']) || isset($_SERVER['HTTP_X_SNIF_CAPTCHA'])) {
    require "$BaseDir/inc/snif-auth-captcha.php";
    $auth = snif_auth_captcha();
} else {
    require "$BaseDir/inc/snif-auth-ves.php";
    $auth = snif_auth_ves();
    if (!isset($auth)) {
	# No credential presented: hand off to the interactive authorization page.
	# When the central Turnstile account is configured (etc/turnstile.sitekey
	# paired with the etc/turnstile.secret the captcha verifier checks against)
	# the page presents Turnstile, so its token verifies against the same
	# account. Absent either half, it defaults to VES.
	# The interactive page origin is per-<base domain> config
	# (etc/<base>.authpage), then a server-wide etc/authpage, then the public
	# SNIF page. The value is the full prefix up to and including "?authUrl=".
	$AuthBase = preg_replace('/^[^.]*\./', '', $cn);
	$pagefile = file_exists("$EtcDir/$AuthBase.authpage") ? "$EtcDir/$AuthBase.authpage"
	    : (file_exists("$EtcDir/authpage") ? "$EtcDir/authpage" : null);
	$AuthPageUrl = $pagefile ? trim(file_get_contents($pagefile)) : "";
	if ($AuthPageUrl === "") $AuthPageUrl = "https://snif.host/auth?authUrl=";
	$loc = $AuthPageUrl . "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
	$sitekey = @trim(file_get_contents("$EtcDir/turnstile.sitekey"));
	if ($sitekey && file_exists("$EtcDir/turnstile.secret")) {
	    $loc .= '&sitekey=' . rawurlencode($sitekey);
	}
	header("Location: $loc");
	exit;
    }
    if (!$auth) {
	header("HTTP/1.0 401 Unauthorized");
	exit;
    }
}

if (!file_put_contents("$AuthDir/$cn.auth", $auth)) {
    header("HTTP/1.0 502 Bad Gateway");
    exit;
}
snif_cluster_enqueue("auth/$cn.auth");

header("HTTP/1.0 202 Accepted");

set_time_limit(2);
# Non-blocking ("n"), as in snif-cert.php: with no snif-certd reading the pipe
# the approval still answers 202 at once, and the connector's next certificate
# request asks again.
$fd = @fopen("$BaseDir/var/snif-certd.ctl", "wn");
if ($fd) {
    stream_set_blocking($fd, false);
    $buf = "SNIF CERT $cn\r\n";
    fwrite($fd, $buf, strlen($buf));
    fclose($fd);
}
