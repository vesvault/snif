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

# SNIF CA Proxy authorization via CAPTCHA (Cloudflare Turnstile by default).
#
# This is the in-browser-demo counterpart of inc/snif-auth-ves.php: a human
# solves a CAPTCHA instead of presenting a VES vaultItem token. CA certificate
# issuance is quota-limited, so the same quota discipline snif_auth_ves()
# enforced per-email is enforced here per-IP and globally per day.
#
# Enable by dropping the Turnstile secret key into etc/turnstile.secret (its
# presence is the on/off switch; absence => 501). The matching public site key
# goes into the demo page. To use a different CAPTCHA provider, swap
# snif_captcha_verify() and the verify host/path below.

$CaptchaSecretFile = $_SERVER['DOCUMENT_ROOT'] . '/../etc/turnstile.secret';
$CaptchaQuotaDir   = $_SERVER['DOCUMENT_ROOT'] . '/../auth/captcha';
$CaptchaVerifyHost = 'challenges.cloudflare.com';
$CaptchaVerifyPath = '/turnstile/v0/siteverify';

# Max certs authorized per client IP per UTC day
define('SNIF_CAPTCHA_IP_MAX', 5);
# Max certs authorized across all clients per UTC day (protects the ACME quota)
define('SNIF_CAPTCHA_DAY_MAX', 200);

function snif_captcha_verify($secret, $token, $ip) {
    # Deliberately NOT sending `remoteip`: the IP that solved the challenge
    # (the browser) and the IP that reaches this CA proxy can differ — IPv4 vs
    # IPv6, or a relay/CDN hop — which makes Cloudflare return success:false
    # (remoteip-mismatch) for an otherwise valid token. The token is already
    # single-use and origin-bound, so remoteip only adds a false-failure mode.
    $post = http_build_query(['secret' => $secret, 'response' => $token]);
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $fd = @stream_socket_client('ssl://' . $GLOBALS['CaptchaVerifyHost'] . ':443', $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fd) {
	error_log("snif-captcha: siteverify connect failed ($errno): $errstr");
	return false;
    }
    $req = [
	'POST ' . $GLOBALS['CaptchaVerifyPath'] . ' HTTP/1.0',
	'Host: ' . $GLOBALS['CaptchaVerifyHost'],
	'Content-Type: application/x-www-form-urlencoded',
	'Content-Length: ' . strlen($post),
	'Connection: close',
	'',
	$post
    ];
    fwrite($fd, join("\r\n", $req));
    $rsp = stream_get_contents($fd);
    fclose($fd);
    if (!preg_match('/\r?\n\r?\n(.*)$/s', $rsp, $m)) {
	error_log("snif-captcha: siteverify unparseable response: $rsp");
	return false;
    }
    $j = json_decode($m[1]);
    if (!$j || empty($j->success)) {
	error_log("snif-captcha: siteverify rejected: " . trim($m[1]));
	return false;
    }
    return true;
}

function snif_captcha_quota($ip) {
    $dir = $GLOBALS['CaptchaQuotaDir'];
    if (!is_dir($dir)) @mkdir($dir, 0770, true);
    $day = gmdate('Ymd');
    $gf = "$dir/day-$day";
    if ((int)@file_get_contents($gf) >= SNIF_CAPTCHA_DAY_MAX) return false;
    $kf = "$dir/ip-$day-" . md5($ip);
    if ((int)@file_get_contents($kf) >= SNIF_CAPTCHA_IP_MAX) return false;
    @file_put_contents($kf, (int)@file_get_contents($kf) + 1);
    @file_put_contents($gf, (int)@file_get_contents($gf) + 1);
    return true;
}

# Returns a non-empty identity string on success; otherwise emits the
# appropriate HTTP status and exits (never returns a falsy value).
function snif_auth_captcha() {
    $secret = @trim(file_get_contents($GLOBALS['CaptchaSecretFile']));
    if (!$secret) {
	header('HTTP/1.0 501 Not Implemented');
	exit;
    }
    $token = isset($_POST['cf-turnstile-response']) ? $_POST['cf-turnstile-response']
	: (isset($_SERVER['HTTP_X_SNIF_CAPTCHA']) ? $_SERVER['HTTP_X_SNIF_CAPTCHA'] : '');
    if (!$token) {
	header('HTTP/1.0 401 Unauthorized');
	exit;
    }
    $ip = $_SERVER['REMOTE_ADDR'];
    if (!snif_captcha_verify($secret, $token, $ip)) {
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    if (!snif_captcha_quota($ip)) {
	header('HTTP/1.0 429 Too Many Requests');
	exit;
    }
    return 'captcha:' . $ip;
}
