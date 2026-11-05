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

# SNIF CA Proxy authorization by CAPTCHA: what approves a certificate
# without a VES account (the in-browser demo, and the authorization page when
# it is enabled). It is the counterpart of inc/snif-auth-ves.php: instead of
# a VES vaultItem token, the browser presents a solved CAPTCHA, of one of two
# kinds, each switched on by its secret file:
#
# - Proof of work, SNIF's own (etc/pow.secret). Nothing here calls another
#   service. GET <auth url>?pow answers a challenge: SHA-256(salt . n) for a
#   secret n in [0, maxnumber], which the browser finds by trying them
#   (snif-pow.js on snif.host). The salt carries an expiry, and the
#   signature is an HMAC over the name being approved and the challenge, so
#   a solution approves that one name. pow.secret holds the HMAC key, and
#   every node of a cluster needs the same one. pow.maxnumber, optional,
#   sets the work (SNIF_POW_MAXNUMBER otherwise).
#
# - Cloudflare Turnstile (etc/turnstile.secret), an option for a relay that
#   prefers it. Each token is checked with Cloudflare, and the page that
#   shows the widget runs Cloudflare's script and sends it the visitor's
#   address. The authorization page at snif.host does not show it: a relay
#   that uses Turnstile serves its own (etc/authpage).
#
# Each setting is per domain: etc/<base>.<file> if it exists, else
# etc/<file>, where <base> is the name less its first label, as for
# etc/<base>.authpage. An empty etc/<base>.pow.secret or
# etc/<base>.turnstile.secret turns that kind off for the domain. With both
# secrets, the proof of work is the one used and the Turnstile files are
# ignored. With neither => 501. Either way, once a name is approved, its
# approval file answers any repeat with 202, on every node
# (secure_html/snif-auth.php), so the approval file is the single-use record.
#
# CA certificate issuance is quota-limited, so the same quota discipline
# snif_auth_ves() enforces per account is enforced here, per UTC day: per
# client address (an IPv6 one by its /64), per IPv6 /48, per domain, and for
# the whole relay (snif_captcha_limits()).

$CaptchaEtcDir   = $_SERVER['DOCUMENT_ROOT'] . '/../etc';
$CaptchaQuotaDir = $_SERVER['DOCUMENT_ROOT'] . '/../auth/captcha';
# Where a Turnstile token is checked. A value set before this file is read
# wins (test/turnstile.t sets one with auto_prepend_file).
if (!isset($TurnstileVerifyUrl)) $TurnstileVerifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

# The default limits, per UTC day (etc/captcha-limit and
# etc/<base>.captcha-limit change them). Max certs authorized:
# per client address (an IPv6 one counts by its /64)
define('SNIF_CAPTCHA_IP_MAX', 5);
# per IPv6 /48, within which one client can hold many /64s
define('SNIF_CAPTCHA_NET_MAX', 20);
# per domain
define('SNIF_CAPTCHA_DOMAIN_MAX', 200);
# across all clients and domains (protects the ACME quota)
define('SNIF_CAPTCHA_DAY_MAX', 200);
# The work: n is drawn from [0, SNIF_POW_MAXNUMBER], so a browser tries half
# that many hashes on average.
define('SNIF_POW_MAXNUMBER', 20000000);
# How long a challenge can be solved for, in seconds
define('SNIF_POW_TTL', 600);

# The domain $cn is under, as for etc/<base>.authpage. The names this is
# asked about have a cfg (secure_html/snif-auth.php), so they are names made
# under a domain the relay serves, and safe in a file name.
function snif_captcha_base($cn) {
    return preg_replace('/^[^.]*\./', '', $cn);
}

# A setting for $cn: etc/<base>.<name> if that file exists, even empty, else
# etc/<name>; trimmed, '' if neither exists. With $cn null, the relay's own.
function snif_captcha_conf($cn, $name) {
    $etc = $GLOBALS['CaptchaEtcDir'];
    if ($cn !== null) {
	$s = @file_get_contents("$etc/" . snif_captcha_base($cn) . ".$name");
	if ($s !== false) return trim($s);
    }
    return trim((string)@file_get_contents("$etc/$name"));
}

function snif_pow_secret($cn) {
    return snif_captcha_conf($cn, 'pow.secret');
}

function snif_turnstile_secret($cn) {
    return snif_captcha_conf($cn, 'turnstile.secret');
}

# Which CAPTCHA approves $cn: 'pow', 'turnstile', or null when neither is on.
function snif_captcha_kind($cn) {
    if (snif_pow_secret($cn) !== '') return 'pow';
    if (snif_turnstile_secret($cn) !== '') return 'turnstile';
    return null;
}

# What the authorization page is told for $cn, appended to its URL: "&pow=1"
# to solve a proof of work; "&sitekey=<key>" to show Turnstile, when
# turnstile.sitekey holds the public key that pairs with the secret;
# otherwise nothing, and the page approves by VES.
function snif_captcha_authpage_param($cn) {
    switch (snif_captcha_kind($cn)) {
    case 'pow':
	return '&pow=1';
    case 'turnstile':
	$k = snif_captcha_conf($cn, 'turnstile.sitekey');
	return $k !== '' ? '&sitekey=' . rawurlencode($k) : '';
    }
    return '';
}

# The work for $cn: <base>.pow.maxnumber, else pow.maxnumber, else
# SNIF_POW_MAXNUMBER; whichever first holds a number above 0.
function snif_pow_maxnumber($cn) {
    $etc = $GLOBALS['CaptchaEtcDir'];
    foreach (["$etc/" . snif_captcha_base($cn) . '.pow.maxnumber', "$etc/pow.maxnumber"] as $f) {
	$n = (int)trim((string)@file_get_contents($f));
	if ($n > 0) return min($n, 1000000000);
    }
    return SNIF_POW_MAXNUMBER;
}

# The limits for $cn, per UTC day: etc/captcha-limit, then
# etc/<base>.captcha-limit, each holding any of address=, net=, domain= and
# day= with a number, e.g. "address=5 net=20 domain=100"; a later file's
# value wins, and day= counts only in etc/captcha-limit, since it is the
# whole relay's. What neither sets is the default above.
function snif_captcha_limits($cn) {
    $lim = ['address' => SNIF_CAPTCHA_IP_MAX, 'net' => SNIF_CAPTCHA_NET_MAX,
	'domain' => SNIF_CAPTCHA_DOMAIN_MAX, 'day' => SNIF_CAPTCHA_DAY_MAX];
    $etc = $GLOBALS['CaptchaEtcDir'];
    foreach (["$etc/captcha-limit", "$etc/" . snif_captcha_base($cn) . '.captcha-limit'] as $i => $f) {
	if (!preg_match_all('/(?<![\w-])(address|net|domain|day)\s*=\s*(\d+)/', (string)@file_get_contents($f), $m, PREG_SET_ORDER)) continue;
	foreach ($m as $kv) if ($i == 0 || $kv[1] != 'day') $lim[$kv[1]] = (int)$kv[2];
    }
    return $lim;
}

function snif_pow_sign($secret, $cn, $challenge) {
    return hash_hmac('sha256', "$cn\n$challenge", $secret);
}

# Answers GET <auth url>?pow with a fresh challenge for $cn, as JSON, and
# exits.
function snif_pow_challenge($cn) {
    $secret = snif_pow_secret($cn);
    if ($secret === '') {
	header('HTTP/1.0 501 Not Implemented');
	exit;
    }
    $max = snif_pow_maxnumber($cn);
    $salt = bin2hex(random_bytes(12)) . '.' . (time() + SNIF_POW_TTL);
    $challenge = hash('sha256', $salt . random_int(0, $max));
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode([
	'algorithm' => 'SHA-256',
	'challenge' => $challenge,
	'salt' => $salt,
	'signature' => snif_pow_sign($secret, $cn, $challenge),
	'maxnumber' => $max,
    ]), "\n";
    exit;
}

# Whether $payload (base64 JSON: challenge, salt, number, signature) solves a
# challenge issued for $cn that has not expired.
function snif_pow_verify($secret, $cn, $payload) {
    $p = json_decode((string)base64_decode(strtr($payload, '-_', '+/'), true));
    if (!is_object($p) || !isset($p->challenge, $p->salt, $p->number, $p->signature)) return false;
    if (!is_string($p->challenge) || !is_string($p->salt) || !is_string($p->signature)) return false;
    if (!is_int($p->number) || $p->number < 0) return false;
    # The expiry is the salt's last part. The signature covers it, through
    # the challenge.
    if (!preg_match('/^[0-9a-f]{24}\.(\d{1,12})$/D', $p->salt, $m) || (int)$m[1] <= time()) return false;
    if (!hash_equals(hash('sha256', $p->salt . $p->number), $p->challenge)) return false;
    return hash_equals(snif_pow_sign($secret, $cn, $p->challenge), $p->signature);
}

# Whether Cloudflare accepts the Turnstile $token for $secret.
function snif_turnstile_verify($secret, $token) {
    # Deliberately NOT sending `remoteip`: the IP that solved the challenge
    # (the browser) and the IP that reaches this CA proxy can differ — IPv4 vs
    # IPv6, or a relay/CDN hop — which makes Cloudflare return success:false
    # (remoteip-mismatch) for an otherwise valid token. The token is already
    # single-use and origin-bound, so remoteip only adds a false-failure mode.
    $u = parse_url($GLOBALS['TurnstileVerifyUrl']);
    $tls = ($u['scheme'] ?? '') === 'https';
    $host = $u['host'] ?? '';
    $port = $u['port'] ?? ($tls ? 443 : 80);
    $post = http_build_query(['secret' => $secret, 'response' => $token]);
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $fd = @stream_socket_client(($tls ? 'ssl://' : 'tcp://') . "$host:$port", $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fd) {
	error_log("snif-captcha: siteverify connect failed ($errno): $errstr");
	return false;
    }
    $req = [
	'POST ' . ($u['path'] ?? '/') . ' HTTP/1.0',
	'Host: ' . $host,
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

# The key the per-address counters are named with. It is the relay's, so
# that an address counts the same under every domain: etc/pow.secret, else
# etc/turnstile.secret. Only on a relay with neither does it fall back to
# the secret $cn's domain uses, and then each such domain counts its
# addresses apart.
function snif_captcha_counter_key($cn) {
    foreach (['pow.secret', 'turnstile.secret'] as $f) {
	$s = snif_captcha_conf(null, $f);
	if ($s !== '') return $s;
    }
    $s = snif_pow_secret($cn);
    return $s !== '' ? $s : snif_turnstile_secret($cn);
}

# The per-address counters' keys for $ip, as keyed hashes, so that the names
# do not give the address away (an unkeyed hash of an IPv4 address is
# reversed by trying them all). 'ip': an IPv4 address, or an IPv6 address by
# its /64, within which one client can choose its address; an IPv4-mapped
# one counts as the IPv4. 'net', for IPv6 only: its /48, within which one
# client can hold many /64s (a tunnel broker hands out a /48 for free).
function snif_captcha_ip_keys($ip, $key) {
    $h = function ($b) use ($key) { return substr(hash_hmac('sha256', $b, $key), 0, 32); };
    $bin = @inet_pton($ip);
    if ($bin === false) return ['ip' => $h($ip)];
    if (strlen($bin) == 16 && substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") $bin = substr($bin, 12);
    if (strlen($bin) != 16) return ['ip' => $h($bin)];
    return ['ip' => $h(substr($bin, 0, 8)), 'net' => $h(substr($bin, 0, 6))];
}

# Counts an approval of $cn from $ip if every limit allows it; false if one
# does not. The counters, one file each and named by the UTC day: day-<day>
# for the relay, dom-<day>-<base> for the domain, ip-<day>-<key> for the
# address and, for IPv6, net-<day>-<key> for its /48. bin/snif-syncd carries
# and bin/snif-arc trims files by these names only.
function snif_captcha_quota($ip, $cn) {
    $dir = $GLOBALS['CaptchaQuotaDir'];
    # The directory and the counters are group-writable, as the VES ones
    # are (inc/snif-auth-ves.php): a root install chowns them to snif, and
    # one this user could no longer rewrite would stop counting, silently,
    # for the rest of the day.
    $um = umask(0002);
    if (!is_dir($dir)) @mkdir($dir, 0770, true);
    umask($um);
    $day = gmdate('Ymd');
    # In a cluster each node counts in its own directory (auth/captcha/<node>)
    # and the quotas count them all.
    $sum = function ($name) use ($dir) {
	$n = 0;
	foreach (snif_cluster_counter_files($dir, $name) as $f) $n += (int)@file_get_contents($f);
	return $n;
    };
    $lim = snif_captcha_limits($cn);
    $k = snif_captcha_ip_keys($ip, snif_captcha_counter_key($cn));
    $counters = ["day-$day" => $lim['day'], "dom-$day-" . snif_captcha_base($cn) => $lim['domain'],
	"ip-$day-$k[ip]" => $lim['address']];
    if (isset($k['net'])) $counters["net-$day-$k[net]"] = $lim['net'];
    foreach ($counters as $name => $max) if ($sum($name) >= $max) return false;
    $wd = snif_cluster_counter_dir($dir);
    $um = umask(0002);
    foreach ($counters as $name => $max) @file_put_contents("$wd/$name", (int)@file_get_contents("$wd/$name") + 1);
    umask($um);
    if (snif_cluster_node()) {
	foreach ($counters as $name => $max) snif_cluster_enqueue("auth/captcha/" . snif_cluster_node() . "/$name");
    }
    return true;
}

# Approves $cn if the request carries a solved CAPTCHA of the kind in use: a
# proof of work in X-SNIF-Captcha, or a Turnstile token in X-SNIF-Captcha or
# the cf-turnstile-response form field. Returns what the approval file
# records, "1": the fact of the approval, not who gave it. Otherwise emits
# the appropriate HTTP status and exits (never returns a falsy value).
function snif_auth_captcha($cn) {
    $kind = snif_captcha_kind($cn);
    if (!$kind) {
	header('HTTP/1.0 501 Not Implemented');
	exit;
    }
    if ($kind == 'pow') {
	$payload = isset($_SERVER['HTTP_X_SNIF_CAPTCHA']) ? $_SERVER['HTTP_X_SNIF_CAPTCHA'] : '';
    } else {
	$payload = isset($_POST['cf-turnstile-response']) ? $_POST['cf-turnstile-response']
	    : (isset($_SERVER['HTTP_X_SNIF_CAPTCHA']) ? $_SERVER['HTTP_X_SNIF_CAPTCHA'] : '');
    }
    if (!is_string($payload) || $payload === '') {
	header('HTTP/1.0 401 Unauthorized');
	exit;
    }
    if ($kind == 'pow' ? !snif_pow_verify(snif_pow_secret($cn), $cn, $payload)
	: !snif_turnstile_verify(snif_turnstile_secret($cn), $payload)) {
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    if (!snif_captcha_quota($_SERVER['REMOTE_ADDR'], $cn)) {
	header('HTTP/1.0 429 Too Many Requests');
	exit;
    }
    return '1';
}
