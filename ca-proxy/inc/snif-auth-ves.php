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

$VESauthDir = $_SERVER['DOCUMENT_ROOT'] . '/../auth/ves';
$VESetcDir = $_SERVER['DOCUMENT_ROOT'] . '/../etc';

# VESapi, which answers who approved: the name its certificate must carry,
# and where to connect. A test points $VESapiAddr at a stand-in and gives
# its CA in $VESapiCAFile; the system's trusted CAs otherwise.
$VESapiHost = 'api.ves.host';
$VESapiAddr = 'api.ves.host:443';
$VESapiCAFile = NULL;

# The approval limit of an account, from etc/<email>.ves-limit, else
# etc/ves-limit, else 10 refilling one a day: the limit and the time one
# approval takes to refill, e.g. "10 1d" (s, m, h or d; a bare number is
# seconds; 0 never refills).
function snif_auth_ves_limit($e) {
    foreach ([$GLOBALS['VESetcDir'] . "/$e.ves-limit", $GLOBALS['VESetcDir'] . '/ves-limit'] as $f) {
	if (preg_match('/^\s*(\d+)\s+(\d+)([smhd]?)\s*$/', (string)@file_get_contents($f), $m))
	    return [(int)$m[1], $m[2] * ['' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400][$m[3]]];
    }
    return [10, 86400];
}

# The approval times in a counter file, one line each. A run of "*" is from
# before the times were kept: one approval per "*", at the time that follows
# it on its line, else at the file's modification time.
function snif_auth_ves_times($f) {
    $s = @file_get_contents($f);
    if ($s === false) return [];
    $ts = [];
    foreach (explode("\n", $s) as $l) {
	if ($l === '') continue;
	preg_match('/^(\**)\s*(\d*)/', $l, $m);
	$t = $m[2] === '' ? filemtime($f) : (int)$m[2];
	for ($i = max(1, strlen($m[1])); $i > 0; $i--) $ts[] = $t;
    }
    return $ts;
}

# A request to VESapi; its result, or NULL. The server's certificate must
# chain to a trusted CA and carry $VESapiHost: the answer decides an
# approval, so a certificate for any other name is refused (until 1.17
# the name went unchecked). A server that cannot be reached, or is
# refused, is NULL with api_req_status 0.
function ves_api_req($meth, $uri, $hdrs, $data=NULL) {
    $host = $GLOBALS['VESapiHost'];
    $ssl = ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host];
    if (!empty($GLOBALS['VESapiCAFile'])) $ssl['cafile'] = $GLOBALS['VESapiCAFile'];
    $ctx = stream_context_create(['ssl' => $ssl]);
    $fd = @stream_socket_client('ssl://' . $GLOBALS['VESapiAddr'], $errno, $errstr, 50, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fd) {
	error_log("snif-auth-ves: no VESapi connection ($errno): $errstr");
	$GLOBALS['api_req_status'] = 0;
	return NULL;
    }
    $req = ["$meth /v1/$uri HTTP/1.0", "Host: $host"];
    if ($hdrs) foreach ($hdrs AS $hdr) $req[] = $hdr;
    if ($data) {
        switch (gettype($data)) {
            case 'array':
            case 'object':
                $data = json_encode($data);
        }
        $req[] = 'Content-Length: ' . strlen($data);
    }
    $req[] = '';
    $req[] = $data;
    fwrite($fd, join("\r\n", $req));
    stream_socket_shutdown($fd, STREAM_SHUT_WR);
    $rsp = stream_get_contents($fd);
    fclose($fd);
    if (!preg_match('/^HTTP\/\S+\s+(\d\d\d)\s.*?\n\r?\n(.*)$/s', $rsp, $rspp) || ($GLOBALS['api_req_status'] = $rspp[1]) != 200) return NULL;
    return json_decode($rspp[2])->result;
}


# Counts an approval for account $e. A leaky bucket: each approval adds one,
# and one leaks out per refill time. An approval appends its time to the file;
# in a cluster each node appends to its own (auth/ves/<node>/<email>) and the
# bucket replays the approvals of them all in time order. Answers 429 and exits
# while the bucket is full; otherwise returns whether the approval was written.
function snif_auth_ves_count($e) {
    list($max, $refill) = snif_auth_ves_limit($e);
    $leak = function ($n, $dt) use ($refill) { return $refill > 0 && $dt > 0 ? max(0, $n - $dt / $refill) : $n; };
    $ts = [];
    foreach (snif_cluster_counter_files($GLOBALS['VESauthDir'], $e) as $cf) $ts = array_merge($ts, snif_auth_ves_times($cf));
    sort($ts);
    $n = 0;
    $t0 = 0;
    foreach ($ts as $t) {
	$n = $leak($n, $t - $t0) + 1;
	$t0 = $t;
    }
    if ($leak($n, time() - $t0) > $max) {
	header('HTTP/1.0 429 Too Many Requests');
	exit;
    }
    $f = snif_cluster_counter_dir($GLOBALS['VESauthDir']) . "/$e";
    # A run of "*" without a time gets its time before the line ends.
    $s = (string)@file_get_contents($f);
    # Group-writable: a root install chowns the tree to snif, and bin/snif-arc
    # replaces a counter it trims as snif, keeping its mode. Under the web
    # server's umask (0022 for php-fpm) either leaves a file this user can no
    # longer append to.
    $um = umask(0002);
    $fd = fopen($f, "a");
    umask($um);
    # One that still cannot be opened is refused like a failed write; PHP
    # has logged why.
    if (!$fd) return false;
    $ok = fwrite($fd, ($s !== '' && substr($s, -1) !== "\n" ? ' ' . filemtime($f) . "\n" : '') . time() . "\n") !== false;
    return fclose($fd) && $ok;
}

# Whether $file, as VESapi answers for the item a token names, is one that
# approves: one of its external ids, in a VES domain with an
# etc/<domain>.ves-item, is a form that file lists for the file's own
# creator. The file holds one form per line, "{email}" standing for the
# creator's email, e.g. "{email}!snif-auth"; "#" starts a comment, and a
# line without "{email}" approves nothing. Such an item is made to approve
# SNIF names: VESapi lets only the owner of <email>'s key name an id after
# it, and the authorization page shares it with no one else, so no one else
# can read its token. Any other item a token reads, such as one shared with
# its holder, approves nothing.
function snif_auth_ves_item_ok($file) {
    $e = strtolower((string)($file->creator->email ?? ''));
    if ($e === '' || !isset($file->externals) || !is_array($file->externals)) return false;
    foreach ($file->externals as $x) {
	$dom = strtolower((string)($x->domain ?? ''));
	$id = strtolower((string)($x->externalId ?? ''));
	if ($id === '' || !preg_match('/^[a-z0-9][a-z0-9._-]*$/D', $dom)) continue;
	$s = @file_get_contents($GLOBALS['VESetcDir'] . "/$dom.ves-item");
	if ($s === false) continue;
	foreach (explode("\n", $s) as $l) {
	    $l = trim(preg_replace('/#.*/', '', $l));
	    if ($l === '' || strpos($l, '{email}') === false) continue;
	    if (strtolower(str_replace('{email}', $e, $l)) === $id) return true;
	}
    }
    return false;
}

# The external ids of $file for the log when it approves nothing: each
# domain, with the id's form, the creator's email shown as {email}. An id that
# does not start with it shows as "(another form)", so that the log names no
# address: it says which item an app approves with, not whose.
function snif_auth_ves_item_forms($file) {
    $e = strtolower((string)($file->creator->email ?? ''));
    $f = [];
    foreach ((isset($file->externals) && is_array($file->externals)) ? $file->externals : [] as $x) {
	$dom = preg_replace('/[^\w.\-]/', '?', strtolower((string)($x->domain ?? '')));
	$id = strtolower((string)($x->externalId ?? ''));
	$f[] = "$dom:" . ($e !== '' && strpos($id, $e) === 0
	    ? '{email}' . preg_replace('/[^\w.!\-]/', '?', substr($id, strlen($e))) : '(another form)');
    }
    return $f ? implode(' ', $f) : '(no external id)';
}

function snif_auth_ves() {
    $h = isset($_SERVER['HTTP_X_VES_AUTHORIZATION']) ? $_SERVER['HTTP_X_VES_AUTHORIZATION'] : '';
    $hp = explode('.', $h, 3);
    if ($hp[0] == 'vaultItem') {
	# VESauth's form only, vaultItem.<id>.<verify token>: the id a number,
	# the token "~" and base64, with its expiry after a "." if it has one.
	# Both go into the request to VESapi: a "/", "?" or "#" in the id would
	# change what is asked, and any other token, a session's, would have
	# VESapi read the item as that session's user, not by the item's token.
	if (count($hp) != 3 || !preg_match('/^\d{1,20}$/D', $hp[1])
	    || !preg_match('/^~[A-Za-z0-9_+\/=-]+(\.\d{1,20})?$/D', $hp[2])) {
	    header('HTTP/1.0 403 Forbidden');
	    exit;
	}
	$rs = ves_api_req('GET', 'vaultItems/' . $hp[1] . '?fields=deleted,file(creator(email),externals(domain,externalId))',
	    ['Authorization: Bearer ' . $hp[2]]);
	# A deleted item approves nothing, as libVES's own VESauth check has it.
	$e = isset($rs->file->creator->email) && empty($rs->deleted) && snif_auth_ves_item_ok($rs->file)
	    ? str_replace('/', '', $rs->file->creator->email) : '';
	if ($e === '' && isset($rs->file))
	    error_log('snif-auth-ves: not an approving item: ' . (empty($rs->deleted) ? '' : 'deleted, ')
		. snif_auth_ves_item_forms($rs->file));
	if ($e && snif_auth_ves_count($e)) {
	    if (snif_cluster_node()) snif_cluster_enqueue("auth/ves/" . snif_cluster_node() . "/$e");
	    return $e;
	}
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    return NULL;
}
