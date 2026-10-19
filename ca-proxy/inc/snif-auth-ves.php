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

function ves_api_req($meth, $uri, $hdrs, $data=NULL) {
    $ctx = stream_context_create(['ssl' => ['verify_peer_name' => false]]);
    $fd = stream_socket_client('ssl://api.ves.host:443', $errno, $errstr, 50, STREAM_CLIENT_CONNECT, $ctx);
    $req = ["$meth /v1/$uri HTTP/1.0", "Host: api.ves.host"];
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


function snif_auth_ves() {
    $hp = explode('.', $_SERVER['HTTP_X_VES_AUTHORIZATION']);
    if ($hp[0] == 'vaultItem') {
	$rs = ves_api_req('GET', 'vaultItems/' . $hp[1] . '?fields=file(creator(email))', ['Authorization: Bearer ' . $hp[2]]);
	$e = str_replace('/', '', $rs->file->creator->email);
	if ($e) {
	    # A leaky bucket: each approval adds one, and one leaks out per
	    # refill time. An approval appends its time to the file; in a cluster
	    # each node appends to its own (auth/ves/<node>/<email>) and the
	    # bucket replays the approvals of them all in time order.
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
	    $fd = fopen($f, "a");
	    fwrite($fd, ($s !== '' && substr($s, -1) !== "\n" ? ' ' . filemtime($f) . "\n" : '') . time() . "\n");
	    if (fclose($fd)) {
		if (snif_cluster_node()) snif_cluster_enqueue("auth/ves/" . snif_cluster_node() . "/$e");
		return $e;
	    }
	}
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    return NULL;
}
