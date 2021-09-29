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

$VESauthDir = $_SERVER['DOCUMENT_ROOT'] . '/../auth/ves';

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
	    $f = $GLOBALS['VESauthDir'] . "/$e";
	    if (filesize($f) > 10) {
		header('HTTP/1.0 429 Too Many Requests');
		exit;
	    }
	    $fd = fopen($f, "a");
	    fwrite($fd, "*");
	    if (fclose($fd)) return $e;
	}
	header('HTTP/1.0 403 Forbidden');
	exit;
    }
    return NULL;
}
