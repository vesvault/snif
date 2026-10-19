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

# A node of a relay cluster (doc/cluster.md) names itself in etc/cluster.node.
# Then CSRs go through the local snif-syncd, files written here are queued for
# every peer, and counters are kept per node. Without that file, nothing here
# changes what a single relay does. The file does not depend on snif-syncd
# running: with the daemon down, a cluster node refuses CSRs rather than
# accepting them alone.

$SnifBase = realpath($_SERVER['DOCUMENT_ROOT'] . '/..');

function snif_cluster_node() {
    static $node = false;
    if ($node === false) {
	$n = trim((string)@file_get_contents($GLOBALS['SnifBase'] . '/etc/cluster.node'));
	$node = preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/', $n) ? $n : null;
    }
    return $node;
}

# One request to the local snif-syncd: the first reply line, or null if the
# daemon cannot be asked.
function snif_cluster_req($line, $body = '') {
    $fd = @stream_socket_client('unix://' . $GLOBALS['SnifBase'] . '/var/snif-syncd.sock', $errno, $errstr, 2);
    if (!$fd) return null;
    stream_set_timeout($fd, 20);
    fwrite($fd, "$line\n$body");
    $r = fgets($fd);
    fclose($fd);
    return $r === false ? null : rtrim($r, "\r\n");
}

# Queue a file, by its path under the CA proxy base, for every peer: a link in
# each sync-queue/<peer>/, which snif-syncd keeps equal to its listed peers.
# This needs no running daemon; the SYNC only wakes it.
function snif_cluster_enqueue($rel) {
    if (!snif_cluster_node()) return;
    $base = $GLOBALS['SnifBase'];
    foreach (glob("$base/sync-queue/*", GLOB_ONLYDIR) as $q) {
	$entry = "$q/$rel";
	if (!is_dir(dirname($entry))) @mkdir(dirname($entry), 02775, true);
	@symlink("$base/$rel", $entry);
    }
    $fd = @stream_socket_client("unix://$base/var/snif-syncd.sock", $errno, $errstr, 1);
    if ($fd) {
	fwrite($fd, "SYNC\n");
	fclose($fd);
    }
}

# A name allocated on another node may not have reached this one yet: ask the
# peers before deciding it does not exist. True if the file is here or a peer
# had it, false if every peer said it has none; answers 503 and exits if the
# peers cannot be asked.
function snif_cluster_have($rel) {
    if (file_exists($GLOBALS['SnifBase'] . "/$rel")) return true;
    if (!snif_cluster_node()) return false;
    $r = snif_cluster_req("FETCH $rel");
    if ($r === 'FOUND') return true;
    if ($r === 'NONE') return false;
    header('HTTP/1.0 503 Service Unavailable');
    exit;
}

# The directory this node writes counter files in: <dir>/<node> in a cluster.
function snif_cluster_counter_dir($dir) {
    $node = snif_cluster_node();
    if (!$node) return $dir;
    if (!is_dir("$dir/$node")) @mkdir("$dir/$node", 02775, true);
    return "$dir/$node";
}

# Every file counter $name is made of: this node's, every other node's, and the
# one from before the cluster.
function snif_cluster_counter_files($dir, $name) {
    $f = ["$dir/$name"];
    if (snif_cluster_node()) foreach (glob("$dir/*", GLOB_ONLYDIR) as $d) $f[] = "$d/$name";
    return $f;
}
