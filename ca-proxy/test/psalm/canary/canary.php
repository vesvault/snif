<?php
// The canary: one flaw per kind of input the plugin gives Psalm, each on
// its own line. Psalm must find every one (EXPECT, below); if it finds
// fewer, the plugin no longer works and a clean run of the CA proxy means
// nothing. Never served: Psalm only reads it.
// EXPECT 8

file_put_contents('/tmp/canary/' . $_SERVER['HTTP_HOST'], 'x');
$uri = $_SERVER['REQUEST_URI'];
file_put_contents("/tmp/canary/$uri", 'x');
$h = isset($_SERVER['HTTP_X_CANARY']) ? $_SERVER['HTTP_X_CANARY'] : '';
file_put_contents('/tmp/canary/' . $h, 'x');
header('X-Canary: ' . ($_SERVER['HTTP_X_CANARY_B'] ?? ''));
file_put_contents('/tmp/canary/' . file_get_contents('php://input'), 'x');
if (preg_match('#^/c/([^/]+)$#', $_SERVER['REQUEST_URI'], $rm)) file_put_contents('/tmp/canary/' . $rm[1], 'x');
function canary_path($n) { return "/tmp/canary/$n"; }
file_put_contents(canary_path(strtolower($_SERVER['PATH_INFO'])), 'x');
require $_SERVER['HTTP_X_CANARY_C'] . '/x.php';
