<?php
// Byte-wise stand-ins for mbstring, for a PHP without it (run.sh loads
// them only then): Psalm uses them to say where a finding is, and crashes
// without them. The CA proxy's sources are ASCII, so bytes are characters.
if (!function_exists("mb_strcut")) { function mb_strcut($s, $st, $l = null, $e = null) { return $l === null ? substr($s, $st) : substr($s, $st, $l); } }
if (!function_exists("mb_substr")) { function mb_substr($s, $st, $l = null, $e = null) { return $l === null ? substr($s, $st) : substr($s, $st, $l); } }
if (!function_exists("mb_strlen")) { function mb_strlen($s, $e = null) { return strlen($s); } }
if (!function_exists("mb_strtolower")) { function mb_strtolower($s, $e = null) { return strtolower($s); } }
if (!function_exists("mb_strtoupper")) { function mb_strtoupper($s, $e = null) { return strtoupper($s); } }
if (!function_exists("mb_strpos")) { function mb_strpos($h, $n, $o = 0, $e = null) { return strpos($h, $n, $o); } }
if (!function_exists("mb_strrpos")) { function mb_strrpos($h, $n, $o = 0, $e = null) { return strrpos($h, $n, $o); } }
if (!function_exists("mb_str_split")) { function mb_str_split($s, $l = 1, $e = null) { return str_split($s, $l); } }
if (!function_exists("mb_check_encoding")) { function mb_check_encoding($v = null, $e = null) { return true; } }
if (!function_exists("mb_internal_encoding")) { function mb_internal_encoding($e = null) { return $e === null ? "UTF-8" : true; } }
