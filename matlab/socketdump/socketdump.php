#!/usr/bin/env php
<?php
/*
 * socketdump.php: a hackish ptrace() socket sniffer using php and strace
 *
 * Author: Paweł Foremski <pawel@foremski.pl> 2011
 * Licensed under GNU GPL v3
 *
 * The idea is to look for socket() calls and trace which of them is used for TCP or UDP.
 * When a read() / write() or its network counterpart is used on such socket, data is dumped
 * and additional information about address and port is extracted, if possible.
 *
 * The tool would be really cool with a point-and-click GUI which would extract the PID
 * of application under the cursor.
 */

error_reporting(E_ALL & ~E_NOTICE);

$N = 12;      /** bytes per flow */
$P = 5;       /** packets per TCP flow */
$S = array(); /** socket info */
$I = array(); /** IP info */
$T = array(); /** TCP seq info */

/* parse command line */
while ($argv[1][0] == "-") {
	if ($argv[1] == "-d")
		define('DEBUG', 1);
	else if ($argv[1] == "-h")
		help();
	else if ($argv[1] == "-s")
		define('READ_STDIN', 1);

	array_shift($argv);
	$argc--;
}

if (!defined('DEBUG'))
	define('DEBUG', 0);
if (!defined('READ_STDIN'))
	define('READ_STDIN', 0);

if (!READ_STDIN) {
	if ($argc < 2)
		help();

	if (is_numeric($argv[1])) {
		$what = "-p $argv[1]";
	} else {
		array_shift($argv);
		$what = "-- " . implode(" ", $argv);
	}

	/* start tracer */
	$proc = proc_open(
		"strace -fqtttvxx -s 12 -e network,read,write $what",
		array(
			0 => STDIN,
			1 => STDOUT,
			2 => array("pipe", "w")
		),
		$pipes);

	if (!$proc)
		die("strace failed\n");

	$src = $pipes[2];
} else {
	$src = STDIN;
}

/* parse output */
$m = array();
$unfinished = array();
$id = 0;
$real_id = 0;
$time_base = 0;

while ($line = fgets($src)) {
	$real_id++;

	/* connect unfinished/resumed lines */
	if (strpos($line, '<')) {
		if (preg_match('/(([a-z]+)\(.*) <unfinished \.\.\.>/', $line, $m)) {
			$unfinished[$m[2]] = $m[1];
			continue;
		} else if (preg_match('/(^.*) <\.\.\. ([a-z]+) resumed> (.*)/', $line, $m)) {
			$orig = $unfinished[$m[2]];
			if (!$orig) {
				fprintf(STDERR, "socketdump: no matching 'unfinished': $line");
				continue;
			}

			$line = $m[1] . " " . $orig . $m[3] . "\n";
			$unfinished[$m[2]] = "";
		}
	}

	/* extract info */
	if (preg_match(
		'/^(\[?p?i?d? *([0-9]+)\]? |)([0-9]+)\.([0-9]+) ([a-z]+)\((.*)\) += (-?[0-9]+)( +E[^ ]+)?/',
		$line, $m)) {

		$pid = ($m[2] ? intval($m[2]) : 0);
		$time = $m[3];
		$time_us = $m[4];
		$fname = "parse_$m[5]";
		$args = $m[6];
		$retval = $m[7];
		$errno = substr($m[8], 1);

		if ($time_base == 0)
			$time_base = $time;

		if (function_exists($fname)) {
			$pkt = $fname($pid, $args, $retval, $errno);

			if (is_array($pkt)) {
				if ($pkt["size"] < $N) continue;
				if ($pkt["tcpseq"] > $P) continue;

				$id++;
				if (DEBUG) {
					printf("# %s", $line);
					printf(
						"%5d %5d %6d %6d %5d   %15s:%-5u %15s:%-5u   %d %d         %s\n\n",
						$id, $real_id, $time - $time_base, $time_us,
						$pkt["size"],
						long2ip($pkt["srcip"]), $pkt["srcport"],
						long2ip($pkt["dstip"]), $pkt["dstport"],
						$pkt["istcp"], $pkt["tcpseq"],
						implode(" ", $pkt["payload"])
					);
				} else {
					printf(
						"%d %d %d %d %d %u %u %u %u %d %d %s\n",
						$id, $real_id, $time - $time_base, $time_us,
						$pkt["size"],
						$pkt["srcip"], $pkt["srcport"],
						$pkt["dstip"], $pkt["dstport"],
						$pkt["istcp"], $pkt["tcpseq"],
						implode(" ", array_slice($pkt["payload"], 0, 2*$N))
					);
				}
			}
		}
	} else if (strpos($line, "\n")) {
		fprintf(STDERR, "socketdump: $line");
	}
}

function parse_socket($pid, $args, $retval, $errno)
{
	global $S;
	global $T;
	if ($retval < 0) return;

	if (preg_match('/PF_INET.*SOCK_STREAM.*IPPROTO_IP/', $args)) {
		$S[$retval] = "tcp";
		$T[$retval]["in"] = 0;
		$T[$retval]["out"] = 0;
	} else if (preg_match('/PF_INET.*SOCK_DGRAM.*IPPROTO_IP/', $args)) {
		$S[$retval] = "udp";
	} else {
		$S[$retval] = null;
	}

	$I[$fd]["src"] = makeup_addr($pid, $retval);
	$I[$fd]["dst"] = makeup_addr($pid, $retval);
}

/*********/

function parse_bind($pid, $args, $retval, $errno)
{
	global $S;
	global $I;
	if ($retval < 0 && $errno != "EINPROGRESS") return;
	$fd = intval($args);
	if (!$S[$fd]) return;

	$I[$fd]["src"] = get_addr($args);
}

/* NB: handles connect too */
function parse_accept($pid, $args, $retval, $errno)
{
	global $S;
	global $I;
	if ($retval < 0 && $errno != "EINPROGRESS") return;
	$fd = intval($args);
	if (!$S[$fd]) return;

	$I[$fd]["dst"] = get_addr($args);
}

function parse_connect($pid, $args, $retval, $errno) { return parse_accept($pid, $args, $retval, $errno); }

/*********/

function parse_read($pid, $args, $retval, $errno)
{
	global $S;
	if ($retval < 0) return;
	$fd = intval($args);
	if (!$S[$fd]) return;

	if (strpos($args, "MSG_PEEK"))
		return;

	$pkt = make_packet("in", $pid, $fd, $args, $retval);

	return $pkt;
}

function parse_recv($pid, $args, $retval, $errno) { return parse_read($pid, $args, $retval, $errno); }
function parse_recvmsg($pid, $args, $retval, $errno) { return parse_read($pid, $args, $retval, $errno); }
function parse_recvfrom($pid, $args, $retval, $errno) { return parse_read($pid, $args, $retval, $errno); }

function parse_write($pid, $args, $retval, $errno)
{
	global $S;
	if ($retval < 0) return;
	$fd = intval($args);
	if (!$S[$fd]) return;

	$pkt = make_packet("out", $pid, $fd, $args, $retval);

	return $pkt;
}

function parse_send($pid, $args, $retval, $errno) { return parse_write($pid, $args, $retval, $errno); }
function parse_sendmsg($pid, $args, $retval, $errno) { return parse_write($pid, $args, $retval, $errno); }
function parse_sendto($pid, $args, $retval, $errno) { return parse_write($pid, $args, $retval, $errno); }

/***************/
function makeup_addr($pid, $fd)
{
	return array(ip2long("127.0.0.1"), $fd);
}

function make_packet($dir, $pid, $fd, $args, $size)
{
	global $S;
	global $T;
	global $I;

	$pkt = array();
	$pkt["payload"] = get_payload($args);
	$pkt["size"] = $size;

	if ($S[$fd] == "tcp") {
		$pkt["istcp"] = 1;
		$pkt["tcpseq"] = ++$T[$fd][$dir];
	} else {
		$pkt["istcp"] = 0;
		$pkt["tcpseq"] = 0;
	}

	if ($dir == "out") { /* out: write, send, sendto */
		$dst = get_addr($args);
		if (!$dst[1])
			$dst = $I[$fd]["dst"];
		if (!$dst[1])
			$dst = makeup_addr($pid, $fd);

		$src = $I[$fd]["src"];
		if (!$src[1])
			$src = makeup_addr($pid, $fd);
	} else { /* in: read, recv, recvfrom */
		$src = get_addr($args);
		if (!$src[1])
			$src = $I[$fd]["dst"];
		if (!$src[1])
			$src = makeup_addr($pid, $fd);

		$dst = $I[$fd]["src"];
		if (!$dst[1])
			$dst = makeup_addr($pid, $fd);
	}

	$pkt["srcip"] = $src[0];
	$pkt["srcport"] = $src[1];
	$pkt["dstip"] = $dst[0];
	$pkt["dstport"] = $dst[1];
	return $pkt;
}

function get_payload($args)
{
	$ret = array();

	if (preg_match('/"([^"]+)"/', $args, $m)) {
		$str = $m[1];
		for ($i = 2; $i < strlen($str); $i += 4) {
			$num = hexdec(substr($str, $i, 2));
			if (DEBUG && $num > 31 && $num < 128) {
				$ret[] = chr($num);
			} else {
				$ret[] = $num >> 4;
				$ret[] = $num & 0x0f;
			}
		}
	}

	return $ret;
}

function get_addr($args)
{
	if (!preg_match('/htons\(([0-9]+)\).*addr\("([0-9.]+)"\)/', $args, $m))
		return array(0, 0);

	return array(ip2long($m[2]), intval($m[1]));
}

function help()
{
	echo "socketdump.php v. 0.1\n";
	echo "usage: socketdump.php [-dhs] [pid|program...]\n";
	echo "  -d    generate debug output\n";
	echo "  -h    help screen\n";
	echo "  -s    parse stdin instead of running strace\n";
	exit(0);
}
