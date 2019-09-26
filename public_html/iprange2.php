<?php
/*
MIT License

Copyright (c) 2018 SQL at the English Wikipedia ( https://en.wikipedia.org/wiki/User:SQL )

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

require __DIR__ . '/../vendor/autoload.php'; 
use Amp\Parallel\Worker;
use Amp\Promise;
function cidrToRange($value) {
	$range = array();
	$split = explode('/', $value);
	if (!empty($split[0]) && is_scalar($split[1]) && filter_var($split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$rangeStart = ip2long($split[0]) & ((-1 << (32 - (int)$split[1])));
		$rangeEnd = ip2long($split[0]) + pow(2, (32 - (int)$split[1])) - 1;

		for ($i = $rangeStart; $i <= $rangeEnd; $i++) {
			$range[] = long2ip($i);
		}
		return $range;
	} else {
		return $value;
	}
}

function interesting( $range ) {
	$hosts = cidrToRange( $range );

	$promises = [];
	foreach ($hosts as $host) {
		$promises[$host] = Worker\enqueueCallable('gethostbyaddr', $host);
	}

	$responses = Promise\wait(Promise\all($promises));
	$interesting = array();
	foreach( $responses as $key => $response ) {
		if( $key != $response ) {
			$interesting[$key] = $response;
		}
	}
	return( $interesting );
}
function showfooter() {
	echo '<br />
	IP Range Resolver by [[<a href="https://en.wikipedia.org/wiki/User:SQL">User:SQL</a>]]<br />Check out <a href="https://tools.wmflabs.org/aivanalysis/queries/">my other tools</a>!<br />
	</body></html>';
}

function showheader() {
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> 
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1" />
<title>IP Range Resolver</title>
</head><body>
<H1>IP Range Resolver</H1>';
}
function showform() {
	echo '
	<form action="iprange.php" method="get">
	  <h3>IP Range:
	  <input type="text" name="iprange" value= "8.8.8.8/24" size = "12"></h3>
	  <br><br>
	  <input type="submit" value="Submit">
	</form>';

}
if( @!isset($_GET['iprange']) ) {
	showheader();
	showform();
	showfooter();
	die();
} else {
	if( preg_match( "/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/i", $_GET['iprange'] ) ) {
		showheader();
		echo "<h3>Invalid IPv4 CIDR</h3>";
		showform();
		showfooter();
		die();	
	}
	$range = explode( "/", $_GET['iprange'] );
	if( $range < 24 || $range > 32 ) {
		showheader();
		echo "<h3>Range is too wide (or too small?)</h3>\n";
		showform();
		showfooter();
	}
}

showheader();
$iprange = $_GET['iprange'];
echo "<H3>Interesting IP addresses in $iprange</H3>\n";
$i = $interesting( $iprange );
echo "<ul>\n";
foreach( $i as $ip => $host ) {
	echo "<li>$ip - $host</li>\n";
}
echo "</ul>\n";
echo "<br /><br />\n";
showform();
showfooter();
