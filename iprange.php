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
	  <input type="text" name="ipbase" value= "0.0.0" size = "12">.<input type="text" name="ipstart" value = "0" size = "2">-<input type="text" name="ipend" value = "255" size = "2"></h3>
	  <br><br>
	  <input type="submit" value="Submit">
	</form>';

}
if( @!isset($_GET['ipbase']) | @!isset($_GET['ipstart']) | @!isset($_GET['ipend']) ) {
	showheader();
	showform();
	showfooter();
	die();
} else {
	$range_start = $_GET['ipstart'];
	$range_end = $_GET['ipend'];
	$range = $_GET['ipbase'];
	$rangebasecheck = explode( ".", $_GET['ipbase'] );
	if( $rangebasecheck[0] < 0 | $rangebasecheck[0] > 255 | $rangebasecheck[1] < 0 | $rangebasecheck[1] > 255 | $rangebasecheck[2] < 0 | $rangebasecheck[2] > 255 ) {
		showheader();
		echo "<h3>Invalid base IP</h3>";
		showform();
		showfooter();
		die();	
	}
	if( $range_start < 0 | $range_start > 255 ) {
		showheader();
		echo "<h3>Invalid range start</h3>";
		showform();
		showfooter();
		die();	
	}
	if( $range_end < 0 | $range_end > 255 ) {
		showheader();
		echo "<h3>Invalid range start</h3>";
		showform();
		showfooter();
		die();	
	}
}

$iprange = array();
for( $range_add = $range_start; $range_add <= $range_end; $range_add++ ) {
	$iprange["$range.$range_add"] = gethostbyaddr( "$range.$range_add" );
}

showheader();
foreach( $iprange as $ip=>$resolv ) {
	if( $ip == $resolv ) {
		$resolv = "NotResolved";
	}
	echo "$ip - $resolv ( <a href=\"https://tools.wmflabs.org/whois/gateway.py?lookup=true&ip=$ip\">who</a> / <a href=\"https://en.wikipedia.org/w/index.php?title=Special:BlockList&ip=$ip\">blocks</a> / <a href=\"https://tools.wmflabs.org/guc/?user=$ip\">global</a> ) <br />\n";
}
echo "<br /><br />\n";
showform();
showfooter();
die();
?>
