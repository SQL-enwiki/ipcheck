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

include("../credentials.php");

function checkSpamhaus( $ip ) {
	//Check spamhaus ZEN DNSBL, more information at https://www.spamhaus.org/zen/
	$origip = $ip;
	$expip = explode( ".", $ip );
	$newip = array_reverse( $expip );
	$ip = implode( ".", $newip );
	$dnsres = dns_get_record( $ip . ".zen.spamhaus.org", DNS_A );
	$spamhaus_result = array();
	if( count( $dnsres ) == 0 ) { $spamhaus_result = FALSE; } else { 
		foreach( $dnsres as $dns ) {
			$results = array();
			array_push( $results, $dns['ip'] );
			switch( $dns['ip'] ) {
				case "127.0.0.2":
					array_push( $results, "SBL Listed (possible spam source), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					break;
				case "127.0.0.3":
					array_push( $results, "SBL/CSS Listed  (possible spam source), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					break;
				case "127.0.0.4":
					array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					break;
				case "127.0.0.5":
					array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					break;
				case "127.0.0.6":
					array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					break;
				case "127.0.0.7":
					array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					break;
				case "127.0.0.10":
					array_push( $results, "PBL Listed (Should not be sending email), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					break;
				case "127.0.0.11":
					array_push( $results, "PBL Listed (Should not be sending email), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					break;
			}
			array_push( $spamhaus_result, $results );
		}
	}
	return( $spamhaus_result );
}

function checkSorbs( $ip ) {
	//Check sorbs DNSBL, more information at http://www.sorbs.net/general/using.shtml
	$dnsres = dns_get_record( $ip . ".dnsbl.sorbs.net", DNS_A );
	$sorbs_result = array();
	if( count( $dnsres ) == 0 ) { $sorbs_result = FALSE; } else { 
		foreach( $dnsres as $dns ) {
			$results = array();
			array_push( $results, $dns['ip'] );
			switch( $dns['ip'] ) {
				case "127.0.0.2":
					array_push( $results, "HTTP Proxy" );
					break;
				case "127.0.0.3":
					array_push( $results, "SOCKS Proxy" );
					break;
				case "127.0.0.4":
					array_push( $results, "MISC Proxy" );
					break;
				case "127.0.0.5":
					array_push( $results, "SMTP Server" );
					break;
				case "127.0.0.6":
					array_push( $results, "Possible Spam Source" );
					break;
				case "127.0.0.7":
					array_push( $results, "Vunerable Web server" );
					break;
				case "127.0.0.8":
					array_push( $results, "Asked not to be testeb by SORBS" );
					break;
				case "127.0.0.9":
					array_push( $results, "Zombie - Possibly Hijacked Netblock" );
					break;
				case "127.0.0.10":
					array_push( $results, "Dynamic IP" );
					break;
			case "127.0.0.11":
					array_push( $results, "Badconf - Invalid A or MX address" );
					break;
			case "127.0.0.12":
					array_push( $results, "ISP indicates no mail should originate here" );
					break;
			case "127.0.0.14":
					array_push( $results, "ISP indicates servers should not be present" );
					break;
			}
			array_push( $sorbs_result, $results );
		}
	}
	return( $sorbs_result );
}

function showfooter() {
	echo '<br />
	The HTML GET parameter "ip" can be used to preload an IP into the form. <br /><br />' . 
	//Need access? <a href="https://en.wikipedia.org/wiki/Special:EmailUser/SQL">Email me</a> (I would expect non-admins / non-checkusers to provide a reason)<br /><br />
	'Tool uses Uses APIs from: 
	<ul>
	<li><a href="https://www.ipqualityscore.com/">IPQualityScore</a></li>
	<li><a href="https://proxycheck.io">proxycheck.io</a></li>
	<li><a href="https://iphub.info">IPHub</a></li>
	<li><a href="https://getipintel.net">GetIPIntel</a></li>
	<li><a href="https://ip.teoh.io/">Teoh.io</a> (Donated a 5000 req/day API key!)</li>
	<li><a href="https://www.iphunter.info/">IPHunter</a></li>
	<li><a href="https://nofraud.co//">NoFraud</a></li>
	</ul>
	Tool uses Uses DNSBLs: 
	<ul>
	<li><a href="http://www.sorbs.net/general/using.shtml">Sorbs</a></li>
	<li><a href="https://www.spamhaus.org/zen/">Spamhaus ZEN</a></li>
	</ul>
	NOTE: No portscanning is done from toolforge. <br />
	Proxy API Checker by [[<a href="https://en.wikipedia.org/wiki/User:SQL">User:SQL</a>]]<br />Check out <a href="https://tools.wmflabs.org/aivanalysis/queries/">my other tools</a>!<br />
	</body></html>';
}

function showheader() {
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> 
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1" />
<title>Proxy API Checker</title>
<style>td, th { border: 2px solid #CCC; } /* Add borders to cells */</style>
</head><body>
<H1>Proxy API Checker</H1>';
}
function showform_token() {
	//Relabel while tokens are off
	if( isset( $_GET['ip'] ) ) { $showip = $_GET['ip']; }
	echo '
	<form action="index.php" method="post">
	  IP To Check:<br>
	  <input type="text" name="ip" value="' . $showip . '">
	  <br>
	  Auth Token:<br>
	  <input type="text" name="token">
	  <br><br>
	  <input type="submit" value="Submit">
	</form>';

}
function showform() {
	if( isset( $_GET['ip'] ) ) { $showip = $_GET['ip']; } else { $showip = ""; }
	echo '
	<form action="index.php" method="post">
	  IP To Check:<br>
	  <input type="text" name="ip" value="' . $showip . '">
	  <br><br>
	  <input type="submit" value="Submit" action="index.php">
	</form>';

}

// if( $_POST['token'] == ''  && $_POST['ip'] == '' ) { //Turn off auth tokens for now
if( @$_POST['ip'] == '' ) {
	showheader();
	showform();
	showfooter();
	die();
}
if( inet_pton( $_POST['ip'] ) === FALSE ) {
	showheader();
	echo "<h2>ERROR</h2>Invalid IP address!<br /><br />";
	showform();
	showfooter();
	die();
}
/*
if( $_POST['token'] == ''  && @isset( $_POST['ip'] ) ) {
	showheader();
	echo "<h2>ERROR</h2>Auth token is required!<br /><br />";
	showform();
	showfooter();
	die();
}

if( @!isset( $_POST['token'] ) && @!isset( $_POST['ip'] ) ) {
	showheader();
	showform();
	showfooter();
	die();
}
*/
$out = "";
// if( $_POST['token'] != '' && $_POST['ip'] != '' ) { //Turn off auth tokens for now
if( $_POST['ip'] != '' ) {	
	$api = array();
	$api['apis'] = array();
	$ip = $_POST['ip'];
	$out .= "<h3>Report for $ip</h3>\n";
	$out .= "<a href='https://en.wikipedia.org/wiki/Special:Contributions/$ip'>$ip</a> ( <a href='https://tools.wmflabs.org/whois/gateway.py?lookup=true&ip=$ip'>whois</a> | <a href='https://en.wikipedia.org/wiki/User_talk:$ip'>talk</a> | <a href='https://en.wikipedia.org/wiki/Special:BlockList?wpTarget=$ip'>active blocks</a> | <a href='https://en.wikipedia.org/w/index.php?title=Special:Log&page=User%3A$ip&type=block'>block log</a> | <a href='https://en.wikipedia.org/w/index.php?title=Special:GlobalBlockList&ip=$ip'>global blocks</a> | <a href='https://en.wikipedia.org/wiki/Special:DeletedContributions/$ip'>deleted contribs</a> | <a href='https://en.wikipedia.org/w/index.php?title=Special:AbuseLog&wpSearchUser=$ip'>filter log</a> )<br /><a href='https://tools.wmflabs.org/ipcheck/index.php?ip=$ip'>Link to this page</a><br /><br />\n";
	//Proxycheck.io setup
	$proxycheckio = json_decode( file_get_contents( "http://proxycheck.io/v2/$ip?key=$proxycheckkey&vpn=1" ), TRUE );
	if( @isset( $proxycheckio['error'] ) ) {
		$out .= "<a href=\"https://proxycheck.io/api/\">Proxycheck.io</a> returned an error: " . $proxycheckio['error'] . "<br />\n";
	} else {
		$out .= "<a href=\"https://proxycheck.io/api/\">Result</a> from Proxycheck.io: " . $proxycheckio[$ip]['proxy'] . "<br />\n";
		$api['apis']['proxycheck'] = $proxycheckio[$ip]['proxy'];
	}
	
	//GetIPIntel.net setup
	$getipintel = json_decode( file_get_contents( "http://check.getipintel.net/check.php?ip=$ip&contact=$email&flags=f&format=json" ), TRUE );
	if( $getipintel['status'] == "error" ) {
		$out .= "<a href=\"https://getipintel.net/#API\">GetIPIntel.net</a> returned an error: " . $getipintel['message'] . "<br />\n";
	} else {
		$chance = round ( $getipintel['result'] * 100, 3 );
		$out .= "GetIPIntel.net's <a href=\"https://getipintel.net/#API\">predicted chance</a> of being a proxy: $chance% <br />\n";
		$api['apis']['getipintel'] = $getipintel['result'];
	}
	//IPQualityScore setup
	$ipqualityscore = json_decode( file_get_contents( "https://www.ipqualityscore.com/api/json/ip/$ipqualityscorekey/$ip" ), TRUE );
	if( $ipqualityscore['success'] != "1" ) {
		$out .= "IPQualityScore returned an error: " . $ipqualityscore['message'] . "<br />\n";
	} else {
		$ipqisp = $ipqualityscore['ISP'];
		if( $ipqualityscore['proxy'] == 1 ) { $ipqproxy = "<br />&nbsp;&nbsp;&nbsp;Proxy: Yes"; } else { $ipqproxy = "<br />&nbsp;&nbsp;&nbsp;Proxy: No"; }
		if( $ipqualityscore['vpn'] == 1 ) { $ipqvpn = "<br />&nbsp;&nbsp;&nbsp;VPN: Yes"; } else { $ipqvpn = "<br />&nbsp;&nbsp;&nbsp;VPN: No"; }
		if( $ipqualityscore['mobile'] == 1 ) { $ipqmobile = "<br />&nbsp;&nbsp;&nbsp;Mobile: Yes"; } else { $ipqmobile = "<br />&nbsp;&nbsp;&nbsp;Mobile: No"; }
		$out .= "<a href=\"https://www.ipqualityscore.com/user/proxy-detection-api/documentation\">IPQualityScore</a> results: $ipqproxy, $ipqvpn, $ipqmobile <br />\n&nbsp;&nbsp;&nbsp;ISP: $ipqisp<br />\n";
		$api['apis']['ipqualityscore'] = $ipqualityscore['proxy'];
		$api['apis']['ipqualityscore'] = $ipqualityscore['ISP'];
		$api['apis']['ipqualityscore'] = $ipqualityscore['mobile'];
		$api['apis']['ipqualityscore'] = $ipqualityscore['vpn'];
		
	}
	//IPHub.info setup
	$opts = array( 'http'=> array( 'header'=>"X-Key: $iphubkey" ) );
	$context = stream_context_create( $opts );
	$iphub = json_decode( file_get_contents( "http://v2.api.iphub.info/ip/$ip", FALSE, $context ), TRUE );
	if( !is_array( $iphub ) ) {
		$out .= "There was an error talking to <a href=\"https://iphub.info/api\">IPHub.info</a>. Bad IP maybe?<br />";
	} else {
		if( @isset( $iphub['isp'] ) ) { $possisp = "\n<br />&nbsp;&nbsp;&nbsp;Possible ISP: " . $iphub['isp']; }
		switch ( $iphub['block'] ) {
			case 0:
				$out .= "IPHub.info reports this IP as a <a href=\"https://iphub.info/api\">Block 0</a>: Residential/Unclassified IP (i.e. safe IP) $possisp<br />";
				$api['apis']['iphub'] = 0;
				break;
			case 1:
				$out .= "IPHub.info reports this IP as a <a href=\"https://iphub.info/api\">Block 1</a>: Non-residential IP (hosting provider, proxy, etc.)$possisp<br />";
				$api['apis']['iphub'] = 1;
				break;
			case 2:
				$out .= "IPHub.info reports this IP as a <a href=\"https://iphub.info/api\">Block 2</a>: Non-residential & residential IP (warning, may flag innocent people)$possisp<br />";
				$api['apis']['iphub'] = 2;
				break;
			default:
				$out .= "There was an error talking to IPHub.info. Bad IP maybe?<br />";
				break;
		}
	}
	//Teoh.io setup
	$techurl = "https://ip.teoh.io/api/vpn/$ip?key=$teohkey";
	$techio = json_decode( file_get_contents( $techurl ), TRUE );
	$type = $techio['type'];
	$risk = $techio['risk'];
	if( $techio['is_hosting'] === TRUE ) { $hosting = "is"; } else { $hosting = "is not"; }
	if( $techio['vpn_or_proxy'] === "yes" ) { $vpnproxy = "is"; } else { $vpnproxy = "is not"; }
	$out .= "<a href='https://ip.teoh.io/vpn-proxy-api'>Tech.io</a> reports:<br />
&nbsp;&nbsp;&nbsp;Connection type is: $type<br />
&nbsp;&nbsp;&nbsp;Risk is $risk<br />
&nbsp;&nbsp;&nbsp;This IP likely $hosting a webhost<br />
&nbsp;&nbsp;&nbsp;This IP likely $vpnproxy a VPN/Proxy<br />";
	$api['apis']['teoh']['type'] = $type;
	$api['apis']['teoh']['risk'] = $risk;
	$api['apis']['teoh']['vpn_or_proxy'] = $techio['vpn_or_proxy'];
	if( $techio['is_hosting'] === TRUE ) { $api['apis']['teoh']['hosting'] = "yes"; } else { $api['apis']['teoh']['hosting'] = "yes"; }
	//IPHunter.info setup
	$opts = array( 'http'=> array( 'header'=>"X-Key: $iphunterkey" ) );
	$context = stream_context_create( $opts );
	$iphunter = json_decode( file_get_contents( "https://www.iphunter.info:8082/v1/ip/$ip", FALSE, $context ), TRUE );
	if( $iphunter['status'] == "error" ) {
		$out .= "There was an error talking to <a href=\"https://www.iphunter.info/api\">IPHunter.info</a>. Bad IP maybe?<br />";
	} else {
		if( @isset( $iphunter['data']['isp'] ) ) { $possisp = "\n<br />&nbsp;&nbsp;&nbsp;Possible ISP: " . $iphunter['data']['isp']; 	$api['apis']['iphunter']['isp'] = $iphunter['data']['isp']; }
		switch ( $iphunter['data']['block'] ) {
			case 0:
				$out .= "IPHunter.info reports this IP as a <a href=\"https://www.iphunter.info/api\">Block 0</a>: Residential/Unclassified IP (i.e. safe IP) $possisp<br />";
				$api['apis']['iphunter']['block'] = 0;
				break;
			case 1:
				$out .= "IPHunter.info reports this IP as a <a href=\"https://www.iphunter.info/api\">Block 1</a>: Non-residential IP (hosting provider, proxy, etc.)$possisp<br />";
				$api['apis']['iphunter']['block'] = 1;
				break;
			case 2:
				$out .= "IPHunter.info reports this IP as a <a href=\"https://www.iphunter.info/api\">Block 2</a>: Non-residential & residential IP (warning, may flag innocent people)$possisp<br />";
				$api['apis']['iphunter']['block'] = 2;
				break;
			default:
				$out .= "There was an error talking to IPHunter.info. Bad IP maybe?<br />";
				break;
		}
	}
	//Nofraud.co setup
	$nofraud = file_get_contents( "http://api.nofraud.co/ip.php?ip=$ip" );
	$chance = round ( $nofraud * 100, 3 );
		$out .= "Nofraud.co's <a href=\"https://nofraud.co/v1/api.php\">predicted chance</a> of being a proxy/VPN: $chance% <br />\n";
		$api['apis']['nofraud'] = $nofraud;
	$api['dnsbl'] = array();
	//Check Sorbs setup
	$sorbsResult = checkSorbs( $ip );
	$out .= "<a href='http://www.sorbs.net/general/using.shtml'>SORBS DNSBL</a> results:<br />\n";
	if( $sorbsResult === FALSE ) { $out .= "&nbsp;&nbsp;&nbsp;No result from SORBS DNSBL.<br />\n"; } else {
		$api['dnsbl']['sorbs'] = array();
		foreach( $sorbsResult as $sr ) {
			$out .= "&nbsp;&nbsp;&nbsp;" . $sr[0] . " - " . $sr[1] . "<br />\n";
			array_push( $api['dnsbl']['sorbs'], $sr[0] );
			
		}
	}
	//Check Spamhaus setup
	$spamhausResult = checkSpamhaus( $ip );
	$out .= "<a href='https://www.spamhaus.org/zen/'>Spamhaus ZEN DNSBL</a> results:<br />\n";
	if( $spamhausResult === FALSE ) { $out .= "&nbsp;&nbsp;&nbsp;No result from Spamhaus ZEN DNSBL.<br />\n"; } else {
		$api['dnsbl']['spamhaus'] = array();
		foreach( $spamhausResult as $sr ) {
			$out .= "&nbsp;&nbsp;&nbsp;" . $sr[0] . " - " . $sr[1] . "<br />\n";
			array_push( $api['dnsbl']['spamhaus'], $sr[0] );
		}
	}
	//Portscan setup
	if( $_POST['portscan'] != "false" ) {
		$api['portscan'] = array();
		// $scanres = json_decode( file_get_contents( $porturl ), true ); // cURL is better. Weird errors with file_get_contents.
		$ch = curl_init( $porturl );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		$scanres = json_decode( curl_exec( $ch ), true );
		$scandate = $scanres['date'];
		unset( $scanres['date'] );
		$out .= "Open ports:<br />\n";
		if( count( $scanres ) == 0 ) { $out .= "&nbsp;&nbsp;&nbsp;None found!<br />\n"; } else {
			foreach( $scanres as $scan ) {
				$out .= "&nbsp;&nbsp;&nbsp;$scan<br />\n";
				array_push( $api['portscan'], $scan );
			}
		}
	}
	
	$m1_hola = json_decode( file_get_contents( "proxies.json" ), true );
	$m2_hola = json_decode( file_get_contents( "hola_dns.json" ), true );
	$is_hola = false;
	
	/* Method 1 */
	$v1 = "";
	foreach( $m1_hola as $h ) {
		if( $ip == $h['ip'] ) {
			$out .= "\nHola VPN: Direct detection method 1: $ip is a Hola node. Operating on port " . $h['info']['port'] . ", identifying as country " . $h['country'] . "\n";
			$api['hola'] = "yes";
			$is_hola = true;
			$v1 = "<br />\n";
		}
	}

	/* Method 2 */
	foreach( $m2_hola as $h ) {
		if( $ip == $h['ip'] ) {
			$out .= "$v1\nHola VPN: Direct detection method 2, $ip is a Hola node. Last seen " . date( "F d, Y", $h['seen'] ) . "\n";
			$api['hola'] = "yes";
			$is_hola = true;
		}
	}
	if( $is_hola === false ) { $out .= "\n<br />IP has not been seen as a Hola node.\n"; $api['hola'] = "no"; }

		$out .= "<br/><br/>Check another: <br/>";
	if( $_POST['api'] == "true" ) { echo json_encode( $api ); die(); } else {
		showheader();
		echo $out;
		showform();
		showfooter();
	die();
	}
}

if( $POST['ip'] == "" ) {
	showheader();
	echo "<h2>ERROR</h2>IP Can't be blank.<br /><br />";
	showform();
	showfooter();
	die();
}
?>
