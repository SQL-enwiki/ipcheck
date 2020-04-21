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
include( "../credentials.php" );
include( "../config.php" );

session_name( 'IPCheck' );
$params = session_get_cookie_params();
session_set_cookie_params(
	$params['lifetime'],
	dirname( $_SERVER['SCRIPT_NAME'] )
);
$ts_pw = posix_getpwuid(posix_getuid());
$ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");
$dbname = $ts_mycnf['user'] . $intdbname;
$mysqli = new mysqli('tools.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'] );
mysqli_query ( $mysqli, "CREATE DATABASE IF NOT EXISTS $dbname;" );
mysqli_select_db( $mysqli, $dbname );

function getGlobalEdits( $user ) {
	$userSanitized = urlencode( $user );
	$api = "https://en.wikipedia.org/w/api.php?action=query&format=json&meta=globaluserinfo&guiuser=$userSanitized&guiprop=editcount";
	$apiResult = json_decode( file_get_contents( $api ), TRUE );
	$res = array();
	$res['edits'] = $apiResult['query']['globaluserinfo']['editcount'];
	$res['age'] = time() - strtotime( $apiResult['query']['globaluserinfo']['registration'] );
	return( $res );
}

function updateRes( $mysqli, $column, $value ) {
	global $res_id;
	$date = time();
	$column = mysqli_real_escape_string( $mysqli, $column );
	$value = mysqli_real_escape_string( $mysqli, $value );
	$query = "UPDATE results set res_date = '$date', $column = '$value' where res_id = '$res_id';";	
	$res = mysqli_query( $mysqli, $query );
}
function checkWebhost( $ip ) {
	include( '../webhostconfig.php' );
	$asn = json_decode( file_get_contents( "https://api.iptoasn.com/v1/as/ip/$ip" ), TRUE );
	$webhost = FALSE;
	foreach( $hosts as $host ) {
		$asnum = $asn['as_number'];
		if( in_array( $asn['as_number'], $host['asns'] ) !== FALSE ) {
			$webhost = $host['name'];
		}
	}
	return( $webhost );
}

require '../vendor/autoload.php';
if( $_GET['api'] != "true" ) {
	if( @isset( $_GET['ip'] ) === TRUE ) {
		$persist_ip = $_GET['ip'];
	}
	include( "oauth.php" );
	if( $_GET['logout'] == "true" ) { 
		session_start();
		session_destroy();
		header( 'Location: index.php' );
	}
} elseif ( $_GET['api'] == "true" ) {
	$key = $_GET['key'];
	$apiq = "select api_user from api where api_key = '$key';";
	$apires = mysqli_query( $mysqli, $apiq );
	$err = mysqli_error( $mysqli );
	$num = mysqli_num_rows( $apires );
	if( mysqli_num_rows( $apires ) == 0 ) { die( "Invalid API Key" ); };
	$row = mysqli_fetch_assoc( $apires );
	$username = $row['api_user'];
	$editcount = 999;
	$age = 99999999;
}
include( "../checkhost/checkhost.php" );

if(file_exists( "../whitelist.php" ) ) {
	include( "../whitelist.php" );
	if( in_array( $username, $whitelist )  === TRUE ) {
		$editcount = 999;
		$age = 99999999;
	}
}
$fail = FALSE;
$age = time() - strtotime( $registration );
$ageDays = round( $age / 86400, 2 );
if( $editcount < 500 || $age < 2592000 ) { $fail = TRUE; }

if( $fail === TRUE ) {
	$globalEdits = getGlobalEdits( $username );
	if( $globalEdits['edits'] < 500 || $globalEdits['age'] < 2592000 ) {
		$globalAgeDays = round( $globalEdits['age'] / 86400, 2 );
		$globalEditCount = $globalEdits['edits'];
		die( "The requirements to use this tool are more than 500 edits, or your account being over 30 days old. Your account has $editcount locally ($globalEditCount globally), and is only $ageDays old locally ($globalAgeDays globally).\n" );
	}
}

if( @!isset( $_GET['wiki'] ) ) { $wikiurl = "https://en.wikipedia.org"; } else {
	$meta = new mysqli('meta.web.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'], 'meta_p');
	$wname = mysqli_real_escape_string( $meta, $_GET['wiki'] );
	$query = "select url from wiki where is_closed = 0 and dbname = '$wname' limit 1;";
	$r = mysqli_query( $meta, $query );
	$row = mysqli_fetch_assoc( $r );
	$wikiurl = $row['url'];
}

//Set up local SQL tables

mysqli_query( $mysqli, "CREATE TABLE IF NOT EXISTS `logging` (
	`log_id` bigint NOT NULL AUTO_INCREMENT,
	`log_user` varchar(512) NOT NULL,
	`log_user_hash` varchar(512) NOT NULL,
	`log_user_ua` varchar(512) NOT NULL,
	`log_search` varchar(512) NOT NULL,
	`log_method` varchar(512) NOT NULL,
	`log_timestamp` varchar(512) NOT NULL,
	`log_cached` bool NOT NULL,
	PRIMARY KEY (`log_id`)
);");

mysqli_query( $mysqli, "CREATE TABLE IF NOT EXISTS `api` (
	`api_id` int(255) NOT NULL AUTO_INCREMENT,
	`api_key` varchar(255) NOT NULL,
	`api_user` varchar(512) NOT NULL,
	PRIMARY KEY (`api_id`)
);" );

mysqli_query( $mysqli, "CREATE TABLE IF NOT EXISTS `results` (
	`res_id` bigint NOT NULL AUTO_INCREMENT,
	`res_ip` varchar(512) NOT NULL,
	`res_date` varchar(512) NOT NULL,
	`res_asn` int(20) NOT NULL,
	`res_asn_wh` int(2) NOT NULL,
	`res_proxycheck` int(2) NOT NULL,
	`res_getipintel` float(20) NOT NULL,
	`res_ipqs_isp` varchar(512) NOT NULL,
	`res_ipqs_proxy` int(2) NOT NULL,
	`res_ipqs_vpn` int(2) NOT NULL,
	`res_ipqs_mobile` int(2) NOT NULL,
	`res_ipqs_recent_abuse` int(2) NOT NULL,
	`res_ipqs_tor` int(2) NOT NULL,
	`res_ipqs_bot` int(2) NOT NULL,
	`res_ipqs_fraudscore` int(10) NOT NULL,
	`res_ipqs_org` varchar(512) NOT NULL,
	`res_iphub_res` int(2) NOT NULL,
	`res_teoh_hosting` int(2) NOT NULL,
	`res_teoh_vpnproxy` int(2) NOT NULL,
	`res_teoh_risk` int(10) NOT NULL,
	`res_teoh_type` varchar(512) NOT NULL,
	`res_iphunter` int(2) NOT NULL,
	`res_ipstack_country` varchar(512) NOT NULL,
	`res_stopforumspam_listed` varchar(512) NOT NULL,
	`res_stopforumspam_freq` varchar(512) NOT NULL,
	`res_stopforumspam_lastseen` varchar(512) NOT NULL,
	`res_stopforumspam_confidence` varchar(512) NOT NULL,
	`res_stopforumspam_country` varchar(512) NOT NULL,
	`res_stopforumspam_delegated` varchar(512) NOT NULL,
	`res_tor` int(2) NOT NULL,
	`res_sorbs` int(2) NOT NULL,
	`res_spamhaus` int(2) NOT NULL,
	`res_spamcop` int(2) NOT NULL,
	PRIMARY KEY (`res_id`)
);");

mysqli_query( $mysqli, "CREATE TABLE IF NOT EXISTS `opinions` (
	`op_id` int(100) auto_increment NOT NULL,
	`op_user_id` varchar(100) NOT NULL,
	`op_opinion` varchar(1000) NOT NULL,
	`op_rationale` blob(2048) NULL,
	`op_date` int(100) NOT NULL,
	PRIMARY KEY( `op_id` )
);" );

$musername = mysqli_real_escape_string( $mysqli, $username );
$apiq = "select api_key from api where api_user = '$musername';";

$res = mysqli_query( $mysqli, $apiq );
if( mysqli_num_rows( $res ) == 0 ) {
	$apikey = md5( password_hash( rand() . $username . time(), PASSWORD_DEFAULT ) );
	$ins = "INSERT INTO api( api_key, api_user ) VALUES ( '$apikey', '$musername' );";
	mysqli_query( $mysqli, $ins );
} else {
	$row = mysqli_fetch_assoc( $res );
	$apikey = $row['api_key'];
}

$loader = new Twig_Loader_Filesystem( __DIR__ . '/../views' );
$twig = new Twig_Environment( $loader, [ 'debug' => true ] );
$twig->addExtension(new Twig_Extension_Debug());

$currentver = substr( file_get_contents( __DIR__. '/../.git/refs/heads/master' ), 0, 7 );

function logit( $user, $search, $method, $cached, $mysqli ) {
	$hash = @md5( $_SERVER['HTTP_ACCEPT_LANGUAGE'] . $_SERVER['HTTP_ACCEPT_ENCODING'] . $_SERVER['HTTP_ACCEPT'] . $_SERVER['HTTP_USER_AGENT'] . $_SERVER['HTTP_DNT'] );
	$ua = $_SERVER['HTTP_USER_AGENT'];
	$timestamp = time();
	$insert = "INSERT INTO logging( log_user, log_user_hash, log_user_ua, log_search, log_method, log_timestamp, log_cached ) values ( '$user', '$hash', '$ua', '$search', '$method', '$timestamp', $cached );";
	mysqli_query( $mysqli, $insert );
}

function reportHit( $service ) {
	//Record monthly stats on how many hits to each API service we're using.
	$min = date( "YMdGi" );
	$day = date( "YMd" );
	$month = date( "YM" );
	if( !file_exists( __DIR__ . "/../stats" ) ) {
		mkdir( __DIR__ . "/../stats" );
	}
	if( file_exists( __DIR__ . "/../stats/$service." . date( "Ym" ) . ".json" ) !== FALSE ) {
		$stat = json_decode( file_get_contents( __DIR__ . "/../stats/$service." . date( "Ym" ) . ".json" ), TRUE );
		if( $stat['month'] == $month ) { $stat['rmonth']++; } else { $stat['rmonth'] = 1; }
		if( $stat['day'] == $day ) { $stat['rday']++; } else { $stat['rday'] = 1; }
		if( $stat['min'] == $min ) { $stat['rmin']++; } else { $stat['rmin'] = 1; }
		$stat['raw']++;
		$stat['month'] = $month;
		$stat['day'] = $day;
		$stat['min'] = $min;
	} else {
		$stat['raw'] = 1;
		$stat['month'] = $month;
		$stat['day'] = $day;
		$stat['min'] = $min;
		$stat['rmonth'] = 1;
		$stat['rday'] = 1;
		$stat['rmin'] = 1;
	}
	$lservice = getLimits();
	
	//Check first limit
	if( $lservice[$service]['type'] == 'min' ) { 
		if( $stat['rmin'] > $lservice[$service]['limit'] ) { return TRUE; }
	} 
	if( $lservice[$service]['type'] == 'day' ) { 
		if( $stat['rday'] > $lservice[$service]['limit'] ) { return TRUE; }
	} 
	if( $lservice[$service]['type'] == 'month' ) { 
		if( $stat['rmonth'] > $lservice[$service]['limit'] ) { return TRUE; }
	} 	
	
	//Check second limit
	if( $lservice[$service]['type2'] == 'min' ) { 
		if( $stat['rmin'] > $lservice[$service]['limit2'] ) { return TRUE; }
	} 
	if( $lservice[$service]['type2'] == 'day' ) { 
		if( $stat['rday'] > $lservice[$service]['limit2'] ) { return TRUE; }
	} 
	if( $lservice[$service]['type2'] == 'month' ) { 
		if( $stat['rmonth'] > $lservice[$service]['limit2'] ) { return TRUE; }
	} 		
	file_put_contents( __DIR__ . "/../stats/$service." . date( "Ym" ) . ".json", json_encode( $stat ) );
	return( FALSE );
}

function checkSpamhaus( $ip ) {
    //Check spamhaus ZEN DNSBL, more information at https://www.spamhaus.org/zen/
	global $mysqli;
    $origip = $ip;
    $expip = explode( ".", $ip );
    $newip = array_reverse( $expip );
    $ip = implode( ".", $newip );
    $dnsres = dns_get_record( $ip . ".zen.spamhaus.org", DNS_A );
    $spamhaus_result = array();
	$value = 0;
    if( count( $dnsres ) == 0 ) { $spamhaus_result = FALSE; } else {
        foreach( $dnsres as $dns ) {
            $results = array();
            array_push( $results, $dns['ip'] );
            switch( $dns['ip'] ) {
                case "127.0.0.2":
                    array_push( $results, "SBL Listed (possible spam source), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.3":
                    array_push( $results, "SBL/CSS Listed  (possible spam source), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.4":
                    array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.5":
                    array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.6":
                    array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.7":
                    array_push( $results, "CBL Listed (proxy/trojan/botnet), see: <a href='https://www.abuseat.org/lookup.cgi?ip=$origip'>details</a>" );
					$value++;
                    break;
                case "127.0.0.10":
                    array_push( $results, "PBL Listed (Should not be sending email), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					$value--;
                    break;
                case "127.0.0.11":
                    array_push( $results, "PBL Listed (Should not be sending email), see: <a href='https://www.spamhaus.org/query/ip/$origip'>details</a>" );
					$value--;
                    break;
            }
            array_push( $spamhaus_result, $results );
        }
    }
	updateRes( $mysqli, "res_spamhaus", $value );
    return( $spamhaus_result );
}

function checkSpamcop( $ip ) {
	global $mysqli;
	$r_ip = explode( ".", $ip );
	$ip = $r_ip[3] . "." . $r_ip[2] . "." . $r_ip[1] . "." . $r_ip[0];
	$dnsres = dns_get_record( $ip . ".bl.spamcop.net", DNS_A );
	if( $dnsres[0]['ip'] != "127.0.0.2" ) { 
		updateRes( $mysqli, "res_spamcop", 0 );
		return( FALSE ); 
	} else { 
		updateRes( $mysqli, "res_spamcop", 1 );
		return( TRUE ); 
	}
}

function checkTor( $ip ) {
	global $mysqli;
	$torapi = "https://onionoo.torproject.org/summary?search=$ip";
	$tor = json_decode( file_get_contents( $torapi ), TRUE );
	if( @$tor['relays'][0]['a'][0] == $ip ) {
		updateRes( $mysqli, "res_tor", 1 );
		return( TRUE );
	} else {
		updateRes( $mysqli, "res_tor", 0 );
		return( FALSE );
	}
}

function checkSorbs( $ip ) {
    //Check sorbs DNSBL, more information at http://www.sorbs.net/general/using.shtml
	global $mysqli;
    $dnsres = dns_get_record( $ip . ".dnsbl.sorbs.net", DNS_A );
    $sorbs_result = array();
	$value = 0;
    if( count( $dnsres ) == 0 ) { $sorbs_result = FALSE; } else {
        foreach( $dnsres as $dns ) {
            $results = array();
            array_push( $results, $dns['ip'] );
            switch( $dns['ip'] ) {
                case "127.0.0.2":
                    array_push( $results, "HTTP Proxy" );
					$value++;
                    break;
                case "127.0.0.3":
                    array_push( $results, "SOCKS Proxy" );
					$value++;
                    break;
                case "127.0.0.4":
                    array_push( $results, "MISC Proxy" );
					$value++;
                    break;
                case "127.0.0.5":
                    array_push( $results, "SMTP Server" );
					$value++;
                    break;
                case "127.0.0.6":
                    array_push( $results, "Possible Spam Source" );
					$value++;
                    break;
                case "127.0.0.7":
                    array_push( $results, "Vunerable Web server" );
					$value++;
                    break;
                case "127.0.0.8":
                    array_push( $results, "Asked not to be testeb by SORBS" );
					$value++;
                    break;
                case "127.0.0.9":
                    array_push( $results, "Zombie - Possibly Hijacked Netblock" );
					$value++;
                    break;
                case "127.0.0.10":
                    array_push( $results, "Dynamic IP" );
					$value--;
                    break;
                case "127.0.0.11":
                    array_push( $results, "Badconf - Invalid A or MX address" );
					$value++;
                    break;
                case "127.0.0.12":
                    array_push( $results, "ISP indicates no mail should originate here" );
					$value--;
                    break;
                case "127.0.0.14":
                    array_push( $results, "ISP indicates servers should not be present" );
					$value--;
                    break;
            }
            array_push( $sorbs_result, $results );
        }
    }
	updateRes( $mysqli, "res_sorbs", $value );
    return( $sorbs_result );
}

if( isset( $theip ) ) { $ip = $theip; } else { $ip = $_GET['ip']; }

$ip = ltrim( rtrim ( $ip ) );

if ( $ip == '' || inet_pton( $ip ) === FALSE ) {
    echo $twig->render( 'base.html.twig', [
		'username' => $username,
		'editcount' => $editcount,
		'registration' => $registration,
        'ip' => '',
		'apikey' => $apikey,
		'currentver' => $currentver,
        'portscan' => isset( $_GET['portscan'] ),
    ] );
    die();
}

$san_ip = mysqli_real_escape_string( $mysqli, $ip );
$res_id_query = "select res_id from results where res_ip = '$san_ip';";
$res_id_result = mysqli_query( $mysqli, $res_id_query );

if( mysqli_num_rows( $res_id_result ) < 1 ) {
	$res_id_update = "insert into results ( res_ip ) values( '$san_ip' );";
	$res_id_update_result = mysqli_query( $mysqli, $res_id_update );
	$res_id_query = "select res_id from results where res_ip = '$san_ip';";
	$res_id_result = mysqli_query( $mysqli, $res_id_query );
}

$res_id_array = mysqli_fetch_assoc( $res_id_result );
$res_id = $res_id_array['res_id'];

$refresh = FALSE;
$mtype = "";
if( isset( $_GET['refresh'] ) ) {
	$refresh = TRUE;
	$mtype = "refresh";
} elseif( file_exists( __DIR__ . "/../cache/$ip.json" ) ) {
	$out = json_decode( file_get_contents( __DIR__ . "/../cache/$ip.json" ), true );
	if( filemtime( __DIR__ . "/../cache/$ip.json" ) + 604800 < time() ) { 
		$refresh = TRUE; 
	} elseif ( @!isset( $out['portscan'] ) && @$_GET['portscan'] == 1 ) {
		$refresh = TRUE;
	}
} else { 
	$refresh = TRUE; 
}
if( $refresh === TRUE ) {
	$out = [
		'webhost' => [
			'title' => 'ASN Webhost Detection'
		],
		'proxycheck' => [
			'title' => 'proxycheck.io'
		],
		'getIPIntel' => [
			'title' => 'GetIPIntel'
		],
		'ipQualityScore' => [
			'title' => 'IPQualityScore'
		],
		'ipHub' => [
			'title' => 'IPHub'
		],
		'teohio' => [
			'title' => 'Teoh.io'
		],
		'ipHunter' => [
			'title' => 'IPHunter'
		],
		/*'noFraud' => [
			'title' => 'Nofraud'
		],*/
		'ipstack' => [
			'title' => 'ipstack.com'
		],
		'stopforumspam' => [
			'title' => 'StopForumSpam'
		],
		'hola' => [
			'title' => 'Hola'
		],
		'tor' => [
			'title' => 'TOR'
		],
		'computeHosts' => [
			'title' => 'Compute Hosts'
		],
		'sorbs' => [
			'title' => 'SORBS DNSBL'
		],
		'spamhaus' => [
			'title' => 'Spamhaus ZEN DNSBL'
		],
		'spamcop' => [
			'title' => 'Spamcop DNSBL'
		],
		'dshield' => [
			'title' => 'DShield'
		],
		'cache' => [
			'title' => 'Cache'
		]
	];
	//ComputeHost Detection
	$wh = checkWebhost( $ip );
	$out['webhost']['result']['webhost'] = $wh;

	// Proxycheck.io setup
	if( reportHit( "proxycheck-io" ) === TRUE ) { $out['proxycheck']['error'] = "API Queries exceeded. Try back later."; } else {
		$proxycheckio = json_decode( file_get_contents( "http://proxycheck.io/v2/$ip?key=$proxycheckkey&vpn=1&port=1&seen=1&risk=1" ), TRUE );
		if( isset( $proxycheckio['error'] ) ) {
			$out['proxycheck']['error'] = $proxycheckio['error'];
		} else {
			$out['proxycheck']['result']['proxy'] = $proxycheckio[$ip]['proxy'] === 'yes';
			if( $proxycheckio[$ip]['proxy'] === 'yes' ) {
				if( isset ( $proxycheckio[$ip]['last seen human'] ) ) { $out['proxycheck']['result']['seen'] = $proxycheckio[$ip]['last seen human']; }
				if( isset ( $proxycheckio[$ip]['port'] ) ) { $out['proxycheck']['result']['port'] = $proxycheckio[$ip]['port']; }
				if( isset ( $proxycheckio[$ip]['type'] ) ) { $out['proxycheck']['result']['pctype'] = $proxycheckio[$ip]['type']; }
				if( isset ( $proxycheckio[$ip]['risk'] ) ) { $out['proxycheck']['result']['riska'] = $proxycheckio[$ip]['risk']; }
					updateRes( $mysqli, "res_proxycheck", 1 );
			} else {
					updateRes( $mysqli, "res_proxycheck", 0 );
			}
		}
	}
	
	// GetIPIntel.net setup
	if( reportHit( "getipintel" ) === TRUE ) { $out['getipintel']['error'] = "API Queries exceeded. Try back later."; } else {
		$getipintel = json_decode( file_get_contents( "http://check.getipintel.net/check.php?ip=$ip&contact=$email&flags=f&format=json" ), TRUE );
		if( $getipintel['status'] === "error" ) {
			$out['getIPIntel']['error'] = $getipintel['message'];
		} else {
			$chance = round ( (int)$getipintel['result'] * 100, 3 );
			updateRes( $mysqli, "res_getipintel", $chance );
			if( $chance == 0 ) { $chance = number_format( $chance, 1 ); }
			$out['getIPIntel']['result'] = [
				'chance' => $chance,
			];
		}
	}

	// IPQualityScore setup
	if( reportHit( "ipqs" ) === TRUE ) { $out['ipqs']['error'] = "API Queries exceeded. Try back later."; } else {
		$ipqualityscore = json_decode( file_get_contents( "https://www.ipqualityscore.com/api/json/ip/$ipqualityscorekey/$ip" ), TRUE );
		if( $ipqualityscore['success'] === "false" ) {
			$out['ipQualityScore']['error'] = $ipqualityscore['message'];
		} else {
			$out['ipQualityScore']['result'] = [
				'proxy' => (bool)$ipqualityscore['proxy'],
				'isp' => $ipqualityscore['ISP'],
				'organization' => $ipqualityscore['organization'],
				'vpn' => (bool)$ipqualityscore['vpn'],
				'mobile' => (bool)$ipqualityscore['mobile'],
				'tor' => (bool)$ipqualityscore['tor'],
				'recent_abuse' => (bool)$ipqualityscore['recent_abuse'],
				'bot_status' => (bool)$ipqualityscore['bot_status'],
				'fraud_score' => $ipqualityscore['fraud_score']				
			];
			updateRes( $mysqli, "res_ipqs_isp", $ipqualityscore['ISP'] );
			updateRes( $mysqli, "res_ipqs_proxy", $ipqualityscore['proxy'] );
			updateRes( $mysqli, "res_ipqs_vpn", $ipqualityscore['vpn'] );
			updateRes( $mysqli, "res_ipqs_mobile", $ipqualityscore['mobile'] );
			updateRes( $mysqli, "res_ipqs_recent_abuse", $ipqualityscore['recent_abuse'] );
			updateRes( $mysqli, "res_ipqs_tor", $ipqualityscore['tor'] );
			updateRes( $mysqli, "res_ipqs_bot", $ipqualityscore['bot_status'] );
			updateRes( $mysqli, "res_ipqs_fraudscore", $ipqualityscore['fraud_score'] );
			updateRes( $mysqli, "res_ipqs_org", $ipqualityscore['organization'] );

		}
	}

	// IPHub.info setup
	if( reportHit( "iphub" ) === TRUE ) { $out['iphub']['error'] = "API Queries exceeded. Try back later."; } else {
		$opts = array( 'http'=> array( 'header'=>"X-Key: $iphubkey" ) );
		$context = stream_context_create( $opts );
		$iphub = json_decode( file_get_contents( "http://v2.api.iphub.info/ip/$ip", FALSE, $context ), TRUE );
		if( !is_array( $iphub ) ) {
			$out['ipHub']['error'] = true;
		} else {
			$out['ipHub']['result'] = [];

			if( isset( $iphub['isp'] ) ) {
				$out['ipHub']['result']['isp'] = $iphub['isp'];
			}
			updateRes( $mysqli, "res_iphub_res", $iphub['block'] );
			if ($iphub['block'] < 3) {
				$out['ipHub']['result']['block'] = $iphub['block'];
			} else {
				$out['ipHub']['error'] = true;
			}
		}
	}
	
	// stopforumspam setup
	if( reportHit( "stopforumspam" ) === TRUE ) { $out['stopforumspam']['error'] = "API Queries exceeded. Try back later."; } else {
		$sfsurl = "http://api.stopforumspam.org/api?ip=$ip&json";
		$sfs = json_decode( file_get_contents( $sfsurl ), true );
		if( $sfs['success'] !== 1 ) {
			$out['stopforumspam']['error'] = true;
		} else {
			$appears = $sfs['ip']['appears'];
			if( $appears == 1 ) {
				$frequency = $sfs['ip']['frequency'];
				$confidence = $sfs['ip']['confidence'];
				$lastseen = $sfs['ip']['lastseen'];
				$country = $sfs['ip']['country'];
				$delegated = $sfs['ip']['delegated'];
				updateRes( $mysqli, "res_stopforumspam_listed", $appears );
				updateRes( $mysqli, "res_stopforumspam_freq", $frequency );
				updateRes( $mysqli, "res_stopforumspam_lastseen", $lastseen );
				updateRes( $mysqli, "res_stopforumspam_confidence", $confidence );
				updateRes( $mysqli, "res_stopforumspam_country", $country );
				updateRes( $mysqli, "res_stopforumspam_delegated", $delegated );
				
				$out['stopforumspam']['result'] = [
					'appears' => $appears,
					'confidence' => $confidence,
					'frequency' => $frequency,
					'lastseen' => $lastseen,
					'sfscountry' => $country,
					'delegated' => $delegated
				];
			} else {
				$out['stopforumspam']['result'] = [
					'appears' => $appears
				];
			}
		}
	}
	
	// Teoh.io setup
	if( reportHit( "teoh" ) === TRUE ) { $out['teoh']['error'] = "API Queries exceeded. Try back later."; } else {
		$teohurl = "https://ip.teoh.io/api/vpn/$ip?key=$teohkey";
		$teohio = json_decode( file_get_contents( $teohurl ), true );
		if( @!isset( $teohio['ip'] ) ) {
			$out['teohio']['error'] = true;
		} else {
			$type = $teohio['type'];
			$risk = $teohio['risk'];
			if( $teohio['vpn_or_proxy'] == "yes" ) { $vpnorproxy = "1"; } else { $vpnorproxy = "0"; }
			switch( $risk ) {
				case "high":
					$numrisk = 3;
					break;
				case "medium":
					$numrisk = 2;
					break;
				case "low":
					$numrisk = 1;
					break;
			}
			updateRes( $mysqli, "res_teoh_hosting", $teohio['is_hosting'] );
			updateRes( $mysqli, "res_teoh_vpnproxy", $vpnorproxy );
			updateRes( $mysqli, "res_teoh_risk", $numrisk );
			updateRes( $mysqli, "res_teoh_type", $type );

			$out['teohio']['result'] = [
				'hosting' => true === $teohio['is_hosting'],
				'vpnOrProxy' => 'yes' === $teohio['vpn_or_proxy'],
				'type' => $teohio['type'],
				'risk' => $teohio['risk'],
			];
		}
	}

	// IPHunter.info setup
	if( reportHit( "iphunter" ) === TRUE ) { $out['iphunter']['error'] = "API Queries exceeded. Try back later."; } else {
		$opts = array( 'http'=> array( 'header'=>"X-Key: $iphunterkey" ) );
		$context = stream_context_create( $opts );
		$iphunter = json_decode( file_get_contents( "https://www.iphunter.info:8082/v1/ip/$ip", false, $context ), true );
		if( $iphunter['status'] === "error" ) {
			$out['ipHunter']['error'] = true;
		} else {
			$out['ipHunter']['result'] = [];

			if ( isset( $iphunter['data']['isp'] ) ) {
				$out['ipHunter']['result']['isp'] = $iphunter['data']['isp'];
			}
			updateRes( $mysqli, "res_iphunter", $iphunter['data']['block'] );

			if ( $iphunter['data']['block'] < 3 ) {
				$out['ipHunter']['result']['block'] = $iphunter['data']['block'];
			} else {
				$out['ipHunter']['error'] = true;
			}
		}
	}
	
	// Nofraud.co setup
	/* Nofraud is unfortunately down. Will uncomment if/when they return.
	if( reportHit( "nofraud" ) === TRUE ) { $out['nofraud']['error'] = "API Queries exceeded. Try back later."; } else {
		if( strpos( $ip, ":" ) === FALSE ) {
			$nofraud = file_get_contents( "http://api.nofraud.co/ip.php?ip=$ip" );
			$chance = round( $nofraud * 100, 3 );
			$out['noFraud']['result'] = [
				'chance' => $chance,
			];
		} else {
			$out['noFraud']['error'] = "Only IPv4 is supported";
		}
	}
	*/
	// ipstack.com setup
	if( reportHit( "ipstack" ) === TRUE ) { $out['ipstack']['error'] = "API Queries exceeded. Try back later."; } else {
		$ipstack = json_decode( file_get_contents( "http://api.ipstack.com/$ip?access_key=$ipstackkey" ), TRUE );
		if( @isset( $ipstack['city'] ) ) { 
			$out['ipstack']['result'] = [
				'city' => $ipstack['city'],
			];
		}
		if( @isset( $ipstack['region_name'] ) ) { 
			$out['ipstack']['result'] = [
				'state' => $ipstack['region_name'],
			];
		}
		if( @isset( $ipstack['zip'] ) ) { 
			$out['ipstack']['result'] = [
				'zip' => $ipstack['zip'],
			];
		}
		if( @isset( $ipstack['country_name'] ) ) { 
			$out['ipstack']['result'] = [
				'country' => $ipstack['country_name'],
			];
		}		
	}	
	//Check for google compute, amazon aws, and microsoft azure
	$check = checkCompute( $ip );
	$cRes = "";
	if( $check !== FALSE ) { 
		$chisp = $check['service'];
		$range = $check['range'];
		if( $chisp == "google" ) { $chisp = "Google Cloud"; }
		if( $chisp == "azure" ) { $chisp = "Microsoft Azure"; }
		if( $chisp == "amazon" ) { $chisp = "Amazon AWS"; }
	} else {
		$chisp = "This IP is not an AWS/Azure/GoogleCloud node.\n";
	}
	$out['computeHosts']['result'] = [
		'cloud' => $chisp,
	];

	//Check if this is a tor node via onionoo
	if( checkTor( $ip ) === TRUE ) {
		$out['tor']['result']['tornode'] = TRUE;
		updateRes( $mysqli, "res_tor", 1 );

	} else {
		$out['tor']['result']['tornode'] = FALSE;
		updateRes( $mysqli, "res_tor", 0 );
	}

	// Check Sorbs setup
	if( reportHit( "sorbs" ) === TRUE ) { $out['sorbs']['error'] = "API Queries exceeded. Try back later."; } else {
		$sorbsResult = checkSorbs( $ip );
		if( $sorbsResult !== false ) {
			$out['sorbs']['result']['entries'] = [];
			foreach( $sorbsResult as $sr ) {
				$out['sorbs']['result']['entries'][] = $sr[0] . " - " . $sr[1];
			}
		}
	}
	
	// Check Spamhaus setup
	if( reportHit( "spamhaus" ) === TRUE ) { $out['spamhaus']['error'] = "API Queries exceeded. Try back later."; } else {
		$spamhausResult = checkSpamhaus( $ip );
		if( $spamhausResult !== false ) {
			$out['spamhaus']['result']['entries'] = [];
			foreach( $spamhausResult as $sr ) {
				$out['spamhaus']['result']['entries'][] = $sr[0] . " - " . $sr[1];
			}
		}
	}

	// Check SpamCop setup
	$spamcopResult = checkSpamcop( $ip );
	if( $spamcopResult !== false ) {
		$out['spamcop']['result']['listed'] = TRUE;
	} else {
		$out['spamcop']['result']['listed'] = FALSE;
	}
	
	//DShield setup
	if( reportHit( "dshield" ) === TRUE ) { $out['dshield']['error'] = "API Queries exceeded. Try back later."; } else {
		$ds = file_get_contents( "https://www.dshield.org/api/ip/$ip?json" );
		$dshield = json_decode( $ds, TRUE );
		if( @count( $dshield['ip']['attacks'] ) > 0 ) { $out['dshield']['result']['attacks'] = $dshield['ip']['attacks']; }
		$feeds = array();
		if( @count( $dshield['ip']['threatfeeds'] ) > 0 ) {
			foreach( $dshield['ip']['threatfeeds'] as $feed=>$data ) {
					$ls = $data['lastseen'];
					$feed = $feed . " lastseen($ls)";
					array_push( $feeds, $feed );
			}
			$tfeeds = implode( ", ", $feeds );
			$out['dshield']['result']['tfeeds'] = $tfeeds;
		}
	}

	// Portscan setup
	if( isset( $_GET['portscan'] ) ) {
		if( reportHit( "portscan" ) === TRUE ) { $out['portscan']['error'] = "API Queries exceeded. Try back later."; } else {
			$out['portscan'] = [
				'title' => 'Open ports'
			];
			$porturl = $purl . "$ip&auth=$auth";
			$ch = curl_init( $porturl );
			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
			$scanres = json_decode( curl_exec( $ch ), true );
			$scandate = $scanres['date'];
			unset( $scanres['date'] );
			$out['portscan']['result']['entries'] = $scanres;
		}
	}
	
	$m1_hola = json_decode( file_get_contents( __DIR__ . "/../sources/proxies.json" ), true );
	$m2_hola = json_decode( file_get_contents( __DIR__ . "/../sources/hola_dns.json" ), true );

	/* Hola - Method 1 */
	foreach( $m1_hola as $h ) {
		if( $ip == $h['ip'] ) {
			$out['hola']['result']['holas'][] = [
				'port' => $h['info']['port'],
				'country' => $h['country'],
			];
		}
	}

	/* Hola - Method 2 */
	foreach( $m2_hola as $h ) {
		if( $ip == $h['ip'] ) {
			$out['hola']['result']['holas'][] = [
				'seen' => date( "F d, Y", $h['seen'] ),
			];
		}
	}
	$ipbase = "";
	if( strpos( $ip, ":" ) === FALSE ) {
		$ipbase_e = explode( ".", $ip );
		$ipbase = $ipbase_e[0] . "." . $ipbase_e[1] . "." . $ipbase_e[2];
		if( substr( $ipbase, -1 ) == "." ) {
			$ipbase = substr( $ipbase, 0, -1 );
		}
	}
	$out['cache']['result']['cached'] = 'no';
	file_put_contents( __DIR__ . "/../cache/$ip.json", json_encode( $out ) );
	if( isset( $_GET['api'] ) ) {
		logit( $username, $ip, "api" . $mtype, 1, $mysqli );
	} else {
		logit( $username, $ip, "manual" . $mtype, 1, $mysqli );
	}
} else {
	$ipbase = "";
	if( strpos( $ip, ":" ) === FALSE ) {
		$ipbase_e = explode( ".", $ip );
		$ipbase = $ipbase_e[0] . "." . $ipbase_e[1] . "." . $ipbase_e[2] . ".";
		if( substr( $ipbase, -1 ) == "." ) {
			$ipbase = substr( $ipbase, 0, -1 );
		}
	}
	$out['cache']['result']['cached'] = 'yes';
	$out['cache']['result']['cachedate'] = date( "M j G:i:s T Y", filemtime( __DIR__ . "/../cache/$ip.json" ) );
	$out['cache']['result']['cacheuntil'] = date( "M j G:i:s T Y", filemtime( __DIR__ . "/../cache/$ip.json" ) + 604800 );
	if( isset( $_GET['api'] ) ) {
		logit( $username, $ip, "api" . $mtype, 0, $mysqli );
	} else {
		logit( $username, $ip, "manual" . $mtype, 0, $mysqli );
	}
}

$host = gethostbyaddr( $ip );
if( $host == $ip ) { $hostname = $ip; } else { $hostname = "$ip - $host"; }

if( isset( $_GET['api'] ) ) {
    echo json_encode( $out );
} else {
    echo $twig->render( 'results.html.twig', [
		'username' => $username,
        'hostname' => $hostname,
		'currentver' => $currentver,
		'ip' => $ip,
        'out' => $out,
		'wikiurl' => $wikiurl,
		'ipbase' => $ipbase,
		'apikey' => $apikey,
        'portscan' => isset( $_GET['portscan'] ),
    ] );
}
?>
