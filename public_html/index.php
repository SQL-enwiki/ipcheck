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

require '../vendor/autoload.php';

include("../credentials.php");

$loader = new Twig_Loader_Filesystem( __DIR__ . '/../views' );
$twig = new Twig_Environment( $loader, [ 'debug' => true ] );
$twig->addExtension(new Twig_Extension_Debug());

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

$ip = $_GET['ip'];

if ( $ip == '' ) {
    echo $twig->render( 'base.html.twig', [
        'ip' => '',
        'portscan' => isset( $_GET['portscan'] ),
    ] );
    die();
}

$out = [
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
    'techio' => [
        'title' => 'Tech.io'
    ],
    'ipHunter' => [
        'title' => 'IPHunter'
    ],
    'noFraud' => [
        'title' => 'Nofraud'
    ],
    'sorbs' => [
        'title' => 'SORBS DNSBL'
    ],
    'spamhaus' => [
        'title' => 'Spamhaus ZEN DNSBL'
    ],
    'hola' => [
        'title' => 'Hola'
    ],
];

// Proxycheck.io setup
$proxycheckio = json_decode( file_get_contents( "http://proxycheck.io/v2/$ip?key=$proxycheckkey&vpn=1" ), TRUE );
if( isset( $proxycheckio['error'] ) ) {
    $out['proxycheck']['error'] = $proxycheckio['error'];
} else {
    $out['proxycheck']['result'] = $proxycheckio[$ip]['proxy'] === 'yes';
}

// GetIPIntel.net setup
$getipintel = json_decode( file_get_contents( "http://check.getipintel.net/check.php?ip=$ip&contact=$email&flags=f&format=json" ), TRUE );
if( $getipintel['status'] === "error" ) {
    $out['getIPIntel']['error'] = $getipintel['message'];
} else {
    $chance = round ( (int)$getipintel['result'] * 100, 3 );
    $out['getIPIntel']['result'] = [
        'chance' => $chance,
    ];
}

// IPQualityScore setup
$ipqualityscore = json_decode( file_get_contents( "https://www.ipqualityscore.com/api/json/ip/$ipqualityscorekey/$ip" ), TRUE );
if( $ipqualityscore['success'] === "false" ) {
    $out['ipQualityScore']['error'] = $ipqualityscore['message'];
} else {
    $out['ipQualityScore']['result'] = [
        'proxy' => (bool)$ipqualityscore['proxy'],
        'isp' => $ipqualityscore['ISP'],
        'vpn' => (bool)$ipqualityscore['vpn'],
        'mobile' => (bool)$ipqualityscore['mobile'],
    ];
}

// IPHub.info setup
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

    if ($iphub['block'] < 3) {
        $out['ipHub']['result']['block'] = $iphub['block'];
    } else {
        $out['ipHub']['error'] = true;
    }
}

// Teoh.io setup
$techurl = "https://ip.teoh.io/api/vpn/$ip?key=$teohkey";
$techio = json_decode( file_get_contents( $techurl ), true );
$type = $techio['type'];
$risk = $techio['risk'];
$out['techio']['result'] = [
    'hosting' => true === $techio['is_hosting'],
    'vpnOrProxy' => 'yes' === $techio['vpn_or_proxy'],
    'type' => $techio['type'],
    'risk' => $techio['risk'],
];

// IPHunter.info setup
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

    if ($iphunter['data']['block'] < 3) {
        $out['ipHunter']['result']['block'] = $iphunter['data']['block'];
    } else {
        $out['ipHunter']['error'] = true;
    }
}

// Nofraud.co setup
$nofraud = file_get_contents( "http://api.nofraud.co/ip.php?ip=$ip" );
$chance = round( $nofraud * 100, 3 );
$out['noFraud']['result'] = [
    'chance' => $chance,
];

// Check Sorbs setup
$sorbsResult = checkSorbs( $ip );
if( $sorbsResult !== false ) {
    $out['sorbs']['result']['entries'] = [];
    foreach( $sorbsResult as $sr ) {
        $out['sorbs']['result']['entries'][] = $sr[0] . " - " . $sr[1];
    }
}

// Check Spamhaus setup
$spamhausResult = checkSpamhaus( $ip );
if( $spamhausResult !== false ) {
    $out['spamhaus']['result']['entries'] = [];
    foreach( $spamhausResult as $sr ) {
        $out['spamhaus']['result']['entries'][] = $sr[0] . " - " . $sr[1];
    }
}

// Portscan setup
if( isset( $_GET['portscan'] ) ) {
    $out['portscan'] = [
        'title' => 'Open ports'
    ];
    $porturl = $purl . "$ip&auth=$auth";
    // $scanres = json_decode( file_get_contents( $porturl ), true ); // cURL is better. Weird errors with file_get_contents.
    $ch = curl_init( $porturl );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    $scanres = json_decode( curl_exec( $ch ), true );
    $scandate = $scanres['date'];
    unset( $scanres['date'] );
    $out['portscan']['result']['entries'] = $scanres;
}

$m1_hola = json_decode( file_get_contents( __DIR__ . "/../proxies.json" ), true );
$m2_hola = json_decode( file_get_contents( __DIR__ . "/../hola_dns.json" ), true );

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

if( isset( $_GET['api'] ) ) {
    echo json_encode( $out );
} else {
    echo $twig->render( 'results.html.twig', [
        'ip' => $ip,
        'out' => $out,
        'portscan' => isset( $_GET['portscan'] ),
    ] );
}
