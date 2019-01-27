<?php
include( __DIR__ . "/../checkhost/checkhost.php" );

//Amazon AWS
$amazonraw = json_decode( file_get_contents( 'https://ip-ranges.amazonaws.com/ip-ranges.json' ), TRUE );
$computeranges = array();
foreach( $amazonraw['prefixes'] as $prefix ) {
	$range = $prefix['ip_prefix'];
	$split = splitrange( $range );
	foreach( $split as $sr ) {
		$arange = array();
		$arange['service'] = "amazon";
		$arange['range'] = $sr;
		array_push( $computeranges, $arange );
	}
}
foreach( $amazonraw['ipv6_prefixes'] as $prefix ) {
	$range = $prefix['ipv6_prefix'];
	$arange = array();
	$arange['service'] = "amazon";
	$arange['range'] = $range;
	array_push( $computeranges, $arange );
}

//Microsoft Azure
$first = file_get_contents( "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653" );
$first = explode( "\n", $first );
foreach( $first as $f ) {
	if( strpos( $f, "download manually" ) !== FALSE ) {
		preg_match( '/href="(.*?)"/i', $f, $matches );
		$url = $matches[1];
		break;
	}
}
$second = file_get_contents( $url );
$second = explode( "\n", $second );
foreach( $second as $s ) {
	$test = preg_match( '/IpRange Subnet="(.*?)" \//', $s, $m );
	if( $test == 1 ) {
		$range = $m[1];
		$split = splitrange( $range );
		foreach( $split as $sr ) {
			$arange = array();
			$arange['service'] = "azure";
			$arange['range'] = $sr;
			array_push( $computeranges, $arange );
		}
	}
}

//Google Compute Engine
$dns = dns_get_record( "_cloud-netblocks.googleusercontent.com", DNS_TXT );
$exp = explode( " ", $dns[0]['txt'] );
foreach( $exp as $e ) {
	if( strpos( $e, "include:" ) !== FALSE ) {
		$e = substr( $e, 8 );
		$subdns = dns_get_record( $e, DNS_TXT );
		$sd = explode( " ", $subdns[0]['txt'] );
		//There are some google cloud domains that aren't listed 35.240.0.0/13, 35.224.0.0/12, 35.208.0.0/12, 35.192.0.0/12
		array_push( $sd, "ip4:35.240.0.0/13" );
		array_push( $sd, "ip4:35.224.0.0/12" );
		array_push( $sd, "ip4:35.208.0.0/12" );
		array_push( $sd, "ip4:35.192.0.0/12" );
		//And, IPv6: 
		array_push( $sd, "ip6:2600:1900::/32" );
		array_push( $sd, "ip6:2600:1901::/32" );
		array_push( $sd, "ip6:2600:1902::/32" );
		array_push( $sd, "ip6:2600:1903::/32" );
		array_push( $sd, "ip6:2600:1904::/32" );
		array_push( $sd, "ip6:2600:1905::/32" );
		array_push( $sd, "ip6:2600:1906::/32" );
		array_push( $sd, "ip6:2600:1907::/32" );
		array_push( $sd, "ip6:2600:1908::/32" );
		array_push( $sd, "ip6:2600:1909::/32" );
		array_push( $sd, "ip6:2600:190a::/32" );
		array_push( $sd, "ip6:2600:190b::/32" );
		array_push( $sd, "ip6:2600:190c::/32" );
		array_push( $sd, "ip6:2600:190d::/32" );
		array_push( $sd, "ip6:2600:190e::/32" );
		array_push( $sd, "ip6:2600:190f::/32" );
		foreach( $sd as $s ) {
			$firsttwo = substr( $s, 0, 2 );
			if( $firsttwo == "ip" ) {
				$range = substr( $s, 4 );
				$srange = splitrange( $range );
				foreach( $srange as $sr ) {
					$grange = array();
					$grange['service'] = "google";
					$grange['range'] = $sr;
					array_push( $computeranges, $grange );
				}
			}
		}
	}
}
$computeranges = array_map("unserialize", array_unique(array_map("serialize", $computeranges)));
file_put_contents( __DIR__ . "/../sources/computehosts.json", json_encode( $computeranges ) );
?>
