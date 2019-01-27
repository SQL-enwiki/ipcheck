<?php

//Match an IPv4 IP to a CIDR
function cidr_match( $ip, $cidr ) {
    list( $subnet, $mask ) = explode( '/', $cidr );
    if ( ( ip2long( $ip ) & ~( ( 1 << ( 32 - $mask ) ) - 1 ) ) == ip2long( $subnet ) ) { 
        return 1;
    }
    return 0;
}

function inet_to_bits( $inet ) {
   @$unpacked = unpack( 'A16', $inet );
   $unpacked = str_split( $unpacked[1] );
   $binaryip = '';
   foreach ( $unpacked as $char ) {
             $binaryip .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
   }
   return $binaryip;
}    

//Match an IPv4 IP to a CIDR
function cidr_match6( $ip, $cidr ) {
	$ip = inet_pton( $ip );
	$binaryip = inet_to_bits( $ip );
	list( $net, $maskbits )=explode( '/',$cidr );
	$net = inet_pton( $net );
	$binarynet = inet_to_bits( $net );
	$ip_net_bits = substr( $binaryip, 0, $maskbits );
	$net_bits = substr( $binarynet, 0, $maskbits );
	if( $ip_net_bits !== $net_bits ) { 
		return( FALSE );
	} else {
		return( TRUE );
	}
}

//Check to see if the host is in the compute JSON list
function checkCompute( $ip ) {
	$ranges = json_decode( file_get_contents( "../checkhost/computehosts.json" ), TRUE );
	$match = FALSE;
	foreach( $ranges as $range ) {
		$r = $range['range'];
		if( strpos( $r, ":" ) === FALSE ) {
			//ipv4
			if( cidr_match( $ip, $r ) ) { $match = TRUE; return( $range ); }
		} else {
			//ipv6
			if( cidr_match6( $ip, $r ) ) { $match = TRUE; return( $range ); }
			
		}
	}
	if( $match === FALSE ) { return( FALSE ); }
}

//Split IPv4 ranges larger than /16's into /16's
function splitrange( $range ) {
	if( strpos( $range, ":" ) !== FALSE ) { return array( $range ); }
    $range = explode( "/", $range );
	if( $range[1] < 16 ) {
		$rangeoct = "/" . 16;
	} else {
		$rangeoct = "/" . $range[1];
	}
    $octet = ip2long( $range[0] ); 
    $sixteens = pow( 2, (16 - $range[1] ) ) - 1;
    $out = array();
    for ( $i = -65536; $i < 65536 * $sixteens; $out[] = ( long2ip( $octet + ( $i += 65536 ) ) ) . $rangeoct );
    return $out;
}

?>