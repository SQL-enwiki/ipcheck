<?php
/**
 * Written in 2013 by Brad Jorsch
 *
 * To the extent possible under law, the author(s) have dedicated all copyright 
 * and related and neighboring rights to this software to the public domain 
 * worldwide. This software is distributed without any warranty. 
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/> for a copy of the 
 * CC0 Public Domain Dedication.
 */

// ******************** CONFIGURATION ********************

/**
 * Set this to point to a file (outside the webserver root!) containing the 
 * following keys:
 * - agent: The HTTP User-Agent to use
 * - consumerKey: The "consumer token" given to you when registering your app
 * - consumerSecret: The "secret token" given to you when registering your app
 */
$inifile = __DIR__ . '/../oauth.ini';

/**
 * Set this to the Special:OAuth/authorize URL. 
 * To work around MobileFrontend redirection, use /wiki/ rather than /w/index.php.
 */
$mwOAuthAuthorizeUrl = 'https://meta.wikimedia.org/wiki/Special:OAuth/authorize';
//
/**
 * Set this to the Special:OAuth URL. 
 * Note that /wiki/Special:OAuth fails when checking the signature, while
 * index.php?title=Special:OAuth works fine.
 */
 //Set this to the wiki you are checking
 // Disable for production
//$mwOAuthUrl = 'https://en.wikipedia.beta.wmflabs.org/w/index.php?title=Special:OAuth';

/**
 * Set this to the interwiki prefix for the OAuth central wiki.
 */
$mwOAuthIW = 'meta';


/**
 * This should normally be "500". But Tool Labs insists on overriding valid 500
 * responses with a useless error page.
 */
$errorCode = 200;

// ****************** END CONFIGURATION ******************

// Setup the session cookie
session_name( 'IPCheck' );
$params = session_get_cookie_params();
session_set_cookie_params(
	$params['lifetime'],
	dirname( $_SERVER['SCRIPT_NAME'] )
);


// Read the ini file
$ini = parse_ini_file( $inifile );
if ( $ini === false ) {
	header( "HTTP/1.1 $errorCode Internal Server Error" );
	echo 'The ini file could not be read';
	exit(0);
}
if ( !isset( $ini['agent'] ) ||
	!isset( $ini['consumerKey'] ) ||
	!isset( $ini['consumerSecret'] )
) {
	header( "HTTP/1.1 $errorCode Internal Server Error" );
	echo 'Required configuration directives not found in ini file';
	exit(0);
}
$gUserAgent = $ini['agent'];
$gConsumerKey = $ini['consumerKey'];
$gConsumerSecret = $ini['consumerSecret'];

// Load the user token (request or access) from the session
$gTokenKey = '';
$gTokenSecret = '';
session_start();

if( isset( $_SESSION['mwOAuthUrl'] ) ) {
	$mwOAuthUrl = $_SESSION['mwOAuthUrl'];
}

$_SESSION['wiki'] = 'enwiki';
$wiki = 'enwiki';
$ts_pw = posix_getpwuid(posix_getuid());
$ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");

$my_oa = new mysqli('meta.web.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'], 'meta_p');
$query = "SELECT url FROM wiki WHERE dbname = '$wiki';";
$site = mysqli_fetch_assoc( mysqli_query( $my_oa, $query ) );
mysqli_close( $my_oa );
//enable for production
$mwOAuthUrl = $site['url'] . '/w/index.php?title=Special:OAuth';
$_SESSION['mwOAuthUrl'] = $mwOAuthUrl;

$wiki = $_SESSION['wiki'];
if ( isset( $_SESSION['tokenKey'] ) ) {
	$gTokenKey = $_SESSION['tokenKey'];
	$gTokenSecret = $_SESSION['tokenSecret'];
}



// Fetch the access token if this is the callback from requesting authorization
if ( isset( $_GET['oauth_verifier'] ) && $_GET['oauth_verifier'] ) {
	$ts_pw = posix_getpwuid(posix_getuid());
	$ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");
	
	$my_oa = new mysqli('meta.web.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'], 'meta_p');
	$query = "SELECT url FROM wiki WHERE dbname = '$wiki';";
	$site = mysqli_fetch_assoc( mysqli_query( $my_oa, $query ) );
	mysqli_close( $my_oa );
	//enable for production
	$mwOAuthUrl = $site['url'] . '/w/index.php?title=Special:OAuth';
	fetchAccessToken();
	session_write_close();
	header('Location: index.php');
}

// Take any requested action
switch ( isset( $_GET['action'] ) ? $_GET['action'] : '' ) {

	case 'authorize':
		doAuthorizationRedirect();
		return;

	case 'identify':
		doIdentify();
		break;

}
$identity = doIdentify( );
if( $identity !== FALSE ) {
	$username = $identity->username;
	$editcount = $identity->editcount;
	$registration = $identity->registered;
	$blocked = $identity->blocked;
	if( isset( $_SESSION['ip'] ) ) { $theip = $_SESSION['ip']; unset( $_SESSION['ip'] ); }
	session_write_close();
} else { session_write_close(); die(); }

// ******************** CODE ********************


/**
 * Utility function to sign a request
 *
 * Note this doesn't properly handle the case where a parameter is set both in 
 * the query string in $url and in $params, or non-scalar values in $params.
 *
 * @param string $method Generally "GET" or "POST"
 * @param string $url URL string
 * @param array $params Extra parameters for the Authorization header or post 
 * 	data (if application/x-www-form-urlencoded).
 * @return string Signature
 */
function sign_request( $method, $url, $params = array() ) {
	global $gConsumerSecret, $gTokenSecret;

	$parts = parse_url( $url );

	// We need to normalize the endpoint URL
	$scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
	$host = isset( $parts['host'] ) ? $parts['host'] : '';
	$port = isset( $parts['port'] ) ? $parts['port'] : ( $scheme == 'https' ? '443' : '80' );
	$path = isset( $parts['path'] ) ? $parts['path'] : '';
	if ( ( $scheme == 'https' && $port != '443' ) ||
		( $scheme == 'http' && $port != '80' ) 
	) {
		// Only include the port if it's not the default
		$host = "$host:$port";
	}

	// Also the parameters
	$pairs = array();
	parse_str( isset( $parts['query'] ) ? $parts['query'] : '', $query );
	$query += $params;
	unset( $query['oauth_signature'] );
	if ( $query ) {
		$query = array_combine(
			// rawurlencode follows RFC 3986 since PHP 5.3
			array_map( 'rawurlencode', array_keys( $query ) ),
			array_map( 'rawurlencode', array_values( $query ) )
		);
		ksort( $query, SORT_STRING );
		foreach ( $query as $k => $v ) {
			$pairs[] = "$k=$v";
		}
	}

	$toSign = rawurlencode( strtoupper( $method ) ) . '&' .
		rawurlencode( "$scheme://$host$path" ) . '&' .
		rawurlencode( join( '&', $pairs ) );
	$key = rawurlencode( $gConsumerSecret ) . '&' . rawurlencode( $gTokenSecret );
	return base64_encode( hash_hmac( 'sha1', $toSign, $key, true ) );
}

/**
 * Request authorization
 * @return void
 */
function doAuthorizationRedirect() {
	global $mwOAuthUrl, $mwOAuthAuthorizeUrl, $gUserAgent, $gConsumerKey, $gTokenSecret, $errorCode;

	// First, we need to fetch a request token.
	// The request is signed with an empty token secret and no token key.
	$gTokenSecret = '';
	$url = $mwOAuthUrl . '/initiate';
	$url .= strpos( $url, '?' ) ? '&' : '?';
	$url .= http_build_query( array(
		'format' => 'json',
		
		// OAuth information
		'oauth_callback' => 'oob', // Must be "oob" or something prefixed by the configured callback URL
		'oauth_consumer_key' => $gConsumerKey,
		'oauth_version' => '1.0',
		'oauth_nonce' => md5( microtime() . mt_rand() ),
		'oauth_timestamp' => time(),

		// We're using secret key signatures here.
		'oauth_signature_method' => 'HMAC-SHA1',
	) );
	$signature = sign_request( 'GET', $url );
	$url .= "&oauth_signature=" . urlencode( $signature );
	$ch = curl_init();
		//TEST111 echo "$url\n";
	curl_setopt( $ch, CURLOPT_URL, $url );
	//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
	curl_setopt( $ch, CURLOPT_HEADER, 0 );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
	$data = curl_exec( $ch );
	if ( !$data ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Curl error: ' . htmlspecialchars( curl_error( $ch ) );
		exit(0);
	}
	curl_close( $ch );
	$token = json_decode( $data );
	if ( is_object( $token ) && isset( $token->error ) ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Error retrieving token: ' . htmlspecialchars( $token->error ) . '<br>' . htmlspecialchars( $token->message );
		exit(0);
	}
	if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Invalid response from token request';
		exit(0);
	}

	// Now we have the request token, we need to save it for later.
	session_start();
	$_SESSION['tokenKey'] = $token->key;
	$_SESSION['tokenSecret'] = $token->secret;
	session_write_close();

	// Then we send the user off to authorize
	$url = $mwOAuthAuthorizeUrl;
	$url .= strpos( $url, '?' ) ? '&' : '?';
	$url .= http_build_query( array(
		'oauth_token' => $token->key,
		'oauth_consumer_key' => $gConsumerKey,
	) );
	header( "Location: $url" );
	echo 'Please see <a href="' . htmlspecialchars( $url ) . '">' . htmlspecialchars( $url ) . '</a>';
}

/**
 * Handle a callback to fetch the access token
 * @return void
 */
function fetchAccessToken() {
	global $mwOAuthUrl, $gUserAgent, $gConsumerKey, $gTokenKey, $gTokenSecret, $errorCode;

	$url = $mwOAuthUrl . '/token';
	$url .= strpos( $url, '?' ) ? '&' : '?';
	$url .= http_build_query( array(
		'format' => 'json',
		'oauth_verifier' => $_GET['oauth_verifier'],

		// OAuth information
		'oauth_consumer_key' => $gConsumerKey,
		'oauth_token' => $gTokenKey,
		'oauth_version' => '1.0',
		'oauth_nonce' => md5( microtime() . mt_rand() ),
		'oauth_timestamp' => time(),

		// We're using secret key signatures here.
		'oauth_signature_method' => 'HMAC-SHA1',
	) );
	$signature = sign_request( 'GET', $url );
	$url .= "&oauth_signature=" . urlencode( $signature );
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $url );
	//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
	curl_setopt( $ch, CURLOPT_HEADER, 0 );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
	$data = curl_exec( $ch );
	if ( !$data ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Curl error: ' . htmlspecialchars( curl_error( $ch ) );
		exit(0);
	}
	curl_close( $ch );
	$token = json_decode( $data );
	if ( is_object( $token ) && isset( $token->error ) ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Error retrieving token: ' . htmlspecialchars( $token->error ) . '<br>' . htmlspecialchars( $token->message );
		exit(0);
	}
	if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Invalid response from token request';
		exit(0);
	}

	// Save the access token
	session_start();
	$_SESSION['tokenKey'] = $gTokenKey = $token->key;
	$_SESSION['tokenSecret'] = $gTokenSecret = $token->secret;
	session_write_close();
}

/**
 * Request a JWT and verify it
 * @return void
 */
function doIdentify() {
	global $mwOAuthUrl, $gUserAgent, $gConsumerKey, $gTokenKey, $gConsumerSecret, $errorCode;

	$url = $mwOAuthUrl . '/identify';
	$headerArr = array(
		// OAuth information
		'oauth_consumer_key' => $gConsumerKey,
		'oauth_token' => $gTokenKey,
		'oauth_version' => '1.0',
		'oauth_nonce' => md5( microtime() . mt_rand() ),
		'oauth_timestamp' => time(),

		// We're using secret key signatures here.
		'oauth_signature_method' => 'HMAC-SHA1',
	);
	$signature = sign_request( 'GET', $url, $headerArr );
	$headerArr['oauth_signature'] = $signature;

	$header = array();
	foreach ( $headerArr as $k => $v ) {
		$header[] = rawurlencode( $k ) . '="' . rawurlencode( $v ) . '"';
	}
	$header = 'Authorization: OAuth ' . join( ', ', $header );

	$ch = curl_init();
	
	curl_setopt( $ch, CURLOPT_URL, $url );
	curl_setopt( $ch, CURLOPT_HTTPHEADER, array( $header ) );
	//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
	curl_setopt( $ch, CURLOPT_HEADER, 0 );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
	$data = curl_exec( $ch );
	if ( !$data ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Curl error: ' . htmlspecialchars( curl_error( $ch ) );
		exit(0);
	}
	$err = json_decode( $data );
	if ( is_object( $err ) && isset( $err->error ) && $err->error === 'mwoauthdatastore-access-token-not-found' ) {
		// We're not authorized!
		//echo 'You haven\'t authorized this application yet! Go <a href="' . htmlspecialchars( $_SERVER['SCRIPT_NAME'] ) . '?action=authorize">here</a> to do that.';
		header('Location: ' . htmlspecialchars( $_SERVER['SCRIPT_NAME'] ) . '?action=authorize');
		return false;
	}

	// There are three fields in the response
	$fields = explode( '.', $data );
	if ( count( $fields ) !== 3 ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Invalid identify response: ' . htmlspecialchars( $data );
		exit(0);
	}

	// Validate the header. MWOAuth always returns alg "HS256".
	$header = base64_decode( strtr( $fields[0], '-_', '+/' ), true );
	if ( $header !== false ) {
		$header = json_decode( $header );
	}
	if ( !is_object( $header ) || $header->typ !== 'JWT' || $header->alg !== 'HS256' ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Invalid header in identify response: ' . htmlspecialchars( $data );
		exit(0);
	}

	// Verify the signature
	$sig = base64_decode( strtr( $fields[2], '-_', '+/' ), true );
	$check = hash_hmac( 'sha256', $fields[0] . '.' . $fields[1], $gConsumerSecret, true );
	if ( $sig !== $check ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'JWT signature validation failed: ' . htmlspecialchars( $data );
		echo '<pre>'; var_dump( base64_encode($sig), base64_encode($check) ); echo '</pre>';
		exit(0);
	}

	// Decode the payload
	$payload = base64_decode( strtr( $fields[1], '-_', '+/' ), true );
	if ( $payload !== false ) {
		$payload = json_decode( $payload );
	}
	if ( !is_object( $payload ) ) {
		header( "HTTP/1.1 $errorCode Internal Server Error" );
		echo 'Invalid payload in identify response: ' . htmlspecialchars( $data );
		exit(0);
	}

	//echo 'JWT payload: <pre>' . htmlspecialchars( var_export( $payload, 1 ) ) . '</pre>';
	//echo '<hr>';
	return( $payload );
}


