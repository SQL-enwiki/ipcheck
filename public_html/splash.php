<?php
session_name( 'IPCheck' );
$params = session_get_cookie_params();
session_set_cookie_params(
	$params['lifetime'],
	dirname( $_SERVER['SCRIPT_NAME'] )
);
require '../vendor/autoload.php';
$loader = new Twig_Loader_Filesystem( __DIR__ . '/../views' );
$twig = new Twig_Environment( $loader, [ 'debug' => true ] );
$twig->addExtension(new Twig_Extension_Debug());

$currentver = substr( file_get_contents( __DIR__. '/../.git/refs/heads/master' ), 0, 7 );

$ts_pw = posix_getpwuid(posix_getuid());
$ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");

$mysqli = new mysqli('meta.web.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'], 'meta_p');

$query = 'select url, lang, family, dbname from wiki where is_closed = 0 order by dbname asc;';
session_start();
if( isset( $_GET['ip'] ) ) { $_SESSION['ip'] = $_GET['ip']; }
session_write_close();
$res = mysqli_query( $mysqli, $query );
$opt = array();
$enwikiIndex = 0;
$commonswikiIndex = 0;
$metawikiIndex = 0;
$baseindex = 0;
while( $row = mysqli_fetch_assoc( $res ) ) {
	$murl = parse_url( $row['url'],  PHP_URL_HOST );
	$murl = substr( $murl, 0, -4 );
	$row['url'] = $murl;
	if( $row['dbname'] == "enwiki" ) { $enwikiIndex = $baseindex; }
	if( $row['dbname'] == "commonswiki" ) { $commonswikiIndex = $baseindex; }
	if( $row['dbname'] == "metawiki" ) { $metawikiIndex = $baseindex; }
	array_push( $opt, $row );
	$baseindex++;
}
echo $twig->render( 'base.html.twig', [
	'splash' => '1',
	'currentver' => $currentver,
	'options' => $opt,
	'commonswiki' = $commonswikiIndex,
	'enwiki' = $enwikiIndex,
	'metawiki' = $metawikiIndex;
] );
?>