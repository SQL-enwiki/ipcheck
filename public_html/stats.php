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

$ts_pw = posix_getpwuid(posix_getuid());
$ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");
$dbname = $ts_mycnf['user'] . '__ipcheck';
$mysqli = new mysqli('tools.db.svc.eqiad.wmflabs', $ts_mycnf['user'], $ts_mycnf['password'] );
mysqli_select_db( $mysqli, $dbname );

require '../vendor/autoload.php';
$loader = new Twig_Loader_Filesystem( __DIR__ . '/../views' );
$twig = new Twig_Environment( $loader, [ 'debug' => true ] );
$twig->addExtension(new Twig_Extension_Debug());

$currentver = substr( file_get_contents( __DIR__. '/../.git/refs/heads/master' ), 0, 7 );


$month = date( "n" );
$year = date( "Y" );
$lastmonth = strtotime( "$month/1/$year" );

$query = "select log_user, count(*) from logging where log_timestamp > $lastmonth and log_cached = 0 group by log_user order by count(*) desc limit 25;";
$res = mysqli_query( $mysqli, $query );

$thismonth = array();
while( $row = mysqli_fetch_assoc( $res ) ) {
	$user = $row['log_user'];
	$count = $row['count(*)'];
	$now = array();
	$now['user'] = $user;
	$now['count'] = $count;
	array_push( $thismonth, $now );
}


$query = "select log_user, count(*) from logging where log_cached = 0 group by log_user order by count(*) desc limit 25;";
$res = mysqli_query( $mysqli, $query );
$alltime = array();
while( $row = mysqli_fetch_assoc( $res ) ) {
	$user = $row['log_user'];
	$count = $row['count(*)'];
	$now = array();
	$now['user'] = $user;
	$now['count'] = $count;
	array_push( $alltime, $now );
}

echo $twig->render( 'base.html.twig', [
	'stats' => '1',
	'thismonth' => $thismonth,
	'currentver' => $currentver,
	'alltime' => $alltime
] );

?>
