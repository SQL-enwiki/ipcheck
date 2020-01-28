<?php

$intdbname = "__ipcheck";

function getLimits() {
	$lservice = array();
	//Set up limits
	$lservice['getipintel'] = array( 'type' => 'min', 'limit' => 15, 'type2' => 'day', 'limit2' => 5000 );
	$lservice['iphub'] = array( 'type' => 'day', 'limit' => 1000, 'type2' => 'day', 'limit2' => 1000 );
	$lservice['iphunter'] = array( 'type' => 'day', 'limit' => 1000, 'type2' => 'day', 'limit2' => 1000 );
	$lservice['ipqs'] = array( 'type' => 'month', 'limit' => 50000, 'type2' => 'month', 'limit2' => 50000 );
	/* $lservice['nofraud'] = array( 'type' => 'day', 'limit' => 600, 'type2' => 'day', 'limit2' => 600 ); */
	$lservice['proxycheck-io'] = array( 'type' => 'day', 'limit' => 1000, 'type2' => 'day', 'limit2' => 1000 );
	$lservice['sorbs'] = array( 'type' => 'min', 'limit' => 1000, 'type2' => 'min', 'limit2' => 1000 );
	$lservice['spamhaus'] = array( 'type' => 'min', 'limit' => 1000, 'type2' => 'min', 'limit2' => 1000 );
	$lservice['teoh'] = array( 'type' => 'day', 'limit' => 5000, 'type2' => 'day', 'limit2' => 5000 );
	$lservice['dshield'] = array( 'type' => 'min', 'limit' => 1000, 'type2' => 'min', 'limit2' => 1000 );
	$lservice['ipstack'] = array( 'type' => 'month', 'limit' => 10000, 'type2' => 'min', 'limit2' => 1000 );
	return( $lservice );
}

?>