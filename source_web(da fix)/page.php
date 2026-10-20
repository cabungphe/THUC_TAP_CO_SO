<?php
require_once __DIR__ . '/init.php';

$allowed_pages = [
	'core.php',
	'cut-support-cost.php',
	'build-customer-trust.php'
];

if( get('page') ) {
	$page = get('page');
	if (in_array($page, $allowed_pages)) {
		include $page;
	} else {
		die('Invalid page.');
	}
} else {
	redirect('/');
}