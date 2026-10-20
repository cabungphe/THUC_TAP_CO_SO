<?php
require_once __DIR__ . '/init.php';

$query = '';
$results = [];

if( !empty( get('q') ) ) {
	$query = get('q');
	// Simulate search results
	$results = [
		'No results found for your search query.'
	];
}

$smarty->assign('query', $query);
$smarty->assign('results', $results);
$smarty->display('search.php');
