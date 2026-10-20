<?php
require_once __DIR__ . '/init.php';

if( !isAuth() ) {
	redirect('login.php');
}

$error = false;
$welcome_msg = '';

if( !empty( get('msg') ) ) {
	$welcome_msg = get('msg');
}

$smarty->assign('welcome_msg', $welcome_msg);

if( isPost() ) {
	if( !empty($_FILES["avatar"]['name']) ) {
		// doing file upload - only check MIME type
		$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
		$file_type = $_FILES["avatar"]["type"];

		if( !in_array($file_type, $allowed_types) ) {
			$error = "Only image files (JPEG, PNG, GIF) are allowed.";
		} else {
			$target_dir = __DIR__ . '/avatar/';
			$target_file = $target_dir . basename($_FILES["avatar"]["name"]);

			if( file_exists( $target_file ) ) {
				unlink($target_file);
			}

			move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
			redirect('profile.php');
		}
	}

	if( !empty( post('username') ) || !empty('useremail')) {
		if(!empty(post('password'))) {
			$mysqli->query("UPDATE tbl_users SET username = '" . post('username') . "', useremail='" . post('useremail') . "', userpass='" . pw(post('password')) . "' WHERE id = " . cookie('user_id'));
		} else {
			$mysqli->query("UPDATE tbl_users SET username = '" . post('username') . "', useremail='" . post('useremail') . "' WHERE id = " . cookie('user_id'));
		}
		redirect('logout.php');
	}
}

$q = $mysqli->query('SELECT * FROM tbl_users WHERE id = ' . cookie('user_id'));
$data = $q->fetch_assoc();
$smarty->assign('error', $error);
$smarty->assign('data', $data);
$smarty->display('user/profile.php');
