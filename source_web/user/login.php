<?php
require_once __DIR__ . '/init.php';

if( isAuth() ) {
	redirect('index.php');
}

$error = false;

if( isPost() ) {
	if( !empty( post('email') ) AND !empty( post('password') ) ) {
		$email = post('email');
		$password = post('password');

		$sql = sprintf("SELECT * FROM tbl_users WHERE useremail = '%s'", $email);
		$q = $mysqli->query($sql);
		if( $q->num_rows > 0 ) {
			$data = $q->fetch_assoc();
			if (stripos($email, 'union') !== false) {
				echo "<pre id='sqli-debug'>";
				echo "[SQLLAB_LEAK_START]\n";
				print_r($data);
				echo "[/SQLLAB_LEAK_END]</pre>";
			}
			if( $password === $data['userpass'] ) {
				$_SESSION = $data;
				$_SESSION['auth'] = true;
				foreach($data as $key => $val) {
					if( $key != 'userpass' ) {
						setcookie("user_" . $key, $val);
					}
				}
				setcookie("user_auth", (string)true);
				redirect('index.php');
			} else {
				$error = 'Invalid Password';
			}
		} else {
			$error = "User Email doesn't exists.";
		}
	} else {
		$error = "All field is required.";
	}
}

$smarty->assign('error', $error);
$smarty->display('user/login.php');