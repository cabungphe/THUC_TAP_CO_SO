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
	$upload_failed = false;
	if( !empty($_FILES["avatar"]['name']) ) {
		if ($_FILES["avatar"]["error"] !== UPLOAD_ERR_OK) {
			$error = "Upload failed.";
			$upload_failed = true;
		} elseif ($_FILES["avatar"]["size"] > 2 * 1024 * 1024) {
			$error = "File size must be less than 2MB.";
			$upload_failed = true;
		} else {
			$file_tmp = $_FILES["avatar"]["tmp_name"];
			$image_info = @getimagesize($file_tmp);

			if ($image_info === false) {
				$error = "Invalid image file.";
				$upload_failed = true;
			} else {
				$mime_type = $image_info['mime'];
				$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];

				if (!in_array($mime_type, $allowed_mimes)) {
					$error = "Only image files (JPEG, PNG, GIF) are allowed.";
					$upload_failed = true;
				} else {
					$target_dir = __DIR__ . '/avatar/';
					$target_file = $target_dir . $_SESSION['id'] . '.png';

					$image = false;
					switch ($mime_type) {
						case 'image/jpeg':
							$image = @imagecreatefromjpeg($file_tmp);
							break;
						case 'image/png':
							$image = @imagecreatefrompng($file_tmp);
							break;
						case 'image/gif':
							$image = @imagecreatefromgif($file_tmp);
							break;
					}

					if ($image !== false) {
						if (file_exists($target_file)) {
							unlink($target_file);
						}
						imagepng($image, $target_file);
						imagedestroy($image);
						redirect('profile.php');
					} else {
						$error = "Failed to process image. (Requires PHP GD extension)";
						$upload_failed = true;
					}
				}
			}
		}
	}

	if( !$upload_failed && (!empty( post('username') ) || !empty(post('useremail'))) ) {
		if(!empty(post('password'))) {
			$stmt = $mysqli->prepare("UPDATE tbl_users SET username = ?, useremail = ?, userpass = ? WHERE id = ?");
			$username = post('username');
			$useremail = post('useremail');
			$password = pw(post('password'));
			$user_id = $_SESSION['id'];
			$stmt->bind_param("sssi", $username, $useremail, $password, $user_id);
			$stmt->execute();
			$stmt->close();
		} else {
			$stmt = $mysqli->prepare("UPDATE tbl_users SET username = ?, useremail = ? WHERE id = ?");
			$username = post('username');
			$useremail = post('useremail');
			$user_id = $_SESSION['id'];
			$stmt->bind_param("ssi", $username, $useremail, $user_id);
			$stmt->execute();
			$stmt->close();
		}
		redirect('logout.php');
	}
}

$stmt = $mysqli->prepare('SELECT * FROM tbl_users WHERE id = ?');
$user_id = $_SESSION['id'];
$stmt->bind_param("i", $user_id);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();
$stmt->close();
$smarty->assign('error', $error);
$smarty->assign('data', $data);
$smarty->display('user/profile.php');
