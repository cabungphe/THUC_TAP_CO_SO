<?php
echo $_GET['q'];
move_uploaded_file($_FILES['avatar']['tmp_name'], __DIR__ . '/avatar/' . basename($_FILES['avatar']['name']));
