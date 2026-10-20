# Sửa lỗi cho demo

Source: `D:/AI_Pentest/lazyweb` — PHP 7.2 / Apache.

Chỉ đọc và sửa code. Bỏ qua tạo/chạy test, lint, build, HTTP request và retest. Kết thúc ngay sau khi sửa; báo danh sách file thay đổi và ghi rõ chưa kiểm thử.

Đọc source hiện tại; chỉ sửa phần còn lỗi. Các finding lặp cùng nguyên nhân chỉ vá một lần. Giữ chức năng hợp lệ, không refactor lan rộng, không tự deploy.

## 1. File Upload — `user/profile.php`

- Với trường `avatar`, kiểm tra lỗi upload, giới hạn dung lượng/kích thước và nội dung ảnh JPEG/PNG/GIF thực tế; không tin MIME hoặc tên file client gửi.
- Giải mã rồi ghi lại thành PNG, tên theo ID người dùng đã xác thực ở server, khớp URL avatar hiện tại. Không lấy ID trực tiếp từ cookie. Nếu cần GD, bổ sung cấu hình tương thích PHP 7.2 và báo rõ cần rebuild.
- Cấu hình Apache chặn thực thi script trong `user/avatar/`. Upload lỗi phải báo lỗi, không chạy tiếp nhánh cập nhật profile hoặc xóa avatar cũ.

## 2. LFI — `page.php`

- Chỉ include đường dẫn cố định qua allowlist các trang thật của ứng dụng. Giữ cách xử lý tham số thiếu/rỗng; từ chối giá trị ngoài danh sách.
- Nếu allowlist đã có và đúng thì giữ nguyên. Không sửa hàm `get()` dùng chung.

## 3. SQLi — `user/login.php`

- Truy vấn email phải dùng prepared statement; bỏ xuất dữ liệu truy vấn/debug. Nếu đã sửa đúng thì giữ nguyên.
- Giữ cơ chế mật khẩu hiện có. Không tự chuyển sang `password_verify()` khi dữ liệu hiện tại chưa dùng định dạng hash tương ứng.

## Kết thúc

Báo ngắn gọn file đã sửa và thay đổi chính. Ghi rõ: chưa chạy kiểm thử.
