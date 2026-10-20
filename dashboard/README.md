# Agent 2 MVP — Root Cause Analysis

MVP độc lập cho Agent 2 trong pipeline:

`Agent 1 finalized findings -> Agent 2 read-only RCA -> structured result -> Agent 3`

## Dashboard Agent 2 + Agent 3

```powershell
cd D:\AI_Pentest\agent2_mvp
py -3 -m pip install -e .
py -3 -m streamlit run app.py
```

Trong **Log Agent 1**, bấm **Browse…** để chọn trực tiếp một hoặc nhiều file JSON
từ Agent 1 (giữ Ctrl/Shift để chọn nhiều file), rồi mở các file đã chọn.
Nếu dùng dữ liệu chung với Agent 1/Agent 4, chọn các file trong
`du_lieu_theo_lab/<lab>/xuat_cho_agent2`. Bấm **Clear selection** để bỏ chọn toàn bộ.

```text
du_lieu_theo_lab/
└── 127.0.0.1/
    ├── phien_kiem_thu/       # Phiên Agent 1
    ├── xuat_cho_agent2/      # Export Agent 1; Agent 4 cũng đọc
    └── phan_tich_agent2/     # Kết quả Agent 2 + nhật ký Agent 3; Agent 4 đọc
        ├── agent2_LFI_phien_01_20250115_143022.json
        └── agent3_fix_LFI_phien_01.md
```

Dashboard hiển thị các file log đã chọn. Với mỗi file nằm trong
`xuat_cho_agent2`, kết quả phân tích sẽ tự lưu một JSON riêng trong
`phan_tich_agent2` của cùng lab, có mã phiên, thời điểm, đường dẫn export,
kết quả và báo cáo; phân tích lại giữ các JSON trước đó. File Markdown theo phiên
chứa hướng dẫn sửa, ban đầu ghi rõ chưa gửi Agent 3. Khi bấm **Gửi cho Agent 3**,
worker lưu hướng dẫn đã chỉnh sửa và cập nhật trạng thái, danh sách file thay đổi,
nhật ký kiểm tra khi kết thúc, kể cả thất bại hoặc trình duyệt đã đóng.
Các giá trị API key được che trước khi lưu. Với thư mục log thông thường,
kết quả hiển thị trên dashboard mà không tự tạo cấu trúc thư mục lab.
Đổi danh sách file log hoặc bỏ chọn toàn bộ sẽ xóa kết quả cũ trên giao diện;
dữ liệu đã lưu vẫn còn trong lab tương ứng.

Agent 3 dùng **Antigravity CLI `agy`**, ghim `gemini-3.1-pro-high` và
`--effort high` (Gemini 3.1 Pro Thinking). Đây là CLI headless chính thức;
`antigravity-ide.cmd chat` chỉ gửi việc vào IDE nên không cung cấp kết quả thực thi.
Agent 2 vẫn dùng cấu hình API riêng trong sidebar.

### Kiểm thử lại bằng Agent 4

Agent 1 export phiên bản 1.3 lưu nguyên request đã quan sát và bằng chứng response.
Trong tab Agent 4, chọn đúng profile và **Phiên Agent 1** của host/port đang mở.
Khi có nhiều phiên, Agent 4 yêu cầu chọn phiên thay vì tự lấy log mới nhất của lab khác.
Danh sách retest được nạp trực tiếp từ log, giữ nguyên request, thứ tự và tất cả các bước;
AI chỉ so sánh response của request khớp nguyên văn, không tạo hoặc sửa testcase.
Kết luận chỉ áp dụng cho request đang đối chiếu. API lỗi vẫn hiển thị testcase gốc.

Log cũ thiếu request đầy đủ chỉ hiển thị nguyên văn các đề xuất đã lưu và ghi rõ
chưa xác nhận đã thực thi; không gán kết quả observation tại bước sinh đề xuất cho nó.
Để có request gốc cho retest, nạp lại extension Agent 1 mới, phân tích các request
đã gửi trong Burp và kết thúc/export phiên. Nạp lại extension Agent 4 sau khi cập nhật.

Cài CLI theo [hướng dẫn Google](https://antigravity.google/docs/cli/install/).
Dashboard tự tìm `.tools/agy/agy.exe` ở thư mục cha, `agy` trong PATH, hoặc
`%LOCALAPPDATA%/agy/bin/agy.exe`. Có thể đặt `AGENT3_CLI` hoặc chọn executable
trong cấu hình nâng cao. Đăng nhập Google một lần bằng `./login-agent3.ps1`.
CLI sử dụng phiên đăng nhập đã lưu; không cần dán token hay API key lên dashboard.

Sau khi Agent 2 xác nhận finding, bấm **Gửi cho Agent 3**:

1. Worker chạy CLI ngầm trong đúng thư mục source, gửi prompt qua stdin.
2. Dashboard nhận sự kiện `stream-json` trực tiếp từ stdout/stderr và hiển thị tiến độ.
3. Dashboard mặc định chỉ sửa code: không tạo/chạy test, lint, build hoặc retest; chạy một lượt CLI.
4. Khi đúng model, CLI exit 0 + result SUCCESS và có thay đổi mã nguồn ứng dụng,
   dashboard ghi `edited`: **Đã sửa mã nguồn. Chưa chạy kiểm thử.** Lỗi xác thực,
   timeout hoặc thiếu kết quả vẫn báo thất bại.
5. API nội bộ `JobManager.start(..., verify=True)` vẫn hỗ trợ chế độ kiểm tra cũ;
   nút Gửi cho Agent 3 trên dashboard không bật chế độ này. Build & Run là nút riêng.

Tiến độ Agent 3 hiện trong bảng cuộn ngắn gọn theo thời gian và giai đoạn.
Không cần auto-poll, nút quét thay đổi hay reset snapshot.
Worker tiếp tục khi Streamlit rerun hoặc trình duyệt kết nối lại; cùng source
trong cùng tiến trình dashboard chỉ có một job đang chạy. Khởi động lại server
không tự khôi phục job.

**Build & Run** là nút riêng bên dưới tiến độ Agent 3. Nút chạy
`docker compose up --build -d` trong source đã chọn, sau đó kiểm tra tất cả
dịch vụ bằng `docker compose ps --all --format json` và đợi healthcheck. Dashboard
chỉ báo thành công khi Docker trả exit code 0 và mọi dịch vụ đang chạy/healthy.
Cần Docker CLI và Docker daemon hoạt động; source phải có compose file ở thư mục
gốc. Nếu Docker chưa sẵn sàng, dashboard hiện nguyên nhân ngắn gọn.

Mỗi lần build ghim `--project-directory` và `--file` theo đường dẫn source đã
chọn; chỉ dùng `.env` và Compose override trong thư mục đó. Biến `COMPOSE_*`
kế thừa từ tiến trình dashboard không được dùng để chọn cấu hình khác.
Trước khi build, dashboard đọc cấu hình Compose đã resolve và hiện build context.
Build context (kể cả additional context), Dockerfile và bind mount phải nằm trong
source đã chọn; đường dẫn trỏ sang checkout khác hoặc source remote sẽ bị từ chối.
Các dịch vụ phụ dùng image sẵn (ví dụ MySQL) vẫn được phép, nhưng phải có ít nhất
một dịch vụ build từ source. Thư mục con của source được phép làm build context.
Ví dụ chọn `E:\lazyweb` thì build từ `E:\lazyweb` hoặc thư mục con của nó;
Compose trỏ sang `C:\lazyweb`/`D:\AI_Pentest\lazyweb` sẽ bị dừng trước khi build.
Các source chỉ build lần lượt trong một tiến trình dashboard để tránh tranh chấp
image/container cùng tên. Tên project, container và cổng vẫn theo Compose của
source; các bản sao cùng cấu hình không được tự tách thành các website độc lập.

Dashboard không đưa API key Agent 2 vào biến môi trường chung; nội dung báo cáo,
JSON, hướng dẫn sửa và thông báo lỗi được che các giá trị key trước khi hiển thị.
Các tiến trình CLI/test/build cũng không nhận biến môi trường chứa API key/token.

### Kiểm tra sau sửa (chỉ khi bật `verify=True`)

Với PHP (như `lazyweb`), worker lint các file PHP thay đổi và chạy
`php tests/security_regression.php`. Agent phải tạo regression test thực thi
hành vi đã sửa, bao gồm input nguy hiểm và input hợp lệ; thiếu test là thất bại.
PHP phải có trong PATH. Kết quả đạt nghĩa là vượt qua bộ test này, không phải
chứng nhận mọi lỗ hổng đã được loại bỏ.

Để dùng bộ test/build của dự án khác, tạo `.agent3-checks.json` trong source.
Đây là danh sách argv, không phải chuỗi shell. Ví dụ:

```json
[
  ["python", "-m", "unittest", "discover", "-s", "tests"],
  ["python", "-m", "compileall", "-q", "src"]
]
```

Danh sách được đọc trước khi sửa và giữ cố định cho cả job. Mỗi lệnh tối đa
5 phút; mỗi lượt CLI tối đa 20 phút. Timeout dừng cây tiến trình và báo lỗi.
Các file đã sửa được giữ lại nếu job thất bại, không tự rollback thay đổi của người dùng.
CLI được cấp quyền tự thực thi thao tác cho lần gửi việc; chỉ dùng với source
và hướng dẫn sửa mà bạn tin cậy. Luồng này không tự deploy hoặc restart dịch vụ.

Giao thức tham khảo: [Antigravity headless](https://antigravity.google/docs/cli/headless/).

## Quyết định được phản ánh trong code

Ở cuối dashboard, bên dưới **Build & Run**, bấm **Gửi cho LLM viết report**
để tạo báo cáo kiểm thử ban đầu của Agent 1 bằng tiếng Việt qua Gemini CLI (`agy`, `gemini-3.1-pro-high`, effort high),
dùng cùng executable và tài khoản Google đã đăng nhập như Agent 3. Phần viết report
không yêu cầu API key Qwen; cấu hình API ở sidebar vẫn dành cho phân tích Agent 2.
Chỉ cần chọn ít nhất một log Agent 1 hợp lệ; không cần chọn source hoặc chạy Agent 2.
Báo cáo chỉ nhận nội dung log Agent 1 đã chọn:
request/payload, response/chỉ dấu quan sát, verdict và testcase đề xuất, kèm
phiên/file nguồn. `observations` là dữ liệu đã ghi nhận; `test_cases` là đề xuất,
không được coi `generated_at_step` hay expected signal là bằng chứng đã thực thi.
Tối đa 24 observation và 24 testcase mỗi log; số bước bị lược bớt, trường dài và
log thiếu request/không đọc được được ghi rõ. Thay đổi nội dung log làm báo cáo cũ
mất hiệu lực trong giao diện. Phạm vi báo cáo gồm các bước kiểm thử ban đầu,
phát hiện, bằng chứng HTTP, kết luận và giới hạn của Agent 1; không nhận kết quả
Agent 2, Agent 3, Build & Run hoặc Agent 4 và không mô tả toàn bộ quy trình.
Dashboard hiển thị báo cáo và nút tải `security_report.md`.
CLI viết report có thời gian chờ tối đa 7 phút, chạy trong thư mục tạm riêng
và chỉ nhận dữ liệu báo cáo đã che bí mật;
yêu cầu tool sẽ dừng lượt viết. CLI lỗi hoặc trả nội dung rỗng sẽ hiện thông báo để thử lại.
Báo cáo được giữ
trong phiên giao diện và được xóa khi lựa chọn hoặc nội dung log thay đổi.
Đổi source hoặc kết quả các giai đoạn sau không làm mất báo cáo Agent 1.

- Xử lý **một batch**, nhưng mỗi finding chạy trong **conversation/state độc lập**.
- Chỉ có hai tool: `search_code` và `read_file`.
- Tool bị giới hạn trong `source_root`; không có write/edit/delete/shell.
- Không đọc `.env`, private key, `node_modules`, `.git`, build artifacts.
- Scope gồm `sqli`, `xss`, `lfi`, `file_upload` (nhận profile `File Upload` từ Agent 1).
- XSS và File Upload dùng cùng luồng Start Analysis → xác minh source → Gửi cho Agent 3 như SQLi/LFI. Agent 2 phân tích và đề xuất; Agent 3 sửa mã nguồn.
- Adapter giữ bằng chứng từng bước, multipart request, tín hiệu upload và response. Với log có request multipart/tín hiệu upload, mỗi handler upload được phân tích một lần; request mở file sau upload là bằng chứng liên quan. Request được che thông tin xác thực; đoạn dài và số bước vượt giới hạn được đánh dấu đã lược bớt. Testcase mới chỉ được đề xuất không được dùng làm bằng chứng đã thực thi.
- Hướng dẫn Agent 3 gộp finding đã xác nhận cùng loại lỗi, phiên bản source và điểm thực thi (sink) trùng/chồng dòng. Mỗi nhóm giữ mã finding, vị trí và mọi chiến lược/ràng buộc khác nhau. Các sink khác nhau được giữ riêng; thiếu sink thì chỉ gộp khi vùng handler trùng chính xác. Báo cáo/JSON phân tích vẫn giữ kết quả riêng của từng finding.
- Không nhét toàn bộ codebase vào prompt; model tự search/read theo finding.
- `confirmed` chỉ được chấp nhận nếu run đó đã gọi `read_file`.
- Khi không đủ bằng chứng có thể trả `unresolved`; khi chạm hard limit trả `analysis_limit_reached`.
- Agent 2 chỉ đề xuất remediation strategy, **không sinh patch**.
- `source_revision` đi cùng batch để giữ provenance của source được phân tích.

## Cấu trúc

```text
agent2_mvp/
├── agent2/
│   ├── agent.py       # per-finding agent loop + batch runner
│   ├── cli.py         # CLI entry point
│   ├── config.py      # hard limits / read policy
│   ├── llm.py         # OpenAI-compatible provider adapter
│   ├── prompts.py     # Agent 2 system protocol
│   ├── schemas.py     # batch/finding/result validation
│   └── tools.py       # read-only search_code/read_file
├── examples/
│   └── finding_batch.json
└── tests/
```

## Chạy test offline

Từ thư mục `agent2_mvp`:

```bash
python -m unittest discover -s tests -v
```

## Chạy với model OpenAI-compatible

Thiết lập 3 biến môi trường:

```text
AGENT2_API_KEY
AGENT2_BASE_URL
AGENT2_MODEL
```

Ví dụ PowerShell (thay bằng endpoint/model mà nhóm quyết định dùng):

```powershell
$env:AGENT2_API_KEY="..."
$env:AGENT2_BASE_URL="https://provider.example/v1"
$env:AGENT2_MODEL="your-model"

python -m agent2.cli `
  --batch .\examples\finding_batch.json `
  --source-root "D:\path\to\target-source" `
  --out .\out\agent2_result.json
```

`AGENT2_BASE_URL` phải là base OpenAI-compatible mà `/chat/completions` có thể được nối vào.

## Input contract MVP

```json
{
  "batch_id": "B-001",
  "source_revision": "snapshot-or-commit-id",
  "findings": [
    {
      "finding_id": "F-001",
      "vulnerability_type": "sqli",
      "endpoint": "/login",
      "method": "POST",
      "parameter": {"name": "username", "location": "body"},
      "evidence": {"summary": "..."}
    }
  ]
}
```

## Output contract MVP

Mỗi finding có một trong các trạng thái:

- `confirmed`
- `unresolved`
- `analysis_limit_reached`
- `failed`

Kết quả `confirmed` chứa `code_locations`, `root_cause`, `remediation`, `confidence`, `metrics` và `source_revision`.

Agent 2 được yêu cầu viết toàn bộ nội dung giải thích bằng tiếng Việt có dấu, gồm nguyên nhân, nguồn/điểm thực thi, luồng dữ liệu, chiến lược khắc phục, lý do, ràng buộc, phương án thay thế và ghi chú. Khóa JSON, giá trị enum, đường dẫn và mã nguồn được giữ nguyên để Agent 3 tiếp tục xử lý. Báo cáo hiển thị độ tin cậy và vai trò mã nguồn bằng tiếng Việt; mã PHP trong dấu backtick được giữ nguyên, dấu `$` ngoài mã được bảo vệ khỏi chế độ công thức.

Báo cáo đã tạo trước thay đổi prompt vẫn giữ nội dung cũ. Chạy lại **Start Analysis** để tạo nội dung tiếng Việt; tải lại trang đơn thuần không dịch kết quả đang lưu trong phiên.

## Chưa chốt / chưa làm trong MVP này

- Provider/model chính thức.
- Adapter trực tiếp từ log schema Agent 1 hiện tại sang `Finalized Finding Batch`.
- HTTP API và nút `Send to Agent 2` trong Burp.
- Human approval gate Agent 2 -> Agent 3.
- Cách sinh `source_revision` chính thức (Git commit, snapshot hash, hay session revision).
