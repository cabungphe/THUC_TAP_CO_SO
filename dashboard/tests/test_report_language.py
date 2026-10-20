from __future__ import annotations

import copy
import unittest

from agent2.agent import Agent2Runner
from agent2.cli import build_user_report
from agent2.config import Agent2Config
from agent2.schemas import Finding


class ReportLanguageTests(unittest.TestCase):
    def test_vietnamese_report_preserves_code_and_raw_protocol_values(self):
        result = {
            "results": [{
                "finding_id": "F-001",
                "vulnerability_type": "sqli",
                "analysis_status": "confirmed",
                "confidence": "high",
                "code_locations": [{
                    "path": "user/login.php", "start_line": 12,
                    "end_line": 16, "role": "vulnerable_handler",
                }],
                "root_cause": {
                    "summary": "Giá trị `$email` được ghép trực tiếp vào câu lệnh SQL.",
                    "source": "Tham số `email` từ `$_POST` tại dòng 12.",
                    "sink": "Thực thi bằng `$mysqli->query($sql)` tại dòng 16.",
                    "data_flow": ["Đọc tham số đầu vào.", "Ghép $email vào $sql."],
                },
                "remediation": {
                    "recommended_strategy": "Dùng truy vấn có tham số.",
                    "rationale": "Tách dữ liệu đầu vào khỏi câu lệnh SQL.",
                    "constraints": ["Giữ nguyên kết nối `$mysqli`."],
                    "alternatives": ["Dùng thư viện tự động gắn tham số."],
                },
                "notes": ["Kiểm tra $email trước khi gọi $mysqli->query($sql)."],
            }],
        }
        original = copy.deepcopy(result)
        report = build_user_report(result)
        for text in (
            "| Độ tin cậy | Cao |", "Hàm xử lý có lỗ hổng",
            "`$email`", "`$_POST`", "`$mysqli->query($sql)`",
            "Dùng truy vấn có tham số.", "Tách dữ liệu đầu vào khỏi câu lệnh SQL.",
            "Giữ nguyên kết nối `$mysqli`.", "Dùng thư viện tự động gắn tham số.",
            r"Ghép \$email vào \$sql.",
            r"Kiểm tra \$email trước khi gọi \$mysqli->query(\$sql).",
        ):
            with self.subTest(text=text):
                self.assertIn(text, report)
        self.assertNotIn("`Tham số", report)
        self.assertNotIn("Data Flow", report)
        self.assertEqual(result, original)

    def test_report_preserves_fenced_code_and_already_escaped_dollars(self):
        code = "```php\n$email = post('email');\n$mysqli->query($sql);\n```"
        report = build_user_report({"results": [{
            "analysis_status": "unresolved", "confidence": "low",
            "reason": "Chưa đủ bằng chứng.",
            "notes": [code, r"Biến \$email cần kiểm tra."],
        }]})
        self.assertIn(code, report)
        self.assertIn(r"Biến \$email cần kiểm tra.", report)
        self.assertNotIn(r"\\$email", report)
        self.assertIn("Chưa xác nhận được", report)
        self.assertIn("| Độ tin cậy | Thấp |", report)

    def test_english_input_still_receives_vietnamese_output_instructions(self):
        captured = []

        class CapturingLLM:
            def complete(self, messages):
                captured.extend(messages)
                return '{"action":"finish","result":{"analysis_status":"unresolved"}}'

        finding = Finding.from_dict({
            "finding_id": "F-001", "vulnerability_type": "sqli",
            "endpoint": "/login", "method": "POST",
            "evidence": {"summary": "User-controlled input reaches the database."},
        })
        result = Agent2Runner(CapturingLLM(), tools=None).analyze_finding(finding, "r1")
        self.assertIn("Vietnamese (tiếng Việt có dấu)", captured[0]["content"])
        self.assertIn("toàn bộ nội dung giải thích", captured[1]["content"])
        self.assertIn(finding.evidence["summary"], captured[1]["content"])
        self.assertEqual(result["analysis_status"], "unresolved")
        self.assertEqual(result["reason"], "Phân tích chưa xác nhận được nguyên nhân gốc rễ.")

    def test_analysis_limit_reason_is_vietnamese(self):
        finding = Finding.from_dict({
            "finding_id": "F-001", "vulnerability_type": "sqli",
            "endpoint": "/login", "method": "POST",
        })
        result = Agent2Runner(None, None, Agent2Config(max_steps=0)).analyze_finding(finding, "r1")
        self.assertEqual(result["analysis_status"], "analysis_limit_reached")
        self.assertIn("đã đạt giới hạn", result["reason"])
        self.assertIn("Vượt giới hạn phân tích", build_user_report({"results": [result]}))


if __name__ == "__main__":
    unittest.main()
