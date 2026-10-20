from copy import deepcopy
import unittest

from agent2.cli import build_agent3_payload, build_user_report


def finding(identifier="F-1"):
    return {
        "finding_id": identifier, "vulnerability_type": "file_upload",
        "analysis_status": "confirmed",
        "code_locations": [{"path": "upload.php", "start_line": 10, "end_line": 20, "role": "sink"}],
        "root_cause": {"summary": "Giải thích dài.", "data_flow": ["Luồng dữ liệu dài."]},
        "remediation": {"recommended_strategy": "Xác thực nội dung ảnh và dùng tên an toàn.",
                        "constraints": ["Giữ avatar hợp lệ.", "Không thực thi script."],
                        "rationale": "Lý do dài."},
        "notes": ["Ghi chú phân tích dài."],
    }


class CompactHandoffTests(unittest.TestCase):
    def test_compact_handoff_retains_requirements_and_full_report(self):
        result = {"results": [finding()]}
        original = deepcopy(result)
        handoff = build_agent3_payload(result, "demo")
        for value in ("upload.php", "10-20", "Giữ avatar hợp lệ.", "Không thực thi script.",
                      "Xác thực nội dung ảnh", "chỉ sửa code", "chưa chạy kiểm thử"):
            self.assertIn(value, handoff)
        for value in ("Giải thích dài.", "Luồng dữ liệu dài.", "Lý do dài.", "Ghi chú phân tích dài."):
            self.assertNotIn(value, handoff)
            self.assertIn(value, build_user_report(result))
        self.assertEqual(result, original)

    def test_same_sink_merges_and_retains_distinct_constraints(self):
        first, duplicate = finding(), finding("F-2")
        handoff = build_agent3_payload({"results": [first, duplicate]})
        self.assertEqual(handoff.count("## Bản sửa"), 1)
        self.assertIn("F-1, F-2", handoff)
        other = finding("F-3")
        other["code_locations"][0].update(start_line=30, end_line=40)
        self.assertEqual(build_agent3_payload({"results": [first, other]}).count("## Bản sửa"), 2)
        other = finding("F-4")
        other["remediation"]["constraints"].append("Giữ điều kiện đặc biệt.")
        merged = build_agent3_payload({"results": [first, other]})
        self.assertEqual(merged.count("## Bản sửa"), 1)
        self.assertIn("Giữ điều kiện đặc biệt.", merged)

    def test_different_wording_and_related_locations_do_not_repeat_same_sink(self):
        first, other = finding(), finding("F-2")
        other["code_locations"] = [
            {"path": "upload.php", "start_line": 12, "end_line": 20, "role": "sink"},
            {"path": "template.php", "start_line": 5, "end_line": 6, "role": "related"},
        ]
        other["remediation"]["recommended_strategy"] = "Ghi lại ảnh để loại mã nhúng."
        result = {"results": [first, other]}
        original = deepcopy(result)
        handoff = build_agent3_payload(result)
        self.assertEqual(handoff.count("## Bản sửa"), 1)
        self.assertIn("Ghi lại ảnh để loại mã nhúng.", handoff)
        self.assertIn("Xác thực nội dung ảnh", handoff)
        self.assertIn("template.php", handoff)
        self.assertEqual(result, original)

    def test_different_types_revisions_and_broad_handlers_stay_separate(self):
        first = finding()
        for field, value in (("vulnerability_type", "lfi"), ("source_revision", "other-source")):
            other = finding("F-2")
            other[field] = value
            self.assertEqual(build_agent3_payload({"results": [first, other]}).count("## Bản sửa"), 2)
        first["code_locations"][0].update(role="vulnerable_handler", start_line=1, end_line=100)
        other = deepcopy(first)
        other["code_locations"][0]["end_line"] = 90
        self.assertEqual(build_agent3_payload({"results": [first, other]}).count("## Bản sửa"), 2)

    def test_unresolved_does_not_generate_a_fix(self):
        item = finding()
        item["analysis_status"] = "unresolved"
        self.assertNotIn("## Bản sửa", build_agent3_payload({"results": [item]}))
