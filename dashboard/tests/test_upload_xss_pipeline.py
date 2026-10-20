"""Offline regression tests; scripted responses do not validate a live model."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from agent2.adapter import convert_agent1_to_batch
from agent2.agent import Agent2Runner
from agent2.cli import build_agent3_payload, build_user_report
from agent2.schemas import Finding, FindingBatch, SchemaError
from agent2.tools import ReadOnlySourceTools


def upload_log():
    return {
        "schema_version": "agent1-to-agent2-1.3",
        "session": {"session_id": "upload-test", "profile": "File Upload",
                    "targets": [{"parameter": "avatar", "location": "body"}],
                    "final_verdict": "vulnerable"},
        "observations": [
            {"step": 1, "request_line": "POST /user/profile.php HTTP/1.1",
             "target": {"parameter": "avatar", "location": "body"},
             "request_content": 'POST /user/profile.php HTTP/1.1\r\nCookie: sid=private; auth=hidden\r\nAuthorization: Bearer private-token\r\nContent-Type: multipart/form-data; boundary=example\r\n\r\n--example\r\nContent-Disposition: form-data; name="avatar"; filename="example.html"\r\nContent-Type: image/jpeg\r\n\r\n<script>alert(1)</script>\r\n--example--',
             "file_upload_signal": {"filename": "example.html", "content_type": "image/jpeg",
                                    "upload_accepted": True},
             "verdict": "inconclusive", "response_status": "HTTP/1.1 302 Found"},
            {"step": 2, "request_line": "GET /user/avatar/example.html HTTP/1.1",
             "target": {"parameter": "unknown", "location": "path"},
             "summary": "Synthetic fixture: uploaded active content served.",
             "response_key_text": "<script>alert(1)</script>", "verdict": "vulnerable"},
        ],
    }


class AdapterTests(unittest.TestCase):
    def test_upload_evidence_routes_credentials_and_input_unchanged(self):
        raw = upload_log()
        original = deepcopy(raw)
        batch = FindingBatch.from_dict(convert_agent1_to_batch(raw))
        self.assertEqual(raw, original)
        self.assertEqual(len(batch.findings), 1)
        first = batch.findings[0]
        self.assertEqual(first.vulnerability_type, "file_upload")
        self.assertEqual((first.method, first.endpoint), ("POST", "/user/profile.php"))
        evidence = first.evidence
        request = evidence["observations"][0]["request_content"]
        self.assertIn('filename="example.html"', request)
        self.assertIn("<script>alert(1)</script>", request)
        self.assertNotIn("private", request)
        self.assertNotIn("hidden", request)
        self.assertEqual(evidence["related_observations"][0]["step"], 2)
        self.assertEqual(evidence["related_observations"][0]["request_line"],
                         "GET /user/avatar/example.html HTTP/1.1")
        self.assertEqual(evidence["total_steps"], 2)

    def test_separate_upload_handlers_stay_separate_and_duplicate_targets_do_not_repeat(self):
        raw = upload_log()
        raw["session"]["targets"] *= 2
        second = deepcopy(raw["observations"][0])
        second.update(step=3, request_line="POST /other/upload.php HTTP/1.1")
        raw["observations"].append(second)
        batch = FindingBatch.from_dict(convert_agent1_to_batch(raw))
        self.assertEqual([f.endpoint for f in batch.findings],
                         ["/user/profile.php", "/other/upload.php"])

    def test_different_upload_targets_on_same_handler_keep_all_observed_evidence(self):
        raw = upload_log()
        second = deepcopy(raw["observations"][0])
        second.update(step=3, target={"parameter": "filename", "location": "body"})
        raw["observations"].append(second)
        batch = FindingBatch.from_dict(convert_agent1_to_batch(raw))
        self.assertEqual(len(batch.findings), 1)
        self.assertEqual([o["step"] for o in batch.findings[0].evidence["observations"]], [1, 3])
        self.assertEqual([t["parameter"] for t in batch.findings[0].evidence["observed_targets"]],
                         ["avatar", "filename"])

    def test_xss_same_parameter_different_routes_and_raw_session(self):
        raw = {"session_id": "xss", "profile": "XSS", "observations": [
            {"request_line": "GET /search.php?q=first HTTP/1.1", "target": {"parameter": "q", "location": "query"},
             "summary": "reflected input", "verdict": "vulnerable"},
            {"request_line": "GET /other.php?q=second HTTP/1.1", "target": {"parameter": "q", "location": "query"},
             "summary": "escaped input", "verdict": "safe"},
        ]}
        batch = FindingBatch.from_dict(convert_agent1_to_batch(raw))
        self.assertEqual([f.endpoint for f in batch.findings], ["/search.php", "/other.php"])
        self.assertTrue(all(f.vulnerability_type == "xss" for f in batch.findings))
        self.assertEqual(batch.findings[1].evidence["observations"][0]["verdict"], "safe")

    def test_direct_batch_aliases_and_unsupported_type(self):
        base = dict(finding_id="f", endpoint="/upload", method="POST")
        for alias in ("File Upload", "file_upload", "file-upload", "Unrestricted File Upload"):
            self.assertEqual(Finding.from_dict(dict(base, vulnerability_type=alias)).vulnerability_type, "file_upload")
        with self.assertRaises(SchemaError):
            Finding.from_dict(dict(base, vulnerability_type="unsupported"))

    def test_large_evidence_has_explicit_omission_metadata(self):
        raw = upload_log()
        raw["observations"] = [dict(raw["observations"][0], step=i,
                                    request_content="x" * 9000) for i in range(30)]
        evidence = convert_agent1_to_batch(raw)["findings"][0]["evidence"]
        self.assertEqual(evidence["omitted_observation_count"], 6)
        self.assertEqual(len(evidence["observations"]), 24)
        self.assertIn("truncated_fields", evidence["observations"][0])


class ScriptedModel:
    def __init__(self, source, strategy):
        self.source = source
        self.strategy = strategy
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        if self.calls == 1:
            assert "observations" in messages[1]["content"]
            return json.dumps({"action": "read_file", "args": {"path": "upload_xss.php"}})
        assert self.source in messages[-1]["content"]
        return json.dumps({"action": "finish", "result": {
            "analysis_status": "confirmed", "confidence": "high",
            "code_locations": [{"path": "upload_xss.php", "start_line": 1, "end_line": 3, "role": "sink"}],
            "root_cause": {"summary": "Kết quả mô phỏng cho kiểm thử offline.",
                           "source": "Dữ liệu từ request", "sink": "Điểm hiển thị hoặc lưu file",
                           "data_flow": ["Request tới handler"]},
            "remediation": {"recommended_strategy": self.strategy,
                            "constraints": ["Kiểm tra input nguy hiểm và input hợp lệ."]},
            "notes": ["Mô hình giả lập, chưa kiểm thử HTTP thực tế."],
        }})


class PipelineTests(unittest.TestCase):
    def test_upload_and_xss_reach_report_and_agent3_after_reading_source(self):
        for profile, source, strategy, label in (
            ("File Upload", "move_uploaded_file", "Xác thực và mã hóa lại ảnh.", "FILE UPLOAD"),
            ("XSS", "echo $_GET", "Escape theo ngữ cảnh HTML.", "XSS"),
        ):
            with self.subTest(profile=profile):
                directory = str(Path(__file__).parent / "fixture_app")
                raw = upload_log()
                raw["session"]["profile"] = profile
                batch = FindingBatch.from_dict(convert_agent1_to_batch(raw))
                batch.findings = batch.findings[:1]
                result = Agent2Runner(ScriptedModel(source, strategy), ReadOnlySourceTools(directory)).analyze_batch(batch)
                self.assertEqual(result["results"][0]["analysis_status"], "confirmed")
                self.assertEqual(result["results"][0]["metrics"]["read_calls"], 1)
                self.assertIn(label, build_user_report(result))
                handoff = build_agent3_payload(result, directory)
                for expected in (strategy, "upload_xss.php", "input hợp lệ", "chưa chạy kiểm thử"):
                    self.assertIn(expected, handoff)
