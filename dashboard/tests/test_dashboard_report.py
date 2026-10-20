from pathlib import Path
import json
import shutil
import uuid
import unittest
from unittest.mock import patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from agent2.llm import LLMError
from agent2.agent3 import MODEL
from agent2.report import generate_report_cli
from test_report_agent1 import log


class DashboardReportTests(unittest.TestCase):
    def setUp(self):
        st.cache_resource.clear()
        directory = Path(__file__).parent / ("dashboard-report-" + uuid.uuid4().hex)
        directory.mkdir()
        self.addCleanup(self.cleanup_directory, directory)
        cli_patch = patch('agent2.report.cli_command', return_value=['fake-cli'])
        cli_patch.start()
        self.addCleanup(cli_patch.stop)
        self.addCleanup(st.cache_resource.clear)
        self.root = str(directory.resolve())
        self.app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
        self.app.session_state["source_root"] = self.root
        self.app.session_state["analysis_source_root"] = self.root
        self.app.session_state["analysis_result"] = {
            "results": [{"finding_id": "F-001", "analysis_status": "unresolved"}],
        }
        self.log_path = directory.resolve() / "agent1.json"
        self.log_path.write_text(json.dumps(log()), encoding="utf-8")
        self.app.session_state["selected_log_files"] = [str(self.log_path)]

    @staticmethod
    def cleanup_directory(directory):
        if directory.resolve().parent == Path(__file__).resolve().parent and directory.name.startswith('dashboard-report-'):
            shutil.rmtree(directory)

    @staticmethod
    def stream_response(response):
        def events(*args):
            yield 'stdout', json.dumps({'event': 'init', 'init': {'model': MODEL}})
            yield 'stdout', json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': response}})
            yield 'exit', 0
        return events

    def configure(self):
        self.app.run(timeout=10)
        for label, value in (("API Key", "test-private-value"),
                             ("API Base URL", "https://example.invalid/v1"),
                             ("Model", "report-model")):
            next(t for t in self.app.text_input if t.label == label).set_value(value)
        self.app.run(timeout=10)

    def test_report_uses_only_agent1_and_survives_source_and_analysis_changes(self):
        self.app.session_state["analysis_result"]["note"] = "test-private-value"
        with patch("agent2.report.process_lines", side_effect=self.stream_response("# Báo cáo\nF-001 test-private-value")) as call:
            self.configure()
            call.assert_not_called()
            buttons = [b.key for b in self.app.main.button]
            self.assertEqual(buttons[-1], "generate_llm_report")
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            self.assertEqual(len(self.app.exception), 0)
            call.assert_called_once()
            prompt = str(call.call_args.args[3])
            self.assertIn("observed-payload", prompt)
            self.assertNotIn("F-001", prompt)
            payload = json.loads(json.loads(call.call_args.args[3])["message"]["content"].split("\n\n")[-1])
            self.assertEqual(set(payload), {"agent1_inputs"})
            self.assertNotIn("test-private-value", prompt)
            self.assertIn("[REDACTED]", self.app.session_state["llm_report"])
            self.assertEqual(len(self.app.get("download_button")), 1)
            self.app.run(timeout=10)
            call.assert_called_once()
            self.assertTrue(self.app.session_state["llm_report"])
            next(t for t in self.app.text_input if t.label == "Source Code Path").set_value("").run(timeout=10)
            self.app.session_state["analysis_result"] = None
            self.app.run(timeout=10)
            self.assertFalse(self.app.button(key="generate_llm_report").disabled)
            self.assertTrue(self.app.session_state["llm_report"])
            call.assert_called_once()

    def test_agent1_report_needs_no_api_configuration_analysis_or_source(self):
        self.app.session_state["analysis_result"] = None
        self.app.session_state["source_root"] = ""
        with patch("agent2.report.process_lines", side_effect=self.stream_response("# Báo cáo")) as call:
            self.configure()
            for label in ("API Key", "API Base URL", "Model"):
                next(t for t in self.app.text_input if t.label == label).set_value(" ")
            self.app.run(timeout=10)
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            call.assert_called_once()
            self.assertEqual(len(self.app.exception), 0)
            self.assertTrue(any("Gemini CLI" in e.value for e in self.app.success))
            self.app.button(key="clear_logs").click()
            self.app.run(timeout=10)
            self.assertTrue(self.app.button(key="generate_llm_report").disabled)
            self.assertEqual(self.app.session_state["llm_report"], "")

    def test_invalid_or_non_agent1_logs_do_not_enable_report(self):
        for contents in ('{"findings": []}', '{"schema_version": "agent1", "observations": null}', 'invalid json'):
            with self.subTest(contents=contents):
                self.log_path.write_text(contents, encoding="utf-8")
                self.app.run(timeout=10)
                self.assertEqual(len(self.app.exception), 0)
                self.assertTrue(self.app.button(key="generate_llm_report").disabled)

    def test_unreadable_selected_log_is_disclosed_with_valid_agent1_log(self):
        missing = str(Path(self.root) / "missing.json")
        self.app.session_state["selected_log_files"] = [str(self.log_path), missing]
        with patch("agent2.report.process_lines", side_effect=self.stream_response("# Báo cáo")) as call:
            self.configure()
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            payload = json.loads(json.loads(call.call_args.args[3])["message"]["content"].split("\n\n")[-1])
            self.assertEqual(payload["agent1_inputs"][1], {
                "log_path": missing, "availability": "unreadable_or_not_loaded",
            })

    def test_selected_agent1_log_is_in_prompt_and_changes_clear_old_report(self):
        path = Path(self.root) / "agent1.json"
        data = log()
        path.write_text(json.dumps(data), encoding="utf-8")
        self.app.session_state["selected_log_files"] = [str(path)]
        self.app.session_state["analysis_log_files"] = [str(path)]
        with patch("agent2.report.process_lines", side_effect=self.stream_response("# Báo cáo")) as call:
            self.configure()
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            wire = json.loads(call.call_args.args[3])
            payload = json.loads(wire["message"]["content"].split("\n\n")[-1])
            evidence = payload["agent1_inputs"][0]
            self.assertEqual(evidence["log_path"], str(path))
            self.assertIn("observed-payload", evidence["observations"][0]["request_content"])
            self.assertEqual(evidence["proposed_testcases"][0]["evidence_kind"], "proposed_testcase")
            self.assertNotIn("private-session", wire["message"]["content"])
            self.assertTrue(self.app.session_state["llm_report"])
            data["observations"][0]["response_key_text"] = "updated response"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.app.run(timeout=10)
            self.assertEqual(self.app.session_state["llm_report"], "")
            call.assert_called_once()

    def test_failure_is_redacted_and_retry_succeeds(self):
        # A failed CLI call must leave no report and allow a clean retry.
        responses = iter([LLMError("Timeout test-private-value"), "# Báo cáo mới"])
        def retry(*args):
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return self.stream_response(response)(*args)
        with patch("agent2.report.process_lines", side_effect=retry) as call:
            self.configure()
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            self.assertEqual(len(self.app.exception), 0)
            self.assertEqual(self.app.session_state["llm_report"], "")
            self.assertTrue(any("Không thể tạo báo cáo" in e.value for e in self.app.error))
            self.assertNotIn("test-private-value", str([e.value for e in self.app.error]))
            self.app.button(key="generate_llm_report").click().run(timeout=10)
            self.assertEqual(call.call_count, 2)
            self.assertEqual(self.app.session_state["llm_report"], "# Báo cáo mới")
            self.app.session_state["analysis_result"] = {"results": []}
            self.app.run(timeout=10)
            self.assertEqual(self.app.session_state["llm_report"], "# Báo cáo mới")
            replacement = Path(self.root) / "other-agent1.json"
            replacement.write_text(json.dumps(log()), encoding="utf-8")
            self.app.session_state["selected_log_files"] = [str(replacement)]
            self.app.run(timeout=10)
            self.assertEqual(self.app.session_state["llm_report"], "")

    def test_empty_or_non_text_response_is_not_a_report(self):
        for answer in (None, "", "  ", []):
            with self.subTest(answer=answer), patch("agent2.report.process_lines", side_effect=self.stream_response(answer)):
                with self.assertRaises(LLMError):
                    generate_report_cli({})


if __name__ == "__main__":
    unittest.main()
