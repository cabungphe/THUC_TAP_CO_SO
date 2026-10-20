"""Exercise the Burp/Jython source offline without Java, network or disk writes."""
import ast
import copy
import json
import os
from pathlib import Path
import re
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]


def load_source(filename, functions=(), methods=(), constants=()):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            nodes.append(node)
        elif isinstance(node, ast.ClassDef):
            nodes.extend(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name in methods)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            nodes.append(node)
    env = dict(copy=copy, json=json, os=os, re=re, time=time, unicode=str, basestring=str)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), filename, "exec"), env)
    return env


class Agent4ReplayTests(unittest.TestCase):
    def setUp(self):
        self.env = load_source("agent4_verify.py", functions=(
            "_to_unicode", "_one_line", "_compact_json", "_utf8_size", "_payload_size",
            "_compact_agent1_export_for_prompt", "_retest_cases_from_chain",
            "_local_retest_result", "_matching_observed_requests", "_list_all_agent1_exports",
            "_find_agent2_log_for_lab", "_find_agent3_instructions_for_lab",
        ), methods=("_call_agent4", "_build_body", "_current_lab", "_refresh_export_choices",
                    "_selected_export"), constants=(
            "AGENT4_SYSTEM_PROMPT", "AGENT4_JSON_TEMPLATE", "MAX_AGENT1_EXPORT_BYTES",
            "MAX_HTTP_RESPONSE_BYTES", "AGENT4_MAX_COMPLETION_TOKENS", "AGENT4_MODEL"))
        self.env.update(LABS_ROOT="labs", AGENT2_LOG_FOLDER="phan_tich_agent2",
                        WAF_SAFE_TRANSPORT=False, GROQ_API_KEY="test-only",
                        _request_response_format=lambda: {"type": "json_object"})
        self.request = "POST /form HTTP/1.1\r\nHost: lab\r\n\r\nx=%27+test+  \r\n"
        self.export = {
            "session": {"profile": "SQLi", "lab_name": "lab", "session_id": "SQLi_phien_01"},
            "observations": [{"step": 1, "request_content": self.request,
                              "target": {"location": "body", "parameter": "x"},
                              "verdict": "vulnerable", "response_key_text": "original evidence"}],
            "test_cases": [{"testcase_id": "TC-next", "generated_at_step": 1,
                            "payload_detail": "suggested, never executed"}],
        }

    def chain(self):
        return self.env["_compact_agent1_export_for_prompt"](self.export)[2]

    def run_worker(self, request=None, generated=None, failure=None):
        api = Mock()
        api.request_combined.return_value = (200, "", "test-model", generated, {})
        api.request_combined.side_effect = failure
        saved = []
        tab = SimpleNamespace(_extender=SimpleNamespace(_api=api), _callbacks=Mock())
        tab._build_body = lambda *args: self.env["_build_body"](tab, *args)
        tab._format_output = lambda *args: "rendered"
        tab._save_result = lambda result, *args: saved.append(copy.deepcopy(result))
        self.env.update(
            _load_agent1_export_from_path=lambda path: copy.deepcopy(self.export),
            SwingUtilities=SimpleNamespace(invokeLater=lambda item: None),
            UpdateUIIfCurrent=lambda *args: None, SetVerifyIfCurrent=lambda *args: None)
        self.env["_call_agent4"](tab, request or self.request, "HTTP/1.1 200 OK\r\n\r\nresponse",
                                 1, "SQLi", "chosen.json", "lab")
        return api, saved, tab

    def test_observed_request_preserves_body_encoding_and_whitespace(self):
        chain = self.chain()
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["payload_detail"], self.request)
        self.assertEqual(chain[0]["actual_result"]["response_key_text"], "original evidence")
        self.assertEqual(chain[0]["source_kind"], "observed_request")
        self.assertNotIn("suggested", json.dumps(chain))

    def test_legacy_keeps_all_suggestions_in_original_order_without_fake_execution(self):
        self.export["observations"][0].pop("request_content")
        self.export["test_cases"] = [dict(testcase_id="TC-%d" % i, generated_at_step=1,
                                          payload_detail="  payload\r\n") for i in range(15)]
        chain = self.chain()
        cases = self.env["_retest_cases_from_chain"](chain)
        self.assertEqual(len(cases), 15)
        self.assertEqual([c["testcase_id"] for c in cases], ["TC-%d" % i for i in range(15)])
        self.assertTrue(all(c["original_payload"] == "  payload\r\n" for c in cases))
        self.assertTrue(all(not c["actual_result"] for c in chain))
        self.assertTrue(all(c["source_kind"] == "legacy_suggestion" for c in chain))

    def test_partial_old_session_reports_missing_requests(self):
        self.export["observations"].append({"step": 2, "request_line": "POST /missing HTTP/1.1"})
        _, evidence, chain = self.env["_compact_agent1_export_for_prompt"](self.export)
        self.assertEqual(json.loads(evidence)["missing_request_steps"], [2])
        self.assertEqual(len(chain), 1)

    def test_model_cannot_replace_payload_target_or_add_testcases(self):
        generated = self.env["_local_retest_result"]([], "comparison")
        generated["retest_testcases"] = [{"retest_payload": "invented", "target": {"parameter": "wrong"}}]
        api, saved, _ = self.run_worker(generated=generated)
        api.request_combined.assert_called_once()
        cases = saved[0]["retest_testcases"]
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["retest_payload"], self.request)
        self.assertEqual(cases[0]["target"]["parameter"], "x")

    def test_changed_request_does_not_call_model_or_claim_fixed(self):
        api, saved, _ = self.run_worker(request=self.request.replace("/form", "/other"))
        api.request_combined.assert_not_called()
        self.assertEqual(saved[0]["verification_status"], "inconclusive")
        self.assertEqual(saved[0]["matched_observation_steps"], [])

    def test_api_failure_still_returns_exact_retest_cases(self):
        _, saved, _ = self.run_worker(failure=RuntimeError("offline"))
        self.assertEqual(saved[0]["verification_status"], "inconclusive")
        self.assertEqual(saved[0]["retest_testcases"][0]["original_payload"], self.request)

    def test_wrong_lab_or_profile_is_rejected(self):
        self.export["session"]["lab_name"] = "other-lab"
        api, saved, tab = self.run_worker()
        self.assertEqual(saved, [])
        api.request_combined.assert_not_called()
        tab._callbacks.printError.assert_called_once()

    def test_large_evidence_is_not_truncated_or_sent(self):
        self.export["observations"][0]["request_content"] = self.request + "z" * 40000
        api, saved, _ = self.run_worker(request=self.export["observations"][0]["request_content"])
        api.request_combined.assert_not_called()
        self.assertEqual(saved[0]["retest_testcases"][0]["retest_payload"],
                         self.export["observations"][0]["request_content"])

    def test_export_discovery_is_scoped_to_current_lab_and_profile(self):
        def listing(path):
            if path == "labs":
                return ["lab", "other-lab"]
            return ["agent1_SQLi_phien_01_cho_agent2.json", "agent1_LFI_phien_01_cho_agent2.json"]
        with patch.object(os.path, "isdir", return_value=True), \
             patch.object(os, "listdir", side_effect=listing), \
             patch.object(os.path, "getmtime", return_value=123):
            exports = self.env["_list_all_agent1_exports"]("SQLi", "lab")
        self.assertEqual(len(exports), 1)
        self.assertEqual(exports[0][1:3], ("lab", "SQLi"))

    def test_related_logs_never_fall_back_to_other_session(self):
        self.env["_list_agent2_logs"] = lambda lab: [(1, "agent2_SQLi_phien_010_20260101.json")]
        self.assertIsNone(self.env["_find_agent2_log_for_lab"]("lab", "SQLi_phien_01"))
        with patch.object(os.path, "isdir", return_value=True), \
             patch.object(os, "listdir", return_value=["agent3_fix_SQLi_phien_010.md"]), \
             patch.object(os.path, "getmtime", return_value=1):
            self.assertIsNone(self.env["_find_agent3_instructions_for_lab"]("lab", "SQLi_phien_01"))

    def test_lab_name_matches_agent1_host_port_sanitizing(self):
        service = SimpleNamespace(getHost=lambda: "test.local", getPort=lambda: 8080,
                                  getProtocol=lambda: "http")
        tab = SimpleNamespace(_controller=SimpleNamespace(getHttpService=lambda: service))
        self.assertEqual(self.env["_current_lab"](tab), "test.local_8080")

    def test_multiple_sessions_require_selection_and_keep_selected_path(self):
        class Combo:
            def __init__(self):
                self.index = -1
                self.items = []

            def getSelectedIndex(self):
                return self.index

            def setSelectedIndex(self, index):
                self.index = index

            def removeAllItems(self):
                self.items = []
                self.index = -1

            def addItem(self, item):
                self.items.append(item)

        choices = [("first.json", "lab", "SQLi", 2), ("second.json", "lab", "SQLi", 1)]
        self.env["_list_all_agent1_exports"] = lambda profile, lab: choices[:]
        tab = SimpleNamespace(_cmbSession=Combo(), _exportChoices=[], _syncingUi=False,
                              _current_lab=lambda: "lab", _selected_profile=lambda: "SQLi")
        tab._selected_export = lambda: self.env["_selected_export"](tab)
        self.env["_refresh_export_choices"](tab)
        self.assertEqual(tab._selected_export(), (None, None, None))
        tab._cmbSession.setSelectedIndex(2)
        choices.reverse()
        self.env["_refresh_export_choices"](tab)
        self.assertEqual(tab._selected_export()[0], "second.json")
        choices[:] = [("other.json", "other-lab", "SQLi", 3)]
        self.env["_refresh_export_choices"](tab)
        self.assertEqual(tab._selected_export()[0], "other.json")

    def test_agent1_exports_request_and_response_evidence_without_changes(self):
        env = load_source("agent1_tram.py", methods=("end_and_export",),
                          functions=("_best_verdict", "_to_unicode", "_one_line"),
                          constants=("_SEVERITY_RANK",))
        writes = []
        env.update(_now_iso=lambda: "now", MAX_SUMMARY_CHARS=4000,
                   _write_json_atomic=lambda path, data: writes.append(data))
        manager = SimpleNamespace(
            _lock=threading.Lock(), _lab_name="lab", _export_dir="exports", _callbacks=Mock(),
            _session=dict(status="active", session_id="SQLi_phien_01", profile="SQLi",
                          observations=self.export["observations"], test_cases=self.export["test_cases"]),
            _persist_locked=lambda: None, _has_confirmed_vulnerability=lambda obs: True)
        env["end_and_export"](manager)
        self.assertEqual(writes[0]["schema_version"], "agent1-to-agent2-1.3")
        self.assertEqual(writes[0]["observations"][0]["request_content"], self.request)
        self.assertEqual(writes[0]["observations"][0]["response_key_text"], "original evidence")
        self.assertEqual(writes[0]["test_cases"], self.export["test_cases"])


if __name__ == "__main__":
    unittest.main()
